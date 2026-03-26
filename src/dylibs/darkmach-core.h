/*
 * darkmach-core.h — Shared infrastructure for Darkmach interceptor dylibs
 * Structured JSON logging, timestamps, output management
 */
#ifndef DARKMACH_CORE_H
#define DARKMACH_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <malloc/malloc.h>
#include <mach/mach.h>

/* ── Log output ── */

static FILE *darkmach_log_file = NULL;
static pthread_mutex_t darkmach_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline void darkmach_log_init(const char *module) {
    if (darkmach_log_file) return;

    /* DARKMACH_OUTPUT_DIR is set by the CLI (e.g. output/actionnetwork/dynamic) */
    const char *out_dir = getenv("DARKMACH_OUTPUT_DIR");
    char path[512];

    if (out_dir && out_dir[0]) {
        snprintf(path, sizeof(path), "%s/darkmach-%s.jsonl", out_dir, module);
        darkmach_log_file = fopen(path, "a");
    }
    /* Fallback to /tmp */
    if (!darkmach_log_file) {
        snprintf(path, sizeof(path), "/tmp/darkmach-%s.jsonl", module);
        darkmach_log_file = fopen(path, "a");
    }
    if (darkmach_log_file) {
        setvbuf(darkmach_log_file, NULL, _IOLBF, 0); /* line buffered */
        fprintf(stderr, "[darkmach-%s] logging to %s\n", module, path);
    }
}

static inline void darkmach_log(const char *module, const char *event, const char *json_data) {
    if (!darkmach_log_file) darkmach_log_init(module);
    if (!darkmach_log_file) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    char ts[64];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec/1000));

    pthread_mutex_lock(&darkmach_log_mutex);
    fprintf(darkmach_log_file,
            "{\"ts\":\"%s\",\"mod\":\"%s\",\"evt\":\"%s\",%s}\n",
            ts, module, event, json_data);
    pthread_mutex_unlock(&darkmach_log_mutex);
}

/* ── ObjC helpers ── */

/* Check if an object is a kind of class (safe runtime check) */
static inline BOOL darkmach_isKindOfClass(id obj, const char *className) {
    if (!obj) return NO;
    Class cls = objc_getClass(className);
    if (!cls) return NO;
    SEL sel = sel_registerName("isKindOfClass:");
    BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
    return isKind(obj, sel, cls);
}

/* Get NSString contents as C string — safe for any object type */
static inline const char *nsstring_to_c(id nsstr) {
    if (!nsstr) return "(null)";
    /* Only send UTF8String if it's actually an NSString */
    if (darkmach_isKindOfClass(nsstr, "NSString") ||
        darkmach_isKindOfClass(nsstr, "__NSCFString") ||
        darkmach_isKindOfClass(nsstr, "__NSCFConstantString")) {
        SEL sel = sel_registerName("UTF8String");
        const char *(*utf8)(id, SEL) = (const char *(*)(id, SEL))objc_msgSend;
        const char *result = utf8(nsstr, sel);
        return result ? result : "(null)";
    }
    /* For non-string objects, use description -> UTF8String */
    SEL descSel = sel_registerName("description");
    id (*desc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id descStr = desc(nsstr, descSel);
    if (descStr && descStr != nsstr) {
        SEL sel = sel_registerName("UTF8String");
        const char *(*utf8)(id, SEL) = (const char *(*)(id, SEL))objc_msgSend;
        const char *result = utf8(descStr, sel);
        return result ? result : "(null)";
    }
    return "(unknown)";
}

/* Check if a pointer is readable without causing SIGSEGV.
 * Uses vm_read_overwrite to probe a single byte at the address.
 * Lightweight alternative to vm_region_64 — one Mach trap, no
 * region iteration. Used to validate C string pointers returned
 * by -description/-UTF8String on partially-constructed objects. */
static inline int is_readable_ptr(const void *ptr) {
    if (!ptr || (uintptr_t)ptr < 0x4000) return 0;
    char buf;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                          (vm_address_t)ptr, 1,
                                          (vm_address_t)&buf, &out);
    return (kr == KERN_SUCCESS && out == 1);
}

/* Check if a pointer looks like a valid ObjC object.
 * Uses malloc_zone_from_ptr to verify heap allocation, then
 * checks that object_getClass returns a known registered class.
 * This prevents SIGSEGV from dereferencing deallocated pointers. */
static inline int is_valid_objc_ptr(const void *ptr) {
    if (!ptr) return 0;
    /* Reject obviously bad addresses (low pages, odd alignment) */
    if ((uintptr_t)ptr < 0x1000) return 0;
    /* Tagged pointers are always safe — high bit set on arm64 */
    if ((uintptr_t)ptr & (1ULL << 63)) return 1;
    /* Check if address is in a known malloc zone (heap-allocated) */
    if (!malloc_zone_from_ptr(ptr)) return 0;
    /* Verify isa points to a registered class */
    Class cls = object_getClass((id)ptr);
    if (!cls) return 0;
    /* objc_lookUpClass returns nil if the class name isn't registered */
    const char *name = class_getName(cls);
    if (!name || name[0] == '\0') return 0;
    return 1;
}

/* Get NSString description of any object (crash-safe).
 * Validates the const char* from UTF8String using is_readable_ptr
 * to catch garbage pointers from partially-constructed objects
 * where -description runs but returns corrupted data. */
static inline const char *nsobject_desc(id obj) {
    if (!obj) return "(null)";
    if (!is_valid_objc_ptr(obj)) return "(invalid object)";
    @try {
        SEL sel = sel_registerName("description");
        id (*desc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id result = desc(obj, sel);
        if (!result) return "(null)";
        /* Validate that the description result is a valid ObjC object
         * before sending UTF8String — it could be garbage from a
         * partially-constructed object's -description */
        if (!is_valid_objc_ptr(result)) return "(invalid description)";
        SEL utf8sel = sel_registerName("UTF8String");
        const char *(*utf8)(id, SEL) = (const char *(*)(id, SEL))objc_msgSend;
        const char *cstr = utf8(result, utf8sel);
        /* Guard against garbage pointers: probe the memory before
         * any strlen/snprintf touches it. is_readable_ptr uses
         * vm_read_overwrite to verify the address is mapped. */
        if (!cstr || !is_readable_ptr(cstr)) return "(null)";
        return cstr;
    } @catch (id ex) {
        return "(invalid object)";
    }
}

/* Safely get integer value from NSNumber */
static inline long nsnumber_long(id num) {
    if (!num) return 0;
    SEL sel = sel_registerName("longValue");
    long (*longVal)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    return longVal(num, sel);
}

/* ── String escaping for JSON ── */

static inline void json_escape(const char *src, char *dst, size_t dst_size) {
    if (!src) { snprintf(dst, dst_size, "null"); return; }

    size_t j = 0;
    dst[j++] = '"';
    for (size_t i = 0; src[i] && j < dst_size - 3; i++) {
        switch (src[i]) {
            case '"':  if (j+2 < dst_size-1) { dst[j++]='\\'; dst[j++]='"'; } break;
            case '\\': if (j+2 < dst_size-1) { dst[j++]='\\'; dst[j++]='\\'; } break;
            case '\n': if (j+2 < dst_size-1) { dst[j++]='\\'; dst[j++]='n'; } break;
            case '\r': if (j+2 < dst_size-1) { dst[j++]='\\'; dst[j++]='r'; } break;
            case '\t': if (j+2 < dst_size-1) { dst[j++]='\\'; dst[j++]='t'; } break;
            default:
                if ((unsigned char)src[i] >= 0x20) {
                    dst[j++] = src[i];
                }
                break;
        }
    }
    dst[j++] = '"';
    dst[j] = '\0';
}

/* ── Method swizzling ── */

static inline void darkmach_swizzle(Class cls, SEL orig_sel, SEL new_sel) {
    Method orig = class_getInstanceMethod(cls, orig_sel);
    Method swiz = class_getInstanceMethod(cls, new_sel);
    if (!orig || !swiz) return;

    BOOL added = class_addMethod(cls, orig_sel,
                                  method_getImplementation(swiz),
                                  method_getTypeEncoding(swiz));
    if (added) {
        class_replaceMethod(cls, new_sel,
                           method_getImplementation(orig),
                           method_getTypeEncoding(orig));
    } else {
        method_exchangeImplementations(orig, swiz);
    }
}

/* ═══════════════════════════════════════════════════════════════
 *  Ring buffer — fixed-capacity circular buffer for tap commands
 *  Used by: net_tap, crypto_tap, auth_tap, event_tap (Sprints 13.1-13.2)
 * ═══════════════════════════════════════════════════════════════ */

#define DARKMACH_RING_CAPACITY 500
#define DARKMACH_RING_ENTRY_SIZE 4096  /* max bytes per entry */

typedef struct {
    char entries[DARKMACH_RING_CAPACITY][DARKMACH_RING_ENTRY_SIZE];
    int head;       /* next write position */
    int count;      /* entries written (capped at CAPACITY) */
    int total;      /* total entries ever written */
} darkmach_ring_t;

static inline void darkmach_ring_init(darkmach_ring_t *ring) {
    memset(ring, 0, sizeof(*ring));
}

static inline void darkmach_ring_push(darkmach_ring_t *ring, const char *entry) {
    strlcpy(ring->entries[ring->head], entry, DARKMACH_RING_ENTRY_SIZE);
    ring->head = (ring->head + 1) % DARKMACH_RING_CAPACITY;
    if (ring->count < DARKMACH_RING_CAPACITY) ring->count++;
    ring->total++;
}

/* Get the Nth most recent entry (0 = most recent). Returns NULL if out of range. */
static inline const char *darkmach_ring_get(darkmach_ring_t *ring, int n) {
    if (n < 0 || n >= ring->count) return NULL;
    int idx = (ring->head - 1 - n + DARKMACH_RING_CAPACITY) % DARKMACH_RING_CAPACITY;
    return ring->entries[idx];
}

/* ═══════════════════════════════════════════════════════════════
 *  Hook table — method tracing infrastructure for trace command
 *  Used by: trace command (Sprint 13.3)
 *  Reference: dev/frida-gum-interceptor-study.md sections 9.2-9.3
 * ═══════════════════════════════════════════════════════════════ */

#define DARKMACH_MAX_HOOKS 256  /* matches static stub count in trampoline.S */
#define DARKMACH_TRACE_LOG_SIZE 500  /* per-hook trace log ring buffer size */

typedef struct {
    Class cls;                  /* hooked class */
    SEL sel;                    /* hooked selector */
    IMP original_imp;           /* saved original implementation */
    char class_name[128];       /* cached class name string */
    char sel_name[256];         /* cached selector name string */
    char type_encoding[512];    /* method type encoding for arg formatting */
    int active;                 /* 1 = hook installed, 0 = slot free */
    int call_count;             /* number of times this hook has fired */
    int verbose;                /* 1 = use -description for @ args (expensive,
                                 * can crash on partially-constructed objects),
                                 * 0 = safe <ClassName: 0xaddr> format (default) */
} darkmach_hook_t;
/* sizeof(darkmach_hook_t) = 936 (928 + 4 verbose + 4 padding for 8-byte align).
 * MUST match HOOK_SIZEOF in darkmach-trampoline.S — update both together. */

/* Global hook table — indexed by stub slot number */
/* Defined in cmd-trace.c, declared here for trampoline access */

/* ═══════════════════════════════════════════════════════════════
 *  Heap scan results — for heap_dump command
 *  Used by: heap_dump (Sprint 13.1)
 *  Reference: dev/frida-gum-heap-study.md
 * ═══════════════════════════════════════════════════════════════ */

#define DARKMACH_HEAP_MAX_RESULTS 10000

typedef struct {
    uintptr_t address;
    size_t size;
} darkmach_heap_candidate_t;

typedef struct {
    darkmach_heap_candidate_t candidates[DARKMACH_HEAP_MAX_RESULTS];
    int count;
} darkmach_heap_scan_t;

/* ═══════════════════════════════════════════════════════════════
 *  Reentrancy guard — prevents recursive trace logging
 *  Used by: trace command to prevent infinite recursion when
 *  traced methods call other traced methods.
 * ═══════════════════════════════════════════════════════════════ */

/* Key for pthread thread-local storage. Initialized once in bridge constructor.
   When non-NULL, the current thread is inside a trace handler — skip logging. */
/* Defined in cmd-trace.c: pthread_key_t darkmach_guard_key; */

#endif /* DARKMACH_CORE_H */
