/* Unity build: #included from bridge/darkmach-bridge.c, not compiled standalone. */
#include "darkmach-bridge.h"
#include <mach/mach_time.h>

/* Legacy hook_method/unhook_method — kept for compat; new code uses trace/untrace. */

#define MAX_HOOKS 64
static struct {
    char className[256];
    char methodName[256];
    IMP originalImp;
    SEL selector;
    Class cls;
    int active;
} hooks[MAX_HOOKS];
static int hook_count = 0;

/* Non-static: darkmach-trampoline.S resolves _darkmach_hook_table at link time. */
darkmach_hook_t darkmach_hook_table[DARKMACH_MAX_HOOKS];

/* Defined in darkmach-trampoline.S; STUB_SIZE must match the stub width there. */
extern char darkmach_stub_table[];

#define STUB_SIZE 12

static inline IMP darkmach_stub_imp(int n) {
    return (IMP)((char *)&darkmach_stub_table + n * STUB_SIZE);
}

/* Without this guard a traced method calling another traced method recurses forever. */
static pthread_key_t darkmach_guard_key;
static int guard_key_initialized = 0;

static inline void trace_guard_init(void) {
    if (!guard_key_initialized) {
        pthread_key_create(&darkmach_guard_key, NULL);
        guard_key_initialized = 1;
    }
}

static inline int trace_guard_enter(void) {
    if (pthread_getspecific(darkmach_guard_key)) return 0;
    pthread_setspecific(darkmach_guard_key, (void *)1);
    return 1;
}

static inline void trace_guard_leave(void) {
    pthread_setspecific(darkmach_guard_key, NULL);
}

static darkmach_ring_t trace_log_ring;
static int trace_log_initialized = 0;

static inline void trace_log_init(void) {
    if (!trace_log_initialized) {
        darkmach_ring_init(&trace_log_ring);
        trace_log_initialized = 1;
    }
}

static int trace_active_count(void) {
    int count = 0;
    for (int i = 0; i < DARKMACH_MAX_HOOKS; i++) {
        if (darkmach_hook_table[i].active) count++;
    }
    return count;
}

static int trace_find_free_slot(void) {
    for (int i = 0; i < DARKMACH_MAX_HOOKS; i++) {
        if (!darkmach_hook_table[i].active) return i;
    }
    return -1;
}

static int trace_find_hook(Class cls, SEL sel) {
    for (int i = 0; i < DARKMACH_MAX_HOOKS; i++) {
        if (darkmach_hook_table[i].active &&
            darkmach_hook_table[i].cls == cls &&
            darkmach_hook_table[i].sel == sel) {
            return i;
        }
    }
    return -1;
}

static const char *typeenc_describe(char c) {
    switch (c) {
        case 'v': return "void";
        case 'c': return "char";
        case 'i': return "int";
        case 's': return "short";
        case 'l': return "long";
        case 'q': return "long long";
        case 'C': return "unsigned char";
        case 'I': return "unsigned int";
        case 'S': return "unsigned short";
        case 'L': return "unsigned long";
        case 'Q': return "unsigned long long";
        case 'f': return "float";
        case 'd': return "double";
        case 'B': return "BOOL";
        case '@': return "id";
        case '#': return "Class";
        case ':': return "SEL";
        case '*': return "char*";
        case '^': return "pointer";
        case '?': return "unknown";
        case '{': return "struct";
        case '[': return "array";
        default:  return "?";
    }
}

static void typeenc_to_arg_types(const char *enc, resp_t *r) {
    if (!enc || !enc[0]) {
        resp_append(r, "[]");
        return;
    }
    resp_append(r, "[");
    int arg_idx = 0;
    int first = 1;
    const char *p = enc;
    while (*p) {
        if (*p >= '0' && *p <= '9') { p++; continue; }

        char type_char = *p;
        const char *desc = NULL;

        if (arg_idx == 0) {
            desc = "id (self)";
        } else if (arg_idx == 1) {
            desc = "SEL (_cmd)";
        } else {
            desc = typeenc_describe(type_char);
        }

        if (!first) resp_append(r, ",");
        resp_append(r, "\"%s\"", desc);
        first = 0;
        arg_idx++;

        if (*p == '{') {
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
                p++;
            }
            continue;
        } else if (*p == '[') {
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '[') depth++;
                else if (*p == ']') depth--;
                p++;
            }
            continue;
        } else if (*p == '^') {
            p++;
            if (*p && *p != '0' && !(*p >= '0' && *p <= '9')) p++;
            continue;
        } else if (*p == '@') {
            p++;
            if (*p == '?') { p++; }
            else if (*p == '"') {
                p++;
                while (*p && *p != '"') p++;
                if (*p == '"') p++;
            }
            continue;
        }
        p++;
    }
    resp_append(r, "]");
}

/* raw_value is an untyped register word: validate before dereferencing, and never message
 * an object — -description on a partially-constructed one reads uninitialized ivars. */
static void format_arg_value(char *buf, size_t bufsz, char type_char,
                             uintptr_t raw_value, int verbose) {
    switch (type_char) {
        case '@': {
            id obj = (id)raw_value;
            if (!obj) {
                snprintf(buf, bufsz, "nil");
            } else if (is_valid_objc_ptr(obj)) {
                if (verbose) {
                    const char *desc = nsobject_desc(obj);
                    if (!desc || !is_readable_ptr(desc)) {
                        Class cls = object_getClass(obj);
                        const char *cls_name = class_getName(cls);
                        snprintf(buf, bufsz, "<%s: 0x%lx>",
                                 cls_name, (unsigned long)raw_value);
                    } else if (strlen(desc) > 256) {
                        snprintf(buf, bufsz, "%.253s...", desc);
                    } else {
                        snprintf(buf, bufsz, "%s", desc);
                    }
                } else {
                    Class cls = object_getClass(obj);
                    const char *cls_name = class_getName(cls);
                    snprintf(buf, bufsz, "<%s: 0x%lx>",
                             cls_name, (unsigned long)raw_value);
                }
            } else {
                snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            }
            break;
        }
        case '#': {
            Class c = (Class)raw_value;
            if (!c) {
                snprintf(buf, bufsz, "nil");
            } else {
                const char *name = class_getName(c);
                if (name && is_readable_ptr(name)) {
                    snprintf(buf, bufsz, "%s", name);
                } else {
                    snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
                }
            }
            break;
        }
        case ':': {
            SEL s = (SEL)raw_value;
            if (!s) {
                snprintf(buf, bufsz, "nil");
            } else {
                const char *name = sel_getName(s);
                if (name && is_readable_ptr(name)) {
                    snprintf(buf, bufsz, "%s", name);
                } else {
                    snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
                }
            }
            break;
        }
        case '*': {
            const char *s = (const char *)raw_value;
            if (s && is_readable_ptr(s)) {
                snprintf(buf, bufsz, "%.256s", s);
            } else {
                snprintf(buf, bufsz, "NULL");
            }
            break;
        }
        case 'i': case 'l':
            snprintf(buf, bufsz, "%d", (int)raw_value);
            break;
        case 'q':
            snprintf(buf, bufsz, "%lld", (long long)raw_value);
            break;
        case 'Q':
            snprintf(buf, bufsz, "%llu", (unsigned long long)raw_value);
            break;
        case 'I': case 'L':
            snprintf(buf, bufsz, "%u", (unsigned int)raw_value);
            break;
        case 'f': {
            /* f and d arrive in SIMD registers — the saved GP word is not the value. */
            snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            break;
        }
        case 'd': {
            snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            break;
        }
        case 'B':
            snprintf(buf, bufsz, "%s", raw_value ? "YES" : "NO");
            break;
        case 'v':
            snprintf(buf, bufsz, "void");
            break;
        default:
            snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            break;
    }
}

/* Called from darkmach-trampoline.S via BL, hence external linkage; the stub prologue
 * there defines the saved_regs layout this reads. */
void darkmach_on_method_enter(darkmach_hook_t *hook, void *saved_regs) {
    if (!trace_guard_enter()) return;

    trace_log_init();

    uintptr_t *gp_regs = (uintptr_t *)saved_regs;

    /* Non-atomic: a lost increment under concurrency is acceptable, per-call atomics are not. */
    hook->call_count++;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char ts[64];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));

    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);

    int slot = (int)(hook - darkmach_hook_table);

    const char *enc = hook->type_encoding;
    int enc_len = (int)strlen(enc);

    char args_json[2048];
    int apos = 0;
    apos += snprintf(args_json + apos, sizeof(args_json) - apos, "{");

    if (enc_len > 0) {
        const char *p = enc;
        int arg_idx = 0;
        int first_user_arg = 1;

        while (*p && apos < (int)sizeof(args_json) - 200) {
            if (*p >= '0' && *p <= '9') { p++; continue; }

            char type_char = *p;

            /* Encoding index 0 is the return type, 1 is self (X0), 2 is _cmd (X1),
             * so the register for encoding index N is gp_regs[N-1]. */
            if (arg_idx >= 3 && arg_idx <= 9) {
                int reg_idx = arg_idx - 1;
                if (reg_idx < 8) {
                    uintptr_t val = gp_regs[reg_idx];
                    char val_buf[512];
                    format_arg_value(val_buf, sizeof(val_buf), type_char, val,
                                     hook->verbose);

                    char val_esc[1024];
                    json_escape(val_buf, val_esc, sizeof(val_esc));

                    if (!first_user_arg)
                        apos += snprintf(args_json + apos,
                                        sizeof(args_json) - apos, ",");
                    apos += snprintf(args_json + apos,
                                    sizeof(args_json) - apos,
                                    "\"arg%d\":{\"type\":\"%s\",\"value\":%s}",
                                    arg_idx,
                                    typeenc_describe(type_char),
                                    val_esc);
                    first_user_arg = 0;
                }
            }
            arg_idx++;

            if (*p == '{') {
                int depth = 1; p++;
                while (*p && depth > 0) {
                    if (*p == '{') depth++;
                    else if (*p == '}') depth--;
                    p++;
                }
            } else if (*p == '[') {
                int depth = 1; p++;
                while (*p && depth > 0) {
                    if (*p == '[') depth++;
                    else if (*p == ']') depth--;
                    p++;
                }
            } else if (*p == '@') {
                p++;
                if (*p == '?') p++;
                else if (*p == '"') {
                    p++;
                    while (*p && *p != '"') p++;
                    if (*p == '"') p++;
                }
            } else if (*p == '^') {
                p++;
                if (*p && !(*p >= '0' && *p <= '9')) p++;
            } else {
                p++;
            }
        }
    }
    apos += snprintf(args_json + apos, sizeof(args_json) - apos, "}");

    char entry[DARKMACH_RING_ENTRY_SIZE];
    char cls_esc[256], sel_esc[512];
    json_escape(hook->class_name, cls_esc, sizeof(cls_esc));
    json_escape(hook->sel_name, sel_esc, sizeof(sel_esc));

    snprintf(entry, sizeof(entry),
             "{\"slot\":%d,\"class\":%s,\"method\":%s,"
             "\"timestamp\":\"%s\",\"thread_id\":\"0x%llx\","
             "\"args\":%s,\"call_count\":%d}",
             slot, cls_esc, sel_esc,
             ts, (unsigned long long)tid,
             args_json, hook->call_count);

    darkmach_ring_push(&trace_log_ring, entry);

    char log_data[512];
    snprintf(log_data, sizeof(log_data),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\","
             "\"call_count\":%d",
             slot, hook->class_name, hook->sel_name, hook->call_count);
    darkmach_log(MOD, "trace_call", log_data);

    trace_guard_leave();
}

static int trace_install_hook(Class cls, SEL sel, const char *className,
                              const char *methodName, int is_class_method,
                              resp_t *r) {
    int existing = trace_find_hook(cls, sel);
    if (existing >= 0) {
        if (r) resp_append(r, "\"error\":\"already traced (slot %d)\"", existing);
        return -1;
    }

    int slot = trace_find_free_slot();
    if (slot < 0) {
        if (r) resp_append(r, "\"error\":\"all 256 trace slots full\"");
        return -1;
    }

    Method m;
    if (is_class_method) {
        m = class_getClassMethod(cls, sel);
    } else {
        m = class_getInstanceMethod(cls, sel);
    }
    if (!m) {
        if (r) resp_append(r, "\"error\":\"method not found\"");
        return -1;
    }

    darkmach_hook_t *hook = &darkmach_hook_table[slot];
    hook->cls = cls;
    hook->sel = sel;
    hook->original_imp = method_getImplementation(m);
    strlcpy(hook->class_name, className, sizeof(hook->class_name));
    strlcpy(hook->sel_name, methodName, sizeof(hook->sel_name));

    const char *enc = method_getTypeEncoding(m);
    if (enc) {
        strlcpy(hook->type_encoding, enc, sizeof(hook->type_encoding));
    } else {
        hook->type_encoding[0] = '\0';
    }
    hook->call_count = 0;
    hook->verbose = 0;

    method_setImplementation(m, darkmach_stub_imp(slot));
    hook->active = 1;

    return slot;
}

#define TRACE_MAX_SUBCLASSES 256
#define TRACE_SHADOW_BUDGET 8

typedef struct {
    Class items[TRACE_MAX_SUBCLASSES];
    int count;
} class_set_t;

static void class_set_add(class_set_t *set, Class c) {
    for (int i = 0; i < set->count; i++) {
        if (set->items[i] == c) return;
    }
    if (set->count < TRACE_MAX_SUBCLASSES) set->items[set->count++] = c;
}

static void class_set_json(const class_set_t *set, resp_t *r) {
    resp_append(r, "[");
    for (int i = 0; i < set->count; i++) {
        if (i > 0) resp_append(r, ",");
        resp_append_json_str(r, class_getName(set->items[i]));
    }
    resp_append(r, "]");
}

static void class_set_build_subclasses(Class cls, class_set_t *set) {
    set->count = 0;
    unsigned int n = 0;
    Class *all = objc_copyClassList(&n);
    if (!all) return;
    for (unsigned int i = 0; i < n; i++) {
        for (Class s = class_getSuperclass(all[i]); s; s = class_getSuperclass(s)) {
            if (s != cls) continue;
            class_set_add(set, all[i]);
            break;
        }
    }
    free(all);
}

/* Subclasses that declare `sel` themselves: a send to one of them stops at its own
 * Method, so swizzling only `base` never sees it — the class-cluster blind spot. */
static void class_set_shadowing(const class_set_t *subs, SEL sel, Method base,
                                class_set_t *out) {
    Method seen[TRACE_MAX_SUBCLASSES];
    int seen_count = 0;
    out->count = 0;

    for (int i = 0; i < subs->count; i++) {
        Method m = class_getInstanceMethod(subs->items[i], sel);
        if (!m || m == base) continue;

        int dup = 0;
        for (int j = 0; j < seen_count; j++) {
            if (seen[j] == m) { dup = 1; break; }
        }
        if (dup) continue;

        seen[seen_count++] = m;
        class_set_add(out, subs->items[i]);
    }
}

/* Budgeted: NSArray's `count` is shadowed 60 ways, and one trace must not consume the
 * whole hook table. Anything past the budget is reported instead of hooked. */
static void trace_install_shadows(const class_set_t *shadows, SEL sel,
                                  const char *methodName, class_set_t *hooked) {
    int budget = shadows->count < TRACE_SHADOW_BUDGET
                     ? shadows->count : TRACE_SHADOW_BUDGET;

    for (int i = 0; i < budget; i++) {
        const char *sub_name = class_getName(shadows->items[i]);
        resp_t tmp = resp_new();
        int slot = trace_install_hook(shadows->items[i], sel, sub_name,
                                      methodName, 0, &tmp);
        resp_free(&tmp);
        if (slot >= 0) class_set_add(hooked, shadows->items[i]);
    }
}

/* Shadow hooks go in with the front hook, so they must come out with it — otherwise
 * untrace leaves the concrete subclasses swizzled with no table entry naming them. */
static void trace_remove_shadows(Class front, SEL sel, class_set_t *removed) {
    for (int i = 0; i < DARKMACH_MAX_HOOKS; i++) {
        darkmach_hook_t *h = &darkmach_hook_table[i];
        if (!h->active || h->sel != sel || h->cls == front) continue;

        int descends = 0;
        for (Class s = class_getSuperclass(h->cls); s; s = class_getSuperclass(s)) {
            if (s == front) { descends = 1; break; }
        }
        if (!descends) continue;

        Method m = class_getInstanceMethod(h->cls, sel);
        if (m) method_setImplementation(m, h->original_imp);
        h->active = 0;
        class_set_add(removed, h->cls);
    }
}

static void generic_hook(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    const char *sel = sel_getName(_cmd);

    char data[2048];
    snprintf(data, sizeof(data),
             "\"class\":\"%s\",\"method\":\"%s\",\"address\":\"0x%lx\"",
             cls, sel, (unsigned long)self);
    darkmach_log(MOD, "hook_call", data);
    fprintf(stderr, "[darkmach-bridge] HOOK: [%s %s] @ 0x%lx\n",
            cls, sel, (unsigned long)self);

    for (int i = 0; i < hook_count; i++) {
        if (hooks[i].active && hooks[i].selector == _cmd &&
            hooks[i].cls == object_getClass(self)) {
            void (*orig)(id, SEL) = (void (*)(id, SEL))hooks[i].originalImp;
            orig(self, _cmd);
            return;
        }
    }
}

static void cmd_hook_method(const char *args, resp_t *r) {
    char className[256], methodName[256];
    if (!json_get_string(args, "class", className, sizeof(className)) ||
        !json_get_string(args, "method", methodName, sizeof(methodName))) {
        resp_append(r, "\"error\":\"missing class or method arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) { resp_append(r, "\"error\":\"class not found\""); return; }

    SEL sel = sel_registerName(methodName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { resp_append(r, "\"error\":\"method not found\""); return; }

    if (hook_count >= MAX_HOOKS) {
        resp_append(r, "\"error\":\"max hooks reached\"");
        return;
    }

    for (int i = 0; i < hook_count; i++) {
        if (hooks[i].active && hooks[i].cls == cls && hooks[i].selector == sel) {
            resp_append(r, "\"error\":\"already hooked\"");
            return;
        }
    }

    int idx = hook_count++;
    strncpy(hooks[idx].className, className, sizeof(hooks[idx].className) - 1);
    strncpy(hooks[idx].methodName, methodName, sizeof(hooks[idx].methodName) - 1);
    hooks[idx].originalImp = method_getImplementation(m);
    hooks[idx].selector = sel;
    hooks[idx].cls = cls;
    hooks[idx].active = 1;

    method_setImplementation(m, (IMP)generic_hook);

    class_set_t subs, shadows;
    class_set_build_subclasses(cls, &subs);
    class_set_shadowing(&subs, sel, m, &shadows);

    resp_append(r, "\"hooked\":true,\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"shadowed_by\":");
    class_set_json(&shadows, r);
    resp_append(r, ",\"hookIndex\":%d", idx);

    char log_buf[1024];
    snprintf(log_buf, sizeof(log_buf),
             "\"class\":\"%s\",\"method\":\"%s\"", className, methodName);
    darkmach_log(MOD, "hook_install", log_buf);
}

static void cmd_unhook_method(const char *args, resp_t *r) {
    char className[256], methodName[256];
    if (!json_get_string(args, "class", className, sizeof(className)) ||
        !json_get_string(args, "method", methodName, sizeof(methodName))) {
        resp_append(r, "\"error\":\"missing class or method arg\"");
        return;
    }

    for (int i = 0; i < hook_count; i++) {
        if (hooks[i].active &&
            strcmp(hooks[i].className, className) == 0 &&
            strcmp(hooks[i].methodName, methodName) == 0) {

            Method m = class_getInstanceMethod(hooks[i].cls, hooks[i].selector);
            if (m) method_setImplementation(m, hooks[i].originalImp);
            hooks[i].active = 0;

            resp_append(r, "\"unhooked\":true,\"class\":");
            resp_append_json_str(r, className);
            resp_append(r, ",\"method\":");
            resp_append_json_str(r, methodName);
            return;
        }
    }
    resp_append(r, "\"error\":\"hook not found\"");
}

static void cmd_trace(const char *args, resp_t *r) {
    trace_guard_init();
    trace_log_init();

    char className[256], methodName[256];
    if (!json_get_string(args, "class", className, sizeof(className)) ||
        !json_get_string(args, "method", methodName, sizeof(methodName))) {
        resp_append(r, "\"error\":\"missing class or method arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) { resp_append(r, "\"error\":\"class not found\""); return; }

    SEL sel = sel_registerName(methodName);

    int is_class_method = 0;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        m = class_getClassMethod(cls, sel);
        if (m) is_class_method = 1;
    }
    if (!m) { resp_append(r, "\"error\":\"method not found\""); return; }

    int slot = trace_install_hook(cls, sel, className, methodName,
                                  is_class_method, r);
    if (slot < 0) return;

    class_set_t shadows = { .count = 0 };
    class_set_t also = { .count = 0 };
    if (!is_class_method) {
        class_set_t subs;
        class_set_build_subclasses(cls, &subs);
        class_set_shadowing(&subs, sel, m, &shadows);
        trace_install_shadows(&shadows, sel, methodName, &also);
    }

    darkmach_hook_t *hook = &darkmach_hook_table[slot];

    resp_append(r, "\"hooked\":true,\"slot\":%d,\"class\":", slot);
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"shadowed_by\":");
    class_set_json(&shadows, r);
    resp_append(r, ",\"also_hooked\":");
    class_set_json(&also, r);
    resp_append(r, ",\"untraced_shadows\":%d", shadows.count - also.count);
    resp_append(r, ",\"type_encoding\":");
    resp_append_json_str(r, hook->type_encoding);
    resp_append(r, ",\"arg_types\":");
    typeenc_to_arg_types(hook->type_encoding, r);

    char log_buf[1024];
    snprintf(log_buf, sizeof(log_buf),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\","
             "\"type_encoding\":\"%s\"",
             slot, className, methodName, hook->type_encoding);
    darkmach_log(MOD, "trace_install", log_buf);
}

/* Memory-management methods recurse infinitely through the trampoline, and construction
 * methods fire while ivars are uninitialized so any message send there can crash. */
static int is_unsafe_method(const char *name) {
    static const char *unsafe[] = {
        "dealloc", ".cxx_destruct", ".cxx_construct",
        "retain", "release", "autorelease",
        "class", "respondsToSelector:", "methodSignatureForSelector:",
        "forwardInvocation:", "doesNotRecognizeSelector:",
        "isKindOfClass:", "isMemberOfClass:", "conformsToProtocol:",
        "isEqual:", "hash", "self", "performSelector:",
        "performSelector:withObject:", "performSelector:withObject:withObject:",
        "description", "debugDescription",
        NULL
    };
    for (int i = 0; unsafe[i]; i++) {
        if (strcmp(name, unsafe[i]) == 0) return 1;
    }
    if (strncmp(name, "init", 4) == 0) {
        /* The uppercase/colon test keeps "initialize" out of the block list. */
        char next = name[4];
        if (next == '\0' || (next >= 'A' && next <= 'Z') || next == ':') {
            return 1;
        }
    }
    if (name[0] == '_') return 1;
    return 0;
}

static void cmd_trace_class(const char *args, resp_t *r) {
    trace_guard_init();
    trace_log_init();

    char className[256];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) { resp_append(r, "\"error\":\"class not found\""); return; }

    unsigned int method_count = 0;
    Method *methods = class_copyMethodList(cls, &method_count);
    if (!methods || method_count == 0) {
        resp_append(r, "\"error\":\"no methods found\"");
        if (methods) free(methods);
        return;
    }

    class_set_t subs;
    class_set_build_subclasses(cls, &subs);
    class_set_t shadows = { .count = 0 };

    int hooked = 0;
    int skipped = 0;
    char hooked_methods[8192];
    int hpos = 0;
    hpos += snprintf(hooked_methods + hpos, sizeof(hooked_methods) - hpos, "[");

    char skipped_reasons[4096];
    int spos = 0;
    spos += snprintf(skipped_reasons + spos, sizeof(skipped_reasons) - spos, "[");

    for (unsigned int i = 0; i < method_count; i++) {
        const char *sel_name = sel_getName(method_getName(methods[i]));

        if (is_unsafe_method(sel_name)) {
            if (skipped > 0)
                spos += snprintf(skipped_reasons + spos,
                                sizeof(skipped_reasons) - spos, ",");
            char reason[512];
            snprintf(reason, sizeof(reason), "%s (unsafe)", sel_name);
            char esc[1024];
            json_escape(reason, esc, sizeof(esc));
            spos += snprintf(skipped_reasons + spos,
                            sizeof(skipped_reasons) - spos, "%s", esc);
            skipped++;
            continue;
        }

        if (trace_find_free_slot() < 0) {
            if (skipped > 0)
                spos += snprintf(skipped_reasons + spos,
                                sizeof(skipped_reasons) - spos, ",");
            spos += snprintf(skipped_reasons + spos,
                            sizeof(skipped_reasons) - spos,
                            "\"slots exhausted (%d remaining methods skipped)\"",
                            method_count - i);
            skipped += (method_count - i);
            break;
        }

        SEL sel = method_getName(methods[i]);
        /* Throwaway resp so per-method errors stay out of the batch response. */
        resp_t tmp = resp_new();
        int slot = trace_install_hook(cls, sel, className, sel_name, 0, &tmp);
        resp_free(&tmp);

        class_set_t sel_shadows;
        class_set_shadowing(&subs, sel, methods[i], &sel_shadows);
        for (int k = 0; k < sel_shadows.count; k++)
            class_set_add(&shadows, sel_shadows.items[k]);

        if (slot >= 0) {
            if (hooked > 0)
                hpos += snprintf(hooked_methods + hpos,
                                sizeof(hooked_methods) - hpos, ",");
            char esc[512];
            json_escape(sel_name, esc, sizeof(esc));
            hpos += snprintf(hooked_methods + hpos,
                            sizeof(hooked_methods) - hpos, "%s", esc);
            hooked++;
        } else {
            if (skipped > 0)
                spos += snprintf(skipped_reasons + spos,
                                sizeof(skipped_reasons) - spos, ",");
            char reason[512];
            snprintf(reason, sizeof(reason), "%s (already traced)", sel_name);
            char esc[1024];
            json_escape(reason, esc, sizeof(esc));
            spos += snprintf(skipped_reasons + spos,
                            sizeof(skipped_reasons) - spos, "%s", esc);
            skipped++;
        }
    }

    hpos += snprintf(hooked_methods + hpos, sizeof(hooked_methods) - hpos, "]");
    spos += snprintf(skipped_reasons + spos, sizeof(skipped_reasons) - spos, "]");

    free(methods);

    resp_append(r, "\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"hooked\":%d,\"skipped\":%d", hooked, skipped);
    resp_append(r, ",\"shadowed_by\":");
    class_set_json(&shadows, r);
    resp_append(r, ",\"methods\":%s", hooked_methods);
    resp_append(r, ",\"skipped_reasons\":%s", skipped_reasons);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf),
             "\"class\":\"%s\",\"hooked\":%d,\"shadowed_by\":%d,\"skipped\":%d",
             className, hooked, shadows.count, skipped);
    darkmach_log(MOD, "trace_class", log_buf);
}

static void cmd_trace_log(const char *args, resp_t *r) {
    trace_log_init();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;
    if (limit > DARKMACH_RING_CAPACITY) limit = DARKMACH_RING_CAPACITY;

    char class_filter[256] = "";
    char method_filter[256] = "";
    json_get_string(args, "class", class_filter, sizeof(class_filter));
    json_get_string(args, "method", method_filter, sizeof(method_filter));
    long slot_filter = json_get_long(args, "slot");
    /* Distinguish "slot not provided" from "slot=0": check if key exists */
    char slot_str[32] = "";
    int has_slot_filter = (json_get_string(args, "slot", slot_str,
                                           sizeof(slot_str)) != NULL);
    if (has_slot_filter) slot_filter = atol(slot_str);

    resp_append(r, "\"entries\":[");
    int returned = 0;

    for (int i = 0; i < trace_log_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&trace_log_ring, i);
        if (!entry) break;

        if (class_filter[0]) {
            char search[300];
            snprintf(search, sizeof(search), "\"class\":\"%s\"", class_filter);
            if (!strstr(entry, search)) continue;
        }
        if (method_filter[0]) {
            char search[300];
            snprintf(search, sizeof(search), "\"method\":\"%s\"", method_filter);
            if (!strstr(entry, search)) continue;
        }
        if (has_slot_filter) {
            char search[64];
            snprintf(search, sizeof(search), "\"slot\":%ld", slot_filter);
            if (!strstr(entry, search)) continue;
        }

        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }

    resp_append(r, "],\"total_entries\":%d,\"returned\":%d",
                trace_log_ring.total, returned);
}

static void cmd_untrace(const char *args, resp_t *r) {
    char slot_str[32] = "";
    int has_slot = (json_get_string(args, "slot", slot_str,
                                    sizeof(slot_str)) != NULL);
    int slot = -1;

    if (has_slot) {
        slot = atoi(slot_str);
        if (slot < 0 || slot >= DARKMACH_MAX_HOOKS) {
            resp_append(r, "\"error\":\"invalid slot (0-255)\"");
            return;
        }
        if (!darkmach_hook_table[slot].active) {
            resp_append(r, "\"error\":\"slot %d is not active\"", slot);
            return;
        }
    } else {
        char className[256], methodName[256];
        if (!json_get_string(args, "class", className, sizeof(className)) ||
            !json_get_string(args, "method", methodName, sizeof(methodName))) {
            resp_append(r, "\"error\":\"provide slot or class+method\"");
            return;
        }

        Class cls = objc_getClass(className);
        if (!cls) { resp_append(r, "\"error\":\"class not found\""); return; }
        SEL sel = sel_registerName(methodName);

        slot = trace_find_hook(cls, sel);
        if (slot < 0) {
            resp_append(r, "\"error\":\"hook not found\"");
            return;
        }
    }

    darkmach_hook_t *hook = &darkmach_hook_table[slot];
    Class front = hook->cls;
    SEL front_sel = hook->sel;
    Method m = class_getInstanceMethod(front, front_sel);
    if (!m) m = class_getClassMethod(front, front_sel);
    if (m) {
        method_setImplementation(m, hook->original_imp);
    }
    hook->active = 0;

    class_set_t removed = { .count = 0 };
    trace_remove_shadows(front, front_sel, &removed);

    resp_append(r, "\"unhooked\":true,\"slot\":%d,\"class\":", slot);
    resp_append_json_str(r, hook->class_name);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, hook->sel_name);
    resp_append(r, ",\"also_unhooked\":");
    class_set_json(&removed, r);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\"",
             slot, hook->class_name, hook->sel_name);
    darkmach_log(MOD, "trace_remove", log_buf);
}

/* verbose=1 calls -description, which can crash on partially-constructed objects — never
 * enable it for classes touched during object_cxxConstructFromClass. */
static void cmd_trace_verbose(const char *args, resp_t *r) {
    long verbose_val = json_get_long(args, "verbose");
    int verbose = (verbose_val != 0) ? 1 : 0;

    char slot_str[32] = "";
    int has_slot = (json_get_string(args, "slot", slot_str,
                                    sizeof(slot_str)) != NULL);

    if (has_slot) {
        int slot = atoi(slot_str);
        if (slot < 0 || slot >= DARKMACH_MAX_HOOKS) {
            resp_append(r, "\"error\":\"invalid slot (0-255)\"");
            return;
        }
        if (!darkmach_hook_table[slot].active) {
            resp_append(r, "\"error\":\"slot %d is not active\"", slot);
            return;
        }
        darkmach_hook_table[slot].verbose = verbose;
        resp_append(r, "\"slot\":%d,\"verbose\":%d,\"class\":", slot, verbose);
        resp_append_json_str(r, darkmach_hook_table[slot].class_name);
        resp_append(r, ",\"method\":");
        resp_append_json_str(r, darkmach_hook_table[slot].sel_name);
        return;
    }

    char className[256];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"provide slot or class arg\"");
        return;
    }

    int updated = 0;
    for (int i = 0; i < DARKMACH_MAX_HOOKS; i++) {
        if (darkmach_hook_table[i].active &&
            strcmp(darkmach_hook_table[i].class_name, className) == 0) {
            darkmach_hook_table[i].verbose = verbose;
            updated++;
        }
    }

    resp_append(r, "\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"verbose\":%d,\"updated\":%d", verbose, updated);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf),
             "\"class\":\"%s\",\"verbose\":%d,\"updated\":%d",
             className, verbose, updated);
    darkmach_log(MOD, "trace_verbose", log_buf);
}
