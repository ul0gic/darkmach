/*
 * darkmach-survival.dylib
 *
 * Strategy A survival kit. For any Strategy A patched iOS app — cryptid=0 with
 * BRK fill in encrypted text region, GOT-based shellcode at LC_MAIN entry — this
 * dylib does the runtime fixups needed to keep the process alive long enough
 * for the bridge to serve introspection queries.
 *
 * Walls mitigated:
 *
 *   Wall 4 (`__init_offsets` SIGILL):
 *     dyld walks the main binary's __TEXT,__init_offsets section
 *     (S_INIT_FUNC_OFFSETS, flags=0x16) during findAndRunAllInitializers and
 *     calls each entry as a constructor. With BRK fill, every entry SIGILLs.
 *     Survival: walk the main binary's load commands, find __init_offsets,
 *     zero its bytes via vm_protect+VM_PROT_COPY (regular mprotect returns
 *     EPERM on signed __TEXT), and clear the section flag so dyld treats it
 *     as S_REGULAR.
 *
 *   Wall 5 (Swift class-by-mangled-name SIGSEGV):
 *     libswiftCore caches pointers from __swift5_typeref/proto/types/etc when
 *     dyld loads the image. Later type lookups dereference these pointers and
 *     SIGSEGV because the underlying bytes are BRK fill. Survival: zero all
 *     __swift5_* sections after dyld init has registered them (callbacks to
 *     libswift then fail gracefully with NULL rather than SIGSEGV); AND
 *     interpose objc_getClass to short-circuit Swift mangled name lookups
 *     (returns NULL for `_TtC<MainExecName>*` patterns, which the shellcode
 *     and most callers handle).
 *
 *   Wall 6 (UIKit scene init SIGSEGV in libswiftCore protocol conformance):
 *     unfixable — UIKit's String→Data dynamic cast walks Swift type metadata
 *     for some app-registered class. Survival: install signal handlers for
 *     SIGSEGV/SIGBUS/SIGILL/SIGTRAP/SIGABRT on an alternate stack; on signal,
 *     park the offending thread in sigsuspend forever. Other threads
 *     (libdispatch workers serving the bridge) keep running, process stays
 *     alive indefinitely.
 *
 * Configuration via environment variables:
 *
 *   DARKMACH_SURVIVAL_FILTER  — substring to match in `_TtC` mangled class
 *                                names that should be intercepted by the
 *                                objc_getClass interpose. If unset, intercepts
 *                                ALL `_TtC` names. Set to e.g. `GrokApp` to
 *                                only intercept `_TtC7GrokApp*` mangles.
 *
 *   DARKMACH_SURVIVAL_QUIET   — if set to anything, suppresses log output
 *                                (default: log to stderr).
 *
 *   DARKMACH_SURVIVAL_DISABLE — if set, skips ALL fixups (allows comparison
 *                                runs to confirm the dylib's effect).
 */

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <objc/runtime.h>


static int s_quiet = 0;

#define LOG(fmt, ...) do { \
    if (!s_quiet) fprintf(stderr, "[darkmach-survival] " fmt "\n", ##__VA_ARGS__); \
} while (0)


/* === Section-zeroing for the main binary === */

static int is_target_section(const char *sectname, const char *segname) {
    if (strcmp(segname, "__TEXT") != 0) return 0;
    /* Init function offsets */
    if (strncmp(sectname, "__init_offsets", 16) == 0) return 1;
    /* All Swift type metadata */
    if (strncmp(sectname, "__swift5_typeref", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_proto", 14) == 0) return 1;
    if (strncmp(sectname, "__swift5_types", 14) == 0) return 1;
    if (strncmp(sectname, "__swift5_fieldmd", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_assocty", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_capture", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_mpenum", 15) == 0) return 1;
    if (strncmp(sectname, "__swift5_protos", 15) == 0) return 1;
    if (strncmp(sectname, "__swift5_builtin", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_reflstr", 16) == 0) return 1;
    if (strncmp(sectname, "__swift5_entry", 14) == 0) return 1;
    if (strncmp(sectname, "__swift_as_entry", 16) == 0) return 1;
    if (strncmp(sectname, "__swift_as_ret", 14) == 0) return 1;
    return 0;
}


static int patch_main_binary(void) {
    uint32_t count = _dyld_image_count();
    const struct mach_header *mh = NULL;
    intptr_t slide = 0;
    const char *name = NULL;
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *m = _dyld_get_image_header(i);
        if (m && m->filetype == MH_EXECUTE) {
            mh = m;
            slide = _dyld_get_image_vmaddr_slide(i);
            name = _dyld_get_image_name(i);
            break;
        }
    }
    if (!mh) {
        LOG("could not find main executable mach_header");
        return -1;
    }
    LOG("main exec: %s base=%p slide=%p", name, mh, (void *)slide);

    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    const uint8_t *lc_ptr = (const uint8_t *)(mh64 + 1);
    int patched = 0;
    long page = sysconf(_SC_PAGESIZE);

    for (uint32_t i = 0; i < mh64->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)lc_ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            struct section_64 *sect = (struct section_64 *)((const uint8_t *)seg +
                                                            sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                if (!is_target_section(sect[s].sectname, sect[s].segname)) continue;

                LOG("found %s,%s addr=0x%llx size=0x%llx flags=0x%x",
                    seg->segname, sect[s].sectname,
                    (unsigned long long)sect[s].addr,
                    (unsigned long long)sect[s].size, sect[s].flags);

                /* Zero section bytes via copy-on-write protection trick. */
                uintptr_t section_vmaddr = (uintptr_t)sect[s].addr + slide;
                size_t section_size = (size_t)sect[s].size;
                if (section_size == 0) continue;
                uintptr_t page_addr = section_vmaddr & ~(page - 1);
                size_t span = (section_vmaddr + section_size) - page_addr;
                if (span % page) span = ((span / page) + 1) * page;

                kern_return_t kr = vm_protect(
                    mach_task_self(), (vm_address_t)page_addr, (vm_size_t)span,
                    FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                if (kr == KERN_SUCCESS) {
                    memset((void *)section_vmaddr, 0, section_size);
                    LOG("  zeroed %zu bytes at 0x%lx via vm_protect+COPY",
                        section_size, (unsigned long)section_vmaddr);
                    vm_protect(mach_task_self(), (vm_address_t)page_addr,
                               (vm_size_t)span, FALSE,
                               VM_PROT_READ | VM_PROT_EXECUTE);
                } else {
                    LOG("  vm_protect failed kr=%d for %s", kr, sect[s].sectname);
                    continue;
                }

                /* Patch section header so dyld/loader sees no contents. */
                uintptr_t lc_addr = (uintptr_t)&sect[s].size;
                uintptr_t lc_page = lc_addr & ~(page - 1);
                kr = vm_protect(mach_task_self(), (vm_address_t)lc_page,
                                (vm_size_t)page, FALSE,
                                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                if (kr == KERN_SUCCESS) {
                    sect[s].size = 0;
                    sect[s].flags &= ~SECTION_TYPE;
                    vm_protect(mach_task_self(), (vm_address_t)lc_page,
                               (vm_size_t)page, FALSE, VM_PROT_READ);
                    LOG("  patched LC: size=0, flags=S_REGULAR");
                }
                patched++;
            }
        }
        lc_ptr += lc->cmdsize;
    }

    LOG("patched %d sections", patched);
    return patched;
}


/* === objc_getClass interpose === */

typedef Class (*objc_getClass_t)(const char *);
static objc_getClass_t orig_objc_getClass = NULL;
static char s_filter[256] = "";  /* substring to match; if empty, match all _TtC */

static void resolve_orig_objc_getClass(void) {
    if (orig_objc_getClass) return;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n || !strstr(n, "libobjc.A.dylib")) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh) continue;
        const uint8_t *lc_ptr = (const uint8_t *)(mh + 1);
        const struct symtab_command *symtab = NULL;
        const struct segment_command_64 *linkedit = NULL;
        for (uint32_t j = 0; j < mh->ncmds; j++) {
            const struct load_command *lc = (const struct load_command *)lc_ptr;
            if (lc->cmd == LC_SYMTAB) {
                symtab = (const struct symtab_command *)lc;
            } else if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit = seg;
            }
            lc_ptr += lc->cmdsize;
        }
        if (!symtab || !linkedit) continue;
        uintptr_t le_base = (uintptr_t)linkedit->vmaddr - linkedit->fileoff + slide;
        const struct nlist_64 *syms =
            (const struct nlist_64 *)(le_base + symtab->symoff);
        const char *strs = (const char *)(le_base + symtab->stroff);
        for (uint32_t s = 0; s < symtab->nsyms; s++) {
            if (syms[s].n_un.n_strx == 0) continue;
            const char *sym_name = strs + syms[s].n_un.n_strx;
            if (strcmp(sym_name, "_objc_getClass") == 0) {
                orig_objc_getClass =
                    (objc_getClass_t)((uintptr_t)syms[s].n_value + slide);
                LOG("resolved real objc_getClass at %p",
                    (void *)orig_objc_getClass);
                return;
            }
        }
    }
    LOG("FAILED to resolve real objc_getClass");
}

static int matches_filter(const char *name) {
    /* Only intercept Swift-mangled names (start with `_TtC`). */
    if (!name) return 0;
    if (!(name[0] == '_' && name[1] == 'T' && name[2] == 't' && name[3] == 'C'))
        return 0;
    /* If filter is empty, match all _TtC. */
    if (!s_filter[0]) return 1;
    /* Otherwise require substring match. */
    return strstr(name, s_filter) != NULL;
}

static Class darkmach_objc_getClass(const char *name) {
    if (!orig_objc_getClass) resolve_orig_objc_getClass();
    if (matches_filter(name)) {
        LOG("intercept: lookup of \"%s\" -> NULL (Swift)", name);
        return NULL;
    }
    return orig_objc_getClass ? orig_objc_getClass(name) : NULL;
}

typedef struct interpose_s {
    const void *replacement;
    const void *replacee;
} interpose_t;

__attribute__((used))
static const interpose_t darkmach_survival_interposes[]
__attribute__((section("__DATA,__interpose"))) = {
    {(const void *)darkmach_objc_getClass, (const void *)objc_getClass},
};


/* === Crash-freeze handler === */

static volatile sig_atomic_t s_crash_count = 0;

static void crash_freeze_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    s_crash_count++;
    if (s_crash_count == 1) {
        char msg[256];
        int n = snprintf(msg, sizeof(msg),
                         "[darkmach-survival] CAUGHT signal %d at addr %p — "
                         "freezing thread; bridge stays alive\n",
                         sig, info ? info->si_addr : NULL);
        write(2, msg, n);
    }
    sigset_t empty;
    sigemptyset(&empty);
    while (1) {
        sigsuspend(&empty);
        sleep(60);
    }
}

static void install_crash_freeze(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_freeze_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    static char altstack[SIGSTKSZ];
    stack_t ss = {.ss_sp = altstack, .ss_size = SIGSTKSZ, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    LOG("crash-freeze handler installed for SEGV/BUS/ILL/TRAP/ABRT");
}


/* === Constructor === */

__attribute__((constructor))
static void darkmach_survival_init(void) {
    if (getenv("DARKMACH_SURVIVAL_QUIET")) s_quiet = 1;
    if (getenv("DARKMACH_SURVIVAL_DISABLE")) {
        LOG("DISABLED via DARKMACH_SURVIVAL_DISABLE");
        return;
    }
    const char *flt = getenv("DARKMACH_SURVIVAL_FILTER");
    if (flt && flt[0]) {
        strncpy(s_filter, flt, sizeof(s_filter) - 1);
        s_filter[sizeof(s_filter) - 1] = '\0';
        LOG("Strategy A survival kit — filter='%s'", s_filter);
    } else {
        LOG("Strategy A survival kit — filter=ALL _TtC*");
    }
    install_crash_freeze();
    patch_main_binary();
}
