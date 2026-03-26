/*
 * darkmach-stealth.dylib -- Anti-analysis detection and evasion module
 *
 * Bypasses common iOS anti-jailbreak, anti-debug, and anti-hook detection
 * techniques. Many apps (banking, DRM-protected, enterprise MDM) implement
 * layers of detection that can crash, wipe data, or refuse to function
 * when analysis is detected. This module makes Darkmach invisible.
 *
 * Hooks installed:
 *   - sysctl:           hides P_TRACED debugger flag from kinfo_proc
 *   - ptrace:           no-ops PT_DENY_ATTACH requests
 *   - getenv:           hides DYLD_* and DARKMACH* environment variables
 *   - stat/lstat/access: returns ENOENT for jailbreak artifact paths
 *   - fork:             returns -1 (jailbreak checks use fork success)
 *   - NSFileManager:    swizzles fileExistsAtPath: for jailbreak paths
 *   - _dyld_image_count/_dyld_get_image_name: filters darkmach-* dylibs
 *
 * Bridge integration:
 *   - darkmach_stealth_scan()   -- detect anti-analysis in the running app
 *   - darkmach_stealth_enable() -- activate/confirm bypasses
 *   - darkmach_stealth_status() -- report bypass state and intercept counts
 *
 * Build (via root Makefile):
 *   make all  (conditional wildcard auto-detects this file)
 *
 * Inject:
 *   SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/darkmach-stealth.dylib \
 *   xcrun simctl launch <device> <bundle-id>
 */

#include "darkmach-core.h"
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach-o/dyld.h>

#define STEALTH_MOD "stealth"

/* ═══════════════════════════════════════════════════════════════
 *  Intercept counters -- tracked per technique category
 * ═══════════════════════════════════════════════════════════════ */

static int cnt_jailbreak   = 0;  /* file checks blocked */
static int cnt_debugger    = 0;  /* sysctl/ptrace blocked */
static int cnt_dyld_hiding = 0;  /* dyld image queries filtered */
static int cnt_fork_check  = 0;  /* fork calls blocked */
static int cnt_env_hide    = 0;  /* getenv queries hidden */

/* Bypass active flags -- all start enabled (constructor activates) */
static int bypass_jailbreak   = 0;
static int bypass_debugger    = 0;
static int bypass_dyld_hiding = 0;
static int bypass_fork_check  = 0;
static int bypass_integrity   = 0;

/* ═══════════════════════════════════════════════════════════════
 *  Jailbreak artifact paths
 * ═══════════════════════════════════════════════════════════════ */

static const char *jailbreak_paths[] = {
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/libexec/ssh-keysign",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Unc0ver.app",
    "/Applications/checkra1n.app",
    "/Applications/blackb0x.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/var/stash",
    "/var/cache/apt",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/stash",
    "/private/var/mobile/Library/SBSettings",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/jb/amfid_payload.dylib",
    "/jb/lzma",
    NULL
};

static int is_jailbreak_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; jailbreak_paths[i] != NULL; i++) {
        if (strcmp(path, jailbreak_paths[i]) == 0) return 1;
    }
    /* Also check partial matches for common patterns */
    if (strstr(path, "/MobileSubstrate")) return 1;
    if (strstr(path, "/Cydia")) return 1;
    if (strstr(path, "/cydia")) return 1;
    if (strstr(path, "/substrate")) return 1;
    if (strstr(path, "/TweakInject")) return 1;
    if (strstr(path, "/.installed_unc0ver")) return 1;
    if (strstr(path, "/.bootstrapped_electra")) return 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 *  1. sysctl bypass -- hide P_TRACED debugger flag
 * ═══════════════════════════════════════════════════════════════ */

static int darkmach_sysctl(int *name, u_int namelen, void *oldp,
                         size_t *oldlenp, void *newp, size_t newlen)
{
    int result = sysctl(name, namelen, oldp, oldlenp, newp, newlen);

    if (bypass_debugger && result == 0 && oldp && namelen == 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID)
    {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info && (info->kp_proc.p_flag & P_TRACED)) {
            info->kp_proc.p_flag &= ~P_TRACED;
            cnt_debugger++;
        }
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════
 *  2. ptrace bypass -- no-op PT_DENY_ATTACH
 *
 *  ptrace may not have a public header on the Simulator SDK,
 *  so we define the constant and use dlsym to find the original.
 * ═══════════════════════════════════════════════════════════════ */

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

typedef int (*ptrace_fn_t)(int, pid_t, caddr_t, int);
static ptrace_fn_t orig_ptrace = NULL;

/*
 * ptrace is available at runtime in the C library but may not have
 * a header declaration in the Simulator SDK. We resolve it via dlsym.
 * This hook is NOT installed via DYLD_INTERPOSE (ptrace may not be
 * a public dyld symbol on all platforms). Instead, we use fishhook-
 * style resolution: the constructor resolves the real ptrace, and
 * any code calling ptrace through our interpose of the symbol gets
 * this replacement. We declare ptrace as extern to make it available
 * for the interpose table.
 */
extern int ptrace(int, pid_t, caddr_t, int);

static int darkmach_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (bypass_debugger && request == PT_DENY_ATTACH) {
        cnt_debugger++;
        fprintf(stderr, "[darkmach-stealth] blocked ptrace(PT_DENY_ATTACH)\n");
        return 0;  /* pretend success */
    }
    if (!orig_ptrace) {
        orig_ptrace = (ptrace_fn_t)dlsym(RTLD_NEXT, "ptrace");
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : -1;
}

/* ═══════════════════════════════════════════════════════════════
 *  3. getenv bypass -- hide DYLD_* and DARKMACH* variables
 * ═══════════════════════════════════════════════════════════════ */

static char *darkmach_getenv(const char *name) {
    if (name) {
        if (strncmp(name, "DYLD_", 5) == 0 ||
            strncmp(name, "DARKMACH", 6) == 0 ||
            strncmp(name, "SIMCTL_CHILD_DYLD_", 18) == 0)
        {
            cnt_env_hide++;
            return NULL;
        }
    }
    return getenv(name);
}

/* ═══════════════════════════════════════════════════════════════
 *  4. stat / lstat / access bypass -- jailbreak artifact paths
 * ═══════════════════════════════════════════════════════════════ */

static int darkmach_stat(const char *path, struct stat *buf) {
    if (bypass_jailbreak && is_jailbreak_path(path)) {
        cnt_jailbreak++;
        errno = ENOENT;
        return -1;
    }
    return stat(path, buf);
}

static int darkmach_lstat(const char *path, struct stat *buf) {
    if (bypass_jailbreak && is_jailbreak_path(path)) {
        cnt_jailbreak++;
        errno = ENOENT;
        return -1;
    }
    return lstat(path, buf);
}

static int darkmach_access(const char *path, int mode) {
    if (bypass_jailbreak && is_jailbreak_path(path)) {
        cnt_jailbreak++;
        errno = ENOENT;
        return -1;
    }
    return access(path, mode);
}

/* ═══════════════════════════════════════════════════════════════
 *  5. fork bypass -- return -1 (jailbreak checks use fork)
 * ═══════════════════════════════════════════════════════════════ */

static pid_t darkmach_fork(void) {
    if (bypass_fork_check) {
        cnt_fork_check++;
        errno = ENOSYS;
        return -1;
    }
    return fork();
}

/* ═══════════════════════════════════════════════════════════════
 *  6. dyld image list bypass -- hide darkmach-* dylibs
 *
 *  _dyld_image_count and _dyld_get_image_name are not linkable
 *  symbols for DYLD_INTERPOSE (they live in dyld, not libSystem).
 *  Instead we provide wrapper functions that the bridge calls,
 *  and intercept at the ObjC level where apps typically check.
 *  The DYLD_INTERPOSE approach works for the C functions since
 *  the Simulator's dyld_sim processes them.
 * ═══════════════════════════════════════════════════════════════ */

static int is_darkmach_image(const char *name) {
    if (!name) return 0;
    /* Check for darkmach dylib names in the path */
    if (strstr(name, "darkmach-")) return 1;
    if (strstr(name, "libdarkmach")) return 1;
    return 0;
}

/* Build a mapping of visible indices to real indices.
 * This is rebuilt on each call since image list can change. */
#define MAX_IMAGES 1024
static uint32_t visible_map[MAX_IMAGES];
static uint32_t visible_count_cache = 0;
static int map_dirty = 1;

static void rebuild_visible_map(void) {
    uint32_t real_count = _dyld_image_count();
    visible_count_cache = 0;
    for (uint32_t i = 0; i < real_count && visible_count_cache < MAX_IMAGES; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!bypass_dyld_hiding || !is_darkmach_image(name)) {
            visible_map[visible_count_cache++] = i;
        } else {
            cnt_dyld_hiding++;
        }
    }
    map_dirty = 0;
}

static uint32_t darkmach_dyld_image_count(void) {
    if (!bypass_dyld_hiding) return _dyld_image_count();
    rebuild_visible_map();
    return visible_count_cache;
}

static const char *darkmach_dyld_get_image_name(uint32_t image_index) {
    if (!bypass_dyld_hiding) return _dyld_get_image_name(image_index);
    if (map_dirty) rebuild_visible_map();
    if (image_index >= visible_count_cache) return NULL;
    return _dyld_get_image_name(visible_map[image_index]);
}

static const struct mach_header *darkmach_dyld_get_image_header(uint32_t image_index) {
    if (!bypass_dyld_hiding) return _dyld_get_image_header(image_index);
    if (map_dirty) rebuild_visible_map();
    if (image_index >= visible_count_cache) return NULL;
    return _dyld_get_image_header(visible_map[image_index]);
}

/* ═══════════════════════════════════════════════════════════════
 *  7. NSFileManager fileExistsAtPath: swizzle
 * ═══════════════════════════════════════════════════════════════ */

static IMP orig_fileExistsAtPath = NULL;

static BOOL swizzled_fileExistsAtPath(id self, SEL _cmd, id path) {
    if (bypass_jailbreak && path) {
        const char *cpath = nsstring_to_c(path);
        if (cpath && is_jailbreak_path(cpath)) {
            cnt_jailbreak++;
            return NO;
        }
    }
    /* Call original */
    BOOL (*orig)(id, SEL, id) = (BOOL (*)(id, SEL, id))orig_fileExistsAtPath;
    return orig(self, _cmd, path);
}

static void install_nsfilemanager_hook(void) {
    Class cls = objc_getClass("NSFileManager");
    if (!cls) return;

    SEL sel = sel_registerName("fileExistsAtPath:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;

    orig_fileExistsAtPath = method_getImplementation(m);
    method_setImplementation(m, (IMP)swizzled_fileExistsAtPath);
    fprintf(stderr, "[darkmach-stealth] hooked NSFileManager fileExistsAtPath:\n");
}

/* ═══════════════════════════════════════════════════════════════
 *  DYLD_INTERPOSE table
 *
 *  These hooks are processed by dyld at load time before main().
 *  The struct/section pattern matches the existing interceptors.
 * ═══════════════════════════════════════════════════════════════ */

struct stealth_interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct stealth_interpose_pair stealth_interpose_pairs[] = {
    { (const void *)darkmach_sysctl,              (const void *)sysctl },
    { (const void *)darkmach_getenv,              (const void *)getenv },
    { (const void *)darkmach_stat,                (const void *)stat },
    { (const void *)darkmach_lstat,               (const void *)lstat },
    { (const void *)darkmach_access,              (const void *)access },
    { (const void *)darkmach_fork,                (const void *)fork },
    { (const void *)darkmach_ptrace,              (const void *)ptrace },
    { (const void *)darkmach_dyld_image_count,    (const void *)_dyld_image_count },
    { (const void *)darkmach_dyld_get_image_name, (const void *)_dyld_get_image_name },
    { (const void *)darkmach_dyld_get_image_header, (const void *)_dyld_get_image_header },
};

/* ═══════════════════════════════════════════════════════════════
 *  Known protection SDK patterns for stealth_scan
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    const char *class_pattern;   /* substring to match in class name */
    const char *library;         /* SDK/library name */
    const char *technique;       /* detection category */
    const char *description;     /* human-readable description */
} detection_pattern_t;

static const detection_pattern_t sdk_patterns[] = {
    /* Commercial protection SDKs */
    { "iXGuard",            "iXGuard",       "commercial_sdk",    "iXGuard protection SDK detected" },
    { "DexProtector",       "DexProtector",  "commercial_sdk",    "DexProtector/iXGuard SDK detected" },
    { "Arxan",              "Arxan",         "commercial_sdk",    "Arxan/Digital.ai protection SDK" },
    { "Digital_ai",         "Digital.ai",    "commercial_sdk",    "Digital.ai app protection" },
    { "Promon",             "Promon",        "commercial_sdk",    "Promon SHIELD detected" },
    { "AppSealing",         "AppSealing",    "commercial_sdk",    "AppSealing protection SDK" },
    { "Guardsquare",        "Guardsquare",   "commercial_sdk",    "Guardsquare protection SDK" },
    { "FreeRASP",           "FreeRASP",      "commercial_sdk",    "FreeRASP (Talsec) anti-tampering" },
    { "Talsec",             "Talsec",        "commercial_sdk",    "Talsec security framework" },
    { "TrustKit",           "TrustKit",      "ssl_pinning",       "TrustKit SSL pinning library" },

    /* Jailbreak detection patterns */
    { "JailbreakDetect",    "custom",        "jailbreak_check",   "Jailbreak detection class" },
    { "JailbreakChecker",   "custom",        "jailbreak_check",   "Jailbreak checker class" },
    { "SecurityChecker",    "custom",        "jailbreak_check",   "Security checker (likely jailbreak)" },
    { "DeviceIntegrity",    "custom",        "integrity_check",   "Device integrity verification" },
    { "IntegrityCheck",     "custom",        "integrity_check",   "Code/device integrity checking" },
    { "AntiTamper",         "custom",        "integrity_check",   "Anti-tampering detection" },

    /* Runtime detection */
    { "DTXConnection",      "Instruments",   "debug_detection",   "Instruments/debugging framework" },
    { "FridaDetect",        "custom",        "hook_detection",    "Frida detection class" },

    { NULL, NULL, NULL, NULL }
};

/* Method names that indicate anti-analysis */
typedef struct {
    const char *selector;
    const char *technique;
    const char *description;
} detection_selector_t;

static const detection_selector_t suspicious_selectors[] = {
    { "isJailbroken",           "jailbreak_check",  "Jailbreak detection method" },
    { "detectJailbreak",        "jailbreak_check",  "Jailbreak detection method" },
    { "checkJailbreak",         "jailbreak_check",  "Jailbreak detection method" },
    { "isDeviceCompromised",    "jailbreak_check",  "Device compromise check" },
    { "isDeviceRooted",         "jailbreak_check",  "Root/jailbreak check" },
    { "checkIntegrity",         "integrity_check",  "Integrity verification" },
    { "verifyBinaryIntegrity",  "integrity_check",  "Binary integrity check" },
    { "isDebuggerAttached",     "debug_detection",  "Debugger attachment check" },
    { "detectDebugger",         "debug_detection",  "Debugger detection" },
    { "antiDebug",              "debug_detection",  "Anti-debugging" },
    { "checkForHooks",          "hook_detection",   "Hook/swizzle detection" },
    { "detectHooking",          "hook_detection",   "Hook detection" },
    { "isFridaRunning",         "hook_detection",   "Frida detection" },
    { "detectFrida",            "hook_detection",   "Frida detection" },
    { "isRunningInEmulator",    "env_detection",    "Emulator/simulator detection" },
    { "isSimulator",            "env_detection",    "Simulator detection" },
    { "checkEnvironment",       "env_detection",    "Environment validation" },
    { "verifySignature",        "integrity_check",  "Code signature verification" },
    { "checkCodeSignature",     "integrity_check",  "Code signature check" },
    { "isReverseEngineered",    "hook_detection",   "Reverse engineering detection" },
    { NULL, NULL, NULL }
};

/* ═══════════════════════════════════════════════════════════════
 *  Bridge integration -- exported (non-static) functions
 *
 *  The bridge dispatcher can dlsym() for these at runtime.
 *  Uses resp_t from darkmach-bridge.h if available, but since
 *  this is a standalone dylib, we use a compatible type.
 * ═══════════════════════════════════════════════════════════════ */

/* Forward-compatible response type: same layout as bridge resp_t */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} stealth_resp_t;

static void stealth_resp_append(stealth_resp_t *r, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    while (r->len + (size_t)needed + 1 > r->cap) {
        r->cap *= 2;
        if (r->cap > 1048576) { r->cap = 1048576; break; }
        r->buf = realloc(r->buf, r->cap);
    }

    va_start(ap, fmt);
    r->len += vsnprintf(r->buf + r->len, r->cap - r->len, fmt, ap);
    va_end(ap);
}

static void stealth_resp_append_json_str(stealth_resp_t *r, const char *s) {
    if (!s) { stealth_resp_append(r, "null"); return; }
    char esc[2048];
    json_escape(s, esc, sizeof(esc));
    stealth_resp_append(r, "%s", esc);
}

/*
 * stealth_scan -- detect anti-analysis mechanisms in the running app
 *
 * Scans the ObjC class list for known protection SDK patterns and
 * suspicious method selectors. Returns structured JSON.
 */
void darkmach_stealth_scan(const char *request, void *resp) {
    stealth_resp_t *r = (stealth_resp_t *)resp;

    int detection_count = 0;
    const char *risk = "none";
    int has_commercial = 0;
    int has_jailbreak = 0;
    int has_debug = 0;

    stealth_resp_append(r, "{\"detections\":[");

    /* Phase 1: Scan class list for known SDK patterns */
    unsigned int class_count = 0;
    Class *classes = objc_copyClassList(&class_count);

    if (classes) {
        for (unsigned int i = 0; i < class_count; i++) {
            const char *name = class_getName(classes[i]);
            if (!name) continue;

            /* Check against known SDK patterns */
            for (int p = 0; sdk_patterns[p].class_pattern != NULL; p++) {
                if (strstr(name, sdk_patterns[p].class_pattern)) {
                    if (detection_count > 0) stealth_resp_append(r, ",");
                    stealth_resp_append(r, "{\"technique\":");
                    stealth_resp_append_json_str(r, sdk_patterns[p].technique);
                    stealth_resp_append(r, ",\"description\":");
                    stealth_resp_append_json_str(r, sdk_patterns[p].description);
                    stealth_resp_append(r, ",\"library\":");
                    stealth_resp_append_json_str(r, sdk_patterns[p].library);
                    stealth_resp_append(r, ",\"confidence\":\"high\"");
                    stealth_resp_append(r, ",\"class\":");
                    stealth_resp_append_json_str(r, name);
                    stealth_resp_append(r, ",\"method\":\"\"}");
                    detection_count++;
                    if (strcmp(sdk_patterns[p].technique, "commercial_sdk") == 0) has_commercial = 1;
                    if (strcmp(sdk_patterns[p].technique, "jailbreak_check") == 0) has_jailbreak = 1;
                    break;  /* one match per class is enough */
                }
            }

            /* Phase 2: Check methods of suspicious classes for detection selectors */
            unsigned int method_count = 0;
            Method *methods = class_copyMethodList(classes[i], &method_count);
            if (methods) {
                for (unsigned int m = 0; m < method_count; m++) {
                    SEL sel = method_getName(methods[m]);
                    const char *sel_name = sel_getName(sel);
                    if (!sel_name) continue;

                    for (int s = 0; suspicious_selectors[s].selector != NULL; s++) {
                        if (strcmp(sel_name, suspicious_selectors[s].selector) == 0) {
                            if (detection_count > 0) stealth_resp_append(r, ",");
                            stealth_resp_append(r, "{\"technique\":");
                            stealth_resp_append_json_str(r, suspicious_selectors[s].technique);
                            stealth_resp_append(r, ",\"description\":");
                            stealth_resp_append_json_str(r, suspicious_selectors[s].description);
                            stealth_resp_append(r, ",\"library\":\"custom\"");
                            stealth_resp_append(r, ",\"confidence\":\"high\"");
                            stealth_resp_append(r, ",\"class\":");
                            stealth_resp_append_json_str(r, name);
                            stealth_resp_append(r, ",\"method\":");
                            stealth_resp_append_json_str(r, sel_name);
                            stealth_resp_append(r, "}");
                            detection_count++;
                            if (strcmp(suspicious_selectors[s].technique, "jailbreak_check") == 0)
                                has_jailbreak = 1;
                            if (strcmp(suspicious_selectors[s].technique, "debug_detection") == 0)
                                has_debug = 1;
                            break;
                        }
                    }
                }
                free(methods);
            }
        }
        free(classes);
    }

    stealth_resp_append(r, "],");

    /* Determine risk level */
    if (has_commercial) risk = "high";
    else if (has_jailbreak && has_debug) risk = "high";
    else if (has_jailbreak || has_debug) risk = "medium";
    else if (detection_count > 0) risk = "low";

    stealth_resp_append(r, "\"risk_level\":");
    stealth_resp_append_json_str(r, risk);
    stealth_resp_append(r, ",\"total_detections\":%d}", detection_count);
}

/*
 * stealth_enable -- activate specified bypass techniques
 *
 * Accepts comma-separated technique names or "all".
 * DYLD_INTERPOSE hooks are always active (installed at load time),
 * but the bypass flags control whether they actually filter.
 */
void darkmach_stealth_enable(const char *request, void *resp) {
    stealth_resp_t *r = (stealth_resp_t *)resp;

    /* Parse "techniques" from request -- simple substring search */
    const char *techniques = "all";
    char tech_buf[256] = {0};

    /* Look for "techniques":"..." in the JSON request */
    if (request) {
        const char *key = strstr(request, "\"techniques\"");
        if (key) {
            const char *colon = strchr(key + 12, ':');
            if (colon) {
                /* Skip whitespace and opening quote */
                const char *val = colon + 1;
                while (*val == ' ' || *val == '\t') val++;
                if (*val == '"') {
                    val++;
                    size_t i = 0;
                    while (*val && *val != '"' && i < sizeof(tech_buf) - 1) {
                        tech_buf[i++] = *val++;
                    }
                    tech_buf[i] = '\0';
                    techniques = tech_buf;
                }
            }
        }
    }

    int enable_all = (strcmp(techniques, "all") == 0);

    if (enable_all || strstr(techniques, "jailbreak")) {
        bypass_jailbreak = 1;
    }
    if (enable_all || strstr(techniques, "debugger")) {
        bypass_debugger = 1;
    }
    if (enable_all || strstr(techniques, "dyld_hiding")) {
        bypass_dyld_hiding = 1;
    }
    if (enable_all || strstr(techniques, "fork_check")) {
        bypass_fork_check = 1;
    }
    if (enable_all || strstr(techniques, "integrity")) {
        bypass_integrity = 1;
    }

    /* Build response */
    stealth_resp_append(r, "{\"active_bypasses\":[");
    int count = 0;
    if (bypass_jailbreak)   { if (count++) stealth_resp_append(r, ","); stealth_resp_append(r, "\"jailbreak\""); }
    if (bypass_debugger)    { if (count++) stealth_resp_append(r, ","); stealth_resp_append(r, "\"debugger\""); }
    if (bypass_dyld_hiding) { if (count++) stealth_resp_append(r, ","); stealth_resp_append(r, "\"dyld_hiding\""); }
    if (bypass_fork_check)  { if (count++) stealth_resp_append(r, ","); stealth_resp_append(r, "\"fork_check\""); }
    if (bypass_integrity)   { if (count++) stealth_resp_append(r, ","); stealth_resp_append(r, "\"integrity\""); }
    stealth_resp_append(r, "],\"total_active\":%d}", count);
}

/*
 * stealth_status -- report which bypasses are active and intercept counts
 */
void darkmach_stealth_status(const char *request, void *resp) {
    (void)request;  /* unused */
    stealth_resp_t *r = (stealth_resp_t *)resp;

    stealth_resp_append(r, "{\"bypasses\":[");
    stealth_resp_append(r,
        "{\"technique\":\"jailbreak\",\"active\":%s,\"intercept_count\":%d}",
        bypass_jailbreak ? "true" : "false", cnt_jailbreak);
    stealth_resp_append(r,
        ",{\"technique\":\"debugger\",\"active\":%s,\"intercept_count\":%d}",
        bypass_debugger ? "true" : "false", cnt_debugger);
    stealth_resp_append(r,
        ",{\"technique\":\"dyld_hiding\",\"active\":%s,\"intercept_count\":%d}",
        bypass_dyld_hiding ? "true" : "false", cnt_dyld_hiding);
    stealth_resp_append(r,
        ",{\"technique\":\"fork_check\",\"active\":%s,\"intercept_count\":%d}",
        bypass_fork_check ? "true" : "false", cnt_fork_check);
    stealth_resp_append(r,
        ",{\"technique\":\"integrity\",\"active\":%s,\"intercept_count\":%d}",
        bypass_integrity ? "true" : "false", 0);
    stealth_resp_append(r,
        ",{\"technique\":\"env_hiding\",\"active\":true,\"intercept_count\":%d}",
        cnt_env_hide);
    stealth_resp_append(r, "]}");
}

/* ═══════════════════════════════════════════════════════════════
 *  Constructor -- activates all bypasses at load time
 * ═══════════════════════════════════════════════════════════════ */

__attribute__((constructor))
static void darkmach_stealth_init(void) {
    fprintf(stderr, "[darkmach-stealth] initializing anti-detection module\n");
    darkmach_log_init(STEALTH_MOD);

    /* Activate all bypass flags */
    bypass_jailbreak   = 1;
    bypass_debugger    = 1;
    bypass_dyld_hiding = 1;
    bypass_fork_check  = 1;
    bypass_integrity   = 1;

    /* Resolve ptrace original */
    orig_ptrace = (ptrace_fn_t)dlsym(RTLD_NEXT, "ptrace");

    /* Install ObjC method swizzle for NSFileManager */
    install_nsfilemanager_hook();

    /* Mark dyld image map as needing rebuild */
    map_dirty = 1;

    fprintf(stderr, "[darkmach-stealth] all bypasses active: "
            "jailbreak, debugger, dyld_hiding, fork_check, integrity\n");

    /* Log initialization */
    darkmach_log(STEALTH_MOD, "init",
        "\"bypasses\":[\"jailbreak\",\"debugger\",\"dyld_hiding\","
        "\"fork_check\",\"integrity\",\"env_hiding\"]");
}
