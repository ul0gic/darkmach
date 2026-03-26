/*
 * cmd-trace.c -- Method hooking/tracing commands for the Sphinx LLM bridge
 *
 * Commands:
 *   hook_method, unhook_method  (legacy simple hooks)
 *   trace, trace_class, trace_log, untrace  (trampoline-based trace system)
 *
 * Provides: hook_count global (used by cmd-recon.c cmd_info)
 *
 * Unity build: #included from bridge/sphinx-bridge.c
 *
 * The trace system uses an ARM64 trampoline (sphinx-trampoline.S) with
 * 256 per-hook stubs. Each stub loads a pointer to its sphinx_hook_t
 * entry into X17 and branches to the shared trampoline, which saves
 * all argument registers, calls sphinx_on_method_enter(), restores
 * registers, and tail-calls the original IMP.
 *
 * Reference: dev/frida-gum-interceptor-study.md sections 9.1-9.5
 */
#include "sphinx-bridge.h"
#include <mach/mach_time.h>

/* ===================================================================
 *  Legacy hook tracking (hook_method / unhook_method)
 *  Kept for backward compatibility. These use generic_hook which
 *  discards arguments. New code should use trace/untrace instead.
 * =================================================================== */

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

/* ===================================================================
 *  Trampoline-based trace system
 * =================================================================== */

/* Hook table -- referenced by sphinx-trampoline.S stubs via ADRP/ADD.
 * Must have external linkage (non-static) so the linker can resolve
 * the sphinx_hook_table symbol from the assembly object.
 * C name is sphinx_hook_table -> mangled symbol is _sphinx_hook_table. */
sphinx_hook_t sphinx_hook_table[SPHINX_MAX_HOOKS];

/* Stub table base address -- defined in sphinx-trampoline.S.
 * Each stub is exactly 12 bytes (3 ARM64 instructions).
 * Stub N lives at: (char *)&sphinx_stub_table + N * 12 */
extern char sphinx_stub_table[];

#define STUB_SIZE 12

/* Compute the IMP address for stub slot N */
static inline IMP sphinx_stub_imp(int n) {
    return (IMP)((char *)&sphinx_stub_table + n * STUB_SIZE);
}

/* Reentrancy guard -- prevents infinite recursion when a traced method
 * calls another traced method. Uses pthread TLS so each thread has
 * its own guard. When non-NULL, the current thread is inside a trace
 * handler and should skip logging. */
static pthread_key_t sphinx_guard_key;
static int guard_key_initialized = 0;

static inline void trace_guard_init(void) {
    if (!guard_key_initialized) {
        pthread_key_create(&sphinx_guard_key, NULL);
        guard_key_initialized = 1;
    }
}

static inline int trace_guard_enter(void) {
    if (pthread_getspecific(sphinx_guard_key)) return 0;  /* already inside */
    pthread_setspecific(sphinx_guard_key, (void *)1);
    return 1;
}

static inline void trace_guard_leave(void) {
    pthread_setspecific(sphinx_guard_key, NULL);
}

/* Trace log ring buffer -- shared across all hooks */
static sphinx_ring_t trace_log_ring;
static int trace_log_initialized = 0;

static inline void trace_log_init(void) {
    if (!trace_log_initialized) {
        sphinx_ring_init(&trace_log_ring);
        trace_log_initialized = 1;
    }
}

/* Count active trace hooks (for info command) */
static int trace_active_count(void) {
    int count = 0;
    for (int i = 0; i < SPHINX_MAX_HOOKS; i++) {
        if (sphinx_hook_table[i].active) count++;
    }
    return count;
}

/* Find first free slot in hook table. Returns -1 if full. */
static int trace_find_free_slot(void) {
    for (int i = 0; i < SPHINX_MAX_HOOKS; i++) {
        if (!sphinx_hook_table[i].active) return i;
    }
    return -1;
}

/* Check if a class+selector is already traced. Returns slot or -1. */
static int trace_find_hook(Class cls, SEL sel) {
    for (int i = 0; i < SPHINX_MAX_HOOKS; i++) {
        if (sphinx_hook_table[i].active &&
            sphinx_hook_table[i].cls == cls &&
            sphinx_hook_table[i].sel == sel) {
            return i;
        }
    }
    return -1;
}

/* ===================================================================
 *  Type encoding helpers -- decode ObjC method type encoding
 *  into human-readable argument type descriptions
 * =================================================================== */

/* Decode a single type encoding character to a human-readable string */
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

/* Parse type encoding string and emit JSON arg_types array.
 * ObjC type encoding: return_type arg0_type offset arg1_type offset ...
 * arg0 = self (id), arg1 = _cmd (SEL), arg2+ = user args */
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
        /* Skip stack offsets (digits) */
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

        /* Skip over complex type specifiers */
        if (*p == '{') {
            /* struct: {name=...} -- skip to closing } */
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
                p++;
            }
            continue;
        } else if (*p == '[') {
            /* array: [count type] */
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
            /* @? = block, @"ClassName" = typed object */
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

/* ===================================================================
 *  Format a single argument value for trace logging
 *  Reads from the saved register area based on type encoding
 * =================================================================== */

static void format_arg_value(char *buf, size_t bufsz, char type_char,
                             uintptr_t raw_value) {
    switch (type_char) {
        case '@': {
            /* ObjC object -- call description */
            id obj = (id)raw_value;
            if (!obj) {
                snprintf(buf, bufsz, "nil");
            } else if (is_valid_objc_ptr(obj)) {
                const char *desc = nsobject_desc(obj);
                /* Guard against bad pointers from partially-constructed objects */
                if (!desc || (uintptr_t)desc < 0x1000) {
                    snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
                } else if (strlen(desc) > 256) {
                    snprintf(buf, bufsz, "%.253s...", desc);
                } else {
                    snprintf(buf, bufsz, "%s", desc);
                }
            } else {
                snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            }
            break;
        }
        case '#': {
            /* Class object */
            Class c = (Class)raw_value;
            if (c) {
                snprintf(buf, bufsz, "%s", class_getName(c));
            } else {
                snprintf(buf, bufsz, "nil");
            }
            break;
        }
        case ':': {
            /* SEL */
            SEL s = (SEL)raw_value;
            if (s) {
                snprintf(buf, bufsz, "%s", sel_getName(s));
            } else {
                snprintf(buf, bufsz, "nil");
            }
            break;
        }
        case '*': {
            /* C string */
            const char *s = (const char *)raw_value;
            if (s && (uintptr_t)s > 0x1000) {
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
            /* Float is passed in SIMD registers, not GP -- show as hex */
            snprintf(buf, bufsz, "0x%lx", (unsigned long)raw_value);
            break;
        }
        case 'd': {
            /* Double is passed in SIMD registers, not GP -- show as hex */
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

/* ===================================================================
 *  sphinx_on_method_enter -- called from ARM64 trampoline
 *
 *  This function has external linkage (non-static) because the
 *  trampoline calls it via BL sphinx_on_method_enter.
 *
 *  Parameters:
 *    hook        - pointer to the sphinx_hook_t for this hook
 *    saved_regs  - pointer to the saved register area on stack:
 *                  [0]:  X0 (self)    [8]:  X1 (_cmd)
 *                  [16]: X2           [24]: X3
 *                  [32]: X4           [40]: X5
 *                  [48]: X6           [56]: X7
 *                  [64]: X8 (indirect result)  [72]: X17 (hook ptr)
 * =================================================================== */

void sphinx_on_method_enter(sphinx_hook_t *hook, void *saved_regs) {
    /* Reentrancy guard */
    if (!trace_guard_enter()) return;

    /* Lazy init */
    trace_log_init();

    /* Read argument registers from saved area */
    uintptr_t *gp_regs = (uintptr_t *)saved_regs;
    /* gp_regs[0] = X0 (self), gp_regs[1] = X1 (_cmd) */
    /* gp_regs[2..7] = X2-X7 (user args), gp_regs[8] = X8, gp_regs[9] = X17 */

    /* Increment call count (atomic would be ideal but int increment is fine
     * for our single-writer-from-reentrancy-guarded-context usage) */
    hook->call_count++;

    /* Get timestamp */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char ts[64];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));

    /* Get thread ID */
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);

    /* Compute slot index from hook pointer */
    int slot = (int)(hook - sphinx_hook_table);

    /* Parse type encoding to extract arg types */
    const char *enc = hook->type_encoding;
    int enc_len = (int)strlen(enc);

    /* Build args JSON: skip self (arg0) and _cmd (arg1), format arg2+ */
    char args_json[2048];
    int apos = 0;
    apos += snprintf(args_json + apos, sizeof(args_json) - apos, "{");

    if (enc_len > 0) {
        const char *p = enc;
        int arg_idx = 0;
        int first_user_arg = 1;

        while (*p && apos < (int)sizeof(args_json) - 200) {
            /* Skip offset digits */
            if (*p >= '0' && *p <= '9') { p++; continue; }

            char type_char = *p;

            /* Only format user args (arg2+) */
            if (arg_idx >= 2 && arg_idx <= 9) {
                /* GP register index: arg_idx maps to X(arg_idx)
                 * arg2 -> gp_regs[2], arg3 -> gp_regs[3], etc. */
                int reg_idx = arg_idx;
                if (reg_idx < 8) {
                    uintptr_t val = gp_regs[reg_idx];
                    char val_buf[512];
                    format_arg_value(val_buf, sizeof(val_buf), type_char, val);

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

            /* Skip complex types */
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

    /* Build trace log entry JSON */
    char entry[SPHINX_RING_ENTRY_SIZE];
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

    sphinx_ring_push(&trace_log_ring, entry);

    /* Also log to file */
    char log_data[512];
    snprintf(log_data, sizeof(log_data),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\","
             "\"call_count\":%d",
             slot, hook->class_name, hook->sel_name, hook->call_count);
    sphinx_log(MOD, "trace_call", log_data);

    trace_guard_leave();
}

/* ===================================================================
 *  Install a trace hook on a single method
 *  Returns slot index on success, -1 on failure (sets error in resp)
 * =================================================================== */

static int trace_install_hook(Class cls, SEL sel, const char *className,
                              const char *methodName, int is_class_method,
                              resp_t *r) {
    /* Check if already traced */
    int existing = trace_find_hook(cls, sel);
    if (existing >= 0) {
        if (r) resp_append(r, "\"error\":\"already traced (slot %d)\"", existing);
        return -1;
    }

    /* Find a free slot */
    int slot = trace_find_free_slot();
    if (slot < 0) {
        if (r) resp_append(r, "\"error\":\"all 256 trace slots full\"");
        return -1;
    }

    /* Get the Method */
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

    /* Populate hook table entry */
    sphinx_hook_t *hook = &sphinx_hook_table[slot];
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

    /* Install the stub as the new IMP */
    method_setImplementation(m, sphinx_stub_imp(slot));
    hook->active = 1;

    return slot;
}

/* ===================================================================
 *  Generic hook that logs the call (legacy hook_method system)
 * =================================================================== */

static void generic_hook(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    const char *sel = sel_getName(_cmd);

    char data[2048];
    snprintf(data, sizeof(data),
             "\"class\":\"%s\",\"method\":\"%s\",\"address\":\"0x%lx\"",
             cls, sel, (unsigned long)self);
    sphinx_log(MOD, "hook_call", data);
    fprintf(stderr, "[sphinx-bridge] HOOK: [%s %s] @ 0x%lx\n",
            cls, sel, (unsigned long)self);

    /* Find and call original */
    for (int i = 0; i < hook_count; i++) {
        if (hooks[i].active && hooks[i].selector == _cmd &&
            hooks[i].cls == object_getClass(self)) {
            void (*orig)(id, SEL) = (void (*)(id, SEL))hooks[i].originalImp;
            orig(self, _cmd);
            return;
        }
    }
}

/* ===================================================================
 *  Command: hook_method (legacy simple hook)
 * =================================================================== */

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

    /* Check if already hooked */
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

    resp_append(r, "\"hooked\":true,\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"hookIndex\":%d", idx);

    char log_buf[1024];
    snprintf(log_buf, sizeof(log_buf),
             "\"class\":\"%s\",\"method\":\"%s\"", className, methodName);
    sphinx_log(MOD, "hook_install", log_buf);
}

/* ===================================================================
 *  Command: unhook_method (legacy)
 * =================================================================== */

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

/* ===================================================================
 *  Command: trace
 *  Install a trampoline-based trace hook with argument capture
 * =================================================================== */

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

    /* Try instance method first, fall back to class method */
    int is_class_method = 0;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        m = class_getClassMethod(cls, sel);
        if (m) is_class_method = 1;
    }
    if (!m) { resp_append(r, "\"error\":\"method not found\""); return; }

    int slot = trace_install_hook(cls, sel, className, methodName,
                                  is_class_method, r);
    if (slot < 0) return;  /* error already set */

    sphinx_hook_t *hook = &sphinx_hook_table[slot];

    resp_append(r, "\"hooked\":true,\"slot\":%d,\"class\":", slot);
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"type_encoding\":");
    resp_append_json_str(r, hook->type_encoding);
    resp_append(r, ",\"arg_types\":");
    typeenc_to_arg_types(hook->type_encoding, r);

    char log_buf[1024];
    snprintf(log_buf, sizeof(log_buf),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\","
             "\"type_encoding\":\"%s\"",
             slot, className, methodName, hook->type_encoding);
    sphinx_log(MOD, "trace_install", log_buf);
}

/* ===================================================================
 *  Command: trace_class
 *  Trace all instance methods of a class
 * =================================================================== */

/* Methods that are unsafe to hook -- cause crashes or infinite recursion */
static int is_unsafe_method(const char *name) {
    static const char *unsafe[] = {
        "dealloc", ".cxx_destruct", "retain", "release", "autorelease",
        "class", "respondsToSelector:", "methodSignatureForSelector:",
        "forwardInvocation:", "doesNotRecognizeSelector:",
        "isKindOfClass:", "isMemberOfClass:", "conformsToProtocol:",
        "isEqual:", "hash", "self", "performSelector:",
        "performSelector:withObject:", "performSelector:withObject:withObject:",
        "description", "debugDescription", "init",
        NULL
    };
    for (int i = 0; unsafe[i]; i++) {
        if (strcmp(name, unsafe[i]) == 0) return 1;
    }
    /* Skip methods starting with underscore (private/internal) */
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

    int hooked = 0;
    int skipped = 0;
    /* Temporary buffers for response */
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

        /* Check if slots are available */
        if (trace_find_free_slot() < 0) {
            /* No more slots -- report partial success */
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
        /* Use a temporary resp_t to catch errors without polluting main response */
        resp_t tmp = resp_new();
        int slot = trace_install_hook(cls, sel, className, sel_name, 0, &tmp);
        resp_free(&tmp);

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
    resp_append(r, ",\"methods\":%s", hooked_methods);
    resp_append(r, ",\"skipped_reasons\":%s", skipped_reasons);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf),
             "\"class\":\"%s\",\"hooked\":%d,\"skipped\":%d",
             className, hooked, skipped);
    sphinx_log(MOD, "trace_class", log_buf);
}

/* ===================================================================
 *  Command: trace_log
 *  Retrieve recent trace entries from the ring buffer
 * =================================================================== */

static void cmd_trace_log(const char *args, resp_t *r) {
    trace_log_init();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;
    if (limit > SPHINX_RING_CAPACITY) limit = SPHINX_RING_CAPACITY;

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
        const char *entry = sphinx_ring_get(&trace_log_ring, i);
        if (!entry) break;

        /* Apply filters by checking JSON string content */
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

/* ===================================================================
 *  Command: untrace
 *  Remove a trace hook by slot index or class+method
 * =================================================================== */

static void cmd_untrace(const char *args, resp_t *r) {
    /* Option A: by slot number */
    char slot_str[32] = "";
    int has_slot = (json_get_string(args, "slot", slot_str,
                                    sizeof(slot_str)) != NULL);
    int slot = -1;

    if (has_slot) {
        slot = atoi(slot_str);
        if (slot < 0 || slot >= SPHINX_MAX_HOOKS) {
            resp_append(r, "\"error\":\"invalid slot (0-255)\"");
            return;
        }
        if (!sphinx_hook_table[slot].active) {
            resp_append(r, "\"error\":\"slot %d is not active\"", slot);
            return;
        }
    } else {
        /* Option B: by class + method */
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

    /* Restore original IMP */
    sphinx_hook_t *hook = &sphinx_hook_table[slot];
    Method m = class_getInstanceMethod(hook->cls, hook->sel);
    if (!m) m = class_getClassMethod(hook->cls, hook->sel);
    if (m) {
        method_setImplementation(m, hook->original_imp);
    }
    hook->active = 0;

    resp_append(r, "\"unhooked\":true,\"slot\":%d,\"class\":", slot);
    resp_append_json_str(r, hook->class_name);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, hook->sel_name);

    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf),
             "\"slot\":%d,\"class\":\"%s\",\"method\":\"%s\"",
             slot, hook->class_name, hook->sel_name);
    sphinx_log(MOD, "trace_remove", log_buf);
}
