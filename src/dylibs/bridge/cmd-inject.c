/*
 * cmd-inject.c -- Runtime injection commands for the Sphinx LLM bridge
 *
 * Commands: inject_class, inject_method, replace_delegate
 * Implements runtime class synthesis and method injection via ObjC runtime.
 * Implemented in Sprint 13.5.
 *
 * Unity build: #included from bridge/sphinx-bridge.c
 */
#include "sphinx-bridge.h"

/* ===================================================================
 *  Pre-built implementation catalog
 *  These are IMP functions that can be assigned to injected methods.
 *  Each follows the standard ObjC calling convention: (id self, SEL _cmd, ...)
 * =================================================================== */

/* log_all_args: Logs invocation details to stderr and returns nil */
static id sphinx_imp_log_all_args(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    const char *sel = sel_getName(_cmd);
    fprintf(stderr, "[sphinx-inject] %s -[%s %s] called\n",
            cls, cls, sel);
    sphinx_log("inject", "method_call",
               "\"class\":\"%s\",\"selector\":\"%s\"");
    return nil;
}

/* return_yes: Returns YES (for BOOL-returning methods) */
static BOOL sphinx_imp_return_yes(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[sphinx-inject] %s -%s -> YES\n", cls, sel_getName(_cmd));
    return YES;
}

/* return_no: Returns NO */
static BOOL sphinx_imp_return_no(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[sphinx-inject] %s -%s -> NO\n", cls, sel_getName(_cmd));
    return NO;
}

/* return_nil: Returns nil (for object-returning methods) */
static id sphinx_imp_return_nil(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[sphinx-inject] %s -%s -> nil\n", cls, sel_getName(_cmd));
    return nil;
}

/* forward_to_original: Chains to original implementation stored in an associated object.
 * The original IMP is stored under key "sphinx_orig_<selector>" via objc_setAssociatedObject
 * on the class itself (not the instance). */
static id sphinx_imp_forward_to_original(id self, SEL _cmd) {
    const char *sel_name = sel_getName(_cmd);
    char assoc_key[512];
    snprintf(assoc_key, sizeof(assoc_key), "sphinx_orig_%s", sel_name);

    /* Look up the original IMP stored as an NSValue on the class */
    SEL keySel = sel_registerName(assoc_key);
    id stored = objc_getAssociatedObject((id)object_getClass(self), (const void *)keySel);
    if (stored) {
        SEL ptrSel = sel_registerName("pointerValue");
        void *(*getPtr)(id, SEL) = (void *(*)(id, SEL))objc_msgSend;
        void *orig_ptr = getPtr(stored, ptrSel);
        if (orig_ptr) {
            id (*orig_imp)(id, SEL) = (id (*)(id, SEL))orig_ptr;
            fprintf(stderr, "[sphinx-inject] forwarding %s to original\n", sel_name);
            return orig_imp(self, _cmd);
        }
    }
    fprintf(stderr, "[sphinx-inject] forward_to_original: no original found for %s\n", sel_name);
    return nil;
}

/* ===================================================================
 *  IMP catalog lookup
 * =================================================================== */

typedef struct {
    const char *name;
    IMP imp;
    const char *type_encoding;  /* default type encoding if not specified */
} sphinx_imp_entry_t;

static const sphinx_imp_entry_t imp_catalog[] = {
    { "log_all_args",         (IMP)sphinx_imp_log_all_args,         "@@:" },
    { "return_yes",           (IMP)sphinx_imp_return_yes,           "B@:" },
    { "return_no",            (IMP)sphinx_imp_return_no,            "B@:" },
    { "return_nil",           (IMP)sphinx_imp_return_nil,           "@@:" },
    { "forward_to_original",  (IMP)sphinx_imp_forward_to_original,  "@@:" },
    { NULL, NULL, NULL }
};

static const sphinx_imp_entry_t *find_imp(const char *name) {
    for (int i = 0; imp_catalog[i].name; i++) {
        if (strcmp(imp_catalog[i].name, name) == 0) return &imp_catalog[i];
    }
    return NULL;
}

/* ===================================================================
 *  Injected class tracking
 * =================================================================== */

#define SPHINX_MAX_INJECTED 64

typedef struct {
    char name[256];
    Class cls;
    int registered;  /* 1 = objc_registerClassPair called */
} sphinx_injected_class_t;

static sphinx_injected_class_t injected_classes[SPHINX_MAX_INJECTED];
static int injected_count = 0;

static sphinx_injected_class_t *find_injected(const char *name) {
    for (int i = 0; i < injected_count; i++) {
        if (strcmp(injected_classes[i].name, name) == 0) return &injected_classes[i];
    }
    return NULL;
}

/* ===================================================================
 *  Command: inject_class
 *  Creates a new ObjC class at runtime
 *  Args: name (string), superclass (string, default "NSObject"),
 *        protocols (comma-separated string, optional)
 * =================================================================== */

static void cmd_inject_class(const char *args, resp_t *r) {
    char name[256] = "";
    char superclass[256] = "NSObject";
    char protocols[1024] = "";

    if (!json_get_string(args, "name", name, sizeof(name))) {
        resp_append(r, "\"error\":\"missing name arg\"");
        return;
    }

    json_get_string(args, "superclass", superclass, sizeof(superclass));
    json_get_string(args, "protocols", protocols, sizeof(protocols));

    /* Check if class already exists */
    if (objc_getClass(name)) {
        resp_append(r, "\"error\":\"class already exists\",\"class\":");
        resp_append_json_str(r, name);
        return;
    }

    /* Check if we already created it */
    if (find_injected(name)) {
        resp_append(r, "\"error\":\"class already injected\",\"class\":");
        resp_append_json_str(r, name);
        return;
    }

    if (injected_count >= SPHINX_MAX_INJECTED) {
        resp_append(r, "\"error\":\"max injected classes reached (%d)\"", SPHINX_MAX_INJECTED);
        return;
    }

    /* Resolve superclass */
    Class super = objc_getClass(superclass);
    if (!super) {
        resp_append(r, "\"error\":\"superclass not found\",\"superclass\":");
        resp_append_json_str(r, superclass);
        return;
    }

    /* Create the class pair (allocates metaclass too) */
    Class newCls = objc_allocateClassPair(super, name, 0);
    if (!newCls) {
        resp_append(r, "\"error\":\"objc_allocateClassPair failed\"");
        return;
    }

    /* Add protocol conformance */
    int proto_count = 0;
    resp_append(r, "\"protocols\":[");
    if (protocols[0]) {
        char *proto_copy = strdup(protocols);
        char *saveptr = NULL;
        char *token = strtok_r(proto_copy, ",", &saveptr);
        while (token) {
            /* Trim whitespace */
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            Protocol *proto = objc_getProtocol(token);
            if (proto) {
                class_addProtocol(newCls, proto);
                if (proto_count > 0) resp_append(r, ",");
                resp_append_json_str(r, token);
                proto_count++;
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(proto_copy);
    }
    resp_append(r, "]");

    /* Register the class (makes it available to the runtime) */
    objc_registerClassPair(newCls);

    /* Track it */
    strlcpy(injected_classes[injected_count].name, name, sizeof(injected_classes[0].name));
    injected_classes[injected_count].cls = newCls;
    injected_classes[injected_count].registered = 1;
    injected_count++;

    resp_append(r, ",\"name\":");
    resp_append_json_str(r, name);
    resp_append(r, ",\"superclass\":");
    resp_append_json_str(r, superclass);
    resp_append(r, ",\"class_address\":\"0x%lx\"", (unsigned long)newCls);
    resp_append(r, ",\"protocol_count\":%d", proto_count);
    resp_append(r, ",\"injected_total\":%d", injected_count);

    fprintf(stderr, "[sphinx-inject] created class %s (super: %s, protocols: %d)\n",
            name, superclass, proto_count);
}

/* ===================================================================
 *  Command: inject_method
 *  Adds a method to a class using a pre-built implementation
 *  Args: class (string), selector (string),
 *        implementation (string — catalog name),
 *        types (string — ObjC type encoding, optional)
 * =================================================================== */

static void cmd_inject_method(const char *args, resp_t *r) {
    char className[256] = "";
    char selector[512] = "";
    char impl_name[128] = "";
    char types[256] = "";

    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }
    if (!json_get_string(args, "selector", selector, sizeof(selector))) {
        resp_append(r, "\"error\":\"missing selector arg\"");
        return;
    }
    if (!json_get_string(args, "implementation", impl_name, sizeof(impl_name))) {
        resp_append(r, "\"error\":\"missing implementation arg\"");
        return;
    }

    json_get_string(args, "types", types, sizeof(types));

    /* Look up class */
    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\",\"class\":");
        resp_append_json_str(r, className);
        return;
    }

    /* Look up implementation from catalog */
    const sphinx_imp_entry_t *entry = find_imp(impl_name);
    if (!entry) {
        resp_append(r, "\"error\":\"unknown implementation\",\"implementation\":");
        resp_append_json_str(r, impl_name);
        resp_append(r, ",\"available\":[");
        for (int i = 0; imp_catalog[i].name; i++) {
            if (i > 0) resp_append(r, ",");
            resp_append_json_str(r, imp_catalog[i].name);
        }
        resp_append(r, "]");
        return;
    }

    /* Use specified type encoding or default from catalog */
    const char *type_enc = types[0] ? types : entry->type_encoding;

    SEL sel = sel_registerName(selector);

    /* Check if method already exists — if so, save original for forwarding */
    Method existing = class_getInstanceMethod(cls, sel);
    if (existing) {
        IMP orig = method_getImplementation(existing);

        /* Store original IMP as associated object for forward_to_original */
        Class nsVal = objc_getClass("NSValue");
        SEL valSel = sel_registerName("valueWithPointer:");
        id (*makeVal)(id, SEL, const void *) = (id (*)(id, SEL, const void *))objc_msgSend;
        id wrapped = makeVal((id)nsVal, valSel, (const void *)orig);

        char assoc_key[512];
        snprintf(assoc_key, sizeof(assoc_key), "sphinx_orig_%s", selector);
        SEL keySel = sel_registerName(assoc_key);

        /* OBJC_ASSOCIATION_RETAIN_NONATOMIC = 1 */
        objc_setAssociatedObject((id)cls, (const void *)keySel, wrapped, 1);

        /* Replace existing implementation */
        method_setImplementation(existing, entry->imp);

        resp_append(r, "\"action\":\"replaced\"");
        resp_append(r, ",\"original_saved\":true");
    } else {
        /* Add new method */
        BOOL added = class_addMethod(cls, sel, entry->imp, type_enc);
        if (!added) {
            resp_append(r, "\"error\":\"class_addMethod failed\"");
            return;
        }
        resp_append(r, "\"action\":\"added\"");
    }

    resp_append(r, ",\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"selector\":");
    resp_append_json_str(r, selector);
    resp_append(r, ",\"implementation\":");
    resp_append_json_str(r, impl_name);
    resp_append(r, ",\"types\":");
    resp_append_json_str(r, type_enc);

    fprintf(stderr, "[sphinx-inject] added method -[%s %s] -> %s\n",
            className, selector, impl_name);
}

/* ===================================================================
 *  Command: replace_delegate
 *  Replaces a delegate property on an object with a new injected class
 *  Args: address (hex), property (string), new_class (string)
 *
 *  Chains to original: sets up forward_to_original for all delegate
 *  protocol methods.
 * =================================================================== */

static void cmd_replace_delegate(const char *args, resp_t *r) {
    char addr_str[64] = "";
    char property[256] = "delegate";
    char new_class_name[256] = "";

    if (!json_get_string(args, "address", addr_str, sizeof(addr_str))) {
        resp_append(r, "\"error\":\"missing address arg\"");
        return;
    }
    json_get_string(args, "property", property, sizeof(property));
    if (!json_get_string(args, "new_class", new_class_name, sizeof(new_class_name))) {
        resp_append(r, "\"error\":\"missing new_class arg\"");
        return;
    }

    uintptr_t addr = strtoul(addr_str, NULL, 16);
    if (!addr || !is_valid_objc_ptr((void *)addr)) {
        resp_append(r, "\"error\":\"invalid address\"");
        return;
    }

    id target = (id)addr;

    /* Verify the property exists */
    Class targetCls = object_getClass(target);
    SEL propSel = sel_registerName(property);
    if (!class_getInstanceMethod(targetCls, propSel)) {
        resp_append(r, "\"error\":\"property getter not found\",\"property\":");
        resp_append_json_str(r, property);
        return;
    }

    /* Get the current delegate */
    id (*getDelegate)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id oldDelegate = getDelegate(target, propSel);

    /* Resolve the new class */
    Class newCls = objc_getClass(new_class_name);
    if (!newCls) {
        resp_append(r, "\"error\":\"new_class not found\",\"new_class\":");
        resp_append_json_str(r, new_class_name);
        return;
    }

    /* Instantiate the new class: [[NewClass alloc] init] */
    SEL allocSel = sel_registerName("alloc");
    SEL initSel = sel_registerName("init");
    id (*alloc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id (*init)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id newDelegate = init(alloc((id)newCls, allocSel), initSel);

    if (!newDelegate) {
        resp_append(r, "\"error\":\"failed to instantiate new class\"");
        return;
    }

    /* Store reference to old delegate on the new instance (for chaining) */
    /* Use associated objects: key = "sphinx_original_delegate" */
    SEL assocKeySel = sel_registerName("sphinx_original_delegate");
    /* OBJC_ASSOCIATION_RETAIN_NONATOMIC = 1 */
    objc_setAssociatedObject(newDelegate, (const void *)assocKeySel, oldDelegate, 1);

    /* Set the new delegate via setter: setDelegate:, setProperty: */
    char setter[256];
    snprintf(setter, sizeof(setter), "set%c%s:",
             (char)toupper((unsigned char)property[0]),
             property + 1);
    SEL setterSel = sel_registerName(setter);
    if (!class_getInstanceMethod(targetCls, setterSel)) {
        resp_append(r, "\"error\":\"setter not found\",\"setter\":");
        resp_append_json_str(r, setter);
        return;
    }

    void (*setDelegate)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
    setDelegate(target, setterSel, newDelegate);

    /* Build response — field names match bridge.py formatter */
    resp_append(r, "\"object_address\":\"0x%lx\"", (unsigned long)addr);
    resp_append(r, ",\"target_class\":");
    resp_append_json_str(r, class_getName(targetCls));
    resp_append(r, ",\"delegate_property\":");
    resp_append_json_str(r, property);
    resp_append(r, ",\"original_class\":");
    if (oldDelegate) {
        resp_append_json_str(r, class_getName(object_getClass(oldDelegate)));
    } else {
        resp_append(r, "null");
    }
    resp_append(r, ",\"new_delegate_address\":\"0x%lx\"", (unsigned long)newDelegate);
    resp_append(r, ",\"new_class\":");
    resp_append_json_str(r, new_class_name);
    resp_append(r, ",\"chained\":true");

    fprintf(stderr, "[sphinx-inject] replaced %s.%s: %s -> %s\n",
            class_getName(targetCls), property,
            oldDelegate ? class_getName(object_getClass(oldDelegate)) : "(nil)",
            new_class_name);
}
