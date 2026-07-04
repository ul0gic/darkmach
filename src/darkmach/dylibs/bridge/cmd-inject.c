/* Runtime injection commands (class synthesis, method injection via ObjC runtime).
 * Unity build: #included from darkmach-bridge.c */
#include "darkmach-bridge.h"


static id darkmach_imp_log_all_args(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    const char *sel = sel_getName(_cmd);
    fprintf(stderr, "[darkmach-inject] %s -[%s %s] called\n",
            cls, cls, sel);
    darkmach_log("inject", "method_call",
               "\"class\":\"%s\",\"selector\":\"%s\"");
    return nil;
}

static BOOL darkmach_imp_return_yes(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[darkmach-inject] %s -%s -> YES\n", cls, sel_getName(_cmd));
    return YES;
}

static BOOL darkmach_imp_return_no(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[darkmach-inject] %s -%s -> NO\n", cls, sel_getName(_cmd));
    return NO;
}

static id darkmach_imp_return_nil(id self, SEL _cmd) {
    const char *cls = class_getName(object_getClass(self));
    fprintf(stderr, "[darkmach-inject] %s -%s -> nil\n", cls, sel_getName(_cmd));
    return nil;
}

/* forward_to_original: Chains to original implementation stored in an associated object.
 * The original IMP is stored under key "darkmach_orig_<selector>" via objc_setAssociatedObject
 * on the class itself (not the instance). */
static id darkmach_imp_forward_to_original(id self, SEL _cmd) {
    const char *sel_name = sel_getName(_cmd);
    char assoc_key[512];
    snprintf(assoc_key, sizeof(assoc_key), "darkmach_orig_%s", sel_name);

    SEL keySel = sel_registerName(assoc_key);
    id stored = objc_getAssociatedObject((id)object_getClass(self), (const void *)keySel);
    if (stored) {
        SEL ptrSel = sel_registerName("pointerValue");
        void *(*getPtr)(id, SEL) = (void *(*)(id, SEL))objc_msgSend;
        void *orig_ptr = getPtr(stored, ptrSel);
        if (orig_ptr) {
            id (*orig_imp)(id, SEL) = (id (*)(id, SEL))orig_ptr;
            fprintf(stderr, "[darkmach-inject] forwarding %s to original\n", sel_name);
            return orig_imp(self, _cmd);
        }
    }
    fprintf(stderr, "[darkmach-inject] forward_to_original: no original found for %s\n", sel_name);
    return nil;
}


typedef struct {
    const char *name;
    IMP imp;
    const char *type_encoding;  /* default type encoding if not specified */
} darkmach_imp_entry_t;

static const darkmach_imp_entry_t imp_catalog[] = {
    { "log_all_args",         (IMP)darkmach_imp_log_all_args,         "@@:" },
    { "return_yes",           (IMP)darkmach_imp_return_yes,           "B@:" },
    { "return_no",            (IMP)darkmach_imp_return_no,            "B@:" },
    { "return_nil",           (IMP)darkmach_imp_return_nil,           "@@:" },
    { "forward_to_original",  (IMP)darkmach_imp_forward_to_original,  "@@:" },
    { NULL, NULL, NULL }
};

static const darkmach_imp_entry_t *find_imp(const char *name) {
    for (int i = 0; imp_catalog[i].name; i++) {
        if (strcmp(imp_catalog[i].name, name) == 0) return &imp_catalog[i];
    }
    return NULL;
}


#define DARKMACH_MAX_INJECTED 64

typedef struct {
    char name[256];
    Class cls;
    int registered;  /* 1 = objc_registerClassPair called */
} darkmach_injected_class_t;

static darkmach_injected_class_t injected_classes[DARKMACH_MAX_INJECTED];
static int injected_count = 0;

static darkmach_injected_class_t *find_injected(const char *name) {
    for (int i = 0; i < injected_count; i++) {
        if (strcmp(injected_classes[i].name, name) == 0) return &injected_classes[i];
    }
    return NULL;
}


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

    if (objc_getClass(name)) {
        resp_append(r, "\"error\":\"class already exists\",\"class\":");
        resp_append_json_str(r, name);
        return;
    }

    if (find_injected(name)) {
        resp_append(r, "\"error\":\"class already injected\",\"class\":");
        resp_append_json_str(r, name);
        return;
    }

    if (injected_count >= DARKMACH_MAX_INJECTED) {
        resp_append(r, "\"error\":\"max injected classes reached (%d)\"", DARKMACH_MAX_INJECTED);
        return;
    }

    Class super = objc_getClass(superclass);
    if (!super) {
        resp_append(r, "\"error\":\"superclass not found\",\"superclass\":");
        resp_append_json_str(r, superclass);
        return;
    }

    Class newCls = objc_allocateClassPair(super, name, 0);
    if (!newCls) {
        resp_append(r, "\"error\":\"objc_allocateClassPair failed\"");
        return;
    }

    int proto_count = 0;
    resp_append(r, "\"protocols\":[");
    if (protocols[0]) {
        char *proto_copy = strdup(protocols);
        char *saveptr = NULL;
        char *token = strtok_r(proto_copy, ",", &saveptr);
        while (token) {
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

    objc_registerClassPair(newCls);

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

    fprintf(stderr, "[darkmach-inject] created class %s (super: %s, protocols: %d)\n",
            name, superclass, proto_count);
}


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

    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\",\"class\":");
        resp_append_json_str(r, className);
        return;
    }

    const darkmach_imp_entry_t *entry = find_imp(impl_name);
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

    const char *type_enc = types[0] ? types : entry->type_encoding;

    SEL sel = sel_registerName(selector);

    Method existing = class_getInstanceMethod(cls, sel);
    if (existing) {
        IMP orig = method_getImplementation(existing);

        Class nsVal = objc_getClass("NSValue");
        SEL valSel = sel_registerName("valueWithPointer:");
        id (*makeVal)(id, SEL, const void *) = (id (*)(id, SEL, const void *))objc_msgSend;
        id wrapped = makeVal((id)nsVal, valSel, (const void *)orig);

        char assoc_key[512];
        snprintf(assoc_key, sizeof(assoc_key), "darkmach_orig_%s", selector);
        SEL keySel = sel_registerName(assoc_key);

        /* OBJC_ASSOCIATION_RETAIN_NONATOMIC = 1 */
        objc_setAssociatedObject((id)cls, (const void *)keySel, wrapped, 1);

        method_setImplementation(existing, entry->imp);

        resp_append(r, "\"action\":\"replaced\"");
        resp_append(r, ",\"original_saved\":true");
    } else {
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

    fprintf(stderr, "[darkmach-inject] added method -[%s %s] -> %s\n",
            className, selector, impl_name);
}

/* replace_delegate: swap a delegate property for an injected class,
 * forwarding all protocol methods to the original. */

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

    Class targetCls = object_getClass(target);
    SEL propSel = sel_registerName(property);
    if (!class_getInstanceMethod(targetCls, propSel)) {
        resp_append(r, "\"error\":\"property getter not found\",\"property\":");
        resp_append_json_str(r, property);
        return;
    }

    id (*getDelegate)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id oldDelegate = getDelegate(target, propSel);

    Class newCls = objc_getClass(new_class_name);
    if (!newCls) {
        resp_append(r, "\"error\":\"new_class not found\",\"new_class\":");
        resp_append_json_str(r, new_class_name);
        return;
    }

    SEL allocSel = sel_registerName("alloc");
    SEL initSel = sel_registerName("init");
    id (*alloc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id (*init)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id newDelegate = init(alloc((id)newCls, allocSel), initSel);

    if (!newDelegate) {
        resp_append(r, "\"error\":\"failed to instantiate new class\"");
        return;
    }

    SEL assocKeySel = sel_registerName("darkmach_original_delegate");
    /* OBJC_ASSOCIATION_RETAIN_NONATOMIC = 1 */
    objc_setAssociatedObject(newDelegate, (const void *)assocKeySel, oldDelegate, 1);

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

    fprintf(stderr, "[darkmach-inject] replaced %s.%s: %s -> %s\n",
            class_getName(targetCls), property,
            oldDelegate ? class_getName(object_getClass(oldDelegate)) : "(nil)",
            new_class_name);
}

/* deeplink: open a URL via UIApplication (triggers the app's URL-scheme handler).
 * Must run on the main thread; tries openURL:options:completionHandler: then openURL:. */

static void cmd_deeplink(const char *args, resp_t *r) {
    char url_str[2048] = "";

    if (!json_get_string(args, "url", url_str, sizeof(url_str))) {
        resp_append(r, "\"error\":\"missing url arg\"");
        return;
    }

    if (url_str[0] == '\0') {
        resp_append(r, "\"error\":\"url is empty\"");
        return;
    }

    Class nsurl_cls = objc_getClass("NSURL");
    if (!nsurl_cls) {
        resp_append(r, "\"error\":\"NSURL class not found\"");
        return;
    }

    Class nsstring_cls = objc_getClass("NSString");
    SEL stringWithUTF8Sel = sel_registerName("stringWithUTF8String:");
    id (*makeNSString)(id, SEL, const char *) =
        (id (*)(id, SEL, const char *))objc_msgSend;
    id ns_url_str = makeNSString((id)nsstring_cls, stringWithUTF8Sel, url_str);
    if (!ns_url_str) {
        resp_append(r, "\"error\":\"failed to create NSString from url\"");
        return;
    }

    SEL urlWithStringSel = sel_registerName("URLWithString:");
    id (*makeURL)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    id nsurl = makeURL((id)nsurl_cls, urlWithStringSel, ns_url_str);
    if (!nsurl) {
        resp_append(r, "\"error\":\"invalid URL\",\"url\":");
        resp_append_json_str(r, url_str);
        return;
    }

    Class uiapp_cls = objc_getClass("UIApplication");
    if (!uiapp_cls) {
        resp_append(r, "\"error\":\"UIApplication class not found\"");
        return;
    }

    SEL sharedSel = sel_registerName("sharedApplication");
    id (*getShared)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id app = getShared((id)uiapp_cls, sharedSel);
    if (!app) {
        resp_append(r, "\"error\":\"UIApplication sharedApplication returned nil\"");
        return;
    }

    SEL schemeSel = sel_registerName("scheme");
    id (*getScheme)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id scheme_ns = getScheme(nsurl, schemeSel);
    const char *scheme_c = scheme_ns ? nsstring_to_c(scheme_ns) : "(none)";

    /* Dispatch openURL: to main thread.
     * Use openURL:options:completionHandler: (iOS 10+).
     * An empty NSDictionary for options: @{} */
    Class nsdict_cls = objc_getClass("NSDictionary");
    SEL dictSel = sel_registerName("dictionary");
    id (*makeDict)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id empty_opts = makeDict((id)nsdict_cls, dictSel);

    __block int dispatched = 0;

    if (pthread_main_np()) {
        SEL openSel = sel_registerName("openURL:options:completionHandler:");
        void (*openURL)(id, SEL, id, id, id) =
            (void (*)(id, SEL, id, id, id))objc_msgSend;
        openURL(app, openSel, nsurl, empty_opts, nil);
        dispatched = 1;
    } else {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            SEL openSel = sel_registerName("openURL:options:completionHandler:");
            void (*openURL)(id, SEL, id, id, id) =
                (void (*)(id, SEL, id, id, id))objc_msgSend;
            openURL(app, openSel, nsurl, empty_opts, nil);
            dispatched = 1;
            dispatch_semaphore_signal(sem);
        });
        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC);
        long result = dispatch_semaphore_wait(sem, timeout);
        if (result != 0) {
            resp_append(r, "\"error\":\"main thread dispatch timed out\",\"url\":");
            resp_append_json_str(r, url_str);
            return;
        }
    }

    resp_append(r, "\"url\":");
    resp_append_json_str(r, url_str);
    resp_append(r, ",\"scheme\":");
    resp_append_json_str(r, scheme_c);
    resp_append(r, ",\"dispatched\":%s", dispatched ? "true" : "false");

    fprintf(stderr, "[darkmach-inject] deeplink opened: %s (scheme: %s)\n",
            url_str, scheme_c);
}
