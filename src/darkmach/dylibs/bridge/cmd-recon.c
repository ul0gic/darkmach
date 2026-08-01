/* Reconnaissance commands. Unity build: #included from darkmach-bridge.c */
#include "darkmach-bridge.h"
#include <dirent.h>
#include <mach-o/getsect.h>
#include <sys/stat.h>

/* Simulator system frameworks live under the runtime root; anything else ships with the app. */
static int image_is_system(const char *path) {
    if (!path) return 1;
    return strstr(path, "/RuntimeRoot/") != NULL ||
           strncmp(path, "/System/", 8) == 0 ||
           strncmp(path, "/usr/lib/", 9) == 0;
}


static void cmd_enumerate_classes(const char *args, resp_t *r) {
    char filter[256] = "";
    json_get_string(args, "filter", filter, sizeof(filter));

    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);

    resp_append(r, "\"classes\":[");
    int first = 1;
    int matched = 0;
    for (unsigned int i = 0; i < count; i++) {
        const char *name = class_getName(classes[i]);
        if (filter[0] && !strstr(name, filter)) continue;
        if (!first) resp_append(r, ",");
        resp_append_json_str(r, name);
        first = 0;
        matched++;
    }
    resp_append(r, "],\"total\":%u,\"matched\":%d", count, matched);
    free(classes);
}


static void cmd_get_methods(const char *args, resp_t *r) {
    char className[512];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\"");
        return;
    }

    resp_append(r, "\"instance_methods\":[");
    unsigned int icount = 0;
    Method *imethods = class_copyMethodList(cls, &icount);
    for (unsigned int i = 0; i < icount; i++) {
        if (i > 0) resp_append(r, ",");
        const char *name = sel_getName(method_getName(imethods[i]));
        const char *types = method_getTypeEncoding(imethods[i]);
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, name);
        resp_append(r, ",\"types\":");
        resp_append_json_str(r, types);
        resp_append(r, "}");
    }
    free(imethods);

    resp_append(r, "],\"class_methods\":[");
    Class metaCls = object_getClass((id)cls);
    unsigned int ccount = 0;
    Method *cmethods = class_copyMethodList(metaCls, &ccount);
    for (unsigned int i = 0; i < ccount; i++) {
        if (i > 0) resp_append(r, ",");
        const char *name = sel_getName(method_getName(cmethods[i]));
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, name);
        resp_append(r, "}");
    }
    free(cmethods);

    resp_append(r, "],\"instance_count\":%u,\"class_count\":%u", icount, ccount);
}


static void cmd_get_properties(const char *args, resp_t *r) {
    char className[512];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\"");
        return;
    }

    resp_append(r, "\"properties\":[");
    unsigned int count = 0;
    objc_property_t *props = class_copyPropertyList(cls, &count);
    for (unsigned int i = 0; i < count; i++) {
        if (i > 0) resp_append(r, ",");
        const char *name = property_getName(props[i]);
        const char *attrs = property_getAttributes(props[i]);
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, name);
        resp_append(r, ",\"attributes\":");
        resp_append_json_str(r, attrs);
        resp_append(r, "}");
    }
    free(props);
    resp_append(r, "],\"count\":%u", count);
}


static void cmd_get_ivars(const char *args, resp_t *r) {
    char className[512];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }

    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\"");
        return;
    }

    resp_append(r, "\"ivars\":[");
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    for (unsigned int i = 0; i < count; i++) {
        if (i > 0) resp_append(r, ",");
        const char *name = ivar_getName(ivars[i]);
        const char *type = ivar_getTypeEncoding(ivars[i]);
        ptrdiff_t offset = ivar_getOffset(ivars[i]);
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, name);
        resp_append(r, ",\"type\":");
        resp_append_json_str(r, type);
        resp_append(r, ",\"offset\":%td}", offset);
    }
    free(ivars);
    resp_append(r, "],\"count\":%u", count);
}


static void cmd_read_property(const char *args, resp_t *r) {
    char prop[256];
    long addr = json_get_long(args, "address");
    if (!json_get_string(args, "property", prop, sizeof(prop))) {
        resp_append(r, "\"error\":\"missing property arg\"");
        return;
    }
    if (addr == 0) {
        resp_append(r, "\"error\":\"missing or zero address\"");
        return;
    }

    id obj = (id)(uintptr_t)addr;
    if (!is_valid_objc_ptr(obj)) {
        resp_append(r, "\"error\":\"object at 0x%lx is no longer valid (deallocated)\"",
                    (unsigned long)addr);
        return;
    }
    SEL sel = sel_registerName(prop);

    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (!responds(obj, respondsSel, sel)) {
        resp_append(r, "\"error\":\"object does not respond to selector\"");
        return;
    }

    id (*getter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id value = getter(obj, sel);

    resp_append(r, "\"property\":");
    resp_append_json_str(r, prop);
    resp_append(r, ",\"address\":\"0x%lx\"", (unsigned long)addr);
    resp_append(r, ",\"value\":");
    resp_append_json_str(r, value ? nsobject_desc(value) : "(null)");
    resp_append(r, ",\"valueClass\":");
    resp_append_json_str(r, value ? class_getName(object_getClass(value)) : "nil");
}


static void cmd_call_method(const char *args, resp_t *r) {
    char method[256];
    long addr = json_get_long(args, "address");
    if (!json_get_string(args, "method", method, sizeof(method))) {
        resp_append(r, "\"error\":\"missing method arg\"");
        return;
    }
    if (addr == 0) {
        resp_append(r, "\"error\":\"missing or zero address\"");
        return;
    }

    id obj = (id)(uintptr_t)addr;
    if (!is_valid_objc_ptr(obj)) {
        resp_append(r, "\"error\":\"object at 0x%lx is no longer valid (deallocated)\"",
                    (unsigned long)addr);
        return;
    }
    SEL sel = sel_registerName(method);

    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (!responds(obj, respondsSel, sel)) {
        resp_append(r, "\"error\":\"object does not respond to selector\"");
        return;
    }

    id (*call)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id result = call(obj, sel);

    resp_append(r, "\"method\":");
    resp_append_json_str(r, method);
    resp_append(r, ",\"result\":");
    resp_append_json_str(r, result ? nsobject_desc(result) : "(null)");
    resp_append(r, ",\"resultClass\":");
    resp_append_json_str(r, result ? class_getName(object_getClass(result)) : "nil");
    resp_append(r, ",\"resultAddress\":\"0x%lx\"", (unsigned long)result);
}


static void dump_view(id view, int depth, resp_t *r, int *count) {
    if (!view || depth > 30) return;

    const char *className = class_getName(object_getClass(view));

    /* Get frame -- on arm64, CGRect returned in registers via objc_msgSend */
    SEL frameSel = sel_registerName("frame");
    typedef struct { double x, y, w, h; } CGRectResult;
    CGRectResult (*getFrame)(id, SEL) = (CGRectResult (*)(id, SEL))objc_msgSend;
    CGRectResult frame = getFrame(view, frameSel);

    SEL accSel = sel_registerName("accessibilityLabel");
    id (*getAcc)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id accLabel = getAcc(view, accSel);
    const char *label = accLabel ? nsobject_desc(accLabel) : NULL;

    SEL textSel = sel_registerName("text");
    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    const char *text = NULL;
    if (responds(view, respondsSel, textSel)) {
        id (*getText)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id textObj = getText(view, textSel);
        if (textObj) text = nsobject_desc(textObj);
    }

    SEL hiddenSel = sel_registerName("isHidden");
    BOOL (*isHidden)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
    BOOL hidden = isHidden(view, hiddenSel);

    if (*count > 0) resp_append(r, ",");
    resp_append(r, "{\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"depth\":%d", depth);
    resp_append(r, ",\"address\":\"0x%lx\"", (unsigned long)view);
    resp_append(r, ",\"frame\":{\"x\":%.1f,\"y\":%.1f,\"w\":%.1f,\"h\":%.1f}",
                frame.x, frame.y, frame.w, frame.h);
    if (hidden) resp_append(r, ",\"hidden\":true");
    if (label) { resp_append(r, ",\"accessibilityLabel\":"); resp_append_json_str(r, label); }
    if (text) { resp_append(r, ",\"text\":"); resp_append_json_str(r, text); }
    resp_append(r, "}");
    (*count)++;

    SEL subviewsSel = sel_registerName("subviews");
    id (*getSubs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id subviews = getSubs(view, subviewsSel);
    if (subviews) {
        SEL countSel = sel_registerName("count");
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        long svCount = getCount(subviews, countSel);

        SEL indexSel = sel_registerName("objectAtIndex:");
        id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

        for (long i = 0; i < svCount; i++) {
            id subview = getAt(subviews, indexSel, (unsigned long)i);
            dump_view(subview, depth + 1, r, count);
        }
    }
}

static void cmd_view_hierarchy(const char *args, resp_t *r) {
    Class appClass = objc_getClass("UIApplication");
    if (!appClass) {
        resp_append(r, "\"error\":\"UIApplication not found\"");
        return;
    }

    SEL sharedSel = sel_registerName("sharedApplication");
    id (*getApp)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id app = getApp((id)appClass, sharedSel);

    SEL windowsSel = sel_registerName("windows");
    id (*getWindows)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id windows = getWindows(app, windowsSel);

    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long winCount = getCount(windows, countSel);

    resp_append(r, "\"views\":[");
    int viewCount = 0;

    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

    for (long i = 0; i < winCount; i++) {
        id window = getAt(windows, indexSel, (unsigned long)i);
        dump_view(window, 0, r, &viewCount);
    }

    resp_append(r, "],\"windowCount\":%ld,\"viewCount\":%d", winCount, viewCount);
}


static void cmd_heap_search(const char *args, resp_t *r) {
    char className[512];
    if (!json_get_string(args, "class", className, sizeof(className))) {
        resp_append(r, "\"error\":\"missing class arg\"");
        return;
    }

    Class targetCls = objc_getClass(className);
    if (!targetCls) {
        resp_append(r, "\"error\":\"class not found\"");
        return;
    }

    resp_append(r, "\"instances\":[");
    int found = 0;

    const char *singletonSels[] = {
        "sharedInstance", "shared", "defaultManager", "sharedManager",
        "currentUser", "sharedClient", "defaultClient",
        "standardUserDefaults", "sharedHTTPCookieStorage",
        "generalPasteboard", "defaultCenter", NULL
    };

    for (int i = 0; singletonSels[i]; i++) {
        SEL sel = sel_registerName(singletonSels[i]);
        Class metaCls = object_getClass((id)targetCls);
        if (class_getClassMethod(targetCls, sel)) {
            id (*getter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id instance = getter((id)targetCls, sel);
            if (instance) {
                if (found > 0) resp_append(r, ",");
                resp_append(r, "{\"address\":\"0x%lx\"", (unsigned long)instance);
                resp_append(r, ",\"via\":");
                resp_append_json_str(r, singletonSels[i]);
                resp_append(r, ",\"description\":");
                resp_append_json_str(r, nsobject_desc(instance));
                resp_append(r, "}");
                found++;
                break;
            }
        }
    }

    Class appClass = objc_getClass("UIApplication");
    if (appClass && found == 0) {
        SEL sharedSel = sel_registerName("sharedApplication");
        id (*getApp)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id app = getApp((id)appClass, sharedSel);
        if (app) {
            SEL delSel = sel_registerName("delegate");
            id (*getDel)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id delegate = getDel(app, delSel);
            SEL isKindSel = sel_registerName("isKindOfClass:");
            BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
            if (delegate && isKind(delegate, isKindSel, targetCls)) {
                resp_append(r, "{\"address\":\"0x%lx\"", (unsigned long)delegate);
                resp_append(r, ",\"via\":\"UIApplication.delegate\"");
                resp_append(r, ",\"description\":");
                resp_append_json_str(r, nsobject_desc(delegate));
                resp_append(r, "}");
                found++;
            }
        }
    }

    resp_append(r, "],\"found\":%d", found);
}


static void cmd_read_memory(const char *args, resp_t *r) {
    long addr = json_get_long(args, "address");
    long size = json_get_long(args, "size");

    if (addr == 0) { resp_append(r, "\"error\":\"missing address\""); return; }
    if (size <= 0 || size > 4096) size = 256;

    vm_size_t vmsize = 0;
    vm_address_t vmaddr = (vm_address_t)addr;
    natural_t nesting = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    kern_return_t kr = vm_region_recurse_64(
        mach_task_self(), &vmaddr, &vmsize, &nesting,
        (vm_region_info_64_t)&info, &count);

    if (kr != KERN_SUCCESS || (vm_address_t)addr < vmaddr ||
        (vm_address_t)addr >= vmaddr + vmsize) {
        resp_append(r, "\"error\":\"address not readable\"");
        return;
    }

    const unsigned char *bytes = (const unsigned char *)(uintptr_t)addr;
    resp_append(r, "\"address\":\"0x%lx\",\"size\":%ld,\"hex\":\"", (unsigned long)addr, size);
    for (long i = 0; i < size; i++) {
        resp_append(r, "%02x", bytes[i]);
    }
    resp_append(r, "\"");

    resp_append(r, ",\"ascii\":\"");
    for (long i = 0; i < size; i++) {
        if (bytes[i] >= 0x20 && bytes[i] < 0x7f)
            resp_append(r, "%c", bytes[i]);
        else
            resp_append(r, ".");
    }
    resp_append(r, "\"");
}


static void cmd_info(const char *args, resp_t *r) {
    Class bundleClass = objc_getClass("NSBundle");
    SEL mainSel = sel_registerName("mainBundle");
    id (*getMain)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id bundle = getMain((id)bundleClass, mainSel);

    SEL idSel = sel_registerName("bundleIdentifier");
    id (*getId)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id bundleId = getId(bundle, idSel);

    SEL infoSel = sel_registerName("infoDictionary");
    id (*getInfo)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id infoDict = getInfo(bundle, infoSel);

    SEL objectForKeySel = sel_registerName("objectForKey:");
    id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;

    Class nsStr = objc_getClass("NSString");
    SEL strSel = sel_registerName("stringWithUTF8String:");
    id (*makeStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;

    id versionKey = makeStr((id)nsStr, strSel, "CFBundleShortVersionString");
    id buildKey = makeStr((id)nsStr, strSel, "CFBundleVersion");
    id nameKey = makeStr((id)nsStr, strSel, "CFBundleDisplayName");

    id version = getObj(infoDict, objectForKeySel, versionKey);
    id build = getObj(infoDict, objectForKeySel, buildKey);
    id name = getObj(infoDict, objectForKeySel, nameKey);

    resp_append(r, "\"bridge\":\"darkmach-bridge\",\"version\":\"0.1.0\"");
    resp_append(r, ",\"pid\":%d", getpid());
    resp_append(r, ",\"bundleId\":");
    resp_append_json_str(r, bundleId ? nsobject_desc(bundleId) : "(null)");
    resp_append(r, ",\"appName\":");
    resp_append_json_str(r, name ? nsobject_desc(name) : "(null)");
    resp_append(r, ",\"appVersion\":");
    resp_append_json_str(r, version ? nsobject_desc(version) : "(null)");
    resp_append(r, ",\"appBuild\":");
    resp_append_json_str(r, build ? nsobject_desc(build) : "(null)");
    resp_append(r, ",\"activeHooks\":%d", hook_count);

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    free(classes);
    resp_append(r, ",\"totalClasses\":%u", classCount);

    resp_append(r, ",\"commands\":[\"info\",\"enumerate_classes\",\"get_methods\","
                "\"get_properties\",\"get_ivars\",\"read_property\",\"call_method\","
                "\"view_hierarchy\",\"keychain_dump\",\"userdefaults_dump\","
                "\"cookies_dump\",\"heap_search\",\"read_memory\","
                "\"hook_method\",\"unhook_method\","
                "\"db_dump\",\"fs_scan\",\"memory_scan\","
                "\"heap_dump\",\"event_tap\",\"env_dump\","
                "\"db_query\",\"db_queries\","
                "\"net_tap\",\"net_filter\",\"crypto_tap\",\"crypto_keys\","
                "\"auth_tap\",\"auth_tokens\","
                "\"trace\",\"trace_class\",\"trace_log\",\"untrace\","
                "\"ui_tap\",\"ui_type\",\"ui_scroll\",\"ui_back\",\"ui_alert_dismiss\","
                "\"webview_list\",\"webview_eval\",\"webview_content\",\"webview_bridge_map\","
                "\"inject_class\",\"inject_method\",\"replace_delegate\","
                "\"entitlement_scan\",\"shared_container_scan\","
                "\"pin_analyze\",\"pin_extract\","
                "\"block_inspect\",\"block_invoke\","
                "\"proto_decode\",\"proto_schema\","
                "\"sdk_map\",\"sdk_keys\","
                "\"mem_forensics\",\"mem_snapshot\",\"mem_diff\","
                "\"timing_probe\",\"timing_compare\"]");
}


/* Gates file content out of responses — binary bytes corrupt the JSON-lines protocol. */
static int is_valid_utf8_text(const unsigned char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (data[i] == 0x00) return 0;  /* embedded NUL = binary */
        if (data[i] < 0x80) {
            i++;
        } else if ((data[i] & 0xE0) == 0xC0) {
            /* 2-byte sequence: 110xxxxx 10xxxxxx */
            if (i + 1 >= len) return 0;
            if ((data[i+1] & 0xC0) != 0x80) return 0;
            /* Reject overlong: code point must be >= 0x80 */
            if ((data[i] & 0x1E) == 0) return 0;
            i += 2;
        } else if ((data[i] & 0xF0) == 0xE0) {
            /* 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx */
            if (i + 2 >= len) return 0;
            if ((data[i+1] & 0xC0) != 0x80) return 0;
            if ((data[i+2] & 0xC0) != 0x80) return 0;
            /* Reject overlong: code point must be >= 0x800 */
            if (data[i] == 0xE0 && (data[i+1] & 0x20) == 0) return 0;
            i += 3;
        } else if ((data[i] & 0xF8) == 0xF0) {
            /* 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
            if (i + 3 >= len) return 0;
            if ((data[i+1] & 0xC0) != 0x80) return 0;
            if ((data[i+2] & 0xC0) != 0x80) return 0;
            if ((data[i+3] & 0xC0) != 0x80) return 0;
            /* Reject overlong: code point must be >= 0x10000 */
            if (data[i] == 0xF0 && (data[i+1] & 0x30) == 0) return 0;
            i += 4;
        } else {
            return 0;
        }
    }
    return 1;
}

static void fs_scan_dir(const char *dir, resp_t *r, int depth, int *file_count, int read_contents) {
    if (depth > 8 || *file_count > 500) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *entry;
    int first_entry = 1;
    while ((entry = readdir(d)) != NULL && *file_count < 500) {
        if (entry->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, entry->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (!first_entry) resp_append(r, ",");
        first_entry = 0;

        if (S_ISDIR(st.st_mode)) {
            resp_append(r, "{\"path\":");
            resp_append_json_str(r, full);
            resp_append(r, ",\"type\":\"dir\",\"children\":[");
            int saved = *file_count;
            (*file_count)++;
            int child_start = *file_count;
            fs_scan_dir(full, r, depth + 1, file_count, read_contents);
            resp_append(r, "]}");
        } else {
            (*file_count)++;
            resp_append(r, "{\"path\":");
            resp_append_json_str(r, full);
            resp_append(r, ",\"name\":");
            resp_append_json_str(r, entry->d_name);
            resp_append(r, ",\"size\":%lld", (long long)st.st_size);

            const char *ext = strrchr(entry->d_name, '.');
            int interesting = 0;
            if (ext && (strcmp(ext, ".json") == 0 || strcmp(ext, ".plist") == 0 ||
                        strcmp(ext, ".xml") == 0 || strcmp(ext, ".config") == 0 ||
                        strcmp(ext, ".key") == 0 || strcmp(ext, ".p12") == 0 ||
                        strcmp(ext, ".cer") == 0 || strcmp(ext, ".pem") == 0 ||
                        strcmp(ext, ".txt") == 0 || strcmp(ext, ".cfg") == 0 ||
                        strcmp(ext, ".env") == 0 || strcmp(ext, ".yaml") == 0 ||
                        strcmp(ext, ".yml") == 0 || strcmp(ext, ".conf") == 0)) {
                interesting = 1;
            }

            if (interesting && read_contents && st.st_size < 32768 && st.st_size > 0) {
                FILE *f = fopen(full, "rb");
                if (f) {
                    unsigned char *content = calloc(1, st.st_size + 1);
                    size_t rd = fread(content, 1, st.st_size, f);
                    fclose(f);

                    if (is_valid_utf8_text(content, rd)) {
                        content[rd] = '\0';
                        resp_append(r, ",\"content\":");
                        resp_append_json_str(r, (const char *)content);
                    } else {
                        resp_append(r, ",\"binary\":true");
                        size_t preview_len = rd < 64 ? rd : 64;
                        char hex_preview[129]; /* 64 bytes * 2 + NUL */
                        for (size_t hi = 0; hi < preview_len; hi++) {
                            snprintf(hex_preview + hi * 2, 3, "%02x", content[hi]);
                        }
                        hex_preview[preview_len * 2] = '\0';
                        resp_append(r, ",\"hex_preview\":");
                        resp_append_json_str(r, hex_preview);
                    }
                    free(content);
                }
            }
            resp_append(r, "}");
        }
        if (r->len > BRIDGE_MAX_RESPONSE - 4096) break;
    }
    closedir(d);
}

static void cmd_fs_scan(const char *args, resp_t *r) {
    char path_filter[512] = "";
    json_get_string(args, "path", path_filter, sizeof(path_filter));
    char read_str[16] = "true";
    json_get_string(args, "read", read_str, sizeof(read_str));
    int read_contents = (strcmp(read_str, "false") != 0);

    id (*homeDir)(void) = (id (*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
    const char *home = "/tmp";
    if (homeDir) {
        id hd = homeDir();
        if (hd) home = nsstring_to_c(hd);
    }

    const char *scan_root = path_filter[0] ? path_filter : home;

    resp_append(r, "\"root\":");
    resp_append_json_str(r, scan_root);
    resp_append(r, ",\"files\":[");
    int file_count = 0;
    fs_scan_dir(scan_root, r, 0, &file_count, read_contents);
    resp_append(r, "],\"total_files\":%d", file_count);
}


static void cmd_memory_scan(const char *args, resp_t *r) {
    char pattern[256] = "";
    json_get_string(args, "pattern", pattern, sizeof(pattern));

    const char *patterns[] = {
        "eyJ",              /* JWT tokens */
        "Bearer ",          /* Bearer auth */
        "Basic ",           /* Basic auth */
        "sk_live_",         /* Stripe live key */
        "pk_live_",         /* Stripe publishable key */
        "AKIA",             /* AWS access key */
        "ghp_",             /* GitHub PAT */
        "api_key",          /* Generic API key */
        "apiKey",           /* Generic API key */
        "secret",           /* Generic secret */
        "password",         /* Password */
        "access_token",     /* OAuth access token */
        "refresh_token",    /* OAuth refresh token */
        NULL
    };
    const char **search_patterns = patterns;
    const char *single_pattern[] = { pattern, NULL };
    if (pattern[0]) search_patterns = single_pattern;

    /* The scan reads its own address space, so query copies echo back as phantom hits. */
    uintptr_t stack_hi = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    uintptr_t stack_lo = stack_hi - pthread_get_stacksize_np(pthread_self());
    uintptr_t args_lo = (uintptr_t)args;
    uintptr_t args_hi = args ? args_lo + strlen(args) + 1 : 0;

    task_t task = mach_task_self();
    vm_address_t addr = 0;
    vm_size_t size = 0;
    natural_t depth = 1;

    resp_append(r, "\"matches\":[");
    int match_count = 0;
    int regions_scanned = 0;
    int self_matches = 0;

    while (1) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = vm_region_recurse_64(task, &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) { depth++; continue; }

        if ((info.protection & VM_PROT_READ) && !(info.protection & VM_PROT_EXECUTE) &&
            size > 0 && size < (1024 * 1024 * 64)) {

            vm_offset_t data = 0;
            mach_msg_type_number_t data_count = 0;
            vm_size_t read_size = size < (1024*1024) ? size : (1024*1024);
            kr = vm_read(task, addr, read_size, &data, &data_count);
            if (kr == KERN_SUCCESS && data_count > 0) {
                regions_scanned++;
                const char *membuf = (const char *)data;

                for (int pi = 0; search_patterns[pi]; pi++) {
                    const char *pat = search_patterns[pi];
                    size_t patlen = strlen(pat);
                    if (patlen == 0) continue;

                    for (size_t off = 0; off + patlen <= data_count && match_count < 200; off++) {
                        if (memcmp(membuf + off, pat, patlen) == 0) {
                            uintptr_t hit = (uintptr_t)(addr + off);
                            uintptr_t resp_lo = (uintptr_t)r->buf;
                            if ((hit >= stack_lo && hit < stack_hi) ||
                                (args_hi && hit >= args_lo && hit < args_hi) ||
                                (hit >= resp_lo && hit < resp_lo + r->cap)) {
                                self_matches++;
                                off += patlen - 1;
                                continue;
                            }

                            size_t ctx_len = data_count - off;
                            if (ctx_len > 200) ctx_len = 200;
                            char ctx[201];
                            size_t ci = 0;
                            for (size_t j = 0; j < ctx_len && ci < 199; j++) {
                                char ch = membuf[off + j];
                                if (ch >= 32 && ch < 127) ctx[ci++] = ch;
                                else if (ch == '\0') break;
                                else ctx[ci++] = '.';
                            }
                            ctx[ci] = '\0';

                            if (match_count > 0) resp_append(r, ",");
                            resp_append(r, "{\"pattern\":");
                            resp_append_json_str(r, pat);
                            resp_append(r, ",\"address\":\"0x%llx\"", (unsigned long long)(addr + off));
                            resp_append(r, ",\"context\":");
                            resp_append_json_str(r, ctx);
                            resp_append(r, "}");
                            match_count++;

                            off += ci > 10 ? ci : 10;
                        }
                    }
                }
                vm_deallocate(task, data, data_count);
            }
        }
        addr += size;
        if (match_count >= 200) break;
    }
    resp_append(r, "],\"match_count\":%d,\"regions_scanned\":%d,\"self_matches\":%d",
                match_count, regions_scanned, self_matches);
}

/* Zone-walk design and its constraints: .project/reference/frida-gum-heap-study.md */

static int heap_class_ptr_cmp(const void *a, const void *b) {
    uintptr_t va = (uintptr_t)*(const Class *)a;
    uintptr_t vb = (uintptr_t)*(const Class *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* In-process memory reader for malloc zone enumeration — trivial identity */
static kern_return_t heap_memory_reader(task_t task, vm_address_t address,
                                        vm_size_t size, void **local_memory) {
    *local_memory = (void *)address;
    return KERN_SUCCESS;
}

/* Zone enumerator callback — MUST NOT call malloc or ObjC!
 * Just collects (address, size) pairs into pre-allocated buffer. */
static void heap_enum_callback(task_t task, void *baton, unsigned type,
                               vm_range_t *ranges, unsigned count) {
    darkmach_heap_scan_t *scan = (darkmach_heap_scan_t *)baton;
    for (unsigned i = 0; i < count && scan->count < DARKMACH_HEAP_MAX_RESULTS; i++) {
        /* Skip allocations too small to be an ObjC object (need at least an isa pointer) */
        if (ranges[i].size < sizeof(void *)) continue;
        scan->candidates[scan->count].address = ranges[i].address;
        scan->candidates[scan->count].size = ranges[i].size;
        scan->count++;
    }
}

static void cmd_heap_dump(const char *args, resp_t *r) {
    char class_filter[512] = "";
    json_get_string(args, "class", class_filter, sizeof(class_filter));
    long limit = json_get_long(args, "limit");
    long offset = json_get_long(args, "offset");
    if (limit <= 0) limit = 1000;
    if (offset < 0) offset = 0;

    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);

    /* Snapshot all registered classes as the isa validation set */
    unsigned int class_count = 0;
    Class *all_classes = objc_copyClassList(&class_count);

    Class target_class = NULL;
    if (class_filter[0]) {
        target_class = objc_getClass(class_filter);
        if (!target_class) {
            free(all_classes);
            resp_append(r, "\"error\":\"class not found: %s\"", class_filter);
            return;
        }
    }

    /* Build a set of valid Class pointers for O(1)-ish lookup.
     * Use a simple sorted array + binary search (good for up to ~30K classes). */
    qsort(all_classes, class_count, sizeof(Class), heap_class_ptr_cmp);

    /* ~160KB of stack, against the Simulator's 8MB default thread stack. */
    darkmach_heap_scan_t scan;
    scan.count = 0;

    vm_address_t *zone_addrs = NULL;
    unsigned zone_count = 0;
    kern_return_t kr = malloc_get_all_zones(mach_task_self(),
                                            heap_memory_reader,
                                            &zone_addrs, &zone_count);
    if (kr == KERN_SUCCESS) {
        for (unsigned z = 0; z < zone_count; z++) {
            malloc_zone_t *zone = (malloc_zone_t *)zone_addrs[z];
            if (zone && zone->introspect && zone->introspect->enumerator) {
                zone->introspect->enumerator(
                    mach_task_self(),
                    &scan,
                    MALLOC_PTR_IN_USE_RANGE_TYPE,
                    zone_addrs[z],
                    heap_memory_reader,
                    (vm_range_recorder_t *)heap_enum_callback);
            }
        }
    }

    int total_scanned = scan.count;

    /* Validate isa pointers after enumeration: read each candidate's first
     * pointer-sized bytes as isa, then binary-search the sorted class list. */
    resp_append(r, "\"instances\":[");
    int total_matched = 0;
    int returned = 0;

    for (int i = 0; i < scan.count; i++) {
        uintptr_t addr = scan.candidates[i].address;
        size_t size = scan.candidates[i].size;

        uintptr_t candidate_isa = *(uintptr_t *)addr;
        if (candidate_isa == 0) continue;

        /* On arm64, if bit 0 is set, it's a non-pointer isa — mask off the extra bits.
         * The mask is ISA_MASK = 0x0000000ffffffff8ULL for arm64 Simulator. */
        if (candidate_isa & 1) {
            candidate_isa &= 0x0000000ffffffff8ULL;
        }

        Class isa_as_class = (Class)candidate_isa;
        int lo = 0, hi = (int)class_count - 1;
        int found = 0;
        while (lo <= hi) {
            int mid = lo + (hi - lo) / 2;
            uintptr_t mid_val = (uintptr_t)all_classes[mid];
            if (mid_val == candidate_isa) { found = 1; break; }
            else if (mid_val < candidate_isa) lo = mid + 1;
            else hi = mid - 1;
        }

        if (!found) continue;

        const char *cls_name = class_getName(isa_as_class);
        if (!cls_name) continue;

        if (target_class) {
            Class check = isa_as_class;
            int matches = 0;
            while (check) {
                if (check == target_class) { matches = 1; break; }
                check = class_getSuperclass(check);
            }
            if (!matches) continue;
        }

        total_matched++;

        if (total_matched <= offset) continue;

        if (returned >= limit) continue;  /* keep counting total_matched */

        if (returned > 0) resp_append(r, ",");
        resp_append(r, "{\"addr\":\"0x%lx\",\"class\":", (unsigned long)addr);
        resp_append_json_str(r, cls_name);
        resp_append(r, ",\"size\":%zu}", size);
        returned++;

        if (r->len > BRIDGE_MAX_RESPONSE - 4096) break;
    }

    gettimeofday(&tv_end, NULL);
    long time_ms = (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
                   (tv_end.tv_usec - tv_start.tv_usec) / 1000;

    resp_append(r, "],\"total_scanned\":%d,\"total_matched\":%d,\"returned\":%d,\"time_ms\":%ld",
                total_scanned, total_matched, returned, time_ms);
    free(all_classes);
}


#include <mach-o/dyld.h>
#include <fcntl.h>
#include <sys/socket.h>

extern char **environ;

static void cmd_env_dump(const char *args, resp_t *r) {
    resp_append(r, "\"env\":{");
    if (environ) {
        int first = 1;
        for (int i = 0; environ[i]; i++) {
            char *eq = strchr(environ[i], '=');
            if (!eq) continue;

            size_t keylen = eq - environ[i];
            char key[512];
            if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
            memcpy(key, environ[i], keylen);
            key[keylen] = '\0';

            const char *val = eq + 1;

            if (!first) resp_append(r, ",");
            resp_append_json_str(r, key);
            resp_append(r, ":");
            resp_append_json_str(r, val);
            first = 0;
        }
    }
    resp_append(r, "}");

    resp_append(r, ",\"args\":[");
    Class piClass = objc_getClass("NSProcessInfo");
    if (piClass) {
        SEL piSel = sel_registerName("processInfo");
        id (*getPI)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id pi = getPI((id)piClass, piSel);

        SEL argsSel = sel_registerName("arguments");
        id (*getArgs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id argsArr = getArgs(pi, argsSel);

        SEL countSel = sel_registerName("count");
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        long argc = argsArr ? getCount(argsArr, countSel) : 0;

        SEL indexSel = sel_registerName("objectAtIndex:");
        id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

        for (long i = 0; i < argc; i++) {
            if (i > 0) resp_append(r, ",");
            id arg = getAt(argsArr, indexSel, (unsigned long)i);
            resp_append_json_str(r, nsstring_to_c(arg));
        }
    }
    resp_append(r, "]");

    resp_append(r, ",\"images\":[");
    uint32_t img_count = _dyld_image_count();
    for (uint32_t i = 0; i < img_count; i++) {
        const char *img_name = _dyld_get_image_name(i);
        const struct mach_header *mh = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        if (i > 0) resp_append(r, ",");
        resp_append(r, "{\"name\":");

        const char *basename = img_name ? strrchr(img_name, '/') : NULL;
        basename = basename ? basename + 1 : (img_name ? img_name : "(null)");
        resp_append_json_str(r, basename);

        resp_append(r, ",\"path\":");
        resp_append_json_str(r, img_name ? img_name : "(null)");
        resp_append(r, ",\"base\":\"0x%lx\"", (unsigned long)mh);
        resp_append(r, ",\"slide\":\"0x%lx\"}", (unsigned long)slide);

        if (r->len > BRIDGE_MAX_RESPONSE - 8192) {
            resp_append(r, ",{\"truncated\":true}");
            break;
        }
    }
    resp_append(r, "]");

    resp_append(r, ",\"fds\":[");
    int first_fd = 1;
    for (int fd = 0; fd < 1024; fd++) {
        int flags = fcntl(fd, F_GETFL);
        if (flags == -1) continue;  /* not a valid fd */

        if (!first_fd) resp_append(r, ",");
        first_fd = 0;

        resp_append(r, "{\"fd\":%d", fd);

        char pathbuf[1024];
        if (fcntl(fd, F_GETPATH, pathbuf) != -1) {
            resp_append(r, ",\"path\":");
            resp_append_json_str(r, pathbuf);
            resp_append(r, ",\"type\":\"file\"");
        } else {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            if (getsockname(fd, (struct sockaddr *)&ss, &slen) == 0) {
                if (ss.ss_family == AF_UNIX) {
                    struct sockaddr_un *sun = (struct sockaddr_un *)&ss;
                    if (sun->sun_path[0]) {
                        resp_append(r, ",\"path\":");
                        resp_append_json_str(r, sun->sun_path);
                    }
                    resp_append(r, ",\"type\":\"socket\"");
                } else if (ss.ss_family == AF_INET || ss.ss_family == AF_INET6) {
                    resp_append(r, ",\"type\":\"socket\"");
                } else {
                    resp_append(r, ",\"type\":\"unknown\"");
                }
            } else {
                resp_append(r, ",\"type\":\"unknown\"");
            }
        }
        resp_append(r, "}");
    }
    resp_append(r, "]");

    resp_append(r, ",\"pid\":%d", getpid());
}


#include <mach-o/loader.h>

typedef struct {
    const char *key;
    const char *risk;
    const char *severity;
} darkmach_ent_risk_t;

static const darkmach_ent_risk_t ent_risk_table[] = {
    { "keychain-access-groups",                                  "cross-app keychain access",        "high" },
    { "com.apple.security.application-groups",                   "shared container data leakage",    "high" },
    { "com.apple.developer.associated-domains",                  "claimed web domains exposed",      "medium" },
    { "com.apple.developer.icloud-container-identifiers",        "iCloud container access",          "medium" },
    { "com.apple.developer.icloud-services",                     "iCloud services access",           "medium" },
    { "com.apple.developer.ubiquity-container-identifiers",      "ubiquity container access",        "medium" },
    { "aps-environment",                                          "push notification environment",    "low" },
    { "com.apple.developer.aps-environment",                     "push notification environment",    "low" },
    { "com.apple.developer.default-data-protection",             "data protection class",            "medium" },
    { "com.apple.developer.networking.wifi-info",                "WiFi SSID access",                 "medium" },
    { "com.apple.developer.nfc.readersession.formats",           "NFC reader access",                "low" },
    { "com.apple.developer.networking.vpn.api",                  "VPN configuration access",         "high" },
    { "com.apple.developer.healthkit",                           "HealthKit data access",            "high" },
    { "com.apple.developer.homekit",                             "HomeKit device control",           "high" },
    { "com.apple.developer.payment-pass-provisioning",           "payment pass provisioning",        "high" },
    { "com.apple.developer.in-app-payments",                     "in-app payment processing",        "high" },
    { "com.apple.developer.siri",                                "Siri intent handling",             "low" },
    { "com.apple.security.app-sandbox",                          "sandbox enabled",                  "info" },
    { "com.apple.security.network.client",                       "outbound network access",          "low" },
    { "com.apple.security.network.server",                       "inbound network access",           "medium" },
    { "com.apple.security.files.user-selected.read-write",       "user-selected file access",        "low" },
    { "com.apple.security.files.all",                            "full filesystem access",           "high" },
    { "com.apple.developer.kernel.extended-virtual-addressing",  "extended virtual addressing",      "low" },
    { NULL, NULL, NULL }
};

static const darkmach_ent_risk_t *find_ent_risk(const char *key) {
    for (int i = 0; ent_risk_table[i].key; i++) {
        if (strstr(key, ent_risk_table[i].key)) return &ent_risk_table[i];
    }
    return NULL;
}

/* Locate the code signature in a loaded image, where __LINKEDIT's VM and file offsets diverge. */
static const uint8_t *locate_code_signature(const struct mach_header_64 *header,
                                            uint32_t *out_size) {
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);
    uint64_t text_vmaddr = 0;
    const struct segment_command_64 *linkedit = NULL;
    const struct linkedit_data_command *sig_cmd = NULL;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_TEXT) == 0) text_vmaddr = seg->vmaddr;
            else if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
        } else if (lc->cmd == LC_CODE_SIGNATURE) {
            sig_cmd = (const struct linkedit_data_command *)lc;
        }
        ptr += lc->cmdsize;
    }

    if (!sig_cmd || !linkedit || sig_cmd->datasize < 12) return NULL;
    if (sig_cmd->dataoff < linkedit->fileoff) return NULL;

    uint64_t seg_off = sig_cmd->dataoff - linkedit->fileoff;
    if (seg_off + sig_cmd->datasize > linkedit->vmsize) return NULL;

    uintptr_t slide = (uintptr_t)header - (uintptr_t)text_vmaddr;
    *out_size = sig_cmd->datasize;
    return (const uint8_t *)(slide + linkedit->vmaddr + seg_off);
}

/* Entitlements live in __TEXT,__entitlements on Simulator binaries and in the code-signature
 * SuperBlob (slot magic 0xfade7171) on device-style ones; both are checked. */
static const char *extract_entitlements_from_header(const struct mach_header_64 *header,
                                                      size_t *out_len) {
    if (!header || header->magic != MH_MAGIC_64) return NULL;

    unsigned long sect_size = 0;
    const uint8_t *sect = getsectiondata(header, SEG_TEXT, "__entitlements", &sect_size);
    if (sect && sect_size > 0) {
        if (out_len) *out_len = sect_size;
        return (const char *)sect;
    }

    uint32_t sig_size = 0;
    const uint8_t *sig_data = locate_code_signature(header, &sig_size);
    if (!sig_data) return NULL;

    if (ntohl(*(uint32_t *)sig_data) != 0xfade0cc0) return NULL;
    uint32_t blob_count = ntohl(*(uint32_t *)(sig_data + 8));

    for (uint32_t b = 0; b < blob_count; b++) {
        uint32_t blob_offset_pos = 12 + b * 8 + 4;
        if (blob_offset_pos + 4 > sig_size) break;

        uint32_t blob_offset = ntohl(*(uint32_t *)(sig_data + blob_offset_pos));
        if (blob_offset + 8 > sig_size) continue;

        uint32_t blob_magic = ntohl(*(uint32_t *)(sig_data + blob_offset));
        uint32_t blob_length = ntohl(*(uint32_t *)(sig_data + blob_offset + 4));

        if (blob_magic == 0xfade7171 && blob_length > 8) {
            if (blob_offset + blob_length > sig_size) continue;
            if (out_len) *out_len = blob_length - 8;
            return (const char *)(sig_data + blob_offset + 8);
        }
    }
    return NULL;
}

/* Parse a simple plist XML key-value — extracts value for a given <key> */
static int plist_extract_string_value(const char *plist, size_t plist_len,
                                       const char *key, char *out, size_t out_sz) {
    char search[512];
    snprintf(search, sizeof(search), "<key>%s</key>", key);
    const char *found = strnstr(plist, search, plist_len);
    if (!found) return 0;

    const char *after_key = found + strlen(search);
    while (*after_key == ' ' || *after_key == '\n' || *after_key == '\r' || *after_key == '\t')
        after_key++;

    if (strncmp(after_key, "<string>", 8) == 0) {
        const char *val_start = after_key + 8;
        const char *val_end = strstr(val_start, "</string>");
        if (val_end) {
            size_t len = val_end - val_start;
            if (len >= out_sz) len = out_sz - 1;
            memcpy(out, val_start, len);
            out[len] = '\0';
            return 1;
        }
    } else if (strncmp(after_key, "<true/>", 7) == 0) {
        strlcpy(out, "true", out_sz);
        return 1;
    } else if (strncmp(after_key, "<false/>", 8) == 0) {
        strlcpy(out, "false", out_sz);
        return 1;
    }
    return 0;
}

/* Extract all <string> values from an <array> that follows a <key> */
static int plist_extract_array_strings(const char *plist, size_t plist_len,
                                        const char *key, resp_t *r) {
    char search[512];
    snprintf(search, sizeof(search), "<key>%s</key>", key);
    const char *found = strnstr(plist, search, plist_len);
    if (!found) return 0;

    const char *after_key = found + strlen(search);
    while (*after_key == ' ' || *after_key == '\n' || *after_key == '\r' || *after_key == '\t')
        after_key++;

    if (strncmp(after_key, "<array>", 7) != 0) return 0;

    const char *arr_start = after_key + 7;
    const char *arr_end = strstr(arr_start, "</array>");
    if (!arr_end) return 0;

    int count = 0;
    const char *p = arr_start;
    while (p < arr_end) {
        const char *str_start = strstr(p, "<string>");
        if (!str_start || str_start >= arr_end) break;
        str_start += 8;
        const char *str_end = strstr(str_start, "</string>");
        if (!str_end || str_end >= arr_end) break;

        char val[512];
        size_t len = str_end - str_start;
        if (len >= sizeof(val)) len = sizeof(val) - 1;
        memcpy(val, str_start, len);
        val[len] = '\0';

        if (count > 0) resp_append(r, ",");
        resp_append_json_str(r, val);
        count++;

        p = str_end + 9;  /* past </string> */
    }
    return count;
}

static void cmd_entitlement_scan(const char *args, resp_t *r) {
    uint32_t image_count = _dyld_image_count();

    resp_append(r, "\"images\":[");
    int images_with_ents = 0;
    int total_ents = 0;
    int app_ents = 0;
    int high_risk_count = 0;

    for (uint32_t img = 0; img < image_count; img++) {
        const struct mach_header *mh = _dyld_get_image_header(img);
        const char *image_name = _dyld_get_image_name(img);
        if (!mh || !image_name) continue;

        if (mh->magic != MH_MAGIC_64) continue;

        const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
        size_t ent_len = 0;
        const char *ent_xml = extract_entitlements_from_header(mh64, &ent_len);
        if (!ent_xml || ent_len == 0) continue;

        if (images_with_ents > 0) resp_append(r, ",");
        resp_append(r, "{\"name\":");

        const char *basename = strrchr(image_name, '/');
        basename = basename ? basename + 1 : image_name;
        resp_append_json_str(r, basename);

        resp_append(r, ",\"image_index\":%u", img);
        resp_append(r, ",\"image_path\":");
        resp_append_json_str(r, image_name);

        int is_system = image_is_system(image_name);
        resp_append(r, ",\"system\":%s", is_system ? "true" : "false");

        /* Two-pass: collect entitlements as dict + risks as array
         * bridge.py expects: "entitlements":{"key":"value"}, "risks":[{"level":"HIGH","description":"..."}] */
        resp_append(r, ",\"entitlements\":{");

        int ent_count = 0;
        int img_risk_count = 0;
        const char *p = ent_xml;
        const char *end = ent_xml + ent_len;

        char risk_buf[4096];
        size_t risk_buf_len = 0;
        risk_buf[0] = '\0';

        while (p < end) {
            const char *key_start = strnstr(p, "<key>", end - p);
            if (!key_start) break;
            key_start += 5;
            const char *key_end = strnstr(key_start, "</key>", end - key_start);
            if (!key_end) break;

            char key[512];
            size_t klen = key_end - key_start;
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, key_start, klen);
            key[klen] = '\0';

            char val[1024] = "";
            const char *val_pos = key_end + 6;  /* past </key> */
            while (*val_pos == ' ' || *val_pos == '\n' || *val_pos == '\r' || *val_pos == '\t')
                val_pos++;

            if (strncmp(val_pos, "<string>", 8) == 0) {
                plist_extract_string_value(p, end - p, key, val, sizeof(val));
            } else if (strncmp(val_pos, "<true/>", 7) == 0) {
                strlcpy(val, "true", sizeof(val));
            } else if (strncmp(val_pos, "<false/>", 8) == 0) {
                strlcpy(val, "false", sizeof(val));
            } else if (strncmp(val_pos, "<array>", 7) == 0) {
                resp_t tmp = resp_new();
                plist_extract_array_strings(ent_xml, ent_len, key, &tmp);
                snprintf(val, sizeof(val), "[%.*s]", (int)tmp.len, tmp.buf);
                resp_free(&tmp);
            }

            if (ent_count > 0) resp_append(r, ",");
            resp_append_json_str(r, key);
            resp_append(r, ":");
            resp_append_json_str(r, val);

            const darkmach_ent_risk_t *risk = find_ent_risk(key);
            if (risk) {
                int n = snprintf(risk_buf + risk_buf_len, sizeof(risk_buf) - risk_buf_len,
                                 "%s{\"level\":\"%s\",\"description\":\"%s\",\"key\":\"%s\"}",
                                 img_risk_count > 0 ? "," : "",
                                 strcmp(risk->severity, "high") == 0 ? "HIGH" :
                                 strcmp(risk->severity, "medium") == 0 ? "MEDIUM" : "LOW",
                                 risk->risk, key);
                if (n > 0 && risk_buf_len + n < sizeof(risk_buf))
                    risk_buf_len += n;
                img_risk_count++;
                high_risk_count++;
            }

            ent_count++;
            total_ents++;

            p = key_end + 6;
        }

        resp_append(r, "},\"risks\":[%s]", risk_buf);
        resp_append(r, ",\"entitlement_count\":%d}", ent_count);
        images_with_ents++;
        if (!is_system) app_ents += ent_count;

        if (r->len > BRIDGE_MAX_RESPONSE - 8192) break;
    }

    resp_append(r, "],\"total_images\":%u,\"images_with_entitlements\":%d"
                ",\"total_entitlements\":%d,\"app_entitlements\":%d,\"risk_count\":%d",
                image_count, images_with_ents, total_ents, app_ents, high_risk_count);
}


static void cmd_shared_container_scan(const char *args, resp_t *r) {
    const struct mach_header *mh = _dyld_get_image_header(0);
    if (!mh || mh->magic != MH_MAGIC_64) {
        resp_append(r, "\"error\":\"cannot read main binary header\"");
        return;
    }

    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    size_t ent_len = 0;
    const char *ent_xml = extract_entitlements_from_header(mh64, &ent_len);

    resp_append(r, "\"containers\":[");
    int container_count = 0;

    if (ent_xml && ent_len > 0) {
        const char *key = "com.apple.security.application-groups";
        char search[512];
        snprintf(search, sizeof(search), "<key>%s</key>", key);
        const char *found = strnstr(ent_xml, search, ent_len);

        if (found) {
            const char *after_key = found + strlen(search);
            while (*after_key == ' ' || *after_key == '\n' || *after_key == '\r' || *after_key == '\t')
                after_key++;

            if (strncmp(after_key, "<array>", 7) == 0) {
                const char *arr_start = after_key + 7;
                const char *arr_end = strstr(arr_start, "</array>");
                if (arr_end) {
                    const char *p = arr_start;
                    while (p < arr_end) {
                        const char *str_start = strstr(p, "<string>");
                        if (!str_start || str_start >= arr_end) break;
                        str_start += 8;
                        const char *str_end = strstr(str_start, "</string>");
                        if (!str_end || str_end >= arr_end) break;

                        char group_id[256];
                        size_t len = str_end - str_start;
                        if (len >= sizeof(group_id)) len = sizeof(group_id) - 1;
                        memcpy(group_id, str_start, len);
                        group_id[len] = '\0';

                        char container_path[1024];
                        const char *home = getenv("HOME");
                        if (!home) home = "/tmp";
                        snprintf(container_path, sizeof(container_path),
                                 "%s/Library/Group Containers/%s", home, group_id);

                        if (container_count > 0) resp_append(r, ",");
                        resp_append(r, "{\"group_id\":");
                        resp_append_json_str(r, group_id);
                        resp_append(r, ",\"path\":");
                        resp_append_json_str(r, container_path);

                        struct stat st;
                        if (stat(container_path, &st) == 0) {
                            resp_append(r, ",\"exists\":true,\"files\":[");

                            DIR *dir = opendir(container_path);
                            int file_count = 0;
                            if (dir) {
                                struct dirent *entry;
                                while ((entry = readdir(dir)) != NULL) {
                                    if (entry->d_name[0] == '.') continue;
                                    if (file_count > 0) resp_append(r, ",");

                                    char full_path[2048];
                                    snprintf(full_path, sizeof(full_path), "%s/%s",
                                             container_path, entry->d_name);

                                    struct stat fst;
                                    stat(full_path, &fst);

                                    resp_append(r, "{\"name\":");
                                    resp_append_json_str(r, entry->d_name);
                                    resp_append(r, ",\"type\":\"%s\"",
                                                S_ISDIR(fst.st_mode) ? "directory" : "file");
                                    if (!S_ISDIR(fst.st_mode)) {
                                        resp_append(r, ",\"size\":%lld", (long long)fst.st_size);
                                    }
                                    resp_append(r, "}");
                                    file_count++;

                                    if (file_count >= 100) break;  /* limit */
                                }
                                closedir(dir);
                            }
                            resp_append(r, "],\"file_count\":%d", file_count);
                        } else {
                            resp_append(r, ",\"exists\":false");
                        }

                        resp_append(r, "}");
                        container_count++;

                        p = str_end + 9;
                    }
                }
            }
        }
    }

    resp_append(r, "],\"container_count\":%d", container_count);
}


typedef struct {
    const char *prefix;
    const char *sdk_name;
    const char *sdk_category;
} darkmach_sdk_fingerprint_t;

static const darkmach_sdk_fingerprint_t sdk_fingerprints[] = {
    { "FIR",          "Firebase",             "analytics" },
    { "GUL",          "GoogleUtilities",      "analytics" },
    { "GDT",          "GoogleDataTransport",  "analytics" },
    { "AMP",          "Amplitude",            "analytics" },
    { "MPT",          "Mixpanel",             "analytics" },
    { "SEG",          "Segment",              "analytics" },
    { "Heap",         "Heap",                 "analytics" },
    { "FSAnalytics",  "Fullstory",            "analytics" },
    { "FS",           "Fullstory",            "analytics" },
    { "ADJ",          "Adjust",               "attribution" },
    { "BNC",          "Branch",               "attribution" },
    { "AF",           "AppsFlyer",            "attribution" },
    { "SKAd",         "SKAdNetwork",          "attribution" },
    { "FBSDK",        "Facebook SDK",         "social" },
    { "FBSDKCore",    "Facebook Core",        "social" },
    { "FBSDKLogin",   "Facebook Login",       "auth" },
    { "GID",          "Google Sign-In",       "auth" },
    { "GSignIn",      "Google Sign-In",       "auth" },
    { "ASAuth",       "Apple Sign-In",        "auth" },
    { "FIRCrash",     "Firebase Crashlytics", "crash" },
    { "Crashlytics",  "Crashlytics",          "crash" },
    { "Sentry",       "Sentry",               "crash" },
    { "BugSnag",      "Bugsnag",              "crash" },
    { "BSG",          "Bugsnag",              "crash" },
    { "PLCrash",      "PLCrashReporter",      "crash" },
    { "ABK",          "Braze",                "engagement" },
    { "BRZ",          "Braze",                "engagement" },
    { "Braze",        "Braze",                "engagement" },
    { "CTInApp",      "CleverTap",            "engagement" },
    { "CleverTap",    "CleverTap",            "engagement" },
    { "OPT",          "Optimizely",           "experimentation" },
    { "LDClient",     "LaunchDarkly",         "feature_flags" },
    { "GAD",          "Google Ads",           "advertising" },
    { "GAM",          "Google Ad Manager",    "advertising" },
    { "MTRGAdView",   "myTarget",             "advertising" },
    { "Unity",        "Unity Ads",            "advertising" },
    { "ISA",          "IronSource",           "advertising" },
    { "VungleSDK",    "Vungle",               "advertising" },
    { "FBAudienceNetwork", "Facebook Audience", "advertising" },
    { "STP",          "Stripe",               "payments" },
    { "BTClient",     "Braintree",            "payments" },
    { "PKPayment",    "Apple Pay",            "payments" },
    { "RCPurchases",  "RevenueCat",           "payments" },
    { "Purchases",    "RevenueCat",           "payments" },
    { "GMSMap",       "Google Maps",          "maps" },
    { "MBMap",        "Mapbox",               "maps" },
    { "MK",           "MapKit",               "maps" },
    { "AFHTTPSession", "AFNetworking",        "networking" },
    { "Alamofire",    "Alamofire",            "networking" },
    { "UNNotification", "UserNotifications",  "push" },
    { "OneSignal",    "OneSignal",            "push" },
    { "Realm",        "Realm",                "database" },
    { "RLM",          "Realm",                "database" },
    { "AWS",          "AWS SDK",              "cloud" },
    { "AWSS3",        "AWS S3",               "cloud" },
    { "Lottie",       "Lottie",               "ui" },
    { "SDWebImage",   "SDWebImage",           "networking" },
    { "Kingfisher",   "Kingfisher",           "networking" },
    { "SVProgress",   "SVProgressHUD",        "ui" },
    { "SnapKit",      "SnapKit",              "ui" },
    { NULL, NULL, NULL }
};

typedef struct {
    const char *sdk_name;
    const char *class_name;
    const char *singleton_sel;
    const char *key_sel;
    const char *key_label;
} darkmach_sdk_key_accessor_t;

static const darkmach_sdk_key_accessor_t sdk_key_accessors[] = {
    { "Firebase", "FIRApp",            "defaultApp",       "options",           NULL },
    { "Amplitude", "Amplitude",        "instance",         "apiKey",            "api_key" },
    { "Mixpanel", "Mixpanel",          "sharedInstance",   "apiToken",          "api_token" },
    { "Adjust", "Adjust",              "instance",         "adid",              "adjust_id" },
    { "Branch", "Branch",              "getInstance",      NULL,                NULL },
    { "AppsFlyer", "AppsFlyerLib",     "shared",           "appsFlyerDevKey",   "dev_key" },
    { "Facebook SDK", "FBSDKSettings", "sharedSettings",   "appID",             "app_id" },
    { "Braze", "Appboy",              "sharedInstance",    "apiKey",            "api_key" },
    { "Sentry", "SentrySDK",          "currentHub",       NULL,                NULL },
    { "Google Ads", "GADMobileAds",    "sharedInstance",   NULL,                NULL },
    { "Stripe", "STPAPIClient",        "sharedClient",     "publishableKey",    "publishable_key" },
    { "RevenueCat", "RCPurchases",     "sharedPurchases",  NULL,                NULL },
    { "OneSignal", "OneSignal",        "appId",            NULL,                "app_id" },
    { NULL, NULL, NULL, NULL, NULL }
};


static const char *sdk_main_image_path(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (mh && mh->filetype == MH_EXECUTE) return _dyld_get_image_name(i);
    }
    return NULL;
}

static int sdk_class_matches(const char *class_name, const char *sdk_name) {
    for (int fp = 0; sdk_fingerprints[fp].prefix; fp++) {
        if (strcmp(sdk_fingerprints[fp].sdk_name, sdk_name) != 0) continue;
        const char *prefix = sdk_fingerprints[fp].prefix;
        if (strncmp(class_name, prefix, strlen(prefix)) == 0) return 1;
    }
    return 0;
}

static void sdk_append_image_version(resp_t *r, const char *img_path) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strcmp(name, img_path) != 0) continue;

        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) return;
        const uint8_t *ptr = (const uint8_t *)mh + sizeof(struct mach_header_64);
        for (uint32_t cmd = 0; cmd < mh->ncmds; cmd++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == LC_ID_DYLIB) {
                uint32_t ver = ((const struct dylib_command *)ptr)->dylib.current_version;
                resp_append(r, ",\"version\":\"%d.%d.%d\"",
                            (ver >> 16) & 0xFFFF, (ver >> 8) & 0xFF, ver & 0xFF);
                return;
            }
            ptr += lc->cmdsize;
        }
        return;
    }
}

static void cmd_sdk_map(const char *args, resp_t *r) {
    uint32_t img_count = _dyld_image_count();
    const char *main_image = sdk_main_image_path();

    unsigned int class_count = 0;
    Class *classes = objc_copyClassList(&class_count);

    typedef struct {
        const char *sdk_name;
        const char *category;
        const char *image_path;
        int app_classes;
        int system_classes;
    } sdk_detection_t;

    #define MAX_SDK_DETECTIONS 64
    sdk_detection_t detections[MAX_SDK_DETECTIONS];
    int detection_count = 0;

    /* Prefixes are short enough to collide across vendors, so variants merge into one record. */
    for (int fp = 0; sdk_fingerprints[fp].prefix; fp++) {
        const char *prefix = sdk_fingerprints[fp].prefix;
        size_t prefix_len = strlen(prefix);
        const char *sdk = sdk_fingerprints[fp].sdk_name;

        int slot = -1;
        for (int d = 0; d < detection_count; d++) {
            if (strcmp(detections[d].sdk_name, sdk) == 0) { slot = d; break; }
        }
        if (slot < 0) {
            if (detection_count >= MAX_SDK_DETECTIONS) continue;
            slot = detection_count++;
            detections[slot].sdk_name = sdk;
            detections[slot].category = sdk_fingerprints[fp].sdk_category;
            detections[slot].image_path = NULL;
            detections[slot].app_classes = 0;
            detections[slot].system_classes = 0;
        }

        for (unsigned int c = 0; c < class_count; c++) {
            const char *name = class_getName(classes[c]);
            if (!name || strncmp(name, prefix, prefix_len) != 0) continue;

            const char *img = class_getImageName(classes[c]);
            if (image_is_system(img)) {
                detections[slot].system_classes++;
                continue;
            }
            if (!detections[slot].image_path) detections[slot].image_path = img;
            detections[slot].app_classes++;
        }
    }

    resp_append(r, "\"sdks\":[");
    int reported = 0;
    for (int d = 0; d < detection_count; d++) {
        if (detections[d].app_classes == 0) continue;

        if (reported > 0) resp_append(r, ",");
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, detections[d].sdk_name);
        resp_append(r, ",\"category\":");
        resp_append_json_str(r, detections[d].category);
        resp_append(r, ",\"class_count\":%d", detections[d].app_classes);

        const char *img_path = detections[d].image_path;
        int own_image = !(main_image && strcmp(img_path, main_image) == 0);
        resp_append(r, ",\"confidence\":");
        resp_append_json_str(r, own_image ? "high" : "medium");

        const char *basename = strrchr(img_path, '/');
        resp_append(r, ",\"image\":");
        resp_append_json_str(r, basename ? basename + 1 : img_path);
        resp_append(r, ",\"image_path\":");
        resp_append_json_str(r, img_path);
        sdk_append_image_version(r, img_path);

        resp_append(r, ",\"classes\":[");
        int emitted = 0;
        for (unsigned int c = 0; c < class_count; c++) {
            const char *name = class_getName(classes[c]);
            if (!name || !sdk_class_matches(name, detections[d].sdk_name)) continue;
            if (image_is_system(class_getImageName(classes[c]))) continue;
            if (emitted > 0) resp_append(r, ",");
            resp_append_json_str(r, name);
            emitted++;
            if (r->len > BRIDGE_MAX_RESPONSE - 8192) break;
        }
        resp_append(r, "]}");
        reported++;
    }
    resp_append(r, "]");

    resp_append(r, ",\"system_frameworks\":[");
    int system_reported = 0;
    for (int d = 0; d < detection_count; d++) {
        if (detections[d].app_classes > 0 || detections[d].system_classes == 0) continue;
        if (system_reported > 0) resp_append(r, ",");
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, detections[d].sdk_name);
        resp_append(r, ",\"system_class_count\":%d}", detections[d].system_classes);
        system_reported++;
    }
    resp_append(r, "]");

    free(classes);

    resp_append(r, ",\"sdk_count\":%d,\"system_framework_count\":%d,\"total_images\":%u",
                reported, system_reported, img_count);
}


static void cmd_sdk_keys(const char *args, resp_t *r) {
    resp_append(r, "\"keys\":[");
    int key_count = 0;

    for (int i = 0; sdk_key_accessors[i].sdk_name; i++) {
        const darkmach_sdk_key_accessor_t *acc = &sdk_key_accessors[i];

        Class cls = objc_getClass(acc->class_name);
        if (!cls) continue;

        SEL singletonSel = sel_registerName(acc->singleton_sel);
        if (!class_getClassMethod(cls, singletonSel)) continue;

        id (*getter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id instance = getter((id)cls, singletonSel);
        if (!instance) continue;

        if (key_count > 0) resp_append(r, ",");
        resp_append(r, "{\"sdk\":");
        resp_append_json_str(r, acc->sdk_name);
        resp_append(r, ",\"class\":");
        resp_append_json_str(r, acc->class_name);

        if (acc->key_sel) {
            SEL keySel = sel_registerName(acc->key_sel);
            SEL respondsSel = sel_registerName("respondsToSelector:");
            BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;

            if (responds(instance, respondsSel, keySel)) {
                id keyVal = getter(instance, keySel);

                if (strcmp(acc->sdk_name, "Firebase") == 0 && keyVal) {
                    resp_append(r, ",\"keys\":{");
                    int fk = 0;

                    static const char *fir_keys[] = {
                        "APIKey", "GCMSenderID", "googleAppID",
                        "databaseURL", "storageBucket", "projectID",
                        "bundleID", "clientID", NULL
                    };
                    for (int k = 0; fir_keys[k]; k++) {
                        SEL fkSel = sel_registerName(fir_keys[k]);
                        if (responds(keyVal, respondsSel, fkSel)) {
                            id fkVal = getter(keyVal, fkSel);
                            if (fkVal) {
                                if (fk > 0) resp_append(r, ",");
                                resp_append_json_str(r, fir_keys[k]);
                                resp_append(r, ":");
                                resp_append_json_str(r, nsobject_desc(fkVal));
                                fk++;
                            }
                        }
                    }
                    resp_append(r, "}");
                } else {
                    const char *label = acc->key_label ? acc->key_label : acc->key_sel;
                    resp_append(r, ",\"%s\":", label);
                    resp_append_json_str(r, keyVal ? nsobject_desc(keyVal) : "(null)");
                }
            } else {
                resp_append(r, ",\"error\":\"accessor not available\"");
            }
        } else {
            resp_append(r, ",\"status\":\"detected\"");
            resp_append(r, ",\"instance_class\":");
            resp_append_json_str(r, class_getName(object_getClass(instance)));
        }

        resp_append(r, "}");
        key_count++;
    }

    resp_append(r, "],\"key_count\":%d", key_count);
}
