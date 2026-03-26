/*
 * cmd-analysis.c -- Deep analysis commands for the Sphinx LLM bridge
 *
 * Commands: webview_list, webview_eval, webview_content, webview_bridge_map
 * Implemented in Sprint 13.5.
 *
 * Unity build: #included from bridge/sphinx-bridge.c
 */
#include "sphinx-bridge.h"

/* ===================================================================
 *  WKWebView heap discovery helper
 *  Walks all WKWebView instances found via heap_dump infrastructure.
 *  Returns array of (address, webview) pairs. Caller must free.
 * =================================================================== */

typedef struct {
    uintptr_t address;
    id webview;
} sphinx_webview_entry_t;

#define SPHINX_MAX_WEBVIEWS 64

typedef struct {
    sphinx_webview_entry_t entries[SPHINX_MAX_WEBVIEWS];
    int count;
} sphinx_webview_list_t;

/* heap_memory_reader and heap_class_ptr_cmp are defined in cmd-recon.c
 * (included before us in the unity build). Reuse the heap walk pattern. */

static void webview_heap_enum_callback(task_t task, void *ctx,
                                        unsigned type,
                                        vm_range_t *ranges,
                                        unsigned range_count) {
    sphinx_heap_scan_t *scan = (sphinx_heap_scan_t *)ctx;
    for (unsigned i = 0; i < range_count; i++) {
        if (scan->count >= SPHINX_HEAP_MAX_RESULTS) return;
        if (ranges[i].size < 32) continue;
        scan->candidates[scan->count].address = ranges[i].address;
        scan->candidates[scan->count].size = ranges[i].size;
        scan->count++;
    }
}

static sphinx_webview_list_t find_webviews(void) {
    sphinx_webview_list_t result;
    result.count = 0;

    Class wkClass = objc_getClass("WKWebView");
    if (!wkClass) return result;

    /* Build class validation set */
    unsigned int class_count = 0;
    Class *all_classes = objc_copyClassList(&class_count);
    qsort(all_classes, class_count, sizeof(Class), heap_class_ptr_cmp);

    /* Walk malloc zones */
    sphinx_heap_scan_t scan;
    scan.count = 0;

    vm_address_t *zone_addrs = NULL;
    unsigned zone_count = 0;
    kern_return_t kr = malloc_get_all_zones(mach_task_self(),
                                            heap_memory_reader,
                                            &zone_addrs, &zone_count);
    if (kr != KERN_SUCCESS) {
        free(all_classes);
        return result;
    }

    for (unsigned z = 0; z < zone_count; z++) {
        malloc_zone_t *zone = (malloc_zone_t *)zone_addrs[z];
        if (zone && zone->introspect && zone->introspect->enumerator) {
            zone->introspect->enumerator(
                mach_task_self(), &scan,
                MALLOC_PTR_IN_USE_RANGE_TYPE,
                zone_addrs[z],
                heap_memory_reader,
                (vm_range_recorder_t *)webview_heap_enum_callback);
        }
    }

    /* Validate: check isa -> WKWebView or subclass */
    for (int i = 0; i < scan.count && result.count < SPHINX_MAX_WEBVIEWS; i++) {
        uintptr_t addr = scan.candidates[i].address;
        uintptr_t candidate_isa = *(uintptr_t *)addr;
        if (candidate_isa == 0) continue;

        if (candidate_isa & 1) {
            candidate_isa &= 0x0000000ffffffff8ULL;
        }

        /* Binary search for valid class */
        int lo = 0, hi = (int)class_count - 1, found = 0;
        while (lo <= hi) {
            int mid = lo + (hi - lo) / 2;
            uintptr_t mid_val = (uintptr_t)all_classes[mid];
            if (mid_val == candidate_isa) { found = 1; break; }
            else if (mid_val < candidate_isa) lo = mid + 1;
            else hi = mid - 1;
        }
        if (!found) continue;

        /* Check WKWebView inheritance */
        Class isa_class = (Class)candidate_isa;
        Class check = isa_class;
        int is_webview = 0;
        while (check) {
            if (check == wkClass) { is_webview = 1; break; }
            check = class_getSuperclass(check);
        }
        if (!is_webview) continue;

        result.entries[result.count].address = addr;
        result.entries[result.count].webview = (id)addr;
        result.count++;
    }

    free(all_classes);
    return result;
}

/* ===================================================================
 *  Helper: get WKWebView URL as C string
 * =================================================================== */

static const char *webview_get_url(id webview) {
    SEL urlSel = sel_registerName("URL");
    id (*getURL)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id url = getURL(webview, urlSel);
    if (!url) return NULL;
    SEL absSel = sel_registerName("absoluteString");
    id (*getAbs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id absStr = getAbs(url, absSel);
    return absStr ? nsstring_to_c(absStr) : NULL;
}

/* ===================================================================
 *  Helper: get WKWebView title as C string
 * =================================================================== */

static const char *webview_get_title(id webview) {
    SEL titleSel = sel_registerName("title");
    id (*getTitle)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id title = getTitle(webview, titleSel);
    return title ? nsstring_to_c(title) : NULL;
}

/* ===================================================================
 *  Helper: get WKWebViewConfiguration properties
 * =================================================================== */

static void webview_append_config(id webview, resp_t *r) {
    SEL configSel = sel_registerName("configuration");
    id (*getConfig)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id config = getConfig(webview, configSel);
    if (!config) { resp_append(r, "\"config\":null"); return; }

    /* WKWebViewConfiguration preferences */
    SEL prefsSel = sel_registerName("preferences");
    id (*getPrefs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id prefs = getPrefs(config, prefsSel);

    BOOL jsEnabled = YES;
    if (prefs) {
        SEL jsSel = sel_registerName("javaScriptEnabled");
        BOOL (*getJS)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
        jsEnabled = getJS(prefs, jsSel);
    }

    resp_append(r, "\"config\":{\"javascript_enabled\":%s",
                jsEnabled ? "true" : "false");

    /* Check allowsInlineMediaPlayback */
    SEL inlineSel = sel_registerName("allowsInlineMediaPlayback");
    BOOL (*getInline)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
    BOOL inlineMedia = getInline(config, inlineSel);
    resp_append(r, ",\"allows_inline_media\":%s", inlineMedia ? "true" : "false");

    resp_append(r, "}");
}

/* ===================================================================
 *  Command: webview_list
 *  Returns all WKWebView instances with URLs, titles, and config
 * =================================================================== */

static void cmd_webview_list(const char *args, resp_t *r) {
    sphinx_webview_list_t wvs = find_webviews();

    resp_append(r, "\"webviews\":[");
    for (int i = 0; i < wvs.count; i++) {
        if (i > 0) resp_append(r, ",");

        id wv = wvs.entries[i].webview;
        const char *url = webview_get_url(wv);
        const char *title = webview_get_title(wv);
        const char *cls_name = class_getName(object_getClass(wv));

        resp_append(r, "{\"address\":\"0x%lx\"", (unsigned long)wvs.entries[i].address);
        resp_append(r, ",\"class\":");
        resp_append_json_str(r, cls_name);
        resp_append(r, ",\"url\":");
        resp_append_json_str(r, url);
        resp_append(r, ",\"title\":");
        resp_append_json_str(r, title);

        /* Flat config: js_enabled at top level (matches bridge.py formatter) */
        SEL configSel = sel_registerName("configuration");
        id (*getConfig)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id config = getConfig(wv, configSel);
        BOOL jsEnabled = YES;
        if (config) {
            SEL prefsSel = sel_registerName("preferences");
            id (*getPrefs)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id prefs = getPrefs(config, prefsSel);
            if (prefs) {
                SEL jsSel = sel_registerName("javaScriptEnabled");
                BOOL (*getJS)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                jsEnabled = getJS(prefs, jsSel);
            }
        }
        resp_append(r, ",\"js_enabled\":%s", jsEnabled ? "true" : "false");

        /* Count user scripts and message handlers */
        int script_count = 0;
        int handler_count = 0;
        if (config) {
            SEL uccSel = sel_registerName("userContentController");
            id (*getUCC)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id ucc = getUCC(config, uccSel);
            if (ucc) {
                SEL scriptsSel = sel_registerName("_userScripts");
                if (class_getInstanceMethod(object_getClass(ucc), scriptsSel)) {
                    id (*getScripts)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id scripts = getScripts(ucc, scriptsSel);
                    if (scripts) {
                        SEL countSel = sel_registerName("count");
                        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
                        script_count = (int)getCount(scripts, countSel);
                    }
                }
                SEL handlersSel = sel_registerName("_scriptMessageHandlers");
                if (class_getInstanceMethod(object_getClass(ucc), handlersSel)) {
                    id (*getHandlers)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id handlers = getHandlers(ucc, handlersSel);
                    if (handlers) {
                        SEL countSel = sel_registerName("count");
                        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
                        handler_count = (int)getCount(handlers, countSel);
                    }
                }
            }
        }

        resp_append(r, ",\"user_scripts\":%d,\"handler_count\":%d}", script_count, handler_count);
    }
    resp_append(r, "],\"count\":%d", wvs.count);
}

/* ===================================================================
 *  Command: webview_eval
 *  Evaluates JavaScript in a specific WKWebView
 *  Args: address (hex), js (string)
 *  Must dispatch to main thread for WKWebView API
 * =================================================================== */

static void cmd_webview_eval(const char *args, resp_t *r) {
    char addr_str[64] = "";
    char js[BRIDGE_MAX_REQUEST] = "";
    json_get_string(args, "address", addr_str, sizeof(addr_str));
    json_get_string(args, "js", js, sizeof(js));

    if (!addr_str[0]) { resp_append(r, "\"error\":\"missing address arg\""); return; }
    if (!js[0]) { resp_append(r, "\"error\":\"missing js arg\""); return; }

    uintptr_t addr = strtoul(addr_str, NULL, 16);
    if (!addr || !is_valid_objc_ptr((void *)addr)) {
        resp_append(r, "\"error\":\"invalid address\"");
        return;
    }

    /* Verify it's a WKWebView */
    id webview = (id)addr;
    if (!sphinx_isKindOfClass(webview, "WKWebView")) {
        resp_append(r, "\"error\":\"object at address is not a WKWebView\"");
        return;
    }

    /* Create NSString from JS */
    Class nsStr = objc_getClass("NSString");
    SEL strSel = sel_registerName("stringWithUTF8String:");
    id (*makeStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;
    id jsString = makeStr((id)nsStr, strSel, js);

    /* evaluateJavaScript:completionHandler: must run on main thread.
     * Use dispatch_sync to main queue and capture result. */
    __block id resultObj = nil;
    __block id errorObj = nil;
    __block BOOL completed = NO;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        SEL evalSel = sel_registerName("evaluateJavaScript:completionHandler:");
        void (*eval)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;

        /* The completionHandler is a block: ^(id result, NSError *error) */
        eval(webview, evalSel, jsString,
             ^(id result, id error) {
                 resultObj = result;
                 errorObj = error;
                 completed = YES;
                 dispatch_semaphore_signal(sem);
             });
    });

    /* Wait up to 5 seconds for completion */
    long timeout = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC));

    if (timeout != 0) {
        resp_append(r, "\"error\":\"JavaScript evaluation timed out (5s)\"");
        return;
    }

    if (errorObj) {
        resp_append(r, "\"error\":\"js_error\",\"js_error\":");
        resp_append_json_str(r, nsobject_desc(errorObj));
        return;
    }

    resp_append(r, "\"address\":\"0x%lx\"", (unsigned long)addr);
    resp_append(r, ",\"result\":");
    if (resultObj) {
        resp_append_json_str(r, nsobject_desc(resultObj));
    } else {
        resp_append(r, "null");
    }
}

/* ===================================================================
 *  Command: webview_content
 *  Returns full HTML source of a WKWebView's loaded page
 *  Args: address (hex)
 * =================================================================== */

static void cmd_webview_content(const char *args, resp_t *r) {
    char addr_str[64] = "";
    json_get_string(args, "address", addr_str, sizeof(addr_str));

    if (!addr_str[0]) { resp_append(r, "\"error\":\"missing address arg\""); return; }

    uintptr_t addr = strtoul(addr_str, NULL, 16);
    if (!addr || !is_valid_objc_ptr((void *)addr)) {
        resp_append(r, "\"error\":\"invalid address\"");
        return;
    }

    id webview = (id)addr;
    if (!sphinx_isKindOfClass(webview, "WKWebView")) {
        resp_append(r, "\"error\":\"object at address is not a WKWebView\"");
        return;
    }

    /* Evaluate document.documentElement.outerHTML */
    Class nsStr = objc_getClass("NSString");
    SEL strSel = sel_registerName("stringWithUTF8String:");
    id (*makeStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;
    id jsString = makeStr((id)nsStr, strSel, "document.documentElement.outerHTML");

    __block id resultObj = nil;
    __block id errorObj = nil;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    dispatch_async(dispatch_get_main_queue(), ^{
        SEL evalSel = sel_registerName("evaluateJavaScript:completionHandler:");
        void (*eval)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;
        eval(webview, evalSel, jsString,
             ^(id result, id error) {
                 resultObj = result;
                 errorObj = error;
                 dispatch_semaphore_signal(sem);
             });
    });

    long timeout = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC));

    if (timeout != 0) {
        resp_append(r, "\"error\":\"content extraction timed out (5s)\"");
        return;
    }

    resp_append(r, "\"address\":\"0x%lx\"", (unsigned long)addr);
    resp_append(r, ",\"url\":");
    const char *url = webview_get_url(webview);
    resp_append_json_str(r, url);

    if (errorObj) {
        resp_append(r, ",\"error\":\"extraction_failed\",\"detail\":");
        resp_append_json_str(r, nsobject_desc(errorObj));
        return;
    }

    resp_append(r, ",\"content\":");
    if (resultObj) {
        const char *content = nsobject_desc(resultObj);
        resp_append_json_str(r, content);
        resp_append(r, ",\"content_length\":%zu", content ? strlen(content) : 0);
    } else {
        resp_append(r, "null,\"content_length\":0");
    }
}

/* ===================================================================
 *  Command: webview_bridge_map
 *  Returns all registered WKScriptMessageHandlers across all WebViews
 * =================================================================== */

static void cmd_webview_bridge_map(const char *args, resp_t *r) {
    sphinx_webview_list_t wvs = find_webviews();

    resp_append(r, "\"handlers\":[");
    int bridge_idx = 0;

    for (int i = 0; i < wvs.count; i++) {
        id wv = wvs.entries[i].webview;

        /* Get configuration -> userContentController */
        SEL configSel = sel_registerName("configuration");
        id (*getConfig)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id config = getConfig(wv, configSel);
        if (!config) continue;

        SEL uccSel = sel_registerName("userContentController");
        id (*getUCC)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id ucc = getUCC(config, uccSel);
        if (!ucc) continue;

        /* Try _scriptMessageHandlers (private API — returns NSDictionary) */
        SEL handlersSel = sel_registerName("_scriptMessageHandlers");
        if (!class_getInstanceMethod(object_getClass(ucc), handlersSel)) continue;

        id (*getHandlers)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id handlers = getHandlers(ucc, handlersSel);
        if (!handlers) continue;

        /* Enumerate the dictionary: allKeys -> iterate */
        SEL keysSel = sel_registerName("allKeys");
        id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id keys = getKeys(handlers, keysSel);
        if (!keys) continue;

        SEL countSel = sel_registerName("count");
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        long keyCount = getCount(keys, countSel);

        SEL objAtIdxSel = sel_registerName("objectAtIndex:");
        id (*objAtIdx)(id, SEL, long) = (id (*)(id, SEL, long))objc_msgSend;

        SEL objForKeySel = sel_registerName("objectForKey:");
        id (*objForKey)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;

        for (long k = 0; k < keyCount; k++) {
            id key = objAtIdx(keys, objAtIdxSel, k);
            if (!key) continue;

            id handler = objForKey(handlers, objForKeySel, key);

            if (bridge_idx > 0) resp_append(r, ",");
            resp_append(r, "{\"webview_address\":\"0x%lx\"", (unsigned long)wvs.entries[i].address);
            resp_append(r, ",\"name\":");
            resp_append_json_str(r, nsstring_to_c(key));
            resp_append(r, ",\"native_class\":");
            if (handler) {
                resp_append_json_str(r, class_getName(object_getClass(handler)));
            } else {
                resp_append(r, "null");
            }

            /* Try to get the actual delegate/handler object from the wrapper */
            if (handler) {
                SEL delegateSel = sel_registerName("delegate");
                if (class_getInstanceMethod(object_getClass(handler), delegateSel)) {
                    id (*getDel)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id del = getDel(handler, delegateSel);
                    if (del) {
                        resp_append(r, ",\"delegate_class\":");
                        resp_append_json_str(r, class_getName(object_getClass(del)));
                    }
                }
            }
            resp_append(r, "}");
            bridge_idx++;
        }

        /* Also enumerate user scripts */
        SEL scriptsSel = sel_registerName("_userScripts");
        if (class_getInstanceMethod(object_getClass(ucc), scriptsSel)) {
            id (*getScripts)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id scripts = getScripts(ucc, scriptsSel);
            if (scripts) {
                long scriptCount = getCount(scripts, countSel);
                for (long s = 0; s < scriptCount; s++) {
                    id script = objAtIdx(scripts, objAtIdxSel, s);
                    if (!script) continue;

                    if (bridge_idx > 0) resp_append(r, ",");
                    resp_append(r, "{\"webview_address\":\"0x%lx\"", (unsigned long)wvs.entries[i].address);
                    resp_append(r, ",\"type\":\"user_script\"");

                    /* WKUserScript.source */
                    SEL sourceSel = sel_registerName("source");
                    id (*getSource)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id source = getSource(script, sourceSel);

                    /* Truncate long scripts */
                    const char *src_c = source ? nsstring_to_c(source) : NULL;
                    if (src_c) {
                        char truncated[1024];
                        size_t len = strlen(src_c);
                        if (len > 500) {
                            snprintf(truncated, sizeof(truncated), "%.500s... [truncated, %zu bytes total]", src_c, len);
                            resp_append(r, ",\"source\":");
                            resp_append_json_str(r, truncated);
                        } else {
                            resp_append(r, ",\"source\":");
                            resp_append_json_str(r, src_c);
                        }
                    } else {
                        resp_append(r, ",\"source\":null");
                    }

                    /* WKUserScript.injectionTime (0=atDocumentStart, 1=atDocumentEnd) */
                    SEL timeSel = sel_registerName("injectionTime");
                    long (*getTime)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
                    long injTime = getTime(script, timeSel);
                    resp_append(r, ",\"injection_time\":\"%s\"",
                                injTime == 0 ? "document_start" : "document_end");

                    /* WKUserScript.isForMainFrameOnly */
                    SEL mainFrameSel = sel_registerName("isForMainFrameOnly");
                    BOOL (*getMainFrame)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                    BOOL mainOnly = getMainFrame(script, mainFrameSel);
                    resp_append(r, ",\"main_frame_only\":%s}", mainOnly ? "true" : "false");
                    bridge_idx++;
                }
            }
        }
    }

    resp_append(r, "],\"total\":%d,\"webview_count\":%d", bridge_idx, wvs.count);
}

/* ===================================================================
 *  ObjC Block Introspection (Sprint 13.6)
 *
 *  Block_layout struct (from LLVM libclosure / Block_private.h):
 *    struct Block_layout {
 *        void *isa;             // _NSConcreteStackBlock, _NSConcreteMallocBlock, _NSConcreteGlobalBlock
 *        volatile int32_t flags;
 *        int32_t reserved;
 *        void (*invoke)(void *, ...);
 *        struct Block_descriptor_1 {
 *            unsigned long reserved;
 *            unsigned long size;      // sizeof(struct Block_layout) + captured vars
 *        } *descriptor;
 *        // Captured variables follow...
 *    };
 *
 *  Flags:
 *    BLOCK_HAS_COPY_DISPOSE  = (1 << 25)
 *    BLOCK_HAS_CTOR          = (1 << 26)
 *    BLOCK_IS_GLOBAL         = (1 << 28)
 *    BLOCK_HAS_STRET         = (1 << 29)
 *    BLOCK_HAS_SIGNATURE     = (1 << 30)
 * =================================================================== */

#define BLOCK_HAS_COPY_DISPOSE  (1 << 25)
#define BLOCK_HAS_CTOR          (1 << 26)
#define BLOCK_IS_GLOBAL         (1 << 28)
#define BLOCK_HAS_STRET         (1 << 29)
#define BLOCK_HAS_SIGNATURE     (1 << 30)

/* Block_descriptor when BLOCK_HAS_COPY_DISPOSE is set */
typedef struct {
    unsigned long reserved;
    unsigned long size;
    void (*copy_helper)(void *dst, const void *src);
    void (*dispose_helper)(const void *);
} sphinx_block_desc_copy_t;

/* Block_descriptor when BLOCK_HAS_SIGNATURE is set (after copy/dispose if present) */
/* The signature pointer lives after the base descriptor (and optionally after copy/dispose helpers) */

typedef struct {
    void *isa;
    int32_t flags;
    int32_t reserved;
    void (*invoke)(void *, ...);
    struct {
        unsigned long reserved;
        unsigned long size;
    } *descriptor;
} sphinx_block_layout_t;

/* Get block type string from isa */
static const char *block_type_name(void *isa) {
    /* Compare against known block class pointers */
    Class stack_cls = objc_getClass("__NSStackBlock__");
    Class malloc_cls = objc_getClass("__NSMallocBlock__");
    Class global_cls = objc_getClass("__NSGlobalBlock__");
    Class stack_cls2 = objc_getClass("__NSStackBlock");
    Class malloc_cls2 = objc_getClass("__NSMallocBlock");
    Class global_cls2 = objc_getClass("__NSGlobalBlock");

    if (isa == (void *)stack_cls || isa == (void *)stack_cls2) return "stack";
    if (isa == (void *)malloc_cls || isa == (void *)malloc_cls2) return "malloc";
    if (isa == (void *)global_cls || isa == (void *)global_cls2) return "global";

    /* Also check by name for runtime variants */
    if (isa) {
        const char *name = class_getName((Class)isa);
        if (name) {
            if (strstr(name, "StackBlock")) return "stack";
            if (strstr(name, "MallocBlock")) return "malloc";
            if (strstr(name, "GlobalBlock")) return "global";
            if (strstr(name, "Block")) return "block_unknown";
        }
    }
    return "unknown";
}

/* Get block signature string if available */
static const char *block_get_signature(const sphinx_block_layout_t *blk) {
    if (!(blk->flags & BLOCK_HAS_SIGNATURE)) return NULL;
    if (!blk->descriptor) return NULL;

    /* The signature pointer is located AFTER the base descriptor fields,
     * and after copy/dispose helpers if BLOCK_HAS_COPY_DISPOSE is set. */
    const unsigned char *desc = (const unsigned char *)blk->descriptor;

    /* Skip base descriptor: reserved (unsigned long) + size (unsigned long) */
    desc += 2 * sizeof(unsigned long);

    /* Skip copy/dispose if present */
    if (blk->flags & BLOCK_HAS_COPY_DISPOSE) {
        desc += 2 * sizeof(void *);
    }

    /* The next pointer-sized value is the signature string pointer */
    const char *sig = *(const char **)desc;

    /* Validate: signature should be a readable pointer to ASCII */
    if (!sig || (uintptr_t)sig < 0x1000) return NULL;

    /* Quick sanity check: first char should be a type encoding char */
    if (sig[0] >= 0x20 && sig[0] < 0x7f) return sig;
    return NULL;
}

/* ===================================================================
 *  Command: block_inspect
 *  Parse Block_layout struct at given address. Returns block metadata,
 *  signature, invoke address, captured variable preview.
 *  Args: address (hex)
 * =================================================================== */

static void cmd_block_inspect(const char *args, resp_t *r) {
    char addr_str[64] = "";
    json_get_string(args, "address", addr_str, sizeof(addr_str));

    if (!addr_str[0]) { resp_append(r, "\"error\":\"missing address arg\""); return; }

    uintptr_t addr = strtoul(addr_str, NULL, 16);
    if (!addr) { resp_append(r, "\"error\":\"invalid address\""); return; }

    /* Verify readable memory */
    if (!is_valid_objc_ptr((void *)addr)) {
        resp_append(r, "\"error\":\"address not a valid object\"");
        return;
    }

    /* Check if it's actually a block */
    const char *cls_name = class_getName(object_getClass((id)addr));
    if (!cls_name || !strstr(cls_name, "Block")) {
        resp_append(r, "\"error\":\"object at address is not a block (class: %s)\"", cls_name ? cls_name : "nil");
        return;
    }

    const sphinx_block_layout_t *blk = (const sphinx_block_layout_t *)addr;

    resp_append(r, "\"address\":\"0x%lx\"", (unsigned long)addr);

    /* Block type */
    const char *btype = block_type_name(blk->isa);
    resp_append(r, ",\"type\":");
    resp_append_json_str(r, btype);
    resp_append(r, ",\"isa_class\":");
    resp_append_json_str(r, cls_name);

    /* Flags */
    int32_t flags = blk->flags;
    resp_append(r, ",\"flags\":\"0x%x\"", (unsigned)flags);
    resp_append(r, ",\"has_copy_dispose\":%s", (flags & BLOCK_HAS_COPY_DISPOSE) ? "true" : "false");
    resp_append(r, ",\"has_ctor\":%s", (flags & BLOCK_HAS_CTOR) ? "true" : "false");
    resp_append(r, ",\"is_global\":%s", (flags & BLOCK_IS_GLOBAL) ? "true" : "false");
    resp_append(r, ",\"has_stret\":%s", (flags & BLOCK_HAS_STRET) ? "true" : "false");
    resp_append(r, ",\"has_signature\":%s", (flags & BLOCK_HAS_SIGNATURE) ? "true" : "false");

    /* Invoke function pointer */
    resp_append(r, ",\"invoke\":\"0x%lx\"", (unsigned long)blk->invoke);

    /* Try to resolve invoke symbol */
    Dl_info dl_info;
    if (dladdr((void *)blk->invoke, &dl_info) && dl_info.dli_sname) {
        resp_append(r, ",\"invoke_symbol\":");
        resp_append_json_str(r, dl_info.dli_sname);
        if (dl_info.dli_fname) {
            const char *basename = strrchr(dl_info.dli_fname, '/');
            resp_append(r, ",\"invoke_image\":");
            resp_append_json_str(r, basename ? basename + 1 : dl_info.dli_fname);
        }
    }

    /* Descriptor */
    if (blk->descriptor) {
        unsigned long desc_size = blk->descriptor->size;
        resp_append(r, ",\"descriptor_size\":%lu", desc_size);

        /* Captured variables: everything after the standard Block_layout fields.
         * Standard layout is 5 pointers (isa, flags+reserved, invoke, descriptor) = 32 bytes on arm64. */
        unsigned long base_size = sizeof(sphinx_block_layout_t);
        if (desc_size > base_size) {
            unsigned long captured_bytes = desc_size - base_size;
            resp_append(r, ",\"captured_bytes\":%lu", captured_bytes);

            /* Preview captured vars as hex + attempt string extraction */
            const unsigned char *captured = (const unsigned char *)addr + base_size;
            unsigned long preview_len = captured_bytes > 256 ? 256 : captured_bytes;

            resp_append(r, ",\"captured_hex\":\"");
            for (unsigned long i = 0; i < preview_len; i++) {
                resp_append(r, "%02x", captured[i]);
            }
            resp_append(r, "\"");

            /* Try to extract captured ObjC objects and strings */
            resp_append(r, ",\"captured_values\":[");
            int cap_count = 0;
            unsigned long num_ptrs = captured_bytes / sizeof(void *);
            if (num_ptrs > 32) num_ptrs = 32;

            for (unsigned long i = 0; i < num_ptrs; i++) {
                uintptr_t val = ((const uintptr_t *)captured)[i];
                if (val == 0) continue;

                /* Check if it looks like an ObjC object */
                if (is_valid_objc_ptr((void *)val)) {
                    if (cap_count > 0) resp_append(r, ",");
                    resp_append(r, "{\"offset\":%lu", i * sizeof(void *));
                    resp_append(r, ",\"address\":\"0x%lx\"", (unsigned long)val);
                    const char *obj_cls = class_getName(object_getClass((id)val));
                    resp_append(r, ",\"class\":");
                    resp_append_json_str(r, obj_cls);

                    /* For NSString, extract value */
                    if (obj_cls && (strstr(obj_cls, "String") || strstr(obj_cls, "NSTaggedPointerString"))) {
                        resp_append(r, ",\"value\":");
                        resp_append_json_str(r, nsstring_to_c((id)val));
                    } else {
                        /* Generic description, truncated */
                        const char *desc = nsobject_desc((id)val);
                        if (desc) {
                            char trunc[256];
                            snprintf(trunc, sizeof(trunc), "%.250s", desc);
                            resp_append(r, ",\"description\":");
                            resp_append_json_str(r, trunc);
                        }
                    }
                    resp_append(r, "}");
                    cap_count++;
                    if (cap_count >= 16) break;
                }
            }
            resp_append(r, "]");
        } else {
            resp_append(r, ",\"captured_bytes\":0");
        }
    }

    /* Signature */
    const char *sig = block_get_signature(blk);
    resp_append(r, ",\"signature\":");
    resp_append_json_str(r, sig);
}

/* ===================================================================
 *  Command: block_invoke
 *  Calls the block's invoke function. DANGEROUS — caller must verify
 *  block is still live. Only supports void-returning, no-arg blocks
 *  for safety. For blocks with arguments, use at own risk.
 *  Args: address (hex)
 * =================================================================== */

static void cmd_block_invoke(const char *args, resp_t *r) {
    char addr_str[64] = "";
    json_get_string(args, "address", addr_str, sizeof(addr_str));

    if (!addr_str[0]) { resp_append(r, "\"error\":\"missing address arg\""); return; }

    uintptr_t addr = strtoul(addr_str, NULL, 16);
    if (!addr) { resp_append(r, "\"error\":\"invalid address\""); return; }

    if (!is_valid_objc_ptr((void *)addr)) {
        resp_append(r, "\"error\":\"address not a valid object\"");
        return;
    }

    /* Verify it's a block */
    const char *cls_name = class_getName(object_getClass((id)addr));
    if (!cls_name || !strstr(cls_name, "Block")) {
        resp_append(r, "\"error\":\"object is not a block (class: %s)\"", cls_name ? cls_name : "nil");
        return;
    }

    const sphinx_block_layout_t *blk = (const sphinx_block_layout_t *)addr;

    /* Refuse to invoke stack blocks — they may be dangling */
    const char *btype = block_type_name(blk->isa);
    if (strcmp(btype, "stack") == 0) {
        resp_append(r, "\"error\":\"refusing to invoke stack block (likely dangling)\"");
        return;
    }

    /* Validate invoke pointer */
    if (!blk->invoke) {
        resp_append(r, "\"error\":\"block has null invoke pointer\"");
        return;
    }

    Dl_info dl_info;
    if (!dladdr((void *)blk->invoke, &dl_info)) {
        resp_append(r, "\"error\":\"block invoke pointer does not resolve to valid code\"");
        return;
    }

    /* Invoke as void(^)(void) — safest signature */
    resp_append(r, "\"address\":\"0x%lx\"", (unsigned long)addr);
    resp_append(r, ",\"invoke\":\"0x%lx\"", (unsigned long)blk->invoke);
    resp_append(r, ",\"warning\":\"invoking block as void(^)(void) — undefined behavior if block expects arguments\"");

    @try {
        void (*block_fn)(void *) = (void (*)(void *))blk->invoke;
        block_fn((void *)addr);
        resp_append(r, ",\"result\":\"invoked successfully\"");
    } @catch (id ex) {
        resp_append(r, ",\"result\":\"exception\"");
        resp_append(r, ",\"exception\":");
        resp_append_json_str(r, nsobject_desc(ex));
    }
}

/* ===================================================================
 *  Protobuf Wire Format Decoder (Sprint 13.6)
 *
 *  Protobuf wire types:
 *    0 = Varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum)
 *    1 = 64-bit (fixed64, sfixed64, double)
 *    2 = Length-delimited (string, bytes, embedded messages, packed repeated)
 *    5 = 32-bit (fixed32, sfixed32, float)
 *
 *  Each field: (field_number << 3) | wire_type as a varint tag.
 * =================================================================== */

#define PB_WIRE_VARINT  0
#define PB_WIRE_64BIT   1
#define PB_WIRE_LEN     2
#define PB_WIRE_32BIT   5

#define PB_MAX_DEPTH    10
#define PB_MAX_FIELDS   200

/* Decode a varint from buffer. Returns bytes consumed, 0 on error. */
static int pb_decode_varint(const uint8_t *buf, size_t len, uint64_t *out) {
    *out = 0;
    for (int i = 0; i < 10 && (size_t)i < len; i++) {
        *out |= (uint64_t)(buf[i] & 0x7F) << (7 * i);
        if (!(buf[i] & 0x80)) return i + 1;
    }
    return 0;
}

/* Check if a byte sequence looks like valid UTF-8 text */
static int pb_looks_like_string(const uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    int printable = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0) return 0;  /* null byte = not a string */
        if (buf[i] >= 0x20 && buf[i] < 0x7f) printable++;
    }
    return (printable * 100 / len) > 70;  /* >70% printable = likely string */
}

/* Check if a byte sequence looks like a valid nested protobuf message */
static int pb_looks_like_message(const uint8_t *buf, size_t len) {
    if (len < 2) return 0;
    /* Try to decode first tag */
    uint64_t tag;
    int consumed = pb_decode_varint(buf, len, &tag);
    if (consumed == 0) return 0;
    int wire_type = tag & 0x07;
    int field_num = (int)(tag >> 3);
    /* Valid field numbers are 1-536870911, wire types 0,1,2,5 */
    if (field_num < 1 || field_num > 536870911) return 0;
    if (wire_type != 0 && wire_type != 1 && wire_type != 2 && wire_type != 5) return 0;
    return 1;
}

/* Recursive protobuf decoder — appends decoded fields to response */
static int pb_decode_message(const uint8_t *buf, size_t len, resp_t *r,
                             int depth, int *field_count) {
    if (depth > PB_MAX_DEPTH) return -1;

    size_t pos = 0;
    int first = 1;

    while (pos < len && *field_count < PB_MAX_FIELDS) {
        /* Decode tag */
        uint64_t tag;
        int consumed = pb_decode_varint(buf + pos, len - pos, &tag);
        if (consumed == 0) break;
        pos += consumed;

        int wire_type = tag & 0x07;
        int field_num = (int)(tag >> 3);
        if (field_num < 1) break;

        if (!first) resp_append(r, ",");
        first = 0;
        (*field_count)++;

        resp_append(r, "{\"field\":%d,\"wire_type\":%d", field_num, wire_type);

        switch (wire_type) {
            case PB_WIRE_VARINT: {
                uint64_t val;
                consumed = pb_decode_varint(buf + pos, len - pos, &val);
                if (consumed == 0) { resp_append(r, ",\"error\":\"truncated varint\"}"); return -1; }
                pos += consumed;
                resp_append(r, ",\"type\":\"varint\",\"value\":%llu", (unsigned long long)val);

                /* Also show signed interpretation (zigzag) */
                int64_t zigzag = (int64_t)((val >> 1) ^ -(val & 1));
                if (zigzag != (int64_t)val) {
                    resp_append(r, ",\"sint_value\":%lld", (long long)zigzag);
                }
                break;
            }

            case PB_WIRE_64BIT: {
                if (pos + 8 > len) { resp_append(r, ",\"error\":\"truncated fixed64\"}"); return -1; }
                uint64_t val;
                memcpy(&val, buf + pos, 8);
                pos += 8;
                double dval;
                memcpy(&dval, &val, 8);
                resp_append(r, ",\"type\":\"fixed64\",\"value\":%llu", (unsigned long long)val);
                /* Show as double if it looks reasonable */
                if (dval > -1e15 && dval < 1e15 && dval != 0.0) {
                    resp_append(r, ",\"double_value\":%.6g", dval);
                }
                break;
            }

            case PB_WIRE_LEN: {
                uint64_t data_len;
                consumed = pb_decode_varint(buf + pos, len - pos, &data_len);
                if (consumed == 0 || pos + consumed + data_len > len) {
                    resp_append(r, ",\"error\":\"truncated length-delimited\"}");
                    return -1;
                }
                pos += consumed;
                const uint8_t *data = buf + pos;
                pos += data_len;

                resp_append(r, ",\"length\":%llu", (unsigned long long)data_len);

                if (data_len == 0) {
                    resp_append(r, ",\"type\":\"bytes\",\"value\":\"\"");
                } else if (pb_looks_like_string(data, (size_t)data_len)) {
                    resp_append(r, ",\"type\":\"string\",\"value\":");
                    /* Truncate long strings */
                    char str_buf[1024];
                    size_t copy_len = (size_t)data_len > 500 ? 500 : (size_t)data_len;
                    memcpy(str_buf, data, copy_len);
                    str_buf[copy_len] = '\0';
                    resp_append_json_str(r, str_buf);
                    if (data_len > 500) {
                        resp_append(r, ",\"truncated\":true");
                    }
                } else if (pb_looks_like_message(data, (size_t)data_len)) {
                    resp_append(r, ",\"type\":\"message\",\"fields\":[");
                    int nested_result = pb_decode_message(data, (size_t)data_len, r, depth + 1, field_count);
                    resp_append(r, "]");
                    if (nested_result < 0) {
                        resp_append(r, ",\"nested_error\":true");
                    }
                } else {
                    resp_append(r, ",\"type\":\"bytes\"");
                    /* Show hex preview */
                    size_t hex_len = (size_t)data_len > 64 ? 64 : (size_t)data_len;
                    resp_append(r, ",\"hex\":\"");
                    for (size_t i = 0; i < hex_len; i++) {
                        resp_append(r, "%02x", data[i]);
                    }
                    if (data_len > 64) resp_append(r, "...");
                    resp_append(r, "\"");
                }
                break;
            }

            case PB_WIRE_32BIT: {
                if (pos + 4 > len) { resp_append(r, ",\"error\":\"truncated fixed32\"}"); return -1; }
                uint32_t val;
                memcpy(&val, buf + pos, 4);
                pos += 4;
                float fval;
                memcpy(&fval, &val, 4);
                resp_append(r, ",\"type\":\"fixed32\",\"value\":%u", val);
                if (fval > -1e10 && fval < 1e10 && fval != 0.0f) {
                    resp_append(r, ",\"float_value\":%.6g", fval);
                }
                break;
            }

            default:
                resp_append(r, ",\"type\":\"unknown_wire_%d\"", wire_type);
                resp_append(r, "}");
                return -1;  /* Unknown wire type — can't skip */
        }

        resp_append(r, "}");
    }

    return 0;
}

/* Decode hex string to bytes */
static size_t hex_decode(const char *hex, uint8_t *out, size_t max_out) {
    size_t len = strlen(hex);
    size_t out_len = 0;
    for (size_t i = 0; i + 1 < len && out_len < max_out; i += 2) {
        unsigned int byte;
        if (sscanf(hex + i, "%2x", &byte) != 1) break;
        out[out_len++] = (uint8_t)byte;
    }
    return out_len;
}

/* Decode base64 string to bytes */
static const uint8_t pb_b64_table[] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,65,64,64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64
};

static size_t pb_b64_decode(const char *src, uint8_t *out, size_t max_out) {
    size_t len = strlen(src);
    size_t out_len = 0;
    uint32_t accum = 0;
    int bits = 0;
    for (size_t i = 0; i < len && out_len < max_out; i++) {
        uint8_t c = (uint8_t)src[i];
        if (c > 127) continue;
        uint8_t val = pb_b64_table[c];
        if (val == 64) continue;  /* skip whitespace/invalid */
        if (val == 65) break;     /* padding '=' */
        accum = (accum << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_len++] = (uint8_t)(accum >> bits);
            accum &= (1 << bits) - 1;
        }
    }
    return out_len;
}

/* ===================================================================
 *  Command: proto_decode
 *  Attempts protobuf decode on hex or base64 input.
 *  Args: data (hex or base64 string)
 * =================================================================== */

static void cmd_proto_decode(const char *args, resp_t *r) {
    char data[BRIDGE_MAX_REQUEST];
    json_get_string(args, "data", data, sizeof(data));

    if (!data[0]) { resp_append(r, "\"error\":\"missing data arg (hex or base64)\""); return; }

    /* Determine encoding: hex if all [0-9a-fA-F], else assume base64 */
    uint8_t decoded[32768];
    size_t decoded_len = 0;

    int is_hex = 1;
    for (int i = 0; data[i] && is_hex; i++) {
        char c = data[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            is_hex = 0;
    }

    if (is_hex && strlen(data) >= 2) {
        decoded_len = hex_decode(data, decoded, sizeof(decoded));
        resp_append(r, "\"encoding\":\"hex\"");
    } else {
        decoded_len = pb_b64_decode(data, decoded, sizeof(decoded));
        resp_append(r, "\"encoding\":\"base64\"");
    }

    if (decoded_len == 0) {
        resp_append(r, ",\"error\":\"failed to decode input data\"");
        return;
    }

    resp_append(r, ",\"raw_bytes\":%zu", decoded_len);

    /* Attempt protobuf decode */
    resp_append(r, ",\"fields\":[");
    int field_count = 0;
    int result = pb_decode_message(decoded, decoded_len, r, 0, &field_count);
    resp_append(r, "]");

    resp_append(r, ",\"total_fields\":%d", field_count);
    if (result < 0) {
        resp_append(r, ",\"parse_warning\":\"partial decode — some fields may be invalid\"");
    }
}

/* ===================================================================
 *  Command: proto_schema
 *  Attempts to reconstruct protobuf schema from GPBDescriptor
 *  runtime metadata on GPBMessage subclasses.
 *  Args: class (optional — specific GPBMessage subclass name)
 * =================================================================== */

static void cmd_proto_schema(const char *args, resp_t *r) {
    char class_filter[512] = "";
    json_get_string(args, "class", class_filter, sizeof(class_filter));

    /* Check if GPBMessage class exists (Google Protobuf ObjC runtime) */
    Class gpbBase = objc_getClass("GPBMessage");
    if (!gpbBase) {
        resp_append(r, "\"error\":\"GPBMessage class not found — app does not use Google Protobuf ObjC\"");
        return;
    }

    resp_append(r, "\"schemas\":[");
    int schema_count = 0;

    unsigned int class_count = 0;
    Class *classes = objc_copyClassList(&class_count);

    SEL descriptorSel = sel_registerName("descriptor");
    SEL fieldsSel = sel_registerName("fields");
    SEL countSel = sel_registerName("count");
    SEL objAtIdxSel = sel_registerName("objectAtIndex:");
    SEL nameSel = sel_registerName("name");
    SEL numberSel = sel_registerName("number");
    SEL dataTypeSel = sel_registerName("dataType");
    SEL fieldTypeSel = sel_registerName("fieldType");
    SEL msgClassSel = sel_registerName("msgClass");
    SEL isKindSel = sel_registerName("isKindOfClass:");

    id (*sendId)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
    long (*sendLong)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

    /* Protobuf data type names (GPBDataType enum values) */
    static const char *gpb_type_names[] = {
        "bool", "fixed32", "sfixed32", "float", "fixed64", "sfixed64", "double",
        "int32", "int64", "sint32", "sint64", "uint32", "uint64",
        "bytes", "string", "message", "group", "enum"
    };
    static const int gpb_type_count = sizeof(gpb_type_names) / sizeof(gpb_type_names[0]);

    /* Protobuf field type names (GPBFieldType enum values) */
    static const char *gpb_field_types[] = { "single", "repeated", "map" };

    for (unsigned int i = 0; i < class_count && schema_count < 200; i++) {
        const char *name = class_getName(classes[i]);

        /* Filter if specified */
        if (class_filter[0] && strcmp(name, class_filter) != 0) continue;

        /* Check if it's a GPBMessage subclass */
        if (!isKind((id)classes[i], isKindSel, gpbBase)) {
            /* isKindOfClass won't work on class objects — check superclass chain */
            Class check = classes[i];
            int is_gpb = 0;
            while (check) {
                if (check == gpbBase) { is_gpb = 1; break; }
                check = class_getSuperclass(check);
            }
            if (!is_gpb) continue;
        }

        /* Get descriptor via class method */
        Class metaCls = object_getClass((id)classes[i]);
        if (!class_getClassMethod(classes[i], descriptorSel)) continue;

        id descriptor = sendId((id)classes[i], descriptorSel);
        if (!descriptor) continue;

        /* Get fields array from descriptor */
        id fields = sendId(descriptor, fieldsSel);
        if (!fields) continue;

        long fcount = sendLong(fields, countSel);
        if (fcount <= 0) continue;

        if (schema_count > 0) resp_append(r, ",");
        resp_append(r, "{\"class\":");
        resp_append_json_str(r, name);
        resp_append(r, ",\"fields\":[");

        for (long f = 0; f < fcount && f < 100; f++) {
            id field = getAt(fields, objAtIdxSel, (unsigned long)f);
            if (!field) continue;

            if (f > 0) resp_append(r, ",");
            resp_append(r, "{");

            /* Field name */
            id fname = sendId(field, nameSel);
            resp_append(r, "\"name\":");
            resp_append_json_str(r, fname ? nsstring_to_c(fname) : "(null)");

            /* Field number */
            long fnum = sendLong(field, numberSel);
            resp_append(r, ",\"number\":%ld", fnum);

            /* Data type */
            long dtype = sendLong(field, dataTypeSel);
            resp_append(r, ",\"data_type\":");
            if (dtype >= 0 && dtype < gpb_type_count) {
                resp_append_json_str(r, gpb_type_names[dtype]);
            } else {
                resp_append(r, "%ld", dtype);
            }

            /* Field type (single, repeated, map) */
            long ftype = sendLong(field, fieldTypeSel);
            resp_append(r, ",\"field_type\":");
            if (ftype >= 0 && ftype < 3) {
                resp_append_json_str(r, gpb_field_types[ftype]);
            } else {
                resp_append(r, "%ld", ftype);
            }

            /* Message class for nested message fields */
            if (dtype == 15) {  /* GPBDataTypeMessage */
                SEL respondsSel = sel_registerName("respondsToSelector:");
                BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
                if (responds(field, respondsSel, msgClassSel)) {
                    id (*getMsgClass)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                    id mc = getMsgClass(field, msgClassSel);
                    if (mc) {
                        resp_append(r, ",\"message_class\":");
                        resp_append_json_str(r, class_getName((Class)mc));
                    }
                }
            }

            resp_append(r, "}");
        }

        resp_append(r, "],\"field_count\":%ld}", fcount);
        schema_count++;
    }

    free(classes);
    resp_append(r, "],\"schema_count\":%d", schema_count);

    if (schema_count == 0 && !class_filter[0]) {
        resp_append(r, ",\"note\":\"no GPBMessage subclasses found — app may use SwiftProtobuf or raw protobuf without ObjC codegen\"");
    }
}
