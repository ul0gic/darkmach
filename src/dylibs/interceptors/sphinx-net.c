/*
 * sphinx-net.dylib — Network interceptor for Sphinx
 * Captures all HTTP/HTTPS traffic: URLs, methods, headers, request/response bodies
 * Hooks NSURLSession at the delegate callback level
 *
 * Build:
 *   clang -shared -o sphinx-net.dylib sphinx-net.c \
 *     -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
 *     -target arm64-apple-ios16.0-simulator \
 *     -framework Foundation -lobjc -w
 *
 * Inject:
 *   SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/sphinx-net.dylib \
 *   xcrun simctl launch <device> <bundle-id>
 */
#include "sphinx-core.h"
#include <dlfcn.h>

#define MOD "net"

/* ── Store original implementations ── */
static IMP orig_dataTaskWithRequest_completion = NULL;
static IMP orig_dataTaskWithURL_completion = NULL;

/* ── Helper: extract headers as JSON string ── */
static void headers_to_json(id headerDict, char *buf, size_t bufsize) {
    if (!headerDict) { snprintf(buf, bufsize, "{}"); return; }

    SEL allKeysSel = sel_registerName("allKeys");
    SEL objectForKeySel = sel_registerName("objectForKey:");
    SEL countSel = sel_registerName("count");

    id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    id (*objectAtIndex)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    id keys = getKeys(headerDict, allKeysSel);
    long count = getCount(keys, countSel);

    size_t pos = 0;
    pos += snprintf(buf + pos, bufsize - pos, "{");

    SEL indexSel = sel_registerName("objectAtIndex:");
    for (long i = 0; i < count && pos < bufsize - 20; i++) {
        id key = objectAtIndex(keys, indexSel, (unsigned long)i);
        id val = getObj(headerDict, objectForKeySel, key);

        const char *k = nsstring_to_c(key);
        const char *v = nsstring_to_c(val);

        char ek[256], ev[1024];
        json_escape(k, ek, sizeof(ek));
        json_escape(v, ev, sizeof(ev));

        if (i > 0) pos += snprintf(buf + pos, bufsize - pos, ",");
        pos += snprintf(buf + pos, bufsize - pos, "%s:%s", ek, ev);
    }
    snprintf(buf + pos, bufsize - pos, "}");
}

/* ── Helper: log a request ── */
static void log_request(id request, const char *source) {
    if (!request) return;

    SEL urlSel = sel_registerName("URL");
    SEL methodSel = sel_registerName("HTTPMethod");
    SEL headersSel = sel_registerName("allHTTPHeaderFields");
    SEL bodySel = sel_registerName("HTTPBody");
    SEL absSel = sel_registerName("absoluteString");

    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;

    id url = get(request, urlSel);
    id urlStr = url ? get(url, absSel) : NULL;
    id method = get(request, methodSel);
    id headers = get(request, headersSel);
    id body = get(request, bodySel);

    const char *url_c = nsstring_to_c(urlStr);
    const char *method_c = nsstring_to_c(method);

    char url_esc[4096];
    json_escape(url_c, url_esc, sizeof(url_esc));

    char method_esc[32];
    json_escape(method_c, method_esc, sizeof(method_esc));

    char headers_json[8192];
    headers_to_json(headers, headers_json, sizeof(headers_json));

    /* Body — truncate to 2KB for logging */
    char body_esc[4096] = "null";
    if (body) {
        SEL lenSel = sel_registerName("length");
        SEL bytesSel = sel_registerName("bytes");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        const void *(*getBytes)(id, SEL) = (const void *(*)(id, SEL))objc_msgSend;

        long len = getLen(body, lenSel);
        const void *bytes = getBytes(body, bytesSel);
        if (bytes && len > 0) {
            long log_len = len > 2048 ? 2048 : len;
            char raw[2050];
            memcpy(raw, bytes, log_len);
            raw[log_len] = '\0';
            json_escape(raw, body_esc, sizeof(body_esc));
        }
    }

    char data[16384];
    snprintf(data, sizeof(data),
             "\"src\":\"%s\",\"method\":%s,\"url\":%s,\"headers\":%s,\"body\":%s",
             source, method_esc, url_esc, headers_json, body_esc);

    sphinx_log(MOD, "request", data);

    /* Also print to stderr for immediate visibility */
    fprintf(stderr, "[sphinx-net] %s %s\n", method_c, url_c);
}

/* ── Helper: log a response ── */
static void log_response(id response, id data_obj, id error) {
    long status = 0;
    char headers_json[8192] = "{}";
    char url_esc[4096] = "null";

    if (response) {
        /* Check if it's an NSHTTPURLResponse */
        Class httpRespClass = objc_getClass("NSHTTPURLResponse");
        SEL isKindSel = sel_registerName("isKindOfClass:");
        BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
        if (httpRespClass && isKind((id)response, isKindSel, httpRespClass)) {
            SEL statusSel = sel_registerName("statusCode");
            long (*getStatus)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
            status = getStatus(response, statusSel);

            SEL headersSel = sel_registerName("allHeaderFields");
            id (*getHeaders)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id headers = getHeaders(response, headersSel);
            headers_to_json(headers, headers_json, sizeof(headers_json));
        }

        SEL urlSel = sel_registerName("URL");
        SEL absSel = sel_registerName("absoluteString");
        id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id url = get(response, urlSel);
        if (url) {
            id urlStr = get(url, absSel);
            json_escape(nsstring_to_c(urlStr), url_esc, sizeof(url_esc));
        }
    }

    /* Response body — truncate to 4KB */
    char body_esc[8192] = "null";
    if (data_obj) {
        SEL lenSel = sel_registerName("length");
        SEL bytesSel = sel_registerName("bytes");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        const void *(*getBytes)(id, SEL) = (const void *(*)(id, SEL))objc_msgSend;

        long len = getLen(data_obj, lenSel);
        const void *bytes = getBytes(data_obj, bytesSel);
        if (bytes && len > 0) {
            long log_len = len > 4096 ? 4096 : len;
            char raw[4098];
            memcpy(raw, bytes, log_len);
            raw[log_len] = '\0';
            json_escape(raw, body_esc, sizeof(body_esc));
        }
    }

    char error_esc[1024] = "null";
    if (error) {
        json_escape(nsobject_desc(error), error_esc, sizeof(error_esc));
    }

    char data[16384];
    snprintf(data, sizeof(data),
             "\"status\":%ld,\"url\":%s,\"headers\":%s,\"body\":%s,\"error\":%s",
             status, url_esc, headers_json, body_esc, error_esc);

    sphinx_log(MOD, "response", data);

    if (status > 0) {
        fprintf(stderr, "[sphinx-net] <- %ld %s\n", status,
                url_esc[0] == '"' ? url_esc+1 : url_esc);
    }
}

/* ── Hook: dataTaskWithRequest:completionHandler: ── */
static id hooked_dataTaskWithRequest_completion(id self, SEL _cmd,
                                                 id request,
                                                 void (^completion)(id, id, id)) {
    log_request(request, "dataTask");

    /* Wrap the completion to capture the response */
    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            log_response(response, data_obj, error);
            completion(data_obj, response, error);
        };
    }

    /* Call original */
    id (*orig)(id, SEL, id, void(^)(id,id,id)) =
        (id (*)(id, SEL, id, void(^)(id,id,id)))orig_dataTaskWithRequest_completion;
    return orig(self, _cmd, request, wrappedCompletion ? wrappedCompletion : completion);
}

/* ── Hook: dataTaskWithURL:completionHandler: ── */
static id hooked_dataTaskWithURL_completion(id self, SEL _cmd,
                                             id url,
                                             void (^completion)(id, id, id)) {
    /* Log the URL */
    char url_esc[4096];
    SEL absSel = sel_registerName("absoluteString");
    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id urlStr = get(url, absSel);
    json_escape(nsstring_to_c(urlStr), url_esc, sizeof(url_esc));

    char data[4096];
    snprintf(data, sizeof(data),
             "\"src\":\"dataTaskURL\",\"method\":\"GET\",\"url\":%s", url_esc);
    sphinx_log(MOD, "request", data);
    fprintf(stderr, "[sphinx-net] GET %s\n", nsstring_to_c(urlStr));

    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            log_response(response, data_obj, error);
            completion(data_obj, response, error);
        };
    }

    id (*orig)(id, SEL, id, void(^)(id,id,id)) =
        (id (*)(id, SEL, id, void(^)(id,id,id)))orig_dataTaskWithURL_completion;
    return orig(self, _cmd, url, wrappedCompletion ? wrappedCompletion : completion);
}

/* ── Constructor: install hooks ── */
__attribute__((constructor))
static void sphinx_net_init(void) {
    fprintf(stderr, "[sphinx-net] initializing network interceptor\n");
    sphinx_log_init(MOD);

    Class sessionClass = objc_getClass("NSURLSession");
    if (!sessionClass) {
        fprintf(stderr, "[sphinx-net] ERROR: NSURLSession class not found\n");
        return;
    }

    /* Hook dataTaskWithRequest:completionHandler: */
    SEL sel1 = sel_registerName("dataTaskWithRequest:completionHandler:");
    Method m1 = class_getInstanceMethod(sessionClass, sel1);
    if (m1) {
        orig_dataTaskWithRequest_completion = method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hooked_dataTaskWithRequest_completion);
        fprintf(stderr, "[sphinx-net] hooked dataTaskWithRequest:completionHandler:\n");
    }

    /* Hook dataTaskWithURL:completionHandler: */
    SEL sel2 = sel_registerName("dataTaskWithURL:completionHandler:");
    Method m2 = class_getInstanceMethod(sessionClass, sel2);
    if (m2) {
        orig_dataTaskWithURL_completion = method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hooked_dataTaskWithURL_completion);
        fprintf(stderr, "[sphinx-net] hooked dataTaskWithURL:completionHandler:\n");
    }

    /* Log what NSURLSession methods are available for future hooking */
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(sessionClass, &methodCount);
    int hookable = 0;
    for (unsigned int i = 0; i < methodCount; i++) {
        const char *name = sel_getName(method_getName(methods[i]));
        if (strstr(name, "dataTask") || strstr(name, "uploadTask") ||
            strstr(name, "downloadTask") || strstr(name, "webSocketTask")) {
            hookable++;
        }
    }
    free(methods);
    fprintf(stderr, "[sphinx-net] %d additional task methods available for hooking\n", hookable);

    char data[256];
    snprintf(data, sizeof(data), "\"hooks\":[\"dataTaskWithRequest\",\"dataTaskWithURL\"]");
    sphinx_log(MOD, "init", data);

    fprintf(stderr, "[sphinx-net] ready\n");
}
