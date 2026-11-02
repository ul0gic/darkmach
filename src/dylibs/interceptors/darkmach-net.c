/* Network interceptor: HTTP/HTTPS traffic via NSURLSession delegate hooks. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>

#define MOD "net"

/* Read by darkmach-bridge's net_tap to tell "no traffic" from "nothing watched". */
int darkmach_net_hooks_installed = 0;

static IMP orig_dataTaskWithRequest_completion = NULL;
static IMP orig_dataTaskWithURL_completion = NULL;

static int net_report_request(const char *src, const char *method, const char *url,
                              const char *headers_json,
                              const void *body, size_t body_len) {
    static int (*record)(const char *, const char *, const char *, const char *,
                         const void *, size_t) = NULL;
    if (!record)
        record = (int (*)(const char *, const char *, const char *, const char *,
                          const void *, size_t))
            dlsym(RTLD_DEFAULT, "darkmach_net_record_request");
    return record ? record(src, method, url, headers_json, body, body_len) : 0;
}

static void net_report_response(int req_id, long status, const char *headers_json,
                                const void *body, size_t body_len, const char *error) {
    static void (*record)(int, long, const char *, const void *, size_t,
                          const char *) = NULL;
    if (!record)
        record = (void (*)(int, long, const char *, const void *, size_t, const char *))
            dlsym(RTLD_DEFAULT, "darkmach_net_record_response");
    if (record) record(req_id, status, headers_json, body, body_len, error);
}

/* Response bodies are frequently gzip or protobuf; json_escape passes bytes >= 0x20
 * through verbatim, so raw binary would make the JSONL line invalid UTF-8. */
static void body_to_json(const void *bytes, size_t len, size_t max_len,
                         char *out, size_t outsz) {
    if (!bytes || len == 0) { snprintf(out, outsz, "null"); return; }

    size_t take = len > max_len ? max_len : len;
    const unsigned char *b = (const unsigned char *)bytes;
    for (size_t i = 0; i < take && i < 256; i++) {
        if (b[i] < 0x09 || (b[i] > 0x0d && b[i] < 0x20 && b[i] != 0x1b)) {
            size_t hex = take > 16 ? 16 : take;
            char prefix[48];
            for (size_t j = 0; j < hex; j++) snprintf(prefix + j * 2, 3, "%02x", b[j]);
            prefix[hex * 2] = '\0';
            snprintf(out, outsz, "\"<binary %zu bytes: %s>\"", len, prefix);
            return;
        }
    }

    char raw[8192];
    size_t copy = take < sizeof(raw) - 1 ? take : sizeof(raw) - 1;
    memcpy(raw, bytes, copy);
    raw[copy] = '\0';
    json_escape(raw, out, outsz);
}

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

static int log_request(id request, const char *source) {
    if (!request) return 0;

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

    const void *body_bytes = NULL;
    size_t body_len = 0;
    if (body) {
        SEL lenSel = sel_registerName("length");
        SEL bytesSel = sel_registerName("bytes");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        const void *(*getBytes)(id, SEL) = (const void *(*)(id, SEL))objc_msgSend;

        long len = getLen(body, lenSel);
        const void *bytes = getBytes(body, bytesSel);
        if (bytes && len > 0) {
            body_bytes = bytes;
            body_len = (size_t)len;
        }
    }

    char body_esc[4096];
    body_to_json(body_bytes, body_len, 2048, body_esc, sizeof(body_esc));

    char data[16384];
    snprintf(data, sizeof(data),
             "\"src\":\"%s\",\"method\":%s,\"url\":%s,\"headers\":%s,\"body\":%s",
             source, method_esc, url_esc, headers_json, body_esc);

    darkmach_log(MOD, "request", data);

    fprintf(stderr, "[darkmach-net] %s %s\n", method_c, url_c);

    return net_report_request(source, method_c, url_c, headers_json,
                              body_bytes, body_len);
}

static void log_response(int req_id, id response, id data_obj, id error) {
    long status = 0;
    char headers_json[8192] = "{}";
    char url_esc[4096] = "null";

    if (response) {
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

    const void *body_bytes = NULL;
    size_t body_len = 0;
    if (data_obj) {
        SEL lenSel = sel_registerName("length");
        SEL bytesSel = sel_registerName("bytes");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        const void *(*getBytes)(id, SEL) = (const void *(*)(id, SEL))objc_msgSend;

        long len = getLen(data_obj, lenSel);
        const void *bytes = getBytes(data_obj, bytesSel);
        if (bytes && len > 0) {
            body_bytes = bytes;
            body_len = (size_t)len;
        }
    }

    char body_esc[8192];
    body_to_json(body_bytes, body_len, 4096, body_esc, sizeof(body_esc));

    const char *error_str = error ? nsobject_desc(error) : NULL;
    char error_esc[1024] = "null";
    if (error_str) {
        json_escape(error_str, error_esc, sizeof(error_esc));
    }

    char data[16384];
    snprintf(data, sizeof(data),
             "\"status\":%ld,\"url\":%s,\"headers\":%s,\"body\":%s,\"error\":%s",
             status, url_esc, headers_json, body_esc, error_esc);

    darkmach_log(MOD, "response", data);

    net_report_response(req_id, status, headers_json, body_bytes, body_len, error_str);

    if (status > 0) {
        fprintf(stderr, "[darkmach-net] <- %ld %s\n", status,
                url_esc[0] == '"' ? url_esc+1 : url_esc);
    }
}

static id hooked_dataTaskWithRequest_completion(id self, SEL _cmd,
                                                 id request,
                                                 void (^completion)(id, id, id)) {
    int req_id = log_request(request, "dataTask");

    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            log_response(req_id, response, data_obj, error);
            completion(data_obj, response, error);
        };
    }

    id (*orig)(id, SEL, id, void(^)(id,id,id)) =
        (id (*)(id, SEL, id, void(^)(id,id,id)))orig_dataTaskWithRequest_completion;
    return orig(self, _cmd, request, wrappedCompletion ? wrappedCompletion : completion);
}

static id hooked_dataTaskWithURL_completion(id self, SEL _cmd,
                                             id url,
                                             void (^completion)(id, id, id)) {
    char url_esc[4096];
    SEL absSel = sel_registerName("absoluteString");
    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id urlStr = get(url, absSel);
    json_escape(nsstring_to_c(urlStr), url_esc, sizeof(url_esc));

    char data[4096];
    snprintf(data, sizeof(data),
             "\"src\":\"dataTaskURL\",\"method\":\"GET\",\"url\":%s", url_esc);
    darkmach_log(MOD, "request", data);
    fprintf(stderr, "[darkmach-net] GET %s\n", nsstring_to_c(urlStr));

    int req_id = net_report_request("dataTaskURL", "GET", nsstring_to_c(urlStr),
                                    "{}", NULL, 0);

    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            log_response(req_id, response, data_obj, error);
            completion(data_obj, response, error);
        };
    }

    id (*orig)(id, SEL, id, void(^)(id,id,id)) =
        (id (*)(id, SEL, id, void(^)(id,id,id)))orig_dataTaskWithURL_completion;
    return orig(self, _cmd, url, wrappedCompletion ? wrappedCompletion : completion);
}

__attribute__((constructor))
static void darkmach_net_init(void) {
    fprintf(stderr, "[darkmach-net] initializing network interceptor\n");
    darkmach_log_init(MOD);

    Class sessionClass = objc_getClass("NSURLSession");
    if (!sessionClass) {
        fprintf(stderr, "[darkmach-net] ERROR: NSURLSession class not found\n");
        return;
    }

    SEL sel1 = sel_registerName("dataTaskWithRequest:completionHandler:");
    Method m1 = class_getInstanceMethod(sessionClass, sel1);
    if (m1) {
        orig_dataTaskWithRequest_completion = method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hooked_dataTaskWithRequest_completion);
        darkmach_net_hooks_installed = 1;
        fprintf(stderr, "[darkmach-net] hooked dataTaskWithRequest:completionHandler:\n");
    }

    SEL sel2 = sel_registerName("dataTaskWithURL:completionHandler:");
    Method m2 = class_getInstanceMethod(sessionClass, sel2);
    if (m2) {
        orig_dataTaskWithURL_completion = method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hooked_dataTaskWithURL_completion);
        darkmach_net_hooks_installed = 1;
        fprintf(stderr, "[darkmach-net] hooked dataTaskWithURL:completionHandler:\n");
    }

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
    fprintf(stderr, "[darkmach-net] %d additional task methods available for hooking\n", hookable);

    char data[256];
    snprintf(data, sizeof(data), "\"hooks\":[\"dataTaskWithRequest\",\"dataTaskWithURL\"]");
    darkmach_log(MOD, "init", data);

    fprintf(stderr, "[darkmach-net] ready\n");
}
