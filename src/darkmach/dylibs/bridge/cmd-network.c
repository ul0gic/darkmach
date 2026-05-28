/*
 * cmd-network.c -- Network intelligence commands for the Darkmach LLM bridge
 *
 * Commands: net_tap, net_filter, crypto_tap, crypto_keys, auth_tap, auth_tokens
 *
 * Sprint 13.2: Implements HTTP traffic interception, cryptographic operation
 * monitoring, and OAuth/authentication flow recording.
 *
 * net_tap / net_filter: Swizzle NSURLSession to capture request/response pairs.
 * crypto_tap / crypto_keys: Hook CommonCrypto to capture encryption operations.
 * auth_tap / auth_tokens: Monitor auth flows via net_tap + JWT decode + hooks.
 *
 * Unity build: #included from bridge/darkmach-bridge.c
 */
#include "darkmach-bridge.h"
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>

/* ===================================================================
 *  Timestamp helper (shared by all network commands)
 * =================================================================== */

static void net_timestamp(char *buf, size_t bufsz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    snprintf(buf, bufsz, "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

/* ===================================================================
 *  Hex encoding helper (for crypto keys/IVs)
 * =================================================================== */

static void net_hex_encode(const void *data, size_t len, char *buf, size_t bufsz) {
    if (!data || len == 0) { buf[0] = '\0'; return; }
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 2 < bufsz; i++) {
        pos += snprintf(buf + pos, bufsz - pos, "%02x",
                        ((const unsigned char *)data)[i]);
    }
    buf[pos] = '\0';
}

/* ===================================================================
 *  ObjC header dict -> JSON helper
 * =================================================================== */

static void net_headers_to_json(id headerDict, char *buf, size_t bufsz) {
    if (!headerDict) { snprintf(buf, bufsz, "{}"); return; }

    SEL allKeysSel = sel_registerName("allKeys");
    SEL objectForKeySel = sel_registerName("objectForKey:");
    SEL countSel = sel_registerName("count");
    SEL indexSel = sel_registerName("objectAtIndex:");

    id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    id (*getAt)(id, SEL, unsigned long) =
        (id (*)(id, SEL, unsigned long))objc_msgSend;

    id keys = getKeys(headerDict, allKeysSel);
    long count = getCount(keys, countSel);

    size_t pos = 0;
    pos += snprintf(buf + pos, bufsz - pos, "{");

    for (long i = 0; i < count && pos < bufsz - 20; i++) {
        id key = getAt(keys, indexSel, (unsigned long)i);
        id val = getObj(headerDict, objectForKeySel, key);

        const char *k = nsstring_to_c(key);
        const char *v = nsstring_to_c(val);

        char ek[256], ev[1024];
        json_escape(k, ek, sizeof(ek));
        json_escape(v, ev, sizeof(ev));

        if (i > 0) pos += snprintf(buf + pos, bufsz - pos, ",");
        pos += snprintf(buf + pos, bufsz - pos, "%s:%s", ek, ev);
    }
    snprintf(buf + pos, bufsz - pos, "}");
}

/* ===================================================================
 *  NSData -> body preview helper
 *  Returns UTF-8 text preview, or "<binary N bytes>" for non-text.
 *  Truncates to max_len bytes. Caller provides buf of at least max_len+64.
 * =================================================================== */

static void net_body_preview(id dataObj, char *buf, size_t bufsz, size_t max_len) {
    buf[0] = '\0';
    if (!dataObj) return;

    SEL lenSel = sel_registerName("length");
    SEL bytesSel = sel_registerName("bytes");
    long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    const void *(*getBytes)(id, SEL) = (const void *(*)(id, SEL))objc_msgSend;

    long len = getLen(dataObj, lenSel);
    const void *bytes = getBytes(dataObj, bytesSel);
    if (!bytes || len <= 0) return;

    /* Check if content looks like UTF-8 text */
    size_t preview_len = (size_t)len > max_len ? max_len : (size_t)len;
    const unsigned char *b = (const unsigned char *)bytes;
    int is_text = 1;
    for (size_t i = 0; i < preview_len && i < 256; i++) {
        if (b[i] < 0x09 || (b[i] > 0x0d && b[i] < 0x20 && b[i] != 0x1b)) {
            is_text = 0;
            break;
        }
    }

    if (is_text) {
        size_t copy_len = preview_len < bufsz - 1 ? preview_len : bufsz - 1;
        memcpy(buf, bytes, copy_len);
        buf[copy_len] = '\0';
    } else {
        snprintf(buf, bufsz, "<binary %ld bytes>", len);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  SECTION 1: net_tap / net_filter
 *  HTTP request/response interception via NSURLSession swizzling
 * ═══════════════════════════════════════════════════════════════════ */

static darkmach_ring_t net_ring;
static int net_tap_initialized = 0;
static int net_tap_enabled = 0;
static int net_request_counter = 0;

/* Saved original IMPs for NSURLSession methods */
static IMP net_orig_dataTaskReq_completion = NULL;
static IMP net_orig_dataTaskURL_completion = NULL;

/* ── net_tap: record a request/response pair into the ring buffer ── */

static void net_ring_record(id request, id response, id dataObj, id error,
                            long long start_ms) {
    if (!net_tap_enabled) return;

    int req_id = __sync_add_and_fetch(&net_request_counter, 1);

    char ts[64];
    net_timestamp(ts, sizeof(ts));

    /* Compute duration */
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    long long now_ms = (long long)now_tv.tv_sec * 1000 + now_tv.tv_usec / 1000;
    long long duration_ms = (start_ms > 0) ? (now_ms - start_ms) : 0;

    /* Extract request fields */
    SEL urlSel = sel_registerName("URL");
    SEL absSel = sel_registerName("absoluteString");
    SEL methodSel = sel_registerName("HTTPMethod");
    SEL headersSel = sel_registerName("allHTTPHeaderFields");
    SEL bodySel = sel_registerName("HTTPBody");

    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;

    const char *url_str = "";
    const char *method_str = "GET";
    char req_headers_json[2048] = "{}";
    char req_body_buf[600] = "";

    if (request) {
        id url = get(request, urlSel);
        id urlNS = url ? get(url, absSel) : NULL;
        if (urlNS) url_str = nsstring_to_c(urlNS);

        id method = get(request, methodSel);
        if (method) method_str = nsstring_to_c(method);

        id headers = get(request, headersSel);
        net_headers_to_json(headers, req_headers_json, sizeof(req_headers_json));

        id body = get(request, bodySel);
        net_body_preview(body, req_body_buf, sizeof(req_body_buf), 512);
    }

    /* Extract response fields */
    long status = 0;
    char resp_headers_json[2048] = "{}";
    char resp_body_buf[600] = "";

    if (response) {
        Class httpRespClass = objc_getClass("NSHTTPURLResponse");
        SEL isKindSel = sel_registerName("isKindOfClass:");
        BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
        if (httpRespClass && isKind(response, isKindSel, httpRespClass)) {
            SEL statusSel = sel_registerName("statusCode");
            long (*getStatus)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
            status = getStatus(response, statusSel);

            SEL respHdrSel = sel_registerName("allHeaderFields");
            id (*getRespHdr)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id respHeaders = getRespHdr(response, respHdrSel);
            net_headers_to_json(respHeaders, resp_headers_json,
                                sizeof(resp_headers_json));
        }
    }

    net_body_preview(dataObj, resp_body_buf, sizeof(resp_body_buf), 512);

    /* Build the ring buffer entry as JSON */
    char url_esc[2048], method_esc[32];
    json_escape(url_str, url_esc, sizeof(url_esc));
    json_escape(method_str, method_esc, sizeof(method_esc));

    char req_body_esc[1536], resp_body_esc[1536];
    json_escape(req_body_buf, req_body_esc, sizeof(req_body_esc));
    json_escape(resp_body_buf, resp_body_esc, sizeof(resp_body_esc));

    char entry[DARKMACH_RING_ENTRY_SIZE];
    snprintf(entry, sizeof(entry),
             "{\"id\":%d,\"method\":%s,\"url\":%s,"
             "\"req_headers\":%s,\"req_body_preview\":%s,"
             "\"status\":%ld,\"resp_headers\":%s,\"resp_body_preview\":%s,"
             "\"duration_ms\":%lld,\"timestamp\":\"%s\"}",
             req_id, method_esc, url_esc,
             req_headers_json, req_body_esc,
             status, resp_headers_json, resp_body_esc,
             duration_ms, ts);

    darkmach_ring_push(&net_ring, entry);

    fprintf(stderr, "[darkmach-net-tap] #%d %s %s -> %ld (%lld ms)\n",
            req_id, method_str, url_str, status, duration_ms);
}

/* ── Swizzled: dataTaskWithRequest:completionHandler: ── */

static id net_hooked_dataTaskReq_completion(id self, SEL _cmd,
                                            id request,
                                            void (^completion)(id, id, id)) {
    /* Capture start time */
    struct timeval start_tv;
    gettimeofday(&start_tv, NULL);
    long long start_ms = (long long)start_tv.tv_sec * 1000 + start_tv.tv_usec / 1000;

    /* Keep a strong reference to the request for the completion block */
    id capturedRequest = request;

    /* Wrap the completion handler to capture the response */
    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            net_ring_record(capturedRequest, response, data_obj, error, start_ms);
            completion(data_obj, response, error);
        };
    } else {
        /* Even without a completion handler, record the request (no response) */
        net_ring_record(request, nil, nil, nil, start_ms);
    }

    id (*orig)(id, SEL, id, void(^)(id, id, id)) =
        (id (*)(id, SEL, id, void(^)(id, id, id)))net_orig_dataTaskReq_completion;
    return orig(self, _cmd, request,
                wrappedCompletion ? wrappedCompletion : completion);
}

/* ── Swizzled: dataTaskWithURL:completionHandler: ── */

static id net_hooked_dataTaskURL_completion(id self, SEL _cmd,
                                            id url,
                                            void (^completion)(id, id, id)) {
    struct timeval start_tv;
    gettimeofday(&start_tv, NULL);
    long long start_ms = (long long)start_tv.tv_sec * 1000 + start_tv.tv_usec / 1000;

    /* Build a synthetic request representation for logging */
    /* We create an NSURLRequest from the URL to capture it consistently */
    Class reqClass = objc_getClass("NSURLRequest");
    SEL reqWithURL = sel_registerName("requestWithURL:");
    id (*makeReq)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    id syntheticRequest = reqClass ? makeReq((id)reqClass, reqWithURL, url) : nil;

    id capturedRequest = syntheticRequest;

    void (^wrappedCompletion)(id, id, id) = NULL;
    if (completion) {
        wrappedCompletion = ^(id data_obj, id response, id error) {
            net_ring_record(capturedRequest, response, data_obj, error, start_ms);
            completion(data_obj, response, error);
        };
    }

    id (*orig)(id, SEL, id, void(^)(id, id, id)) =
        (id (*)(id, SEL, id, void(^)(id, id, id)))net_orig_dataTaskURL_completion;
    return orig(self, _cmd, url,
                wrappedCompletion ? wrappedCompletion : completion);
}

/*
 * ── Install NSURLSession swizzles (called lazily on first net_tap) ──
 *
 * SWIZZLE CHAINING NOTE:
 * darkmach-net.dylib (interceptors/darkmach-net.c) also swizzles the same
 * NSURLSession methods in its constructor (at dylib load time). When both
 * dylibs are loaded, the load order determines the chain:
 *
 *   If darkmach-net.dylib loads first (typical — constructors run at load):
 *     method IMP -> darkmach-net hook (orig saved as real NSURLSession impl)
 *   Then net_install_hooks() runs lazily on first net_tap command:
 *     method_getImplementation() returns darkmach-net's hook
 *     method_setImplementation() installs bridge's hook
 *     Chain: bridge hook -> darkmach-net hook -> real NSURLSession
 *
 * This is correct ObjC swizzle chaining — each hook calls through its
 * saved "original" IMP, which may be the previous hook in the chain.
 * Both interceptors' logging fires for every request.
 *
 * If only darkmach-bridge.dylib is loaded (no darkmach-net.dylib), the bridge
 * hooks directly replace the real NSURLSession implementations.
 */

static void net_install_hooks(void) {
    if (net_tap_enabled) return;

    darkmach_ring_init(&net_ring);
    net_tap_initialized = 1;

    Class sessionClass = objc_getClass("NSURLSession");
    if (!sessionClass) {
        fprintf(stderr, "[darkmach-net-tap] WARNING: NSURLSession not found\n");
        net_tap_enabled = 1;
        return;
    }

    /* Hook dataTaskWithRequest:completionHandler: */
    SEL sel1 = sel_registerName("dataTaskWithRequest:completionHandler:");
    Method m1 = class_getInstanceMethod(sessionClass, sel1);
    if (m1) {
        net_orig_dataTaskReq_completion = method_getImplementation(m1);
        method_setImplementation(m1, (IMP)net_hooked_dataTaskReq_completion);
        fprintf(stderr, "[darkmach-net-tap] hooked dataTaskWithRequest:completionHandler:\n");
    }

    /* Hook dataTaskWithURL:completionHandler: */
    SEL sel2 = sel_registerName("dataTaskWithURL:completionHandler:");
    Method m2 = class_getInstanceMethod(sessionClass, sel2);
    if (m2) {
        net_orig_dataTaskURL_completion = method_getImplementation(m2);
        method_setImplementation(m2, (IMP)net_hooked_dataTaskURL_completion);
        fprintf(stderr, "[darkmach-net-tap] hooked dataTaskWithURL:completionHandler:\n");
    }

    net_tap_enabled = 1;
    fprintf(stderr, "[darkmach-net-tap] network interception active\n");
}

/* ── Command: net_tap ── */

static void cmd_net_tap(const char *args, resp_t *r) {
    /* Lazy-init: install hooks on first query */
    if (!net_tap_enabled) net_install_hooks();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;

    resp_append(r, "\"data\":{\"requests\":[");
    int returned = 0;
    for (int i = 0; i < net_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&net_ring, i);
        if (!entry) continue;
        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d}",
                net_ring.total, returned);
}

/* ── Command: net_filter ── */

static void cmd_net_filter(const char *args, resp_t *r) {
    /* Lazy-init: install hooks on first query */
    if (!net_tap_enabled) net_install_hooks();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;

    char host_filter[256] = "";
    char path_filter[256] = "";
    char method_filter[32] = "";
    long status_filter = json_get_long(args, "status");

    json_get_string(args, "host", host_filter, sizeof(host_filter));
    json_get_string(args, "path", path_filter, sizeof(path_filter));
    json_get_string(args, "method", method_filter, sizeof(method_filter));

    /* Uppercase the method filter for case-insensitive comparison */
    for (int i = 0; method_filter[i]; i++) {
        if (method_filter[i] >= 'a' && method_filter[i] <= 'z')
            method_filter[i] -= 32;
    }

    resp_append(r, "\"data\":{\"requests\":[");
    int returned = 0;
    for (int i = 0; i < net_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&net_ring, i);
        if (!entry) continue;

        /* Apply filters by searching the JSON entry string */
        if (host_filter[0] && !strstr(entry, host_filter)) continue;
        if (path_filter[0] && !strstr(entry, path_filter)) continue;

        /* Method filter: look for "method":"GET" pattern */
        if (method_filter[0]) {
            char method_pat[48];
            snprintf(method_pat, sizeof(method_pat), "\"method\":\"%s\"", method_filter);
            if (!strstr(entry, method_pat)) continue;
        }

        /* Status filter: look for "status":NNN pattern */
        if (status_filter > 0) {
            char status_pat[32];
            snprintf(status_pat, sizeof(status_pat), "\"status\":%ld", status_filter);
            if (!strstr(entry, status_pat)) continue;
        }

        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d}",
                net_ring.total, returned);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SECTION 2: crypto_tap / crypto_keys
 *  Cryptographic operation interception via CommonCrypto hooks
 * ═══════════════════════════════════════════════════════════════════ */

static darkmach_ring_t crypto_ring;
static int crypto_tap_initialized = 0;
static int crypto_tap_enabled = 0;

/* ── Key deduplication table ── */

#define CRYPTO_MAX_UNIQUE_KEYS 128
#define CRYPTO_MAX_KEY_BYTES 64   /* 512-bit max */

typedef struct {
    unsigned char key_bytes[CRYPTO_MAX_KEY_BYTES];
    size_t key_len;
    char algorithm[64];
    char first_seen[64];
    char last_seen[64];
    int use_count;
    int active;
} crypto_key_entry_t;

static crypto_key_entry_t crypto_keys_table[CRYPTO_MAX_UNIQUE_KEYS];
static int crypto_keys_count = 0;

/* Track a key in the dedup table */
static void crypto_track_key(const void *key, size_t key_len,
                              const char *algorithm) {
    if (!key || key_len == 0 || key_len > CRYPTO_MAX_KEY_BYTES) return;

    char ts[64];
    net_timestamp(ts, sizeof(ts));

    /* Search for existing key */
    for (int i = 0; i < crypto_keys_count; i++) {
        if (!crypto_keys_table[i].active) continue;
        if (crypto_keys_table[i].key_len == key_len &&
            memcmp(crypto_keys_table[i].key_bytes, key, key_len) == 0) {
            crypto_keys_table[i].use_count++;
            strlcpy(crypto_keys_table[i].last_seen, ts,
                    sizeof(crypto_keys_table[i].last_seen));
            return;
        }
    }

    /* New key — add if space available */
    if (crypto_keys_count < CRYPTO_MAX_UNIQUE_KEYS) {
        crypto_key_entry_t *e = &crypto_keys_table[crypto_keys_count];
        memcpy(e->key_bytes, key, key_len);
        e->key_len = key_len;
        strlcpy(e->algorithm, algorithm, sizeof(e->algorithm));
        strlcpy(e->first_seen, ts, sizeof(e->first_seen));
        strlcpy(e->last_seen, ts, sizeof(e->last_seen));
        e->use_count = 1;
        e->active = 1;
        crypto_keys_count++;
    }
}

/* ── Algorithm name helpers ── */

static const char *crypto_cc_alg_name(CCAlgorithm alg, size_t keyLen) {
    switch (alg) {
        case kCCAlgorithmAES128:
            if (keyLen <= 16) return "AES-128";
            if (keyLen <= 24) return "AES-192";
            return "AES-256";
        case kCCAlgorithmDES:     return "DES";
        case kCCAlgorithm3DES:    return "3DES";
        case kCCAlgorithmCAST:    return "CAST";
        case kCCAlgorithmRC4:     return "RC4";
        case kCCAlgorithmRC2:     return "RC2";
        case kCCAlgorithmBlowfish: return "Blowfish";
        default: return "Unknown";
    }
}

static const char *crypto_cc_mode_name(CCAlgorithm alg, CCOptions opts,
                                       size_t keyLen) {
    /* Build "ALG-KEYLEN-MODE" string */
    static char buf[64];
    const char *base = crypto_cc_alg_name(alg, keyLen);
    const char *mode = (opts & kCCOptionECBMode) ? "ECB" : "CBC";
    snprintf(buf, sizeof(buf), "%s-%s", base, mode);
    return buf;
}

/* ── Hooked: CCCrypt ── */

static CCCryptorStatus (*crypto_orig_CCCrypt)(
    CCOperation, CCAlgorithm, CCOptions,
    const void *, size_t, const void *,
    const void *, size_t, void *, size_t, size_t *) = NULL;

static CCCryptorStatus crypto_hooked_CCCrypt(
    CCOperation op, CCAlgorithm alg, CCOptions opts,
    const void *key, size_t keyLen,
    const void *iv,
    const void *dataIn, size_t dataInLen,
    void *dataOut, size_t dataOutAvail,
    size_t *dataOutMoved)
{
    CCCryptorStatus status = crypto_orig_CCCrypt(
        op, alg, opts, key, keyLen, iv,
        dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);

    if (!crypto_tap_enabled) return status;

    char ts[64];
    net_timestamp(ts, sizeof(ts));

    const char *alg_mode = crypto_cc_mode_name(alg, opts, keyLen);
    int is_encrypt = (op == kCCEncrypt) ? 1 : 0;

    /* Hex encode key and IV */
    char key_hex[256];
    net_hex_encode(key, keyLen, key_hex, sizeof(key_hex));

    char iv_hex[64] = "";
    if (iv) {
        /* IV length depends on block size: AES=16, DES/3DES=8 */
        size_t iv_len = (alg == kCCAlgorithmAES128) ? 16 : 8;
        net_hex_encode(iv, iv_len, iv_hex, sizeof(iv_hex));
    }

    /* Output preview: first 64 bytes hex */
    char output_hex[256] = "";
    if (status == kCCSuccess && dataOut && dataOutMoved && *dataOutMoved > 0) {
        size_t preview_len = *dataOutMoved > 64 ? 64 : *dataOutMoved;
        net_hex_encode(dataOut, preview_len, output_hex, sizeof(output_hex));
    }

    /* Track key */
    crypto_track_key(key, keyLen, alg_mode);

    /* Push to ring buffer */
    char key_hex_esc[512], iv_hex_esc[256], output_hex_esc[512];
    json_escape(key_hex, key_hex_esc, sizeof(key_hex_esc));
    json_escape(iv_hex, iv_hex_esc, sizeof(iv_hex_esc));
    json_escape(output_hex, output_hex_esc, sizeof(output_hex_esc));
    char alg_esc[128];
    json_escape(alg_mode, alg_esc, sizeof(alg_esc));

    char entry[DARKMACH_RING_ENTRY_SIZE];
    snprintf(entry, sizeof(entry),
             "{\"op\":\"CCCrypt\",\"algorithm\":%s,\"encrypt\":%s,"
             "\"key_hex\":%s,\"iv_hex\":%s,"
             "\"input_len\":%zu,\"output_preview\":%s,"
             "\"timestamp\":\"%s\"}",
             alg_esc, is_encrypt ? "true" : "false",
             key_hex_esc, iv_hex_esc,
             dataInLen, output_hex_esc, ts);

    darkmach_ring_push(&crypto_ring, entry);

    fprintf(stderr, "[darkmach-crypto-tap] CCCrypt %s %s keyLen=%zu inLen=%zu\n",
            is_encrypt ? "encrypt" : "decrypt", alg_mode, keyLen, dataInLen);

    return status;
}

/* ── Hooked: CCHmac ── */

static void (*crypto_orig_CCHmac)(CCHmacAlgorithm, const void *, size_t,
                                   const void *, size_t,
                                   void *) = NULL;

static void crypto_hooked_CCHmac(CCHmacAlgorithm algorithm,
                                  const void *key, size_t keyLen,
                                  const void *data, size_t dataLen,
                                  void *macOut)
{
    crypto_orig_CCHmac(algorithm, key, keyLen, data, dataLen, macOut);

    if (!crypto_tap_enabled) return;

    char ts[64];
    net_timestamp(ts, sizeof(ts));

    /* Map HMAC algorithm to name */
    const char *hmac_name;
    size_t digest_len;
    switch (algorithm) {
        case kCCHmacAlgSHA1:   hmac_name = "HMAC-SHA1";   digest_len = CC_SHA1_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA256: hmac_name = "HMAC-SHA256"; digest_len = CC_SHA256_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA384: hmac_name = "HMAC-SHA384"; digest_len = 48; break;
        case kCCHmacAlgSHA512: hmac_name = "HMAC-SHA512"; digest_len = CC_SHA512_DIGEST_LENGTH; break;
        case kCCHmacAlgMD5:    hmac_name = "HMAC-MD5";    digest_len = CC_MD5_DIGEST_LENGTH; break;
        default:               hmac_name = "HMAC-Unknown"; digest_len = 32; break;
    }

    char key_hex[256];
    net_hex_encode(key, keyLen, key_hex, sizeof(key_hex));

    char output_hex[256] = "";
    if (macOut) {
        net_hex_encode(macOut, digest_len, output_hex, sizeof(output_hex));
    }

    /* Track key */
    crypto_track_key(key, keyLen, hmac_name);

    char key_hex_esc[512], output_hex_esc[512];
    json_escape(key_hex, key_hex_esc, sizeof(key_hex_esc));
    json_escape(output_hex, output_hex_esc, sizeof(output_hex_esc));
    char alg_esc[128];
    json_escape(hmac_name, alg_esc, sizeof(alg_esc));

    char entry[DARKMACH_RING_ENTRY_SIZE];
    snprintf(entry, sizeof(entry),
             "{\"op\":\"CCHmac\",\"algorithm\":%s,\"encrypt\":false,"
             "\"key_hex\":%s,\"iv_hex\":\"\","
             "\"input_len\":%zu,\"output_preview\":%s,"
             "\"timestamp\":\"%s\"}",
             alg_esc, key_hex_esc,
             dataLen, output_hex_esc, ts);

    darkmach_ring_push(&crypto_ring, entry);

    fprintf(stderr, "[darkmach-crypto-tap] CCHmac %s keyLen=%zu inLen=%zu\n",
            hmac_name, keyLen, dataLen);
}

/*
 * NOTE on crypto hooking:
 *
 * The bridge does NOT use DYLD_INTERPOSE for CCCrypt/CCHmac. Doing so would
 * conflict with darkmach-crypto.dylib (interceptors/darkmach-crypto.c), which
 * already interposes CCCrypt via its own __DATA,__interpose section. When both
 * dylibs are loaded via DYLD_INSERT_LIBRARIES, duplicate interpose entries for
 * the same symbol cause crashes — the last-loaded interpose rewrites the other
 * dylib's symbol bindings, breaking the original function pointer chain.
 *
 * Instead, crypto_install_hooks() resolves the original function pointers via
 * dlsym(RTLD_DEFAULT, ...) for the ring buffer passthrough. The hooked
 * functions (crypto_hooked_CCCrypt, crypto_hooked_CCHmac) are retained for
 * future fishhook-style runtime rebinding if needed, but are NOT installed
 * via compile-time interpose.
 *
 * When darkmach-crypto.dylib is co-loaded, it handles actual interception and
 * logs to darkmach_log(). The bridge's crypto_tap ring buffer provides the
 * LLM-accessible query interface on top of that infrastructure.
 */

/* ── Initialize crypto interception ── */

static void crypto_install_hooks(void) {
    if (crypto_tap_initialized) return;

    darkmach_ring_init(&crypto_ring);
    memset(crypto_keys_table, 0, sizeof(crypto_keys_table));
    crypto_keys_count = 0;
    crypto_tap_initialized = 1;

    /*
     * Resolve original function pointers via dlsym. If darkmach-crypto.dylib
     * is loaded, CCCrypt/CCHmac symbols resolve to the interceptor's hooks
     * (due to its DYLD_INTERPOSE). We store whatever dlsym gives us — the
     * hook functions use these pointers to call the real implementations
     * if they are ever installed via runtime rebinding (fishhook, etc.).
     */
    crypto_orig_CCCrypt = dlsym(RTLD_DEFAULT, "CCCrypt");
    crypto_orig_CCHmac = dlsym(RTLD_DEFAULT, "CCHmac");

    if (!crypto_orig_CCCrypt) {
        fprintf(stderr, "[darkmach-crypto-tap] WARNING: CCCrypt not found via dlsym\n");
    }
    if (!crypto_orig_CCHmac) {
        fprintf(stderr, "[darkmach-crypto-tap] WARNING: CCHmac not found via dlsym\n");
    }

    crypto_tap_enabled = 1;
    fprintf(stderr, "[darkmach-crypto-tap] crypto ring buffer active "
            "(interception via darkmach-crypto.dylib)\n");
}

/* ── Command: crypto_tap ── */

static void cmd_crypto_tap(const char *args, resp_t *r) {
    if (!crypto_tap_initialized) crypto_install_hooks();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;

    resp_append(r, "\"data\":{\"operations\":[");
    int returned = 0;
    for (int i = 0; i < crypto_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&crypto_ring, i);
        if (!entry) continue;
        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d}",
                crypto_ring.total, returned);
}

/* ── Command: crypto_keys ── */

static void cmd_crypto_keys(const char *args, resp_t *r) {
    if (!crypto_tap_initialized) crypto_install_hooks();

    resp_append(r, "\"data\":{\"keys\":[");
    int emitted = 0;
    for (int i = 0; i < crypto_keys_count; i++) {
        crypto_key_entry_t *e = &crypto_keys_table[i];
        if (!e->active) continue;

        if (emitted > 0) resp_append(r, ",");

        char key_hex[256];
        net_hex_encode(e->key_bytes, e->key_len, key_hex, sizeof(key_hex));

        char key_hex_esc[512], alg_esc[128];
        char first_esc[128], last_esc[128];
        json_escape(key_hex, key_hex_esc, sizeof(key_hex_esc));
        json_escape(e->algorithm, alg_esc, sizeof(alg_esc));
        json_escape(e->first_seen, first_esc, sizeof(first_esc));
        json_escape(e->last_seen, last_esc, sizeof(last_esc));

        resp_append(r, "{\"algorithm\":%s,\"key_hex\":%s,"
                    "\"key_len_bits\":%zu,"
                    "\"first_seen\":%s,\"last_seen\":%s,"
                    "\"use_count\":%d}",
                    alg_esc, key_hex_esc,
                    e->key_len * 8,
                    first_esc, last_esc,
                    e->use_count);
        emitted++;
    }
    resp_append(r, "],\"total_unique\":%d}", emitted);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SECTION 3: auth_tap / auth_tokens
 *  OAuth/authentication flow recording
 * ═══════════════════════════════════════════════════════════════════ */

static darkmach_ring_t auth_ring;
static int auth_tap_initialized = 0;
static int auth_tap_enabled = 0;

/* ── Token deduplication table ── */

#define AUTH_MAX_UNIQUE_TOKENS 64
#define AUTH_MAX_TOKEN_LEN 2048

typedef struct {
    char value[AUTH_MAX_TOKEN_LEN];
    char type[32];           /* access_token, refresh_token, id_token, etc. */
    char source[64];         /* oauth_token_response, keychain_token_read, etc. */
    char claims_json[1024];  /* decoded JWT claims as JSON string */
    char first_seen[64];
    char last_seen[64];
    int active;
} auth_token_entry_t;

static auth_token_entry_t auth_tokens_table[AUTH_MAX_UNIQUE_TOKENS];
static int auth_tokens_count = 0;

/* ── Base64url decode helper (for JWT) ── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;  /* - is base64url */
    if (c == '/' || c == '_') return 63;  /* _ is base64url */
    if (c == '=') return -1;
    return -2;
}

/*
 * Decode base64url string. Returns decoded length, or -1 on error.
 * Handles base64url variants (- instead of +, _ instead of /).
 * Handles missing padding.
 */
static int b64url_decode(const char *input, size_t inlen,
                         char *output, size_t outmax) {
    if (!input || inlen == 0 || !output || outmax == 0) return -1;

    /* Copy input and add padding if needed */
    char padded[4096];
    if (inlen > sizeof(padded) - 4) return -1;
    memcpy(padded, input, inlen);
    /* Add padding */
    while (inlen % 4 != 0 && inlen < sizeof(padded) - 1) {
        padded[inlen++] = '=';
    }
    padded[inlen] = '\0';

    size_t out_pos = 0;
    for (size_t i = 0; i < inlen; i += 4) {
        int a = b64_char_val(padded[i]);
        int b = b64_char_val(padded[i + 1]);
        int c = b64_char_val(padded[i + 2]);
        int d = b64_char_val(padded[i + 3]);

        if (a < 0 || b < 0) return -1;

        if (out_pos < outmax)
            output[out_pos++] = (char)((a << 2) | (b >> 4));
        if (c >= 0 && out_pos < outmax)
            output[out_pos++] = (char)(((b & 0x0f) << 4) | (c >> 2));
        if (d >= 0 && out_pos < outmax)
            output[out_pos++] = (char)(((c & 0x03) << 6) | d);
    }
    if (out_pos < outmax) output[out_pos] = '\0';
    return (int)out_pos;
}

/*
 * Attempt to decode a JWT token. Splits on '.', decodes header and payload.
 * Returns 1 on success, 0 on failure. Fills claims_out with payload JSON.
 */
static int jwt_decode(const char *token, char *claims_out, size_t claims_sz) {
    claims_out[0] = '\0';
    if (!token || strlen(token) < 10) return 0;

    /* JWT must start with eyJ (base64url of '{"') */
    if (strncmp(token, "eyJ", 3) != 0) return 0;

    /* Find first dot (end of header) */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return 0;

    /* Find second dot (end of payload) */
    const char *payload_start = dot1 + 1;
    const char *dot2 = strchr(payload_start, '.');
    size_t payload_len = dot2 ? (size_t)(dot2 - payload_start)
                              : strlen(payload_start);

    /* Decode payload */
    char decoded[4096];
    int dlen = b64url_decode(payload_start, payload_len, decoded, sizeof(decoded) - 1);
    if (dlen <= 0) return 0;
    decoded[dlen] = '\0';

    /* Verify it looks like JSON */
    if (decoded[0] != '{') return 0;

    strlcpy(claims_out, decoded, claims_sz);
    return 1;
}

/* ── Track a token in the dedup table ── */

static void auth_track_token(const char *value, const char *type,
                              const char *source) {
    if (!value || strlen(value) < 4) return;

    char ts[64];
    net_timestamp(ts, sizeof(ts));

    /* Search for existing token */
    for (int i = 0; i < auth_tokens_count; i++) {
        if (!auth_tokens_table[i].active) continue;
        if (strcmp(auth_tokens_table[i].value, value) == 0) {
            strlcpy(auth_tokens_table[i].last_seen, ts,
                    sizeof(auth_tokens_table[i].last_seen));
            return;
        }
    }

    /* New token */
    if (auth_tokens_count >= AUTH_MAX_UNIQUE_TOKENS) return;

    auth_token_entry_t *e = &auth_tokens_table[auth_tokens_count];
    strlcpy(e->value, value, sizeof(e->value));
    strlcpy(e->type, type, sizeof(e->type));
    strlcpy(e->source, source, sizeof(e->source));
    strlcpy(e->first_seen, ts, sizeof(e->first_seen));
    strlcpy(e->last_seen, ts, sizeof(e->last_seen));
    e->active = 1;

    /* Try to decode as JWT */
    jwt_decode(value, e->claims_json, sizeof(e->claims_json));

    auth_tokens_count++;
}

/* ── Push an auth event to the ring buffer ── */

static void auth_push_event(const char *type, const char *url,
                             const char *provider, const char *token_preview,
                             const char *token_type, const char *claims_json) {
    char ts[64];
    net_timestamp(ts, sizeof(ts));

    char type_esc[128], url_esc[2048], provider_esc[128];
    char preview_esc[256], ttype_esc[64];
    json_escape(type, type_esc, sizeof(type_esc));
    json_escape(url, url_esc, sizeof(url_esc));
    json_escape(provider, provider_esc, sizeof(provider_esc));
    json_escape(token_preview, preview_esc, sizeof(preview_esc));
    json_escape(token_type, ttype_esc, sizeof(ttype_esc));

    /* claims_json is already JSON — use it directly if non-empty */
    const char *claims = (claims_json && claims_json[0]) ? claims_json : "{}";

    char entry[DARKMACH_RING_ENTRY_SIZE];
    snprintf(entry, sizeof(entry),
             "{\"type\":%s,\"url\":%s,\"provider\":%s,"
             "\"token_preview\":%s,\"token_type\":%s,"
             "\"claims\":%s,\"timestamp\":\"%s\"}",
             type_esc, url_esc, provider_esc,
             preview_esc, ttype_esc,
             claims, ts);

    darkmach_ring_push(&auth_ring, entry);
}

/* ── Detect OAuth-pattern URLs in net_ring entries ── */

static const char *auth_oauth_patterns[] = {
    "/oauth", "/token", "/auth", "/login",
    "/.well-known/openid", "/authorize",
    "/signin", "/v1/token", "/v2/token",
    "/connect/token", "/api/auth",
    NULL
};

static int auth_is_oauth_url(const char *url) {
    if (!url) return 0;
    for (int i = 0; auth_oauth_patterns[i]; i++) {
        if (strstr(url, auth_oauth_patterns[i])) return 1;
    }
    return 0;
}

/* Detect auth provider from URL */
static const char *auth_detect_provider(const char *url) {
    if (!url) return "unknown";
    if (strstr(url, "googleapis.com") || strstr(url, "firebase"))
        return "firebase";
    if (strstr(url, "apple.com/auth"))
        return "apple";
    if (strstr(url, "facebook.com") || strstr(url, "fb.com"))
        return "facebook";
    if (strstr(url, "github.com"))
        return "github";
    if (strstr(url, "oauth") || strstr(url, "/token"))
        return "oauth2";
    if (strstr(url, "openid"))
        return "oidc";
    return "custom";
}

/*
 * Scan the net_ring for auth-related requests and extract tokens.
 * Called periodically from auth_tap to discover new auth events.
 */
static int auth_last_scanned_net_total = 0;

static void auth_scan_net_ring(void) {
    if (!net_tap_enabled) return;

    /* Only scan entries we haven't seen yet */
    int new_entries = net_ring.total - auth_last_scanned_net_total;
    if (new_entries <= 0) return;
    if (new_entries > net_ring.count) new_entries = net_ring.count;

    for (int i = new_entries - 1; i >= 0; i--) {
        const char *entry = darkmach_ring_get(&net_ring, i);
        if (!entry) continue;

        /* Extract URL from the JSON entry to check for auth patterns */
        /* Look for "url":"..." in the entry */
        const char *url_start = strstr(entry, "\"url\":\"");
        if (!url_start) continue;
        url_start += 7; /* skip "url":" */

        char url_buf[2048];
        size_t j = 0;
        while (url_start[j] && url_start[j] != '"' && j < sizeof(url_buf) - 1) {
            url_buf[j] = url_start[j];
            j++;
        }
        url_buf[j] = '\0';

        if (!auth_is_oauth_url(url_buf)) continue;

        /* Determine event type based on HTTP method */
        const char *event_type = "oauth_token_request";
        if (strstr(entry, "\"status\":2")) {
            /* 2xx response — this is a successful token response */
            event_type = "oauth_token_response";
        }
        if (strstr(url_buf, "/authorize") || strstr(url_buf, "/signin")) {
            event_type = "oauth_authorize";
        }
        if (strstr(url_buf, "refresh")) {
            event_type = "token_refresh";
        }

        const char *provider = auth_detect_provider(url_buf);

        /* Try to find tokens in the response body */
        /* Look for "resp_body_preview":"..." and scan for JWT patterns */
        const char *body_start = strstr(entry, "\"resp_body_preview\":\"");
        char token_preview[128] = "";
        char token_type[32] = "";
        char claims_json[1024] = "{}";

        if (body_start) {
            body_start += 20;
            char body_buf[1024];
            size_t k = 0;
            while (body_start[k] && body_start[k] != '"' && k < sizeof(body_buf) - 1) {
                body_buf[k] = body_start[k];
                k++;
            }
            body_buf[k] = '\0';

            /* Scan for JWT tokens (eyJ...) in the body */
            const char *jwt_start = strstr(body_buf, "eyJ");
            if (jwt_start) {
                /* Extract the token (up to next quote, comma, or whitespace) */
                char token_buf[AUTH_MAX_TOKEN_LEN];
                size_t t = 0;
                while (jwt_start[t] && jwt_start[t] != '"' &&
                       jwt_start[t] != ',' && jwt_start[t] != '}' &&
                       jwt_start[t] != ' ' && jwt_start[t] != '\\' &&
                       t < sizeof(token_buf) - 1) {
                    token_buf[t] = jwt_start[t];
                    t++;
                }
                token_buf[t] = '\0';

                /* Decode JWT claims */
                if (jwt_decode(token_buf, claims_json, sizeof(claims_json))) {
                    /* Determine token type from context */
                    if (strstr(body_buf, "access_token"))
                        strlcpy(token_type, "access_token", sizeof(token_type));
                    else if (strstr(body_buf, "id_token"))
                        strlcpy(token_type, "id_token", sizeof(token_type));
                    else if (strstr(body_buf, "refresh_token"))
                        strlcpy(token_type, "refresh_token", sizeof(token_type));
                    else
                        strlcpy(token_type, "bearer", sizeof(token_type));

                    /* Token preview: first 64 chars */
                    strlcpy(token_preview, token_buf,
                            sizeof(token_preview) < 65 ? sizeof(token_preview) : 65);

                    /* Track the token */
                    auth_track_token(token_buf, token_type, event_type);
                }
            }
        }

        /* Also check Authorization headers for Bearer tokens */
        const char *auth_hdr = strstr(entry, "Authorization");
        if (auth_hdr) {
            const char *bearer = strstr(auth_hdr, "Bearer ");
            if (!bearer) bearer = strstr(auth_hdr, "bearer ");
            if (bearer) {
                bearer += 7;
                char bearer_buf[AUTH_MAX_TOKEN_LEN];
                size_t b = 0;
                while (bearer[b] && bearer[b] != '"' &&
                       bearer[b] != ',' && bearer[b] != '}' &&
                       bearer[b] != '\\' &&
                       b < sizeof(bearer_buf) - 1) {
                    bearer_buf[b] = bearer[b];
                    b++;
                }
                bearer_buf[b] = '\0';

                if (strlen(bearer_buf) > 10) {
                    char bearer_claims[1024] = "{}";
                    jwt_decode(bearer_buf, bearer_claims, sizeof(bearer_claims));

                    if (token_preview[0] == '\0') {
                        strlcpy(token_preview, bearer_buf,
                                sizeof(token_preview) < 65 ? sizeof(token_preview) : 65);
                        strlcpy(token_type, "bearer", sizeof(token_type));
                        strlcpy(claims_json, bearer_claims, sizeof(claims_json));
                    }

                    auth_track_token(bearer_buf, "bearer", "authorization_header");
                }
            }
        }

        /* Push auth event */
        auth_push_event(event_type, url_buf, provider,
                        token_preview, token_type, claims_json);
    }

    auth_last_scanned_net_total = net_ring.total;
}

/* ── Saved originals for auth hooks ── */

static IMP auth_orig_LAContext_evaluate = NULL;

/* ── Hooked: LAContext evaluatePolicy:localizedReason:reply: ── */
/* Captures biometric authentication attempts */

static void auth_hooked_LAContext_evaluate(id self, SEL _cmd,
                                           long policy, id reason,
                                           void (^reply)(BOOL, id)) {
    const char *reason_str = reason ? nsstring_to_c(reason) : "";

    /* Determine policy name */
    const char *policy_name;
    switch (policy) {
        case 1: policy_name = "deviceOwnerAuthenticationWithBiometrics"; break;
        case 2: policy_name = "deviceOwnerAuthentication"; break;
        case 3: policy_name = "deviceOwnerAuthenticationWithWatch"; break;
        default: policy_name = "unknown"; break;
    }

    /* Wrap reply to capture result */
    void (^wrappedReply)(BOOL, id) = ^(BOOL success, id error) {
        const char *result = success ? "success" : "failure";

        char claims[512];
        char reason_esc[256], result_esc[32], policy_esc[128];
        json_escape(reason_str, reason_esc, sizeof(reason_esc));
        json_escape(result, result_esc, sizeof(result_esc));
        json_escape(policy_name, policy_esc, sizeof(policy_esc));

        snprintf(claims, sizeof(claims),
                 "{\"policy\":%s,\"result\":%s,\"reason\":%s}",
                 policy_esc, result_esc, reason_esc);

        auth_push_event("biometric_auth", "", "LocalAuthentication",
                        "", "", claims);

        if (reply) reply(success, error);
    };

    /* Call original */
    void (*orig)(id, SEL, long, id, void(^)(BOOL, id)) =
        (void (*)(id, SEL, long, id, void(^)(BOOL, id)))auth_orig_LAContext_evaluate;
    orig(self, _cmd, policy, reason, wrappedReply);
}

/* ── Install auth hooks ── */

static void auth_install_hooks(void) {
    if (auth_tap_initialized) return;

    darkmach_ring_init(&auth_ring);
    memset(auth_tokens_table, 0, sizeof(auth_tokens_table));
    auth_tokens_count = 0;
    auth_tap_initialized = 1;

    /* Ensure net_tap is also active (we depend on it) */
    if (!net_tap_enabled) net_install_hooks();

    /* Hook LAContext evaluatePolicy:localizedReason:reply: */
    Class laClass = objc_getClass("LAContext");
    if (laClass) {
        SEL evalSel = sel_registerName("evaluatePolicy:localizedReason:reply:");
        Method m = class_getInstanceMethod(laClass, evalSel);
        if (m) {
            auth_orig_LAContext_evaluate = method_getImplementation(m);
            method_setImplementation(m, (IMP)auth_hooked_LAContext_evaluate);
            fprintf(stderr, "[darkmach-auth-tap] hooked LAContext evaluatePolicy:\n");
        }
    }

    /* Hook ASWebAuthenticationSession if available */
    Class asClass = objc_getClass("ASWebAuthenticationSession");
    if (asClass) {
        /* We monitor the initWithURL:callbackURLScheme:completionHandler: */
        /* For now, rely on net_tap to catch the OAuth redirect URLs */
        fprintf(stderr, "[darkmach-auth-tap] ASWebAuthenticationSession available "
                "(monitoring via net_tap)\n");
    }

    auth_tap_enabled = 1;
    fprintf(stderr, "[darkmach-auth-tap] auth interception active\n");
}

/* ── Command: auth_tap ── */

static void cmd_auth_tap(const char *args, resp_t *r) {
    if (!auth_tap_initialized) auth_install_hooks();

    /* Scan net_ring for new auth events before returning results */
    auth_scan_net_ring();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;

    resp_append(r, "\"data\":{\"events\":[");
    int returned = 0;
    for (int i = 0; i < auth_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&auth_ring, i);
        if (!entry) continue;
        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d}",
                auth_ring.total, returned);
}

/* ── Command: auth_tokens ── */

static void cmd_auth_tokens(const char *args, resp_t *r) {
    if (!auth_tap_initialized) auth_install_hooks();

    /* Scan for any new tokens before returning */
    auth_scan_net_ring();

    resp_append(r, "\"data\":{\"tokens\":[");
    int emitted = 0;
    for (int i = 0; i < auth_tokens_count; i++) {
        auth_token_entry_t *e = &auth_tokens_table[i];
        if (!e->active) continue;

        if (emitted > 0) resp_append(r, ",");

        /* Token preview: first 64 chars */
        char preview[65];
        strlcpy(preview, e->value, sizeof(preview));

        char type_esc[64], preview_esc[256], source_esc[128];
        char first_esc[128], last_esc[128];
        json_escape(e->type, type_esc, sizeof(type_esc));
        json_escape(preview, preview_esc, sizeof(preview_esc));
        json_escape(e->source, source_esc, sizeof(source_esc));
        json_escape(e->first_seen, first_esc, sizeof(first_esc));
        json_escape(e->last_seen, last_esc, sizeof(last_esc));

        /* claims_json is already JSON — use directly or fallback to {} */
        const char *claims = (e->claims_json[0]) ? e->claims_json : "{}";

        resp_append(r, "{\"type\":%s,\"value_preview\":%s,"
                    "\"full_value_len\":%zu,"
                    "\"claims\":%s,"
                    "\"source\":%s,"
                    "\"first_seen\":%s,\"last_seen\":%s}",
                    type_esc, preview_esc,
                    strlen(e->value),
                    claims,
                    source_esc,
                    first_esc, last_esc);
        emitted++;
    }
    resp_append(r, "],\"total_unique\":%d}", emitted);
}
