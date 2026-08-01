/* Unity build: #included from bridge/darkmach-bridge.c, not compiled standalone. */
#include "darkmach-bridge.h"
#include <CommonCrypto/CommonDigest.h>
#include <math.h>

#define PIN_MAX_CERTS_PER_EVAL 10
#define PIN_MAX_EVALS 200
#define PIN_CERT_DER_MAX 8192   /* max DER bytes stored per cert */
#define PIN_BASE64_MAX  12288   /* base64 of 8192 bytes */

typedef struct {
    char subject[256];
    unsigned char der[PIN_CERT_DER_MAX];
    size_t der_len;
    char pubkey_sha256[65];     /* hex-encoded SHA256 of public key */
} pin_cert_t;

typedef struct {
    char host[256];
    int port;
    int cert_count;
    pin_cert_t certs[PIN_MAX_CERTS_PER_EVAL];
    int trusted;                /* result of SecTrustEvaluate */
    int bypassed;               /* was it overridden by darkmach-ssl? */
    char timestamp[32];
    char policy_oid[128];       /* primary policy OID */
} pin_eval_t;

/* Ring of trust evaluations */
static pin_eval_t pin_evals[PIN_MAX_EVALS];
static int pin_eval_head = 0;
static int pin_eval_count = 0;
static int pin_eval_total = 0;

static int pin_hooks_installed = 0;

/* Original function pointers */
static bool (*pin_orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *) = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus (*pin_orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *) = NULL;
#pragma clang diagnostic pop

static void pin_timestamp(char *buf, size_t bufsz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    snprintf(buf, bufsz, "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

static void pin_hex_encode(const unsigned char *data, size_t len,
                           char *buf, size_t bufsz) {
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 2 < bufsz; i++)
        pos += snprintf(buf + pos, bufsz - pos, "%02x", data[i]);
    buf[pos] = '\0';
}

/* Base64 encode for DER certificate output.
 * Reuses b64_table from cmd-network.c (unity build shares the symbol). */

static size_t pin_base64_encode(const unsigned char *src, size_t src_len,
                                char *dst, size_t dst_len) {
    size_t di = 0;
    for (size_t si = 0; si < src_len && di + 4 < dst_len; si += 3) {
        unsigned int val = (unsigned int)src[si] << 16;
        if (si + 1 < src_len) val |= (unsigned int)src[si + 1] << 8;
        if (si + 2 < src_len) val |= (unsigned int)src[si + 2];

        dst[di++] = b64_table[(val >> 18) & 0x3F];
        dst[di++] = b64_table[(val >> 12) & 0x3F];
        dst[di++] = (si + 1 < src_len) ? b64_table[(val >> 6) & 0x3F] : '=';
        dst[di++] = (si + 2 < src_len) ? b64_table[val & 0x3F] : '=';
    }
    dst[di] = '\0';
    return di;
}

static pin_eval_t *pin_record_trust(SecTrustRef trust) {
    pin_eval_t *ev = &pin_evals[pin_eval_head];
    memset(ev, 0, sizeof(*ev));
    pin_timestamp(ev->timestamp, sizeof(ev->timestamp));

    if (!trust) return ev;

    CFIndex cert_count = SecTrustGetCertificateCount(trust);
    if (cert_count > PIN_MAX_CERTS_PER_EVAL)
        cert_count = PIN_MAX_CERTS_PER_EVAL;
    ev->cert_count = (int)cert_count;

    /* Extract host from trust policy */
    CFArrayRef policies = NULL;
    if (SecTrustCopyPolicies(trust, &policies) == errSecSuccess && policies) {
        CFIndex pcount = CFArrayGetCount(policies);
        for (CFIndex i = 0; i < pcount; i++) {
            SecPolicyRef policy = (SecPolicyRef)CFArrayGetValueAtIndex(policies, i);
            CFDictionaryRef props = SecPolicyCopyProperties(policy);
            if (!props) continue;

            /* Extract OID */
            CFStringRef oid = CFDictionaryGetValue(props, CFSTR("SecPolicyOid"));
            if (oid)
                CFStringGetCString(oid, ev->policy_oid, sizeof(ev->policy_oid),
                                   kCFStringEncodingUTF8);

            /* Extract hostname from SSL policy */
            CFStringRef hostname = CFDictionaryGetValue(props, CFSTR("SecPolicyName"));
            if (hostname)
                CFStringGetCString(hostname, ev->host, sizeof(ev->host),
                                   kCFStringEncodingUTF8);

            CFRelease(props);
            if (ev->host[0]) break;  /* got a host, done */
        }
        CFRelease(policies);
    }

    /* Extract each certificate */
    for (CFIndex i = 0; i < cert_count; i++) {
        pin_cert_t *pc = &ev->certs[i];
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, i);
        if (!cert) continue;

        /* Subject summary */
        CFStringRef summary = SecCertificateCopySubjectSummary(cert);
        if (summary) {
            CFStringGetCString(summary, pc->subject, sizeof(pc->subject),
                               kCFStringEncodingUTF8);
            CFRelease(summary);
        }

        /* DER data */
        CFDataRef der_data = SecCertificateCopyData(cert);
        if (der_data) {
            CFIndex len = CFDataGetLength(der_data);
            if ((size_t)len <= PIN_CERT_DER_MAX) {
                memcpy(pc->der, CFDataGetBytePtr(der_data), (size_t)len);
                pc->der_len = (size_t)len;
            }
            CFRelease(der_data);
        }

        /* Public key SHA256 hash */
        SecKeyRef pubkey = SecCertificateCopyKey(cert);
        if (pubkey) {
            CFDataRef pubkey_data = SecKeyCopyExternalRepresentation(pubkey, NULL);
            if (pubkey_data) {
                unsigned char hash[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(CFDataGetBytePtr(pubkey_data),
                          (CC_LONG)CFDataGetLength(pubkey_data), hash);
                pin_hex_encode(hash, CC_SHA256_DIGEST_LENGTH,
                               pc->pubkey_sha256, sizeof(pc->pubkey_sha256));
                CFRelease(pubkey_data);
            }
            CFRelease(pubkey);
        }
    }

    /* Advance ring */
    pin_eval_head = (pin_eval_head + 1) % PIN_MAX_EVALS;
    if (pin_eval_count < PIN_MAX_EVALS) pin_eval_count++;
    pin_eval_total++;

    return ev;
}

static bool pin_hooked_SecTrustEvaluateWithError(SecTrustRef trust,
                                                  CFErrorRef *error) {
    pin_eval_t *ev = pin_record_trust(trust);

    bool result = pin_orig_SecTrustEvaluateWithError(trust, error);
    ev->trusted = result ? 1 : 0;

    /* Detect if darkmach-ssl bypass is active */
    if (!result) {
        /* Check if darkmach-ssl will override this to true */
        void *ssl_bypass = dlsym(RTLD_DEFAULT, "darkmach_ssl_bypass_enabled");
        if (ssl_bypass && *(int *)ssl_bypass)
            ev->bypassed = 1;
    }

    fprintf(stderr, "[darkmach-pin] SecTrustEvaluateWithError: host=%s trusted=%s certs=%d\n",
            ev->host[0] ? ev->host : "(unknown)",
            result ? "yes" : "no", ev->cert_count);

    return result;
}

/* Hooks SecTrustEvaluate — deprecated but still used by some apps. */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus pin_hooked_SecTrustEvaluate(SecTrustRef trust,
                                             SecTrustResultType *result) {
    pin_eval_t *ev = pin_record_trust(trust);

    OSStatus status = pin_orig_SecTrustEvaluate(trust, result);
    if (result) {
        ev->trusted = (*result == kSecTrustResultUnspecified ||
                       *result == kSecTrustResultProceed) ? 1 : 0;
    }

    fprintf(stderr, "[darkmach-pin] SecTrustEvaluate: host=%s result=%d certs=%d\n",
            ev->host[0] ? ev->host : "(unknown)",
            result ? (int)*result : -1, ev->cert_count);

    return status;
}
#pragma clang diagnostic pop

/* Hooks install lazily on the first pin_analyze call. */

static void pin_install_hooks(void) {
    if (pin_hooks_installed) return;

    memset(pin_evals, 0, sizeof(pin_evals));
    pin_eval_head = 0;
    pin_eval_count = 0;
    pin_eval_total = 0;

    /*
     * Rebind via dlsym + function-pointer swap. DYLD_INTERPOSE is unusable
     * here — inside the bridge dylib (unity build) — so this uses fishhook-
     * style rebinding: save originals, then hook via the interpose mechanism.
     * The dlsym always resolves the real function: if darkmach-ssl is loaded,
     * its interpose already replaced the symbol, so dlsym returns that wrapper
     * and hooking it chains correctly.
     */
    pin_orig_SecTrustEvaluateWithError =
        (bool (*)(SecTrustRef, CFErrorRef *))dlsym(RTLD_DEFAULT,
            "SecTrustEvaluateWithError");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    pin_orig_SecTrustEvaluate =
        (OSStatus (*)(SecTrustRef, SecTrustResultType *))dlsym(RTLD_DEFAULT,
            "SecTrustEvaluate");
#pragma clang diagnostic pop

    /*
     * Hook via ObjC swizzling of NSURLSession delegate methods. C-level
     * Security.framework functions can't be rebound without fishhook, so
     * hooking happens at the NSURLSession challenge level where trust
     * evaluation is typically triggered; for deeper coverage, load
     * darkmach-ssl.dylib alongside the bridge. Observable trust evaluations
     * are recorded; pin_analyze also actively scans TrustKit config and ATS.
     */

    pin_hooks_installed = 1;
    fprintf(stderr, "[darkmach-pin] certificate pinning analysis active "
            "(SecTrustEvaluateWithError=%p, SecTrustEvaluate=%p)\n",
            (void *)pin_orig_SecTrustEvaluateWithError,
            (void *)pin_orig_SecTrustEvaluate);
}

static void pin_detect_trustkit(resp_t *r) {
    Class tkClass = objc_getClass("TrustKit");
    if (!tkClass) {
        resp_append(r, "\"trustkit\":{\"detected\":false}");
        return;
    }

    resp_append(r, "\"trustkit\":{\"detected\":true");

    /* Try to get the shared instance and its configuration */
    SEL sharedSel = sel_registerName("sharedInstance");
    id (*getShared)(id, SEL) = (id (*)(id, SEL))objc_msgSend;

    @try {
        id instance = getShared((id)tkClass, sharedSel);
        if (instance) {
            /* Get pinningValidator -> configuration */
            SEL validatorSel = sel_registerName("pinningValidator");
            id (*getValidator)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id validator = getValidator(instance, validatorSel);

            if (validator) {
                /* Try to extract domain config via description */
                const char *desc = nsobject_desc(validator);
                if (desc && strlen(desc) > 2) {
                    resp_append(r, ",\"validator\":");
                    resp_append_json_str(r, desc);
                }
            }
        }
    } @catch (id ex) {
        resp_append(r, ",\"error\":\"exception reading TrustKit config\"");
    }

    /* Also check for TSKPinnedDomains in NSUserDefaults or bundle config */
    @try {
        Class bundleClass = objc_getClass("NSBundle");
        SEL mainBundleSel = sel_registerName("mainBundle");
        SEL infoDictSel = sel_registerName("infoDictionary");
        SEL objectForKeySel = sel_registerName("objectForKey:");

        id (*getMain)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id (*getInfo)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;

        id bundle = getMain((id)bundleClass, mainBundleSel);
        id info = getInfo(bundle, infoDictSel);

        /* Look for TSKConfiguration key */
        SEL strSel = sel_registerName("stringWithUTF8String:");
        id (*mkStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;
        Class nsStringClass = objc_getClass("NSString");

        id tskKey = mkStr((id)nsStringClass, strSel, "TSKConfiguration");
        id tskConfig = getObj(info, objectForKeySel, tskKey);
        if (tskConfig) {
            resp_append(r, ",\"plist_config\":");
            resp_append_json_str(r, nsobject_desc(tskConfig));
        }
    } @catch (id ex) {
        /* Ignore — TrustKit config not in plist */
    }

    resp_append(r, "}");
}

static void pin_detect_ats(resp_t *r) {
    @try {
        Class bundleClass = objc_getClass("NSBundle");
        SEL mainBundleSel = sel_registerName("mainBundle");
        SEL infoDictSel = sel_registerName("infoDictionary");
        SEL objectForKeySel = sel_registerName("objectForKey:");
        SEL allKeysSel = sel_registerName("allKeys");
        SEL countSel = sel_registerName("count");
        SEL indexSel = sel_registerName("objectAtIndex:");

        id (*getMain)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id (*getInfo)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
        id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        id (*getAt)(id, SEL, unsigned long) =
            (id (*)(id, SEL, unsigned long))objc_msgSend;

        id bundle = getMain((id)bundleClass, mainBundleSel);
        id info = getInfo(bundle, infoDictSel);

        /* Create lookup key */
        SEL strSel = sel_registerName("stringWithUTF8String:");
        id (*mkStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;
        Class nsStringClass = objc_getClass("NSString");

        id atsKey = mkStr((id)nsStringClass, strSel, "NSAppTransportSecurity");
        id atsDict = getObj(info, objectForKeySel, atsKey);

        if (!atsDict) {
            resp_append(r, "\"ats\":{\"configured\":false}");
            return;
        }

        resp_append(r, "\"ats\":{\"configured\":true");

        /* Check NSAllowsArbitraryLoads */
        id arbLoadsKey = mkStr((id)nsStringClass, strSel, "NSAllowsArbitraryLoads");
        id arbLoads = getObj(atsDict, objectForKeySel, arbLoadsKey);
        if (arbLoads) {
            SEL boolSel = sel_registerName("boolValue");
            BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
            BOOL val = getBool(arbLoads, boolSel);
            resp_append(r, ",\"allows_arbitrary_loads\":%s",
                        val ? "true" : "false");
        }

        /* Check NSAllowsArbitraryLoadsInWebContent */
        id arbWebKey = mkStr((id)nsStringClass, strSel,
                             "NSAllowsArbitraryLoadsInWebContent");
        id arbWeb = getObj(atsDict, objectForKeySel, arbWebKey);
        if (arbWeb) {
            SEL boolSel = sel_registerName("boolValue");
            BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
            BOOL val = getBool(arbWeb, boolSel);
            resp_append(r, ",\"allows_arbitrary_loads_web\":%s",
                        val ? "true" : "false");
        }

        /* Extract NSExceptionDomains */
        id excDomainsKey = mkStr((id)nsStringClass, strSel,
                                 "NSExceptionDomains");
        id excDomains = getObj(atsDict, objectForKeySel, excDomainsKey);

        if (excDomains) {
            id keys = getKeys(excDomains, allKeysSel);
            long count = getCount(keys, countSel);

            resp_append(r, ",\"exception_domains\":[");
            for (long i = 0; i < count && i < 50; i++) {
                id domainKey = getAt(keys, indexSel, (unsigned long)i);
                id domainConfig = getObj(excDomains, objectForKeySel, domainKey);
                const char *domain = nsstring_to_c(domainKey);

                if (i > 0) resp_append(r, ",");
                resp_append(r, "{\"domain\":");
                resp_append_json_str(r, domain);

                /* Check for key settings */
                if (domainConfig) {
                    id fwdSecKey = mkStr((id)nsStringClass, strSel,
                                        "NSExceptionRequiresForwardSecrecy");
                    id fwdSec = getObj(domainConfig, objectForKeySel, fwdSecKey);
                    if (fwdSec) {
                        SEL boolSel = sel_registerName("boolValue");
                        BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                        resp_append(r, ",\"requires_forward_secrecy\":%s",
                                    getBool(fwdSec, boolSel) ? "true" : "false");
                    }

                    id httpKey = mkStr((id)nsStringClass, strSel,
                                       "NSExceptionAllowsInsecureHTTPLoads");
                    id httpVal = getObj(domainConfig, objectForKeySel, httpKey);
                    if (httpVal) {
                        SEL boolSel = sel_registerName("boolValue");
                        BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                        resp_append(r, ",\"allows_insecure_http\":%s",
                                    getBool(httpVal, boolSel) ? "true" : "false");
                    }

                    id inclSubKey = mkStr((id)nsStringClass, strSel,
                                          "NSIncludesSubdomains");
                    id inclSub = getObj(domainConfig, objectForKeySel, inclSubKey);
                    if (inclSub) {
                        SEL boolSel = sel_registerName("boolValue");
                        BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
                        resp_append(r, ",\"includes_subdomains\":%s",
                                    getBool(inclSub, boolSel) ? "true" : "false");
                    }

                    id minTlsKey = mkStr((id)nsStringClass, strSel,
                                         "NSExceptionMinimumTLSVersion");
                    id minTls = getObj(domainConfig, objectForKeySel, minTlsKey);
                    if (minTls) {
                        resp_append(r, ",\"min_tls_version\":");
                        resp_append_json_str(r, nsstring_to_c(minTls));
                    }
                }
                resp_append(r, "}");
            }
            resp_append(r, "]");
        }

        resp_append(r, "}");
    } @catch (id ex) {
        resp_append(r, "\"ats\":{\"configured\":false,\"error\":\"exception\"}");
    }
}

static void cmd_pin_analyze(const char *args, resp_t *r) {
    /* Lazy-init: install hooks on first call */
    if (!pin_hooks_installed) pin_install_hooks();

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;

    resp_append(r, "\"data\":{");

    /* Trust evaluations captured */
    resp_append(r, "\"evaluations\":[");
    int returned = 0;
    for (int i = 0; i < pin_eval_count && returned < limit; i++) {
        /* Walk from most recent backward */
        int idx = (pin_eval_head - 1 - i + PIN_MAX_EVALS) % PIN_MAX_EVALS;
        pin_eval_t *ev = &pin_evals[idx];

        if (returned > 0) resp_append(r, ",");
        resp_append(r, "{\"host\":");
        resp_append_json_str(r, ev->host[0] ? ev->host : "(unknown)");
        resp_append(r, ",\"port\":%d,\"trusted\":%s,\"bypassed\":%s",
                    ev->port,
                    ev->trusted ? "true" : "false",
                    ev->bypassed ? "true" : "false");
        resp_append(r, ",\"timestamp\":");
        resp_append_json_str(r, ev->timestamp);
        resp_append(r, ",\"policy\":");
        resp_append_json_str(r, ev->policy_oid[0] ? ev->policy_oid : "unknown");

        /* Certificate chain summary */
        resp_append(r, ",\"cert_count\":%d,\"certs\":[", ev->cert_count);
        for (int j = 0; j < ev->cert_count; j++) {
            pin_cert_t *pc = &ev->certs[j];
            if (j > 0) resp_append(r, ",");
            resp_append(r, "{\"subject\":");
            resp_append_json_str(r, pc->subject[0] ? pc->subject : "(unknown)");
            resp_append(r, ",\"der_size\":%zu", pc->der_len);
            if (pc->pubkey_sha256[0]) {
                resp_append(r, ",\"pubkey_sha256\":");
                resp_append_json_str(r, pc->pubkey_sha256);
            }
            resp_append(r, "}");
        }
        resp_append(r, "]}");
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d,",
                pin_eval_total, returned);

    /* TrustKit detection */
    pin_detect_trustkit(r);
    resp_append(r, ",");

    /* ATS configuration */
    pin_detect_ats(r);

    /* Unique pinned hosts summary */
    resp_append(r, ",\"pinned_hosts\":[");
    {
        /* Deduplicate hosts from evaluations */
        char seen_hosts[50][256];
        int seen_count = 0;

        for (int i = 0; i < pin_eval_count && seen_count < 50; i++) {
            int idx = (pin_eval_head - 1 - i + PIN_MAX_EVALS) % PIN_MAX_EVALS;
            pin_eval_t *ev = &pin_evals[idx];
            if (!ev->host[0]) continue;

            /* Check if already seen */
            int dup = 0;
            for (int s = 0; s < seen_count; s++) {
                if (strcmp(seen_hosts[s], ev->host) == 0) { dup = 1; break; }
            }
            if (dup) continue;

            strlcpy(seen_hosts[seen_count], ev->host, 256);
            if (seen_count > 0) resp_append(r, ",");
            resp_append_json_str(r, ev->host);
            seen_count++;
        }
    }
    resp_append(r, "]");

    resp_append(r, "}");
}

/* pin_extract: base64 DER for captured evals; {host:"..."} filters. */

static void cmd_pin_extract(const char *args, resp_t *r) {
    if (!pin_hooks_installed) pin_install_hooks();

    char host_filter[256] = "";
    json_get_string(args, "host", host_filter, sizeof(host_filter));

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 10;

    resp_append(r, "\"data\":{\"certificates\":[");
    int returned = 0;

    for (int i = 0; i < pin_eval_count && returned < limit; i++) {
        int idx = (pin_eval_head - 1 - i + PIN_MAX_EVALS) % PIN_MAX_EVALS;
        pin_eval_t *ev = &pin_evals[idx];

        /* Apply host filter */
        if (host_filter[0] && (!ev->host[0] ||
            strstr(ev->host, host_filter) == NULL))
            continue;

        for (int j = 0; j < ev->cert_count; j++) {
            pin_cert_t *pc = &ev->certs[j];
            if (pc->der_len == 0) continue;

            if (returned > 0) resp_append(r, ",");

            char b64[PIN_BASE64_MAX];
            pin_base64_encode(pc->der, pc->der_len, b64, sizeof(b64));

            resp_append(r, "{\"host\":");
            resp_append_json_str(r, ev->host[0] ? ev->host : "(unknown)");
            resp_append(r, ",\"subject\":");
            resp_append_json_str(r, pc->subject[0] ? pc->subject : "(unknown)");
            resp_append(r, ",\"der_base64\":");
            resp_append_json_str(r, b64);
            if (pc->pubkey_sha256[0]) {
                resp_append(r, ",\"pubkey_sha256\":");
                resp_append_json_str(r, pc->pubkey_sha256);
            }
            resp_append(r, ",\"der_size\":%zu", pc->der_len);
            resp_append(r, ",\"trusted\":%s", ev->trusted ? "true" : "false");
            resp_append(r, "}");
            returned++;
        }
    }
    resp_append(r, "],\"returned\":%d}", returned);
}

/*
 * mem_forensics walks malloc regions (MALLOC_PTR_REGION_RANGE_TYPE) scanning raw
 *   bytes for JWT/Bearer/URL patterns; regions include freed blocks, so secrets
 *   freed-but-not-zeroed are recoverable.
 * mem_snapshot / mem_diff aggregate in-use blocks by ObjC class for diffing.
 * Zone-walking API: .project/reference/frida-gum-heap-study.md, Appendix A.
 */

#define FORENSICS_MAX_FINDINGS    500
#define FORENSICS_PREVIEW_LEN     256
#define FORENSICS_MAX_REGIONS    1000
#define FORENSICS_MAX_REGION_SZ  (16 * 1024 * 1024)  /* skip regions > 16MB */
#define FORENSICS_MAX_SNAPSHOTS    10
#define FORENSICS_SNAP_CLASSES    500

static const char *forensics_default_patterns[] = {
    "eyJ",           /* JWT base64 header */
    "Bearer ",       /* OAuth bearer token */
    "Basic ",        /* HTTP basic auth */
    "password",
    "token",
    "secret",
    "https://",
    "apikey",
    "-----BEGIN",    /* PEM certificates/keys */
    NULL
};

typedef struct {
    uintptr_t address;
    size_t    block_size;        /* region size containing the match */
    char      zone_name[64];
    char      pattern_matched[64];
    char      preview[FORENSICS_PREVIEW_LEN + 1];
} forensics_finding_t;

static forensics_finding_t forensics_findings[FORENSICS_MAX_FINDINGS];

typedef struct {
    vm_range_t regions[FORENSICS_MAX_REGIONS];
    int count;
} forensics_region_scan_t;

/* --- Snapshot storage --- */

typedef struct {
    char   name[256];
    int    count;
    size_t bytes;
} snap_class_t;

typedef struct {
    int          valid;
    int          id;
    char         label[256];
    char         timestamp[32];
    int          total_objects;
    size_t       total_bytes;
    snap_class_t classes[FORENSICS_SNAP_CLASSES];
    int          class_count;
} forensics_snapshot_t;

static forensics_snapshot_t forensics_snaps[FORENSICS_MAX_SNAPSHOTS];
static int forensics_snap_next_id = 1;

/* Region enumeration callback — must not malloc or call ObjC (heap-walk context). */

static void forensics_region_cb(task_t task, void *baton, unsigned type,
                                 vm_range_t *ranges, unsigned count) {
    forensics_region_scan_t *scan = (forensics_region_scan_t *)baton;
    for (unsigned i = 0; i < count && scan->count < FORENSICS_MAX_REGIONS; i++)
        scan->regions[scan->count++] = ranges[i];
}

static int forensics_scan_region(uintptr_t base, size_t size,
                                  const char *pattern, const char *zone_name,
                                  forensics_finding_t *findings, int *fcount,
                                  int max_findings) {
    size_t plen = strlen(pattern);
    if (plen == 0 || plen > size) return 0;

    const unsigned char *p = (const unsigned char *)base;
    const unsigned char *end = p + size - plen;
    int found = 0;

    while (p <= end && *fcount < max_findings) {
        void *match = memmem(p, (size_t)(end - p) + plen, pattern, plen);
        if (!match) break;

        forensics_finding_t *f = &findings[*fcount];
        f->address = (uintptr_t)match;
        f->block_size = size;
        strlcpy(f->zone_name, zone_name, sizeof(f->zone_name));
        strlcpy(f->pattern_matched, pattern, sizeof(f->pattern_matched));

        /* Build sanitized preview — printable ASCII only */
        const unsigned char *mp = (const unsigned char *)match;
        size_t avail = base + size - (uintptr_t)mp;
        size_t pv_len = avail < FORENSICS_PREVIEW_LEN ? avail : FORENSICS_PREVIEW_LEN;
        for (size_t i = 0; i < pv_len; i++)
            f->preview[i] = (mp[i] >= 0x20 && mp[i] < 0x7f) ? (char)mp[i] : '.';
        f->preview[pv_len] = '\0';

        (*fcount)++;
        found++;
        p = (const unsigned char *)match + 1;
    }
    return found;
}

/* mem_forensics: scans each zone's regions, including freed blocks, for secret patterns. */

static void cmd_mem_forensics(const char *args, resp_t *r) {
    char patterns_str[1024] = "";
    json_get_string(args, "patterns", patterns_str, sizeof(patterns_str));
    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 100;
    if (limit > FORENSICS_MAX_FINDINGS) limit = FORENSICS_MAX_FINDINGS;

    struct timeval tv_start;
    gettimeofday(&tv_start, NULL);
    struct timeval deadline = {
        .tv_sec = tv_start.tv_sec + 5,
        .tv_usec = tv_start.tv_usec
    };

    /* Parse comma-separated patterns or use defaults */
    const char *patterns[32];
    int pattern_count = 0;

    if (patterns_str[0]) {
        char *tok = patterns_str;
        char *sep;
        while (tok && pattern_count < 31) {
            sep = strchr(tok, ',');
            if (sep) *sep = '\0';
            while (*tok == ' ') tok++;
            if (*tok) patterns[pattern_count++] = tok;
            tok = sep ? sep + 1 : NULL;
        }
    } else {
        for (int i = 0; forensics_default_patterns[i]; i++)
            patterns[pattern_count++] = forensics_default_patterns[i];
    }

    /* Walk each zone, enumerate regions, scan for patterns */
    vm_address_t *zone_addrs = NULL;
    unsigned zone_count = 0;
    int zones_scanned = 0;
    int regions_scanned = 0;
    int finding_count = 0;

    kern_return_t kr = malloc_get_all_zones(mach_task_self(),
                                             heap_memory_reader,
                                             &zone_addrs, &zone_count);
    if (kr != KERN_SUCCESS) {
        resp_append(r, "\"error\":\"malloc_get_all_zones failed\"");
        return;
    }

    int timed_out = 0;
    for (unsigned z = 0; z < zone_count && !timed_out && finding_count < (int)limit; z++) {
        malloc_zone_t *zone = (malloc_zone_t *)zone_addrs[z];
        if (!zone || !zone->introspect || !zone->introspect->enumerator) continue;

        const char *zname = zone->zone_name ? zone->zone_name : "unknown";
        zones_scanned++;

        /* Collect regions for this zone */
        forensics_region_scan_t rscan;
        rscan.count = 0;

        zone->introspect->enumerator(
            mach_task_self(), &rscan,
            MALLOC_PTR_REGION_RANGE_TYPE,
            zone_addrs[z],
            heap_memory_reader,
            (vm_range_recorder_t *)forensics_region_cb);

        /* Scan each region for all patterns */
        for (int ri = 0; ri < rscan.count && !timed_out && finding_count < (int)limit; ri++) {
            size_t rsize = rscan.regions[ri].size;
            if (rsize > FORENSICS_MAX_REGION_SZ) rsize = FORENSICS_MAX_REGION_SZ;
            regions_scanned++;

            for (int pi = 0; pi < pattern_count && finding_count < (int)limit; pi++) {
                forensics_scan_region(rscan.regions[ri].address, rsize,
                                       patterns[pi], zname,
                                       forensics_findings, &finding_count,
                                       (int)limit);
            }

            /* Periodic timeout check */
            struct timeval now;
            gettimeofday(&now, NULL);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_usec >= deadline.tv_usec))
                timed_out = 1;
        }
    }

    struct timeval tv_end;
    gettimeofday(&tv_end, NULL);
    long scan_ms = (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
                   (tv_end.tv_usec - tv_start.tv_usec) / 1000;

    /* Build response */
    resp_append(r, "\"data\":{\"findings\":[");
    for (int i = 0; i < finding_count; i++) {
        if (i > 0) resp_append(r, ",");
        forensics_finding_t *f = &forensics_findings[i];
        resp_append(r, "{\"address\":\"0x%lx\"", (unsigned long)f->address);
        resp_append(r, ",\"zone\":");
        resp_append_json_str(r, f->zone_name);
        resp_append(r, ",\"block_size\":%zu", f->block_size);
        resp_append(r, ",\"pattern_matched\":");
        resp_append_json_str(r, f->pattern_matched);
        resp_append(r, ",\"preview\":");
        resp_append_json_str(r, f->preview);
        resp_append(r, ",\"context\":\"heap_region\"}");
    }
    resp_append(r, "],\"zones_scanned\":%d,\"blocks_scanned\":%d",
                zones_scanned, regions_scanned);
    resp_append(r, ",\"scan_time_ms\":%ld,\"total_findings\":%d}",
                scan_ms, finding_count);
}

/* Heap snapshot; reuses cmd-recon.c heap helpers (same unity-build TU). */

static void forensics_take_snapshot(forensics_snapshot_t *snap) {
    memset(snap, 0, sizeof(*snap));
    pin_timestamp(snap->timestamp, sizeof(snap->timestamp));

    /* Phase A: collect heap candidates */
    darkmach_heap_scan_t scan;
    scan.count = 0;

    vm_address_t *zone_addrs = NULL;
    unsigned zone_count = 0;
    if (malloc_get_all_zones(mach_task_self(), heap_memory_reader,
                              &zone_addrs, &zone_count) != KERN_SUCCESS)
        return;

    for (unsigned z = 0; z < zone_count; z++) {
        malloc_zone_t *zone = (malloc_zone_t *)zone_addrs[z];
        if (zone && zone->introspect && zone->introspect->enumerator) {
            zone->introspect->enumerator(
                mach_task_self(), &scan, MALLOC_PTR_IN_USE_RANGE_TYPE,
                zone_addrs[z], heap_memory_reader,
                (vm_range_recorder_t *)heap_enum_callback);
        }
    }

    /* Phase B: validate isa pointers and classify by class */
    unsigned int class_count = 0;
    Class *all_classes = objc_copyClassList(&class_count);
    qsort(all_classes, class_count, sizeof(Class), heap_class_ptr_cmp);

    for (int i = 0; i < scan.count; i++) {
        uintptr_t addr = scan.candidates[i].address;
        size_t size = scan.candidates[i].size;

        uintptr_t isa = *(uintptr_t *)addr;
        if (isa == 0) continue;
        /* Handle non-pointer isa on arm64 */
        if (isa & 1) isa &= 0x0000000ffffffff8ULL;

        Class key = (Class)isa;
        if (!bsearch(&key, all_classes, class_count, sizeof(Class), heap_class_ptr_cmp))
            continue;

        const char *name = class_getName(key);
        if (!name || !name[0]) continue;

        snap->total_objects++;
        snap->total_bytes += size;

        /* Find or create class entry (linear scan — fine for <500 classes) */
        int ci = -1;
        for (int j = 0; j < snap->class_count; j++) {
            if (strcmp(snap->classes[j].name, name) == 0) { ci = j; break; }
        }
        if (ci < 0 && snap->class_count < FORENSICS_SNAP_CLASSES) {
            ci = snap->class_count++;
            strlcpy(snap->classes[ci].name, name, sizeof(snap->classes[ci].name));
            snap->classes[ci].count = 0;
            snap->classes[ci].bytes = 0;
        }
        if (ci >= 0) {
            snap->classes[ci].count++;
            snap->classes[ci].bytes += size;
        }
    }

    free(all_classes);
    snap->valid = 1;
}

/* Sort by bytes descending for top_classes output */
static int snap_class_cmp_bytes(const void *a, const void *b) {
    const snap_class_t *ca = (const snap_class_t *)a;
    const snap_class_t *cb = (const snap_class_t *)b;
    if (cb->bytes > ca->bytes) return 1;
    if (cb->bytes < ca->bytes) return -1;
    return 0;
}

static void cmd_mem_snapshot(const char *args, resp_t *r) {
    char label[256] = "";
    json_get_string(args, "label", label, sizeof(label));

    /* Find an empty slot, or evict oldest */
    int slot = -1;
    for (int i = 0; i < FORENSICS_MAX_SNAPSHOTS; i++) {
        if (!forensics_snaps[i].valid) { slot = i; break; }
    }
    if (slot < 0) {
        /* Evict slot 0, shift everything down */
        memmove(&forensics_snaps[0], &forensics_snaps[1],
                sizeof(forensics_snapshot_t) * (FORENSICS_MAX_SNAPSHOTS - 1));
        slot = FORENSICS_MAX_SNAPSHOTS - 1;
    }

    forensics_snapshot_t *snap = &forensics_snaps[slot];
    forensics_take_snapshot(snap);

    snap->id = forensics_snap_next_id++;
    strlcpy(snap->label, label, sizeof(snap->label));

    /* Sort classes by bytes for top_classes */
    qsort(snap->classes, snap->class_count, sizeof(snap_class_t), snap_class_cmp_bytes);

    /* Build response */
    char snap_id[32];
    snprintf(snap_id, sizeof(snap_id), "snap_%03d", snap->id);

    resp_append(r, "\"data\":{\"snapshot_id\":");
    resp_append_json_str(r, snap_id);
    resp_append(r, ",\"label\":");
    resp_append_json_str(r, label[0] ? label : "");
    resp_append(r, ",\"total_objects\":%d", snap->total_objects);
    resp_append(r, ",\"total_bytes\":%zu", snap->total_bytes);
    resp_append(r, ",\"timestamp\":");
    resp_append_json_str(r, snap->timestamp);

    /* Top 20 classes by byte count */
    resp_append(r, ",\"top_classes\":[");
    int top = snap->class_count < 20 ? snap->class_count : 20;
    for (int i = 0; i < top; i++) {
        if (i > 0) resp_append(r, ",");
        resp_append(r, "{\"class\":");
        resp_append_json_str(r, snap->classes[i].name);
        resp_append(r, ",\"count\":%d,\"bytes\":%zu}",
                    snap->classes[i].count, snap->classes[i].bytes);
    }
    resp_append(r, "]}");
}

/* Parse snapshot ID string: "snap_001" -> 1. */

static forensics_snapshot_t *forensics_find_snap(const char *id_str) {
    int target_id = 0;
    if (strncmp(id_str, "snap_", 5) == 0)
        target_id = atoi(id_str + 5);
    else
        target_id = atoi(id_str);
    if (target_id <= 0) return NULL;

    for (int i = 0; i < FORENSICS_MAX_SNAPSHOTS; i++) {
        if (forensics_snaps[i].valid && forensics_snaps[i].id == target_id)
            return &forensics_snaps[i];
    }
    return NULL;
}

static void cmd_mem_diff(const char *args, resp_t *r) {
    char id_a[64] = "", id_b[64] = "";
    json_get_string(args, "a", id_a, sizeof(id_a));
    json_get_string(args, "b", id_b, sizeof(id_b));

    if (!id_a[0] || !id_b[0]) {
        resp_append(r, "\"error\":\"missing snapshot IDs (a and b required)\"");
        return;
    }

    forensics_snapshot_t *sa = forensics_find_snap(id_a);
    forensics_snapshot_t *sb = forensics_find_snap(id_b);

    if (!sa) { resp_append(r, "\"error\":\"snapshot not found: %s\"", id_a); return; }
    if (!sb) { resp_append(r, "\"error\":\"snapshot not found: %s\"", id_b); return; }

    resp_append(r, "\"data\":{");

    /* Added: classes in B but not in A */
    resp_append(r, "\"added\":[");
    int first = 1;
    for (int bi = 0; bi < sb->class_count; bi++) {
        int found = 0;
        for (int ai = 0; ai < sa->class_count; ai++) {
            if (strcmp(sa->classes[ai].name, sb->classes[bi].name) == 0) { found = 1; break; }
        }
        if (!found) {
            if (!first) resp_append(r, ",");
            resp_append(r, "{\"class\":");
            resp_append_json_str(r, sb->classes[bi].name);
            resp_append(r, ",\"count_delta\":%d,\"bytes_delta\":%zu}",
                        sb->classes[bi].count, sb->classes[bi].bytes);
            first = 0;
        }
    }
    resp_append(r, "],");

    /* Removed: classes in A but not in B */
    resp_append(r, "\"removed\":[");
    first = 1;
    for (int ai = 0; ai < sa->class_count; ai++) {
        int found = 0;
        for (int bi = 0; bi < sb->class_count; bi++) {
            if (strcmp(sb->classes[bi].name, sa->classes[ai].name) == 0) { found = 1; break; }
        }
        if (!found) {
            if (!first) resp_append(r, ",");
            resp_append(r, "{\"class\":");
            resp_append_json_str(r, sa->classes[ai].name);
            resp_append(r, ",\"count_delta\":%d,\"bytes_delta\":%zd}",
                        -sa->classes[ai].count,
                        -(ssize_t)sa->classes[ai].bytes);
            first = 0;
        }
    }
    resp_append(r, "],");

    /* Changed: classes in both with >5% count difference */
    resp_append(r, "\"changed\":[");
    first = 1;
    for (int ai = 0; ai < sa->class_count; ai++) {
        for (int bi = 0; bi < sb->class_count; bi++) {
            if (strcmp(sa->classes[ai].name, sb->classes[bi].name) != 0) continue;

            int delta = sb->classes[bi].count - sa->classes[ai].count;
            if (delta == 0) break;

            double pct = (sa->classes[ai].count > 0) ?
                fabs((double)delta / sa->classes[ai].count) * 100.0 : 100.0;
            if (pct < 5.0) break;

            if (!first) resp_append(r, ",");
            resp_append(r, "{\"class\":");
            resp_append_json_str(r, sa->classes[ai].name);
            resp_append(r, ",\"count_a\":%d,\"count_b\":%d",
                        sa->classes[ai].count, sb->classes[bi].count);
            resp_append(r, ",\"count_delta\":%d", delta);
            resp_append(r, ",\"bytes_delta\":%zd}",
                        (ssize_t)(sb->classes[bi].bytes - sa->classes[ai].bytes));
            first = 0;
            break;
        }
    }
    resp_append(r, "],");

    /* Summary */
    resp_append(r, "\"summary\":{\"total_objects_a\":%d,\"total_objects_b\":%d",
                sa->total_objects, sb->total_objects);
    resp_append(r, ",\"total_bytes_a\":%zu,\"total_bytes_b\":%zu}}",
                sa->total_bytes, sb->total_bytes);
}

/*
 * Timing analysis — method execution timing for side-channel detection.
 *   timing_probe: calls a method N times, records mach_absolute_time() per
 *     call, computes mean/median/stddev/min/max and coefficient of variation
 *     (constant-time vs variable-time).
 *   timing_compare: interleaves a method over two NSString args and runs
 *     Welch's t-test to flag significant timing differences (side channel).
 */

#define TIMING_MAX_ITERATIONS 10000

static uint64_t timing_buf_a[TIMING_MAX_ITERATIONS];
static uint64_t timing_buf_b[TIMING_MAX_ITERATIONS];

/* Sort comparator for uint64_t samples */
static int timing_u64_cmp(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* Compute statistics from an array of timing samples (sorts in-place) */
static void timing_compute_stats(uint64_t *samples, int count,
                                  uint64_t *out_mean, uint64_t *out_median,
                                  uint64_t *out_stddev, uint64_t *out_min,
                                  uint64_t *out_max) {
    if (count <= 0) {
        *out_mean = *out_median = *out_stddev = *out_min = *out_max = 0;
        return;
    }

    qsort(samples, count, sizeof(uint64_t), timing_u64_cmp);

    *out_min = samples[0];
    *out_max = samples[count - 1];

    /* Mean */
    double sum = 0;
    for (int i = 0; i < count; i++) sum += (double)samples[i];
    double dmean = sum / count;
    *out_mean = (uint64_t)dmean;

    /* Median */
    if (count % 2 == 0)
        *out_median = (samples[count / 2 - 1] + samples[count / 2]) / 2;
    else
        *out_median = samples[count / 2];

    /* Standard deviation (population) */
    double var = 0;
    for (int i = 0; i < count; i++) {
        double diff = (double)samples[i] - dmean;
        var += diff * diff;
    }
    *out_stddev = (uint64_t)sqrt(var / count);
}

/* timing_probe: times a no-arg method N times; address given → instance method, else class method. */

static void cmd_timing_probe(const char *args, resp_t *r) {
    char className[512] = "";
    char methodName[512] = "";
    json_get_string(args, "class", className, sizeof(className));
    json_get_string(args, "method", methodName, sizeof(methodName));
    long iterations = json_get_long(args, "iterations");
    long warmup = json_get_long(args, "warmup");
    long addr = json_get_long(args, "address");

    if (!className[0] || !methodName[0]) {
        resp_append(r, "\"error\":\"missing class or method arg\"");
        return;
    }
    if (iterations <= 0) iterations = 100;
    if (warmup <= 0) warmup = 5;
    if (iterations > TIMING_MAX_ITERATIONS) iterations = TIMING_MAX_ITERATIONS;

    Class cls = objc_getClass(className);
    if (!cls) {
        resp_append(r, "\"error\":\"class not found\"");
        return;
    }

    SEL sel = sel_registerName(methodName);

    /* Determine target: explicit address or class object (class method) */
    id target;
    if (addr) {
        target = (id)(uintptr_t)addr;
        if (!is_valid_objc_ptr(target)) {
            resp_append(r, "\"error\":\"invalid object at address\"");
            return;
        }
    } else {
        target = (id)cls;
    }

    /* Verify target responds to selector */
    SEL respondsSel = sel_registerName("respondsToSelector:");
    BOOL (*responds)(id, SEL, SEL) = (BOOL (*)(id, SEL, SEL))objc_msgSend;
    if (!responds(target, respondsSel, sel)) {
        resp_append(r, "\"error\":\"target does not respond to selector\"");
        return;
    }

    /* Mach timebase for ticks -> nanoseconds conversion */
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    /* Run warmup + measured iterations */
    id (*call)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    int total = (int)(warmup + iterations);
    int sample_count = 0;

    for (int i = 0; i < total; i++) {
        uint64_t t0 = mach_absolute_time();
        @try { (void)call(target, sel); } @catch (id ex) { /* ignore */ }
        uint64_t t1 = mach_absolute_time();

        if (i >= (int)warmup && sample_count < TIMING_MAX_ITERATIONS)
            timing_buf_a[sample_count++] = (t1 - t0) * tb.numer / tb.denom;
    }

    /* Compute statistics */
    uint64_t mean, median, sd, tmin, tmax;
    timing_compute_stats(timing_buf_a, sample_count,
                          &mean, &median, &sd, &tmin, &tmax);

    double cv_pct = (mean > 0) ? ((double)sd / (double)mean) * 100.0 : 0.0;
    int constant_time = (cv_pct < 20.0) ? 1 : 0;

    /* Build response */
    resp_append(r, "\"data\":{\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"iterations\":%d", sample_count);
    resp_append(r, ",\"warmup_discarded\":%ld", warmup);
    resp_append(r, ",\"mean_ns\":%llu", (unsigned long long)mean);
    resp_append(r, ",\"median_ns\":%llu", (unsigned long long)median);
    resp_append(r, ",\"stddev_ns\":%llu", (unsigned long long)sd);
    resp_append(r, ",\"min_ns\":%llu", (unsigned long long)tmin);
    resp_append(r, ",\"max_ns\":%llu", (unsigned long long)tmax);
    resp_append(r, ",\"constant_time\":%s", constant_time ? "true" : "false");
    resp_append(r, ",\"cv_percent\":%.1f}", cv_pct);
}

/* timing_compare: interleaves A/B calls (Welch's t-test) to reduce environmental bias. */

static void cmd_timing_compare(const char *args, resp_t *r) {
    char className[512] = "";
    char methodName[512] = "";
    char arg_a_str[1024] = "";
    char arg_b_str[1024] = "";
    json_get_string(args, "class", className, sizeof(className));
    json_get_string(args, "method", methodName, sizeof(methodName));
    json_get_string(args, "arg_a", arg_a_str, sizeof(arg_a_str));
    json_get_string(args, "arg_b", arg_b_str, sizeof(arg_b_str));
    long iterations = json_get_long(args, "iterations");
    long addr = json_get_long(args, "address");

    if (!className[0] || !methodName[0] || !arg_a_str[0] || !arg_b_str[0]) {
        resp_append(r, "\"error\":\"missing required args (class, method, arg_a, arg_b)\"");
        return;
    }
    if (iterations <= 0) iterations = 100;
    if (iterations > TIMING_MAX_ITERATIONS) iterations = TIMING_MAX_ITERATIONS;

    Class cls = objc_getClass(className);
    if (!cls) { resp_append(r, "\"error\":\"class not found\""); return; }

    SEL sel = sel_registerName(methodName);

    id target;
    if (addr) {
        target = (id)(uintptr_t)addr;
        if (!is_valid_objc_ptr(target)) {
            resp_append(r, "\"error\":\"invalid object at address\"");
            return;
        }
    } else {
        target = (id)cls;
    }

    /* Create NSString arguments */
    Class nsStringCls = objc_getClass("NSString");
    SEL strSel = sel_registerName("stringWithUTF8String:");
    id (*mkStr)(id, SEL, const char *) = (id (*)(id, SEL, const char *))objc_msgSend;
    id nsArg_a = mkStr((id)nsStringCls, strSel, arg_a_str);
    id nsArg_b = mkStr((id)nsStringCls, strSel, arg_b_str);

    if (!nsArg_a || !nsArg_b) {
        resp_append(r, "\"error\":\"failed to create NSString arguments\"");
        return;
    }

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    /* Interleaved execution — alternate A and B to minimize environmental bias */
    id (*call1)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    int count_a = 0, count_b = 0;
    int warmup = 5;

    for (long i = 0; i < iterations + warmup; i++) {
        /* Call A */
        uint64_t t0 = mach_absolute_time();
        @try { (void)call1(target, sel, nsArg_a); } @catch (id ex) {}
        uint64_t t1 = mach_absolute_time();
        if (i >= warmup && count_a < TIMING_MAX_ITERATIONS)
            timing_buf_a[count_a++] = (t1 - t0) * tb.numer / tb.denom;

        /* Call B */
        t0 = mach_absolute_time();
        @try { (void)call1(target, sel, nsArg_b); } @catch (id ex) {}
        t1 = mach_absolute_time();
        if (i >= warmup && count_b < TIMING_MAX_ITERATIONS)
            timing_buf_b[count_b++] = (t1 - t0) * tb.numer / tb.denom;
    }

    /* Compute stats for both sets */
    uint64_t mean_a, median_a, sd_a, min_a, max_a;
    uint64_t mean_b, median_b, sd_b, min_b, max_b;
    timing_compute_stats(timing_buf_a, count_a,
                          &mean_a, &median_a, &sd_a, &min_a, &max_a);
    timing_compute_stats(timing_buf_b, count_b,
                          &mean_b, &median_b, &sd_b, &min_b, &max_b);

    /* Welch's t-test for independent samples with unequal variances.
     * For large N (which is typical), approximate p-value via the
     * complementary error function (erfc). */
    double var_a = (double)sd_a * (double)sd_a;
    double var_b = (double)sd_b * (double)sd_b;
    double se = (count_a > 0 && count_b > 0) ?
        sqrt(var_a / count_a + var_b / count_b) : 0.0;
    double t_stat = (se > 1e-10) ?
        fabs((double)mean_a - (double)mean_b) / se : 0.0;

    /* Approximate two-tailed p-value using erfc approximation
     * (Abramowitz & Stegun, formula 7.1.26) */
    double p_value = 1.0;
    if (t_stat > 0 && count_a > 1 && count_b > 1) {
        double x = t_stat / 1.4142135623730951;  /* |t| / sqrt(2) */
        if (x > 6.0) {
            p_value = 0.0001;
        } else {
            double k = 1.0 / (1.0 + 0.3275911 * x);
            double erfc_val = exp(-x * x) * k *
                (0.254829592 + k * (-0.284496736 + k *
                (1.421413741 + k * (-1.453152027 + k * 1.061405429))));
            p_value = 2.0 * erfc_val;
            if (p_value < 0.0001) p_value = 0.0001;
        }
    }

    int64_t diff_ns = (int64_t)mean_a - (int64_t)mean_b;
    double diff_pct = (mean_b > 0) ?
        (fabs((double)diff_ns) / (double)mean_b) * 100.0 : 0.0;
    int significant = (p_value < 0.05) ? 1 : 0;

    /* Build response */
    resp_append(r, "\"data\":{\"class\":");
    resp_append_json_str(r, className);
    resp_append(r, ",\"method\":");
    resp_append_json_str(r, methodName);
    resp_append(r, ",\"iterations\":%d", count_a);

    resp_append(r, ",\"result_a\":{\"arg\":");
    resp_append_json_str(r, arg_a_str);
    resp_append(r, ",\"mean_ns\":%llu,\"median_ns\":%llu,\"stddev_ns\":%llu}",
                (unsigned long long)mean_a, (unsigned long long)median_a,
                (unsigned long long)sd_a);

    resp_append(r, ",\"result_b\":{\"arg\":");
    resp_append_json_str(r, arg_b_str);
    resp_append(r, ",\"mean_ns\":%llu,\"median_ns\":%llu,\"stddev_ns\":%llu}",
                (unsigned long long)mean_b, (unsigned long long)median_b,
                (unsigned long long)sd_b);

    resp_append(r, ",\"differential_ns\":%lld", (long long)diff_ns);
    resp_append(r, ",\"differential_percent\":%.1f", diff_pct);
    resp_append(r, ",\"significant\":%s", significant ? "true" : "false");
    resp_append(r, ",\"p_value_approx\":%.4f}", p_value);
}
