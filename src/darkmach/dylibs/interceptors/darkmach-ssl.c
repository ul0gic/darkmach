/* SSL interceptor: certificate validation, pinning configs, trust evaluation.
 * Env: DARKMACH_SSL_BYPASS=1 bypasses pinning (default: log only). See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <Security/Security.h>

#define MOD "ssl"

/* CFNetwork's URLSession trust path calls this SPI, not the public evaluators. */
extern OSStatus SecTrustEvaluateFastAsync(SecTrustRef trust, dispatch_queue_t queue,
                                          SecTrustCallback result);

static int ssl_bypass_enabled = 0;

/* Read by darkmach-bridge's pin_analyze to tell "nothing pinned" from "nothing watched". */
int darkmach_ssl_trust_hooks_installed = 0;

static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *) = NULL;
static OSStatus (*orig_SecTrustEvaluateAsyncWithError)(SecTrustRef, dispatch_queue_t,
    void (^)(SecTrustRef, bool, CFErrorRef)) = NULL;
static OSStatus (*orig_SecTrustEvaluateFastAsync)(SecTrustRef, dispatch_queue_t,
    SecTrustCallback) = NULL;

static void ssl_report_trust(SecTrustRef trust, int trusted, int bypassed) {
    static void (*record)(SecTrustRef, int, int) = NULL;
    if (!record)
        record = (void (*)(SecTrustRef, int, int))dlsym(RTLD_DEFAULT,
            "darkmach_pin_record_trust");
    if (record) record(trust, trusted, bypassed);
}

static void trust_to_json(SecTrustRef trust, char *buf, size_t bufsize) {
    if (!trust) { snprintf(buf, bufsize, "null"); return; }

    CFIndex certCount = SecTrustGetCertificateCount(trust);

    char subject_esc[1024] = "null";
    if (certCount > 0) {
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, 0);
        if (cert) {
            CFStringRef summary = SecCertificateCopySubjectSummary(cert);
            if (summary) {
                char summary_buf[512];
                CFStringGetCString(summary, summary_buf, sizeof(summary_buf),
                                   kCFStringEncodingUTF8);
                json_escape(summary_buf, subject_esc, sizeof(subject_esc));
                CFRelease(summary);
            }
        }
    }

    char policies_desc[1024] = "null";
    CFArrayRef policies = NULL;
    if (SecTrustCopyPolicies(trust, &policies) == errSecSuccess && policies) {
        CFIndex pcount = CFArrayGetCount(policies);
        size_t pos = 0;
        pos += snprintf(policies_desc + pos, sizeof(policies_desc) - pos, "[");
        for (CFIndex i = 0; i < pcount && pos < sizeof(policies_desc) - 20; i++) {
            SecPolicyRef policy = (SecPolicyRef)CFArrayGetValueAtIndex(policies, i);
            CFDictionaryRef props = SecPolicyCopyProperties(policy);
            if (props) {
                CFStringRef oid = CFDictionaryGetValue(props, CFSTR("SecPolicyOid"));
                if (oid) {
                    char oid_buf[256];
                    CFStringGetCString(oid, oid_buf, sizeof(oid_buf),
                                       kCFStringEncodingUTF8);
                    if (i > 0) pos += snprintf(policies_desc + pos,
                                               sizeof(policies_desc) - pos, ",");
                    pos += snprintf(policies_desc + pos,
                                   sizeof(policies_desc) - pos, "\"%s\"", oid_buf);
                }
                CFRelease(props);
            }
        }
        snprintf(policies_desc + pos, sizeof(policies_desc) - pos, "]");
        CFRelease(policies);
    }

    snprintf(buf, bufsize,
             "\"certCount\":%ld,\"leafSubject\":%s,\"policies\":%s",
             (long)certCount, subject_esc, policies_desc);
}

static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust,
                                              CFErrorRef *error) {
    char trust_json[4096];
    trust_to_json(trust, trust_json, sizeof(trust_json));

    bool trusted = orig_SecTrustEvaluateWithError(trust, error);

    char error_desc[1024] = "null";
    if (error && *error) {
        CFStringRef errStr = CFErrorCopyDescription(*error);
        if (errStr) {
            char err_buf[512];
            CFStringGetCString(errStr, err_buf, sizeof(err_buf),
                               kCFStringEncodingUTF8);
            json_escape(err_buf, error_desc, sizeof(error_desc));
            CFRelease(errStr);
        }
    }

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"evaluate\",\"result\":%s,\"bypassed\":%s,%s,\"error\":%s",
             trusted ? "true" : "false",
             (ssl_bypass_enabled && !trusted) ? "true" : "false",
             trust_json, error_desc);
    darkmach_log(MOD, "trust", data);

    fprintf(stderr, "[darkmach-ssl] SecTrustEvaluateWithError: %s%s\n",
            trusted ? "TRUSTED" : "UNTRUSTED",
            (ssl_bypass_enabled && !trusted) ? " -> BYPASSED" : "");

    int bypassed = (ssl_bypass_enabled && !trusted);
    ssl_report_trust(trust, bypassed ? 1 : (trusted ? 1 : 0), bypassed);

    if (bypassed) {
        if (error) *error = NULL;
        return true;
    }

    return trusted;
}

static OSStatus hooked_SecTrustEvaluateFastAsync(SecTrustRef trust,
                                                  dispatch_queue_t queue,
                                                  SecTrustCallback result)
{
    char trust_json[4096];
    trust_to_json(trust, trust_json, sizeof(trust_json));

    char data[4096];
    snprintf(data, sizeof(data), "\"op\":\"evaluate_fast_async\",%s", trust_json);
    darkmach_log(MOD, "trust", data);

    return orig_SecTrustEvaluateFastAsync(trust, queue,
        ^(SecTrustRef t, SecTrustResultType tr) {
            int trusted = (tr == kSecTrustResultProceed ||
                           tr == kSecTrustResultUnspecified);
            ssl_report_trust(t, trusted, 0);
            fprintf(stderr, "[darkmach-ssl] SecTrustEvaluateFastAsync: %s (result=%d)\n",
                    trusted ? "TRUSTED" : "UNTRUSTED", (int)tr);
            result(t, tr);
        });
}

static OSStatus hooked_SecTrustEvaluateAsyncWithError(
    SecTrustRef trust, dispatch_queue_t queue,
    void (^handler)(SecTrustRef, bool, CFErrorRef))
{
    char trust_json[4096];
    trust_to_json(trust, trust_json, sizeof(trust_json));

    char data[4096];
    snprintf(data, sizeof(data),
             "\"op\":\"evaluate_async\",%s", trust_json);
    darkmach_log(MOD, "trust", data);
    fprintf(stderr, "[darkmach-ssl] SecTrustEvaluateAsyncWithError (async)\n");

    void (^wrappedHandler)(SecTrustRef, bool, CFErrorRef) =
        ^(SecTrustRef t, bool result, CFErrorRef error) {
            int bypassed = (ssl_bypass_enabled && !result);
            ssl_report_trust(t, bypassed ? 1 : (result ? 1 : 0), bypassed);

            if (bypassed) {
                fprintf(stderr, "[darkmach-ssl] async trust BYPASSED\n");
                char bypass_data[256];
                snprintf(bypass_data, sizeof(bypass_data),
                         "\"op\":\"async_bypass\",\"originalResult\":false");
                darkmach_log(MOD, "trust", bypass_data);
                handler(t, true, NULL);
            } else {
                handler(t, result, error);
            }
        };

    return orig_SecTrustEvaluateAsyncWithError(trust, queue, wrappedHandler);
}


static IMP orig_didReceiveChallenge = NULL;

/* Where apps implement custom certificate pinning */
static void hooked_didReceiveChallenge(id self, SEL _cmd, id session,
                                        id challenge, id completionHandler) {
    SEL protSpaceSel = sel_registerName("protectionSpace");
    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id protSpace = get(challenge, protSpaceSel);

    const char *host = "(unknown)";
    const char *method = "(unknown)";
    long port = 0;

    if (protSpace) {
        SEL hostSel = sel_registerName("host");
        SEL methodSel = sel_registerName("authenticationMethod");
        SEL portSel = sel_registerName("port");

        id hostStr = get(protSpace, hostSel);
        id methodStr = get(protSpace, methodSel);
        long (*getPort)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        port = getPort(protSpace, portSel);

        host = nsobject_desc(hostStr);
        method = nsobject_desc(methodStr);
    }

    char host_esc[512], method_esc[256];
    json_escape(host, host_esc, sizeof(host_esc));
    json_escape(method, method_esc, sizeof(method_esc));

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"challenge\",\"host\":%s,\"port\":%ld,\"method\":%s,"
             "\"delegate\":\"%s\"",
             host_esc, port, method_esc, class_getName(object_getClass(self)));
    darkmach_log(MOD, "challenge", data);

    fprintf(stderr, "[darkmach-ssl] auth challenge: %s:%ld method=%s delegate=%s\n",
            host, port, method, class_getName(object_getClass(self)));

    void (*orig)(id, SEL, id, id, id) =
        (void (*)(id, SEL, id, id, id))orig_didReceiveChallenge;
    orig(self, _cmd, session, challenge, completionHandler);
}

struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_SecTrustEvaluateWithError,
      (const void *)SecTrustEvaluateWithError },
    { (const void *)hooked_SecTrustEvaluateAsyncWithError,
      (const void *)SecTrustEvaluateAsyncWithError },
    { (const void *)hooked_SecTrustEvaluateFastAsync,
      (const void *)SecTrustEvaluateFastAsync },
};

__attribute__((constructor))
static void darkmach_ssl_init(void) {
    fprintf(stderr, "[darkmach-ssl] initializing SSL interceptor\n");
    darkmach_log_init(MOD);

    /* Direct references, never dlsym: dlsym returns this image's own interposed hook. */
    orig_SecTrustEvaluateWithError = SecTrustEvaluateWithError;
    orig_SecTrustEvaluateAsyncWithError = SecTrustEvaluateAsyncWithError;
    orig_SecTrustEvaluateFastAsync = SecTrustEvaluateFastAsync;

    darkmach_ssl_trust_hooks_installed =
        (orig_SecTrustEvaluateWithError && orig_SecTrustEvaluateAsyncWithError &&
         orig_SecTrustEvaluateFastAsync) ? 1 : 0;

    const char *bypass = getenv("DARKMACH_SSL_BYPASS");
    if (bypass && bypass[0] == '1') {
        ssl_bypass_enabled = 1;
        fprintf(stderr, "[darkmach-ssl] *** SSL PINNING BYPASS ENABLED ***\n");
    }

    Class sessionDelegateClass = objc_getClass("__NSURLSessionLocal");
    if (sessionDelegateClass) {
        SEL challengeSel = sel_registerName(
            "URLSession:didReceiveChallenge:completionHandler:");
        Method m = class_getInstanceMethod(sessionDelegateClass, challengeSel);
        if (m) {
            orig_didReceiveChallenge = method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_didReceiveChallenge);
            fprintf(stderr, "[darkmach-ssl] hooked __NSURLSessionLocal challenge handler\n");
        }
    }

    char data[512];
    snprintf(data, sizeof(data),
             "\"hooks\":[\"SecTrustEvaluateWithError\",\"SecTrustEvaluateAsyncWithError\","
             "\"SecTrustEvaluateFastAsync\",\"AuthChallenge\"],"
             "\"installed\":%s,\"bypass\":%s",
             darkmach_ssl_trust_hooks_installed ? "true" : "false",
             ssl_bypass_enabled ? "true" : "false");
    darkmach_log(MOD, "init", data);

    fprintf(stderr, "[darkmach-ssl] ready — trust evaluation %s%s\n",
            darkmach_ssl_trust_hooks_installed ? "hooked (3 evaluators)"
                                               : "NOT hooked",
            ssl_bypass_enabled ? " + BYPASS" : "");
}
