/*
 * sphinx-ssl.dylib — SSL/TLS interceptor for Sphinx
 * Captures certificate validation, SSL pinning configs, trust evaluation
 * Optional: bypass certificate pinning for traffic inspection
 *
 * Build:
 *   clang -shared -o sphinx-ssl.dylib sphinx-ssl.c \
 *     -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
 *     -target arm64-apple-ios16.0-simulator \
 *     -framework Foundation -framework Security -lobjc -w
 *
 * Inject:
 *   SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/sphinx-ssl.dylib \
 *   xcrun simctl launch <device> <bundle-id>
 *
 * Environment:
 *   SPHINX_SSL_BYPASS=1  — bypass certificate pinning (allow all certs)
 *   Default: log only, do not bypass
 */
#include "sphinx-core.h"
#include <dlfcn.h>
#include <Security/Security.h>

#define MOD "ssl"

static int ssl_bypass_enabled = 0;

/* ── Original function pointers ── */
static bool (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *) = NULL;
static OSStatus (*orig_SecTrustEvaluateAsyncWithError)(SecTrustRef, dispatch_queue_t,
    void (^)(SecTrustRef, bool, CFErrorRef)) = NULL;

/* ── Helper: extract certificate info from trust ── */
static void trust_to_json(SecTrustRef trust, char *buf, size_t bufsize) {
    if (!trust) { snprintf(buf, bufsize, "null"); return; }

    /* Get certificate count */
    CFIndex certCount = SecTrustGetCertificateCount(trust);

    /* Get the leaf certificate subject summary */
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

    /* Get trust policies */
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

/* ── Hooked: SecTrustEvaluateWithError ── */
static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust,
                                              CFErrorRef *error) {
    char trust_json[4096];
    trust_to_json(trust, trust_json, sizeof(trust_json));

    bool trusted = orig_SecTrustEvaluateWithError(trust, error);

    /* Log the evaluation result */
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
    sphinx_log(MOD, "trust", data);

    fprintf(stderr, "[sphinx-ssl] SecTrustEvaluateWithError: %s%s\n",
            trusted ? "TRUSTED" : "UNTRUSTED",
            (ssl_bypass_enabled && !trusted) ? " -> BYPASSED" : "");

    /* Bypass if enabled */
    if (ssl_bypass_enabled && !trusted) {
        if (error) *error = NULL;
        return true;
    }

    return trusted;
}

/* ── Hooked: SecTrustEvaluateAsyncWithError ── */
static OSStatus hooked_SecTrustEvaluateAsyncWithError(
    SecTrustRef trust, dispatch_queue_t queue,
    void (^handler)(SecTrustRef, bool, CFErrorRef))
{
    char trust_json[4096];
    trust_to_json(trust, trust_json, sizeof(trust_json));

    char data[4096];
    snprintf(data, sizeof(data),
             "\"op\":\"evaluate_async\",%s", trust_json);
    sphinx_log(MOD, "trust", data);
    fprintf(stderr, "[sphinx-ssl] SecTrustEvaluateAsyncWithError (async)\n");

    if (ssl_bypass_enabled) {
        /* Wrap handler to force trust */
        void (^wrappedHandler)(SecTrustRef, bool, CFErrorRef) =
            ^(SecTrustRef t, bool result, CFErrorRef error) {
                if (!result) {
                    fprintf(stderr, "[sphinx-ssl] async trust BYPASSED\n");
                    char bypass_data[256];
                    snprintf(bypass_data, sizeof(bypass_data),
                             "\"op\":\"async_bypass\",\"originalResult\":false");
                    sphinx_log(MOD, "trust", bypass_data);
                    handler(t, true, NULL);
                } else {
                    handler(t, result, error);
                }
            };
        return orig_SecTrustEvaluateAsyncWithError(trust, queue, wrappedHandler);
    }

    return orig_SecTrustEvaluateAsyncWithError(trust, queue, handler);
}

/* ── NSURLSession delegate interception ── */

static IMP orig_didReceiveChallenge = NULL;

/*
 * Hook URLSession:didReceiveChallenge:completionHandler:
 * This is where apps implement custom certificate pinning
 */
static void hooked_didReceiveChallenge(id self, SEL _cmd, id session,
                                        id challenge, id completionHandler) {
    /* Extract challenge info */
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
    sphinx_log(MOD, "challenge", data);

    fprintf(stderr, "[sphinx-ssl] auth challenge: %s:%ld method=%s delegate=%s\n",
            host, port, method, class_getName(object_getClass(self)));

    /* Call original delegate method */
    void (*orig)(id, SEL, id, id, id) =
        (void (*)(id, SEL, id, id, id))orig_didReceiveChallenge;
    orig(self, _cmd, session, challenge, completionHandler);
}

/* ── DYLD interpose for Security framework functions ── */
struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_SecTrustEvaluateWithError,
      (const void *)SecTrustEvaluateWithError },
};

/* ── Constructor ── */
__attribute__((constructor))
static void sphinx_ssl_init(void) {
    fprintf(stderr, "[sphinx-ssl] initializing SSL interceptor\n");
    sphinx_log_init(MOD);

    orig_SecTrustEvaluateWithError = SecTrustEvaluateWithError;

    /* Check bypass env var */
    const char *bypass = getenv("SPHINX_SSL_BYPASS");
    if (bypass && bypass[0] == '1') {
        ssl_bypass_enabled = 1;
        fprintf(stderr, "[sphinx-ssl] *** SSL PINNING BYPASS ENABLED ***\n");
    }

    /* Hook SecTrustEvaluateAsyncWithError if available */
    void *sym = dlsym(RTLD_DEFAULT, "SecTrustEvaluateAsyncWithError");
    if (sym) {
        orig_SecTrustEvaluateAsyncWithError =
            (OSStatus (*)(SecTrustRef, dispatch_queue_t,
                         void (^)(SecTrustRef, bool, CFErrorRef)))sym;
        fprintf(stderr, "[sphinx-ssl] SecTrustEvaluateAsyncWithError available\n");
    }

    /* Scan for NSURLSession delegates that implement auth challenges */
    /* We'll hook the common delegate method on NSURLSession's internal classes */
    Class sessionDelegateClass = objc_getClass("__NSURLSessionLocal");
    if (sessionDelegateClass) {
        SEL challengeSel = sel_registerName(
            "URLSession:didReceiveChallenge:completionHandler:");
        Method m = class_getInstanceMethod(sessionDelegateClass, challengeSel);
        if (m) {
            orig_didReceiveChallenge = method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_didReceiveChallenge);
            fprintf(stderr, "[sphinx-ssl] hooked __NSURLSessionLocal challenge handler\n");
        }
    }

    char data[512];
    snprintf(data, sizeof(data),
             "\"hooks\":[\"SecTrustEvaluateWithError\",\"AuthChallenge\"],"
             "\"bypass\":%s",
             ssl_bypass_enabled ? "true" : "false");
    sphinx_log(MOD, "init", data);

    fprintf(stderr, "[sphinx-ssl] ready — trust evaluation%s hooked\n",
            ssl_bypass_enabled ? " + BYPASS" : "");
}
