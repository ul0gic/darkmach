/* Keychain interceptor: SecItem add/read/update/delete hooks. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <Security/Security.h>

#define MOD "keychain"

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef) = NULL;
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef) = NULL;

static void query_to_json(CFDictionaryRef query, char *buf, size_t bufsize) {
    if (!query) { snprintf(buf, bufsize, "{}"); return; }

    id dict = (id)query;
    SEL objectForKeySel = sel_registerName("objectForKey:");
    id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;

    id service = getObj(dict, objectForKeySel, (id)kSecAttrService);
    id account = getObj(dict, objectForKeySel, (id)kSecAttrAccount);
    id group = getObj(dict, objectForKeySel, (id)kSecAttrAccessGroup);
    id label = getObj(dict, objectForKeySel, (id)kSecAttrLabel);
    id secClass = getObj(dict, objectForKeySel, (id)kSecClass);

    char svc_esc[512] = "null", acct_esc[512] = "null";
    char grp_esc[512] = "null", lbl_esc[512] = "null";
    char cls_esc[256] = "null";

    if (service) json_escape(nsobject_desc(service), svc_esc, sizeof(svc_esc));
    if (account) json_escape(nsobject_desc(account), acct_esc, sizeof(acct_esc));
    if (group)   json_escape(nsobject_desc(group), grp_esc, sizeof(grp_esc));
    if (label)   json_escape(nsobject_desc(label), lbl_esc, sizeof(lbl_esc));
    if (secClass) json_escape(nsobject_desc(secClass), cls_esc, sizeof(cls_esc));

    snprintf(buf, bufsize,
             "\"service\":%s,\"account\":%s,\"group\":%s,\"label\":%s,\"class\":%s",
             svc_esc, acct_esc, grp_esc, lbl_esc, cls_esc);
}

static void result_to_json(CFTypeRef result, char *buf, size_t bufsize) {
    if (!result) { snprintf(buf, bufsize, "null"); return; }

    id obj = (id)result;

    SEL isKindSel = sel_registerName("isKindOfClass:");
    BOOL (*isKind)(id, SEL, Class) = (BOOL (*)(id, SEL, Class))objc_msgSend;
    if (isKind(obj, isKindSel, objc_getClass("NSData"))) {
        SEL lenSel = sel_registerName("length");
        SEL bytesSel = sel_registerName("bytes");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        const unsigned char *(*getBytes)(id, SEL) =
            (const unsigned char *(*)(id, SEL))objc_msgSend;

        long len = getLen(obj, lenSel);
        const unsigned char *bytes = getBytes(obj, bytesSel);

        if (bytes && len > 0 && len < 4096) {
            char *attempt = malloc(len + 1);
            memcpy(attempt, bytes, len);
            attempt[len] = '\0';

            int printable = 1;
            for (long i = 0; i < len; i++) {
                if (bytes[i] < 0x20 && bytes[i] != '\n' && bytes[i] != '\r' && bytes[i] != '\t') {
                    printable = 0;
                    break;
                }
            }

            if (printable) {
                json_escape(attempt, buf, bufsize);
            } else {
                size_t pos = 0;
                pos += snprintf(buf + pos, bufsize - pos, "\"hex:");
                long log_len = len > 128 ? 128 : len;
                for (long i = 0; i < log_len && pos < bufsize - 4; i++) {
                    pos += snprintf(buf + pos, bufsize - pos, "%02x", bytes[i]);
                }
                if (len > 128) pos += snprintf(buf + pos, bufsize - pos, "...");
                snprintf(buf + pos, bufsize - pos, "\"");
            }
            free(attempt);
        } else {
            snprintf(buf, bufsize, "\"<data %ld bytes>\"", len);
        }
    }
    else if (isKind(obj, isKindSel, objc_getClass("NSDictionary"))) {
        SEL objectForKeySel = sel_registerName("objectForKey:");
        id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
        id valueData = getObj(obj, objectForKeySel, (id)kSecValueData);
        if (valueData) {
            result_to_json((CFTypeRef)valueData, buf, bufsize);
        } else {
            json_escape(nsobject_desc(obj), buf, bufsize);
        }
    }
    else if (isKind(obj, isKindSel, objc_getClass("NSArray"))) {
        SEL countSel = sel_registerName("count");
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        snprintf(buf, bufsize, "\"<array %ld items>\"", getCount(obj, countSel));
    }
    else {
        json_escape(nsobject_desc(obj), buf, bufsize);
    }
}

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    if (!orig_SecItemAdd) return errSecUnimplemented;

    char query_json[2048];
    query_to_json(attributes, query_json, sizeof(query_json));

    OSStatus status = orig_SecItemAdd(attributes, result);

    char data[4096];
    snprintf(data, sizeof(data), "\"op\":\"add\",\"status\":%d,%s", (int)status, query_json);
    darkmach_log(MOD, "secitem", data);
    fprintf(stderr, "[darkmach-keychain] SecItemAdd status=%d\n", (int)status);

    return status;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!orig_SecItemCopyMatching) return errSecUnimplemented;

    char query_json[2048];
    query_to_json(query, query_json, sizeof(query_json));

    OSStatus status = orig_SecItemCopyMatching(query, result);

    char result_json[4096] = "null";
    if (status == errSecSuccess && result && *result) {
        result_to_json(*result, result_json, sizeof(result_json));
    }

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"read\",\"status\":%d,%s,\"result\":%s",
             (int)status, query_json, result_json);
    darkmach_log(MOD, "secitem", data);
    fprintf(stderr, "[darkmach-keychain] SecItemCopyMatching status=%d\n", (int)status);

    return status;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    if (!orig_SecItemUpdate) return errSecUnimplemented;

    char query_json[2048];
    query_to_json(query, query_json, sizeof(query_json));

    OSStatus status = orig_SecItemUpdate(query, attrs);

    char data[4096];
    snprintf(data, sizeof(data), "\"op\":\"update\",\"status\":%d,%s", (int)status, query_json);
    darkmach_log(MOD, "secitem", data);
    fprintf(stderr, "[darkmach-keychain] SecItemUpdate status=%d\n", (int)status);

    return status;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    if (!orig_SecItemDelete) return errSecUnimplemented;

    char query_json[2048];
    query_to_json(query, query_json, sizeof(query_json));

    OSStatus status = orig_SecItemDelete(query);

    char data[4096];
    snprintf(data, sizeof(data), "\"op\":\"delete\",\"status\":%d,%s", (int)status, query_json);
    darkmach_log(MOD, "secitem", data);
    fprintf(stderr, "[darkmach-keychain] SecItemDelete status=%d\n", (int)status);

    return status;
}


struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_SecItemAdd,          (const void *)SecItemAdd },
    { (const void *)hooked_SecItemCopyMatching,  (const void *)SecItemCopyMatching },
    { (const void *)hooked_SecItemUpdate,        (const void *)SecItemUpdate },
    { (const void *)hooked_SecItemDelete,        (const void *)SecItemDelete },
};

__attribute__((constructor))
static void darkmach_keychain_init(void) {
    fprintf(stderr, "[darkmach-keychain] initializing keychain interceptor\n");
    darkmach_log_init(MOD);

    orig_SecItemAdd = SecItemAdd;
    orig_SecItemCopyMatching = SecItemCopyMatching;
    orig_SecItemUpdate = SecItemUpdate;
    orig_SecItemDelete = SecItemDelete;

    darkmach_log(MOD, "init",
               "\"hooks\":[\"SecItemAdd\",\"SecItemCopyMatching\",\"SecItemUpdate\",\"SecItemDelete\"]");
    fprintf(stderr, "[darkmach-keychain] ready — 4 SecItem functions hooked\n");
}
