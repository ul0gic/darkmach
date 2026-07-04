/* Local storage interceptor: NSUserDefaults, filesystem writes, pasteboard. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <fcntl.h>

#define MOD "storage"


static IMP orig_setObject_forKey = NULL;
static IMP orig_objectForKey = NULL;
static IMP orig_setBool_forKey = NULL;
static IMP orig_setInteger_forKey = NULL;

static void hooked_setObject_forKey(id self, SEL _cmd, id value, id key) {
    const char *key_c = nsobject_desc(key);
    const char *val_c = nsobject_desc(value);

    char key_esc[1024], val_esc[4096];
    json_escape(key_c, key_esc, sizeof(key_esc));
    json_escape(val_c, val_esc, sizeof(val_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"write\",\"store\":\"NSUserDefaults\",\"key\":%s,\"value\":%s",
             key_esc, val_esc);
    darkmach_log(MOD, "defaults", data);
    fprintf(stderr, "[darkmach-storage] defaults write %s\n", key_c);

    void (*orig)(id, SEL, id, id) = (void (*)(id, SEL, id, id))orig_setObject_forKey;
    orig(self, _cmd, value, key);
}

static id hooked_objectForKey(id self, SEL _cmd, id key) {
    id (*orig)(id, SEL, id) = (id (*)(id, SEL, id))orig_objectForKey;
    id result = orig(self, _cmd, key);

    const char *key_c = nsobject_desc(key);
    const char *val_c = result ? nsobject_desc(result) : "(null)";

    char key_esc[1024], val_esc[4096];
    json_escape(key_c, key_esc, sizeof(key_esc));
    json_escape(val_c, val_esc, sizeof(val_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"read\",\"store\":\"NSUserDefaults\",\"key\":%s,\"value\":%s",
             key_esc, val_esc);
    darkmach_log(MOD, "defaults", data);

    return result;
}

static void hooked_setBool_forKey(id self, SEL _cmd, BOOL value, id key) {
    const char *key_c = nsobject_desc(key);

    char key_esc[1024];
    json_escape(key_c, key_esc, sizeof(key_esc));

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"write\",\"store\":\"NSUserDefaults\",\"key\":%s,\"value\":%s",
             key_esc, value ? "true" : "false");
    darkmach_log(MOD, "defaults", data);
    fprintf(stderr, "[darkmach-storage] defaults write %s = %s\n", key_c, value ? "true" : "false");

    void (*orig)(id, SEL, BOOL, id) = (void (*)(id, SEL, BOOL, id))orig_setBool_forKey;
    orig(self, _cmd, value, key);
}

static void hooked_setInteger_forKey(id self, SEL _cmd, long value, id key) {
    const char *key_c = nsobject_desc(key);

    char key_esc[1024];
    json_escape(key_c, key_esc, sizeof(key_esc));

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"write\",\"store\":\"NSUserDefaults\",\"key\":%s,\"value\":%ld",
             key_esc, value);
    darkmach_log(MOD, "defaults", data);
    fprintf(stderr, "[darkmach-storage] defaults write %s = %ld\n", key_c, value);

    void (*orig)(id, SEL, long, id) = (void (*)(id, SEL, long, id))orig_setInteger_forKey;
    orig(self, _cmd, value, key);
}


static ssize_t (*orig_write)(int, const void *, size_t) = NULL;
static int (*orig_open)(const char *, int, ...) = NULL;

#define MAX_FD_TRACK 256
static char fd_paths[MAX_FD_TRACK][512];
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static int hooked_open(const char *path, int flags, ...) {
    int fd;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, int);
        va_end(ap);
        fd = orig_open(path, flags, mode);
    } else {
        fd = orig_open(path, flags);
    }

    if (fd >= 0 && fd < MAX_FD_TRACK && (flags & (O_WRONLY | O_RDWR))) {
        pthread_mutex_lock(&fd_mutex);
        strncpy(fd_paths[fd], path, sizeof(fd_paths[fd]) - 1);
        fd_paths[fd][sizeof(fd_paths[fd]) - 1] = '\0';
        pthread_mutex_unlock(&fd_mutex);

        char path_esc[1024];
        json_escape(path, path_esc, sizeof(path_esc));

        char data[2048];
        snprintf(data, sizeof(data),
                 "\"op\":\"open\",\"path\":%s,\"flags\":%d,\"fd\":%d",
                 path_esc, flags, fd);
        darkmach_log(MOD, "file", data);
    }

    return fd;
}

static ssize_t hooked_write(int fd, const void *buf, size_t count) {
    ssize_t result = orig_write(fd, buf, count);

    if (fd >= 3 && fd < MAX_FD_TRACK) {
        pthread_mutex_lock(&fd_mutex);
        int has_path = fd_paths[fd][0] != '\0';
        char path_copy[512] = "";
        if (has_path) strncpy(path_copy, fd_paths[fd], sizeof(path_copy) - 1);
        pthread_mutex_unlock(&fd_mutex);

        if (has_path) {
            /* Skip Darkmach's own log files */
            if (strstr(path_copy, "darkmach-") && strstr(path_copy, ".jsonl"))
                return result;

            char path_esc[1024];
            json_escape(path_copy, path_esc, sizeof(path_esc));

            char preview[512] = "null";
            if (buf && count > 0) {
                size_t plen = count > 128 ? 128 : count;
                char raw[130];
                memcpy(raw, buf, plen);
                raw[plen] = '\0';

                int printable = 1;
                for (size_t i = 0; i < plen; i++) {
                    if (((unsigned char *)raw)[i] < 0x20 &&
                        raw[i] != '\n' && raw[i] != '\r' && raw[i] != '\t') {
                        printable = 0;
                        break;
                    }
                }
                if (printable) {
                    json_escape(raw, preview, sizeof(preview));
                } else {
                    snprintf(preview, sizeof(preview), "\"<binary %zu bytes>\"", count);
                }
            }

            char data[2048];
            snprintf(data, sizeof(data),
                     "\"op\":\"write\",\"path\":%s,\"fd\":%d,\"bytes\":%zu,\"preview\":%s",
                     path_esc, fd, count, preview);
            darkmach_log(MOD, "file", data);
        }
    }

    return result;
}


static IMP orig_pasteboard_setString = NULL;
static IMP orig_pasteboard_string = NULL;

static void hooked_pasteboard_setString(id self, SEL _cmd, id string) {
    const char *str_c = nsobject_desc(string);

    char str_esc[4096];
    json_escape(str_c, str_esc, sizeof(str_esc));

    char data[4096];
    snprintf(data, sizeof(data),
             "\"op\":\"write\",\"store\":\"UIPasteboard\",\"value\":%s", str_esc);
    darkmach_log(MOD, "pasteboard", data);
    fprintf(stderr, "[darkmach-storage] pasteboard write: %s\n", str_c);

    void (*orig)(id, SEL, id) = (void (*)(id, SEL, id))orig_pasteboard_setString;
    orig(self, _cmd, string);
}

static id hooked_pasteboard_string(id self, SEL _cmd) {
    id (*orig)(id, SEL) = (id (*)(id, SEL))orig_pasteboard_string;
    id result = orig(self, _cmd);

    if (result) {
        const char *str_c = nsobject_desc(result);
        char str_esc[4096];
        json_escape(str_c, str_esc, sizeof(str_esc));

        char data[4096];
        snprintf(data, sizeof(data),
                 "\"op\":\"read\",\"store\":\"UIPasteboard\",\"value\":%s", str_esc);
        darkmach_log(MOD, "pasteboard", data);
    }

    return result;
}

/*
 * libc open/write are not interposed: dyld, libSystem, and the ObjC runtime
 * call them before constructors run, so a DYLD interpose crashes early process
 * init. The NSFileManager hooks below are the safe alternative.
 */


static IMP orig_createFileAtPath = NULL;
static IMP orig_contentsAtPath = NULL;

static BOOL hooked_createFileAtPath(id self, SEL _cmd, id path, id data, id attrs) {
    const char *path_c = nsobject_desc(path);

    char path_esc[2048];
    json_escape(path_c, path_esc, sizeof(path_esc));

    long dataLen = 0;
    if (data) {
        SEL lenSel = sel_registerName("length");
        long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        dataLen = getLen(data, lenSel);
    }

    char log_data[4096];
    snprintf(log_data, sizeof(log_data),
             "\"op\":\"createFile\",\"path\":%s,\"bytes\":%ld",
             path_esc, dataLen);
    darkmach_log(MOD, "file", log_data);
    fprintf(stderr, "[darkmach-storage] createFile %s (%ld bytes)\n", path_c, dataLen);

    BOOL (*orig)(id, SEL, id, id, id) = (BOOL (*)(id, SEL, id, id, id))orig_createFileAtPath;
    return orig(self, _cmd, path, data, attrs);
}

static id hooked_contentsAtPath(id self, SEL _cmd, id path) {
    id (*orig)(id, SEL, id) = (id (*)(id, SEL, id))orig_contentsAtPath;
    id result = orig(self, _cmd, path);

    const char *path_c = nsobject_desc(path);

    if (path_c && (strstr(path_c, "/Documents/") || strstr(path_c, "/Library/") ||
                   strstr(path_c, "/tmp/") || strstr(path_c, "/Caches/"))) {
        long dataLen = 0;
        if (result) {
            SEL lenSel = sel_registerName("length");
            long (*getLen)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
            dataLen = getLen(result, lenSel);
        }

        char path_esc[2048];
        json_escape(path_c, path_esc, sizeof(path_esc));

        char log_data[4096];
        snprintf(log_data, sizeof(log_data),
                 "\"op\":\"readFile\",\"path\":%s,\"bytes\":%ld",
                 path_esc, dataLen);
        darkmach_log(MOD, "file", log_data);
    }

    return result;
}


static IMP orig_setCookie = NULL;
static IMP orig_cookies = NULL;
static IMP orig_cookiesForURL = NULL;

static void hooked_setCookie(id self, SEL _cmd, id cookie) {
    if (cookie) {
        SEL nameSel = sel_registerName("name");
        SEL valueSel = sel_registerName("value");
        SEL domainSel = sel_registerName("domain");
        SEL pathSel = sel_registerName("path");
        SEL secureSel = sel_registerName("isSecure");
        SEL httpOnlySel = sel_registerName("isHTTPOnly");

        id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        BOOL (*getBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;

        const char *name = nsobject_desc(get(cookie, nameSel));
        const char *value = nsobject_desc(get(cookie, valueSel));
        const char *domain = nsobject_desc(get(cookie, domainSel));
        const char *cpath = nsobject_desc(get(cookie, pathSel));
        BOOL secure = getBool(cookie, secureSel);
        BOOL httpOnly = getBool(cookie, httpOnlySel);

        char name_esc[256], value_esc[2048], domain_esc[512];
        json_escape(name, name_esc, sizeof(name_esc));
        json_escape(value, value_esc, sizeof(value_esc));
        json_escape(domain, domain_esc, sizeof(domain_esc));

        char log_data[4096];
        snprintf(log_data, sizeof(log_data),
                 "\"op\":\"setCookie\",\"name\":%s,\"value\":%s,"
                 "\"domain\":%s,\"path\":\"%s\",\"secure\":%s,\"httpOnly\":%s",
                 name_esc, value_esc, domain_esc, cpath,
                 secure ? "true" : "false", httpOnly ? "true" : "false");
        darkmach_log(MOD, "cookie", log_data);
        fprintf(stderr, "[darkmach-storage] setCookie %s=%s domain=%s\n",
                name, value, domain);
    }

    void (*orig)(id, SEL, id) = (void (*)(id, SEL, id))orig_setCookie;
    orig(self, _cmd, cookie);
}

static id hooked_cookies(id self, SEL _cmd) {
    id (*orig)(id, SEL) = (id (*)(id, SEL))orig_cookies;
    id result = orig(self, _cmd);

    if (result) {
        SEL countSel = sel_registerName("count");
        long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
        long count = getCount(result, countSel);

        if (count > 0) {
            char log_data[512];
            snprintf(log_data, sizeof(log_data),
                     "\"op\":\"readAllCookies\",\"count\":%ld", count);
            darkmach_log(MOD, "cookie", log_data);
        }
    }

    return result;
}

static id hooked_cookiesForURL(id self, SEL _cmd, id url) {
    id (*orig)(id, SEL, id) = (id (*)(id, SEL, id))orig_cookiesForURL;
    id result = orig(self, _cmd, url);

    SEL absSel = sel_registerName("absoluteString");
    id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    const char *url_c = nsobject_desc(get(url, absSel));

    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long count = result ? getCount(result, countSel) : 0;

    char url_esc[2048];
    json_escape(url_c, url_esc, sizeof(url_esc));

    char log_data[4096];
    snprintf(log_data, sizeof(log_data),
             "\"op\":\"cookiesForURL\",\"url\":%s,\"count\":%ld", url_esc, count);
    darkmach_log(MOD, "cookie", log_data);

    return result;
}

__attribute__((constructor))
static void darkmach_storage_init(void) {
    fprintf(stderr, "[darkmach-storage] initializing storage interceptor\n");
    darkmach_log_init(MOD);

    Class udClass = objc_getClass("NSUserDefaults");
    if (udClass) {
        SEL sel1 = sel_registerName("setObject:forKey:");
        Method m1 = class_getInstanceMethod(udClass, sel1);
        if (m1) {
            orig_setObject_forKey = method_getImplementation(m1);
            method_setImplementation(m1, (IMP)hooked_setObject_forKey);
        }

        SEL sel2 = sel_registerName("objectForKey:");
        Method m2 = class_getInstanceMethod(udClass, sel2);
        if (m2) {
            orig_objectForKey = method_getImplementation(m2);
            method_setImplementation(m2, (IMP)hooked_objectForKey);
        }

        SEL sel3 = sel_registerName("setBool:forKey:");
        Method m3 = class_getInstanceMethod(udClass, sel3);
        if (m3) {
            orig_setBool_forKey = method_getImplementation(m3);
            method_setImplementation(m3, (IMP)hooked_setBool_forKey);
        }

        SEL sel4 = sel_registerName("setInteger:forKey:");
        Method m4 = class_getInstanceMethod(udClass, sel4);
        if (m4) {
            orig_setInteger_forKey = method_getImplementation(m4);
            method_setImplementation(m4, (IMP)hooked_setInteger_forKey);
        }

        fprintf(stderr, "[darkmach-storage] hooked NSUserDefaults (4 methods)\n");
    }

    Class pbClass = objc_getClass("UIPasteboard");
    if (pbClass) {
        SEL sel5 = sel_registerName("setString:");
        Method m5 = class_getInstanceMethod(pbClass, sel5);
        if (m5) {
            orig_pasteboard_setString = method_getImplementation(m5);
            method_setImplementation(m5, (IMP)hooked_pasteboard_setString);
        }

        SEL sel6 = sel_registerName("string");
        Method m6 = class_getInstanceMethod(pbClass, sel6);
        if (m6) {
            orig_pasteboard_string = method_getImplementation(m6);
            method_setImplementation(m6, (IMP)hooked_pasteboard_string);
        }

        fprintf(stderr, "[darkmach-storage] hooked UIPasteboard (2 methods)\n");
    }

    Class fmClass = objc_getClass("NSFileManager");
    if (fmClass) {
        SEL sel7 = sel_registerName("createFileAtPath:contents:attributes:");
        Method m7 = class_getInstanceMethod(fmClass, sel7);
        if (m7) {
            orig_createFileAtPath = method_getImplementation(m7);
            method_setImplementation(m7, (IMP)hooked_createFileAtPath);
        }

        SEL sel8 = sel_registerName("contentsAtPath:");
        Method m8 = class_getInstanceMethod(fmClass, sel8);
        if (m8) {
            orig_contentsAtPath = method_getImplementation(m8);
            method_setImplementation(m8, (IMP)hooked_contentsAtPath);
        }

        fprintf(stderr, "[darkmach-storage] hooked NSFileManager (2 methods)\n");
    }

    Class cookieClass = objc_getClass("NSHTTPCookieStorage");
    if (cookieClass) {
        SEL sel9 = sel_registerName("setCookie:");
        Method m9 = class_getInstanceMethod(cookieClass, sel9);
        if (m9) {
            orig_setCookie = method_getImplementation(m9);
            method_setImplementation(m9, (IMP)hooked_setCookie);
        }

        SEL sel10 = sel_registerName("cookies");
        Method m10 = class_getInstanceMethod(cookieClass, sel10);
        if (m10) {
            orig_cookies = method_getImplementation(m10);
            method_setImplementation(m10, (IMP)hooked_cookies);
        }

        SEL sel11 = sel_registerName("cookiesForURL:");
        Method m11 = class_getInstanceMethod(cookieClass, sel11);
        if (m11) {
            orig_cookiesForURL = method_getImplementation(m11);
            method_setImplementation(m11, (IMP)hooked_cookiesForURL);
        }

        fprintf(stderr, "[darkmach-storage] hooked NSHTTPCookieStorage (3 methods)\n");
    }

    darkmach_log(MOD, "init",
               "\"hooks\":[\"NSUserDefaults(4)\","
               "\"UIPasteboard(2)\","
               "\"NSFileManager(2)\","
               "\"NSHTTPCookieStorage(3)\"]");
    fprintf(stderr, "[darkmach-storage] ready — defaults + pasteboard + files + cookies hooked\n");
}
