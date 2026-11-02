/* Data dump commands. Unity build: #included from darkmach-bridge.c */
#include "darkmach-bridge.h"
#include <sqlite3.h>
#include <dirent.h>
#include <sys/stat.h>
#include <os/lock.h>


static void cmd_keychain_dump(const char *args, resp_t *r) {
    const void *secClasses[] = {
        kSecClassGenericPassword,
        kSecClassInternetPassword,
        kSecClassCertificate,
        kSecClassKey,
        kSecClassIdentity
    };
    const char *classNames[] = {
        "GenericPassword", "InternetPassword", "Certificate", "Key", "Identity"
    };

    resp_append(r, "\"items\":[");
    int total = 0;

    for (int c = 0; c < 5; c++) {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(
            NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, secClasses[c]);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching(query, &result);

        if (status != errSecSuccess) {
            CFDictionaryRemoveValue(query, kSecReturnData);
            status = SecItemCopyMatching(query, &result);
        }

        if (status != errSecSuccess) {
            CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
            status = SecItemCopyMatching(query, &result);
        }

        if (status == errSecSuccess && result) {
            id arr = (id)result;
            SEL countSel = sel_registerName("count");
            long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;

            if (darkmach_isKindOfClass(arr, "NSArray")) {
                long count = getCount(arr, countSel);
                SEL indexSel = sel_registerName("objectAtIndex:");
                id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

                for (long i = 0; i < count; i++) {
                    id item = getAt(arr, indexSel, (unsigned long)i);
                    if (total > 0) resp_append(r, ",");
                    resp_append(r, "{\"class\":\"%s\",\"data\":", classNames[c]);
                    resp_append_json_str(r, nsobject_desc(item));
                    resp_append(r, "}");
                    total++;
                }
            }
            CFRelease(result);
        }
        CFRelease(query);
    }

    resp_append(r, "],\"count\":%d", total);
}


static void cmd_userdefaults_dump(const char *args, resp_t *r) {
    Class udClass = objc_getClass("NSUserDefaults");
    SEL stdSel = sel_registerName("standardUserDefaults");
    id (*getStd)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id defaults = getStd((id)udClass, stdSel);

    SEL dictSel = sel_registerName("dictionaryRepresentation");
    id (*getDict)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id dict = getDict(defaults, dictSel);

    SEL allKeysSel = sel_registerName("allKeys");
    id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id keys = getKeys(dict, allKeysSel);

    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long count = getCount(keys, countSel);

    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

    SEL objectForKeySel = sel_registerName("objectForKey:");
    id (*getObj)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;

    resp_append(r, "\"entries\":[");
    for (long i = 0; i < count; i++) {
        id key = getAt(keys, indexSel, (unsigned long)i);
        id val = getObj(dict, objectForKeySel, key);

        if (i > 0) resp_append(r, ",");
        resp_append(r, "{\"key\":");
        resp_append_json_str(r, nsobject_desc(key));
        resp_append(r, ",\"value\":");
        resp_append_json_str(r, val ? nsobject_desc(val) : "(null)");
        resp_append(r, ",\"type\":");
        resp_append_json_str(r, val ? class_getName(object_getClass(val)) : "nil");
        resp_append(r, "}");
    }
    resp_append(r, "],\"count\":%ld", count);
}


static void cmd_cookies_dump(const char *args, resp_t *r) {
    Class csClass = objc_getClass("NSHTTPCookieStorage");
    SEL sharedSel = sel_registerName("sharedHTTPCookieStorage");
    id (*getShared)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id storage = getShared((id)csClass, sharedSel);

    SEL cookiesSel = sel_registerName("cookies");
    id (*getCookies)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id cookies = getCookies(storage, cookiesSel);

    SEL countSel = sel_registerName("count");
    long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
    long count = cookies ? getCount(cookies, countSel) : 0;

    SEL indexSel = sel_registerName("objectAtIndex:");
    id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

    resp_append(r, "\"cookies\":[");
    for (long i = 0; i < count; i++) {
        id cookie = getAt(cookies, indexSel, (unsigned long)i);
        id (*get)(id, SEL) = (id (*)(id, SEL))objc_msgSend;

        id name = get(cookie, sel_registerName("name"));
        id value = get(cookie, sel_registerName("value"));
        id domain = get(cookie, sel_registerName("domain"));
        id path = get(cookie, sel_registerName("path"));

        if (i > 0) resp_append(r, ",");
        resp_append(r, "{\"name\":");
        resp_append_json_str(r, nsobject_desc(name));
        resp_append(r, ",\"value\":");
        resp_append_json_str(r, nsobject_desc(value));
        resp_append(r, ",\"domain\":");
        resp_append_json_str(r, nsobject_desc(domain));
        resp_append(r, ",\"path\":");
        resp_append_json_str(r, nsobject_desc(path));
        resp_append(r, "}");
    }
    resp_append(r, "],\"count\":%ld", count);
}


static void find_db_files(const char *dir, char db_paths[][1024], int *count, int max) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && *count < max) {
        if (entry->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, entry->d_name);
        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            find_db_files(full, db_paths, count, max);
        } else {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && (strcmp(ext, ".db") == 0 || strcmp(ext, ".sqlite") == 0 ||
                        strcmp(ext, ".sqlite3") == 0 || strcmp(ext, ".sql") == 0)) {
                strncpy(db_paths[*count], full, 1023);
                db_paths[*count][1023] = '\0';
                (*count)++;
            }
        }
    }
    closedir(d);
}

static void cmd_db_dump(const char *args, resp_t *r) {
    char table_filter[256] = "";
    json_get_string(args, "table", table_filter, sizeof(table_filter));

    Class bundleClass = objc_getClass("NSBundle");
    SEL mainSel = sel_registerName("mainBundle");
    id (*getMain)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id bundle = getMain((id)bundleClass, mainSel);
    SEL pathSel = sel_registerName("bundlePath");
    id (*getPath)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id bundlePath = getPath(bundle, pathSel);

    Class fmClass = objc_getClass("NSFileManager");
    SEL defSel = sel_registerName("defaultManager");
    id (*getFM)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    id fm = getFM((id)fmClass, defSel);

    id (*homeDir)(void) = (id (*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
    const char *home = "(unknown)";
    if (homeDir) {
        id hd = homeDir();
        if (hd) home = nsstring_to_c(hd);
    }

    char (*db_paths)[1024] = calloc(64, 1024);
    int db_count = 0;
    find_db_files(home, db_paths, &db_count, 64);

    resp_append(r, "\"home\":");
    resp_append_json_str(r, home);
    resp_append(r, ",\"databases\":[");

    for (int di = 0; di < db_count; di++) {
        if (di > 0) resp_append(r, ",");
        resp_append(r, "{\"path\":");
        resp_append_json_str(r, db_paths[di]);

        sqlite3 *db = NULL;
        int rc = sqlite3_open_v2(db_paths[di], &db, SQLITE_OPEN_READONLY, NULL);
        if (rc != SQLITE_OK) {
            resp_append(r, ",\"error\":");
            resp_append_json_str(r, sqlite3_errmsg(db));
            resp_append(r, "}");
            if (db) sqlite3_close(db);
            continue;
        }

        resp_append(r, ",\"tables\":[");
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", -1, &stmt, NULL);
        int first_table = 1;
        while (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
            const char *tname = (const char *)sqlite3_column_text(stmt, 0);
            if (!tname) continue;
            if (table_filter[0] && !strstr(tname, table_filter)) continue;

            if (!first_table) resp_append(r, ",");
            first_table = 0;
            resp_append(r, "{\"name\":");
            resp_append_json_str(r, tname);

            char schema_sql[512];
            snprintf(schema_sql, sizeof(schema_sql), "PRAGMA table_info(\"%s\")", tname);
            sqlite3_stmt *schema_stmt = NULL;
            sqlite3_prepare_v2(db, schema_sql, -1, &schema_stmt, NULL);
            resp_append(r, ",\"columns\":[");
            int first_col = 1;
            while (sqlite3_step(schema_stmt) == SQLITE_ROW) {
                if (!first_col) resp_append(r, ",");
                first_col = 0;
                const char *cname = (const char *)sqlite3_column_text(schema_stmt, 1);
                const char *ctype = (const char *)sqlite3_column_text(schema_stmt, 2);
                int pk = sqlite3_column_int(schema_stmt, 5);
                resp_append(r, "{\"name\":");
                resp_append_json_str(r, cname ? cname : "?");
                resp_append(r, ",\"type\":");
                resp_append_json_str(r, ctype ? ctype : "?");
                if (pk) resp_append(r, ",\"pk\":true");
                resp_append(r, "}");
            }
            sqlite3_finalize(schema_stmt);
            resp_append(r, "]");

            char count_sql[256];
            snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM \"%s\"", tname);
            sqlite3_stmt *count_stmt = NULL;
            int row_count = 0;
            if (sqlite3_prepare_v2(db, count_sql, -1, &count_stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(count_stmt) == SQLITE_ROW)
                    row_count = sqlite3_column_int(count_stmt, 0);
                sqlite3_finalize(count_stmt);
            }
            resp_append(r, ",\"row_count\":%d", row_count);

            char data_sql[256];
            snprintf(data_sql, sizeof(data_sql), "SELECT * FROM \"%s\" LIMIT 100", tname);
            sqlite3_stmt *data_stmt = NULL;
            if (sqlite3_prepare_v2(db, data_sql, -1, &data_stmt, NULL) == SQLITE_OK) {
                resp_append(r, ",\"rows\":[");
                int first_row = 1;
                int ncols = sqlite3_column_count(data_stmt);
                while (sqlite3_step(data_stmt) == SQLITE_ROW) {
                    if (!first_row) resp_append(r, ",");
                    first_row = 0;
                    resp_append(r, "{");
                    for (int c = 0; c < ncols; c++) {
                        if (c > 0) resp_append(r, ",");
                        const char *cn = sqlite3_column_name(data_stmt, c);
                        resp_append_json_str(r, cn ? cn : "?");
                        resp_append(r, ":");
                        int ctype = sqlite3_column_type(data_stmt, c);
                        if (ctype == SQLITE_NULL) {
                            resp_append(r, "null");
                        } else if (ctype == SQLITE_INTEGER) {
                            resp_append(r, "%lld", sqlite3_column_int64(data_stmt, c));
                        } else if (ctype == SQLITE_FLOAT) {
                            resp_append(r, "%f", sqlite3_column_double(data_stmt, c));
                        } else if (ctype == SQLITE_BLOB) {
                            int blen = sqlite3_column_bytes(data_stmt, c);
                            resp_append(r, "\"<blob %d bytes>\"", blen);
                        } else {
                            const char *tv = (const char *)sqlite3_column_text(data_stmt, c);
                            resp_append_json_str(r, tv ? tv : "");
                        }
                    }
                    resp_append(r, "}");
                    if (r->len > BRIDGE_MAX_RESPONSE - 4096) break;
                }
                resp_append(r, "]");
                sqlite3_finalize(data_stmt);
            }

            resp_append(r, "}");
            if (r->len > BRIDGE_MAX_RESPONSE - 4096) break;
        }
        if (stmt) sqlite3_finalize(stmt);
        sqlite3_close(db);
        resp_append(r, "]}");
    }
    resp_append(r, "]");
    free(db_paths);
}


static darkmach_ring_t event_ring;
static int event_ring_initialized = 0;
static id event_observer = NULL;  /* retained observer token from NSNotificationCenter */
static char event_name_filter[256] = "";  /* capture-time filter */

static void cmd_event_tap(const char *args, resp_t *r) {
    char action[64] = "recent";
    json_get_string(args, "action", action, sizeof(action));

    if (!event_ring_initialized) {
        darkmach_ring_init(&event_ring);
        event_ring_initialized = 1;
    }

    if (strcmp(action, "enable") == 0) {
        json_get_string(args, "name_filter", event_name_filter, sizeof(event_name_filter));

        if (event_observer) {
            Class ncClass = objc_getClass("NSNotificationCenter");
            SEL defSel = sel_registerName("defaultCenter");
            id (*getCenter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id center = getCenter((id)ncClass, defSel);

            SEL removeSel = sel_registerName("removeObserver:");
            void (*removeObs)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
            removeObs(center, removeSel, event_observer);
            event_observer = NULL;
        }

        Class ncClass = objc_getClass("NSNotificationCenter");
        SEL defSel = sel_registerName("defaultCenter");
        id (*getCenter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
        id center = getCenter((id)ncClass, defSel);

        SEL addSel = sel_registerName("addObserverForName:object:queue:usingBlock:");
        id (*addObs)(id, SEL, id, id, id, void(^)(id)) =
            (id (*)(id, SEL, id, id, id, void(^)(id)))objc_msgSend;

        event_observer = addObs(center, addSel, nil, nil, nil, ^(id notification) {
            SEL nameSel = sel_registerName("name");
            id (*getName)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id nameObj = getName(notification, nameSel);
            const char *name = nameObj ? nsstring_to_c(nameObj) : "(null)";

            if (event_name_filter[0] && !strstr(name, event_name_filter)) return;

            SEL objSel = sel_registerName("object");
            id (*getObj)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id postingObj = getObj(notification, objSel);
            const char *obj_class = postingObj ? class_getName(object_getClass(postingObj)) : "nil";

            SEL uiSel = sel_registerName("userInfo");
            id (*getUI)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id userInfo = getUI(notification, uiSel);

            char keys_buf[2048] = "";
            if (userInfo) {
                SEL allKeysSel = sel_registerName("allKeys");
                id (*getKeys)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
                id keys = getKeys(userInfo, allKeysSel);

                SEL countSel = sel_registerName("count");
                long (*getCount)(id, SEL) = (long (*)(id, SEL))objc_msgSend;
                long kcount = getCount(keys, countSel);

                SEL indexSel = sel_registerName("objectAtIndex:");
                id (*getAt)(id, SEL, unsigned long) = (id (*)(id, SEL, unsigned long))objc_msgSend;

                size_t pos = 0;
                for (long k = 0; k < kcount && k < 20; k++) {
                    id key = getAt(keys, indexSel, (unsigned long)k);
                    const char *keyStr = nsstring_to_c(key);
                    if (k > 0 && pos < sizeof(keys_buf) - 2) {
                        keys_buf[pos++] = ',';
                    }
                    char esc_key[256];
                    json_escape(keyStr, esc_key, sizeof(esc_key));
                    size_t elen = strlen(esc_key);
                    if (pos + elen < sizeof(keys_buf) - 1) {
                        memcpy(keys_buf + pos, esc_key, elen);
                        pos += elen;
                    }
                }
                keys_buf[pos] = '\0';
            }

            struct timeval tv;
            gettimeofday(&tv, NULL);
            struct tm tm;
            localtime_r(&tv.tv_sec, &tm);
            char ts[64];
            snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
                     tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec/1000));

            char entry[DARKMACH_RING_ENTRY_SIZE];
            char esc_name[512], esc_class[256];
            json_escape(name, esc_name, sizeof(esc_name));
            json_escape(obj_class, esc_class, sizeof(esc_class));
            snprintf(entry, sizeof(entry),
                     "{\"name\":%s,\"object_class\":%s,\"user_info_keys\":[%s],\"timestamp\":\"%s\"}",
                     esc_name, esc_class, keys_buf, ts);
            darkmach_ring_push(&event_ring, entry);
        });

        if (event_observer) {
            SEL retainSel = sel_registerName("retain");
            id (*retain)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            retain(event_observer, retainSel);
        }

        resp_append(r, "\"enabled\":true,\"name_filter\":");
        resp_append_json_str(r, event_name_filter);

    } else if (strcmp(action, "disable") == 0) {
        if (event_observer) {
            Class ncClass = objc_getClass("NSNotificationCenter");
            SEL defSel = sel_registerName("defaultCenter");
            id (*getCenter)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id center = getCenter((id)ncClass, defSel);

            SEL removeSel = sel_registerName("removeObserver:");
            void (*removeObs)(id, SEL, id) = (void (*)(id, SEL, id))objc_msgSend;
            removeObs(center, removeSel, event_observer);

            SEL releaseSel = sel_registerName("release");
            void (*release)(id, SEL) = (void (*)(id, SEL))objc_msgSend;
            release(event_observer, releaseSel);
            event_observer = NULL;
        }
        event_name_filter[0] = '\0';

        resp_append(r, "\"disabled\":true,\"total_captured\":%d", event_ring.total);

    } else {
        char query_filter[256] = "";
        json_get_string(args, "name_filter", query_filter, sizeof(query_filter));
        long limit = json_get_long(args, "limit");
        if (limit <= 0) limit = 50;

        resp_append(r, "\"events\":[");
        int returned = 0;
        for (int i = 0; i < event_ring.count && returned < limit; i++) {
            const char *entry = darkmach_ring_get(&event_ring, i);
            if (!entry) continue;

            if (query_filter[0] && !strstr(entry, query_filter)) continue;

            if (returned > 0) resp_append(r, ",");
            resp_append(r, "%s", entry);
            returned++;
        }
        resp_append(r, "],\"total_captured\":%d,\"returned\":%d",
                    event_ring.total, returned);
    }
}


static void cmd_db_query(const char *args, resp_t *r) {
    char path[1024] = "";
    char sql[4096] = "";

    if (!json_get_string(args, "path", path, sizeof(path)) || !path[0]) {
        resp_append(r, "\"error\":\"missing path arg\"");
        return;
    }
    if (!json_get_string(args, "sql", sql, sizeof(sql)) || !sql[0]) {
        resp_append(r, "\"error\":\"missing sql arg\"");
        return;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        if (db) sqlite3_close(db);
        db = NULL;
        rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
    }
    if (rc != SQLITE_OK) {
        resp_append(r, "\"error\":");
        resp_append_json_str(r, db ? sqlite3_errmsg(db) : "failed to open database");
        if (db) sqlite3_close(db);
        return;
    }

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        resp_append(r, "\"error\":");
        resp_append_json_str(r, sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    int ncols = sqlite3_column_count(stmt);
    if (ncols > 0) {
        resp_append(r, "\"columns\":[");
        for (int c = 0; c < ncols; c++) {
            if (c > 0) resp_append(r, ",");
            const char *cname = sqlite3_column_name(stmt, c);
            resp_append_json_str(r, cname ? cname : "?");
        }
        resp_append(r, "],\"rows\":[");

        int row_count = 0;
        int truncated = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && row_count < 500) {
            if (row_count > 0) resp_append(r, ",");
            resp_append(r, "[");
            for (int c = 0; c < ncols; c++) {
                if (c > 0) resp_append(r, ",");
                int ctype = sqlite3_column_type(stmt, c);
                if (ctype == SQLITE_NULL) {
                    resp_append(r, "null");
                } else if (ctype == SQLITE_INTEGER) {
                    resp_append(r, "%lld", sqlite3_column_int64(stmt, c));
                } else if (ctype == SQLITE_FLOAT) {
                    resp_append(r, "%g", sqlite3_column_double(stmt, c));
                } else if (ctype == SQLITE_BLOB) {
                    int blen = sqlite3_column_bytes(stmt, c);
                    resp_append(r, "\"<blob %d bytes>\"", blen);
                } else {
                    const char *tv = (const char *)sqlite3_column_text(stmt, c);
                    resp_append_json_str(r, tv ? tv : "");
                }
            }
            resp_append(r, "]");
            row_count++;
            if (r->len > BRIDGE_MAX_RESPONSE - 4096) { truncated = 1; break; }
        }
        if (!truncated && sqlite3_step(stmt) == SQLITE_ROW) truncated = 1;

        resp_append(r, "],\"row_count\":%d", row_count);
        if (truncated) resp_append(r, ",\"truncated\":true");
    } else {
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            resp_append(r, "\"error\":");
            resp_append_json_str(r, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return;
        }
        int affected = sqlite3_changes(db);
        long long last_id = sqlite3_last_insert_rowid(db);
        resp_append(r, "\"affected\":%d,\"last_insert_id\":%lld", affected, last_id);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}


/* Entry budget: these sum to 2372 of DARKMACH_RING_ENTRY_SIZE, so a capture can
 * never truncate into invalid JSON. */
#define DB_OP_MAX   32
#define DB_PATH_MAX 128
#define DB_SQL_MAX  2048

static darkmach_ring_t db_query_ring;
static int db_query_ring_initialized = 0;
static int db_rows_merged = 0;
static os_unfair_lock db_query_lock = OS_UNFAIR_LOCK_INIT;
static unsigned long db_entry_sids[DARKMACH_RING_CAPACITY];

static void db_query_ensure_init_locked(void) {
    if (db_query_ring_initialized) return;
    darkmach_ring_init(&db_query_ring);
    memset(db_entry_sids, 0, sizeof(db_entry_sids));
    db_query_ring_initialized = 1;
}

static void db_timestamp(char *buf, size_t bufsz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    snprintf(buf, bufsz, "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}


/* Called by darkmach-db.dylib, which owns the sqlite3 interposes. Statement ids
 * come from its stmt_map and are the join key for darkmach_db_record_rows. */
__attribute__((visibility("default")))
void darkmach_db_record_query(const char *op, unsigned long sid, const char *path,
                              const char *sql, int rc)
{
    char ts[64];
    db_timestamp(ts, sizeof(ts));

    char op_esc[DB_OP_MAX], path_esc[DB_PATH_MAX], sql_esc[DB_SQL_MAX];
    json_escape(op ? op : "query", op_esc, sizeof(op_esc));
    json_escape(path ? path : "(unknown)", path_esc, sizeof(path_esc));
    json_escape(sql ? sql : "", sql_esc, sizeof(sql_esc));

    char entry[DARKMACH_RING_ENTRY_SIZE];
    snprintf(entry, sizeof(entry),
             "{\"op\":%s,\"sid\":%lu,\"path\":%s,\"sql\":%s,\"rc\":%d,"
             "\"rows\":0,\"rows_total\":0,\"timestamp\":\"%s\"}",
             op_esc, sid, path_esc, sql_esc, rc, ts);

    os_unfair_lock_lock(&db_query_lock);
    db_query_ensure_init_locked();
    darkmach_ring_push(&db_query_ring, entry);
    int slot = (db_query_ring.head - 1 + DARKMACH_RING_CAPACITY) % DARKMACH_RING_CAPACITY;
    db_entry_sids[slot] = sid;
    os_unfair_lock_unlock(&db_query_lock);
}


/* Spliced onto the entry the prepare pushed, not pushed as rows: a statement
 * stepping thousands of times would otherwise evict the whole ring. */
__attribute__((visibility("default")))
void darkmach_db_record_rows(unsigned long sid, long rows, long total)
{
    if (sid == 0) return;

    os_unfair_lock_lock(&db_query_lock);
    db_query_ensure_init_locked();

    for (int slot = 0; slot < DARKMACH_RING_CAPACITY; slot++) {
        if (db_entry_sids[slot] != sid) continue;

        char *entry = db_query_ring.entries[slot];
        char *tail = strstr(entry, ",\"rows\":");
        if (!tail) break;
        *tail = '\0';

        char ts[64];
        db_timestamp(ts, sizeof(ts));
        char rest[192];
        snprintf(rest, sizeof(rest),
                 ",\"rows\":%ld,\"rows_total\":%ld,\"timestamp\":\"%s\"}",
                 rows, total, ts);
        strlcat(entry, rest, DARKMACH_RING_ENTRY_SIZE);
        db_rows_merged++;
        break;
    }
    os_unfair_lock_unlock(&db_query_lock);
}


static int db_capture_installed(void) {
    static const int *db_flag = NULL;
    if (!db_flag)
        db_flag = (const int *)dlsym(RTLD_DEFAULT, "darkmach_db_hooks_installed");
    return (db_flag && *db_flag) ? 1 : 0;
}

static const char *DB_NOT_CAPTURING =
    "SQLite queries are not being captured — darkmach-db.dylib, which owns the sqlite3 "
    "interposes, is not loaded; a zero count here means unobserved, not absent";

static void cmd_db_queries(const char *args, resp_t *r) {
    if (!db_capture_installed())
        resp_append(r, "\"error\":\"%s\",", DB_NOT_CAPTURING);

    long limit = json_get_long(args, "limit");
    if (limit <= 0) limit = 50;
    char path_filter[512] = "";
    json_get_string(args, "path_filter", path_filter, sizeof(path_filter));

    os_unfair_lock_lock(&db_query_lock);
    db_query_ensure_init_locked();

    resp_append(r, "\"capturing\":%s,\"source\":\"darkmach-db.dylib\","
                "\"rows_merged\":%d,\"queries\":[",
                db_capture_installed() ? "true" : "false", db_rows_merged);
    int returned = 0;
    for (int i = 0; i < db_query_ring.count && returned < limit; i++) {
        const char *entry = darkmach_ring_get(&db_query_ring, i);
        if (!entry) continue;

        if (path_filter[0] && !strstr(entry, path_filter)) continue;

        if (returned > 0) resp_append(r, ",");
        resp_append(r, "%s", entry);
        returned++;
    }
    resp_append(r, "],\"total_captured\":%d,\"returned\":%d",
                db_query_ring.total, returned);

    os_unfair_lock_unlock(&db_query_lock);
}
