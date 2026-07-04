/* Database interceptor: SQLite C API via DYLD interpose. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <sqlite3.h>

#define MOD "db"

#define MAX_DB_TRACK 64
static struct {
    sqlite3 *handle;
    char path[512];
} db_map[MAX_DB_TRACK];
static pthread_mutex_t db_map_mutex = PTHREAD_MUTEX_INITIALIZER;

static void db_map_set(sqlite3 *db, const char *path) {
    pthread_mutex_lock(&db_map_mutex);
    int slot = -1;
    for (int i = 0; i < MAX_DB_TRACK; i++) {
        if (db_map[i].handle == db) { slot = i; break; }
        if (!db_map[i].handle && slot == -1) slot = i;
    }
    if (slot >= 0) {
        db_map[slot].handle = db;
        strncpy(db_map[slot].path, path ? path : "(memory)", sizeof(db_map[slot].path) - 1);
    }
    pthread_mutex_unlock(&db_map_mutex);
}

static const char *db_map_get(sqlite3 *db) {
    pthread_mutex_lock(&db_map_mutex);
    for (int i = 0; i < MAX_DB_TRACK; i++) {
        if (db_map[i].handle == db) {
            pthread_mutex_unlock(&db_map_mutex);
            return db_map[i].path;
        }
    }
    pthread_mutex_unlock(&db_map_mutex);
    return "(unknown)";
}

static void db_map_remove(sqlite3 *db) {
    pthread_mutex_lock(&db_map_mutex);
    for (int i = 0; i < MAX_DB_TRACK; i++) {
        if (db_map[i].handle == db) {
            db_map[i].handle = NULL;
            db_map[i].path[0] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&db_map_mutex);
}

static const char *short_path(const char *path) {
    if (!path) return "(null)";
    const char *last = strrchr(path, '/');
    return last ? last + 1 : path;
}

static int (*orig_sqlite3_open)(const char *, sqlite3 **) = NULL;
static int (*orig_sqlite3_open_v2)(const char *, sqlite3 **, int, const char *) = NULL;
static int (*orig_sqlite3_close)(sqlite3 *) = NULL;
static int (*orig_sqlite3_close_v2)(sqlite3 *) = NULL;
static int (*orig_sqlite3_exec)(sqlite3 *, const char *, int (*)(void *, int, char **, char **),
                                 void *, char **) = NULL;
static int (*orig_sqlite3_prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **) = NULL;
static int (*orig_sqlite3_prepare_v3)(sqlite3 *, const char *, int, unsigned int,
                                       sqlite3_stmt **, const char **) = NULL;
static int (*orig_sqlite3_step)(sqlite3_stmt *) = NULL;
static int (*orig_sqlite3_finalize)(sqlite3_stmt *) = NULL;

#define MAX_STMT_TRACK 256
static struct {
    sqlite3_stmt *stmt;
    char sql[2048];
    sqlite3 *db;
} stmt_map[MAX_STMT_TRACK];
static pthread_mutex_t stmt_map_mutex = PTHREAD_MUTEX_INITIALIZER;

static void stmt_map_set(sqlite3_stmt *stmt, const char *sql, sqlite3 *db) {
    pthread_mutex_lock(&stmt_map_mutex);
    int slot = -1;
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt == stmt) { slot = i; break; }
        if (!stmt_map[i].stmt && slot == -1) slot = i;
    }
    if (slot >= 0) {
        stmt_map[slot].stmt = stmt;
        stmt_map[slot].db = db;
        strncpy(stmt_map[slot].sql, sql ? sql : "", sizeof(stmt_map[slot].sql) - 1);
    }
    pthread_mutex_unlock(&stmt_map_mutex);
}

static const char *stmt_map_get_sql(sqlite3_stmt *stmt, sqlite3 **out_db) {
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt == stmt) {
            if (out_db) *out_db = stmt_map[i].db;
            pthread_mutex_unlock(&stmt_map_mutex);
            return stmt_map[i].sql;
        }
    }
    pthread_mutex_unlock(&stmt_map_mutex);
    if (out_db) *out_db = NULL;
    return "(unknown)";
}

static void stmt_map_remove(sqlite3_stmt *stmt) {
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt == stmt) {
            stmt_map[i].stmt = NULL;
            stmt_map[i].sql[0] = '\0';
            stmt_map[i].db = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&stmt_map_mutex);
}

static int hooked_sqlite3_open(const char *filename, sqlite3 **ppDb) {
    int rc = orig_sqlite3_open(filename, ppDb);

    if (rc == SQLITE_OK && ppDb && *ppDb) {
        db_map_set(*ppDb, filename);
    }

    char path_esc[1024];
    json_escape(filename, path_esc, sizeof(path_esc));

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"open\",\"path\":%s,\"file\":\"%s\",\"rc\":%d",
             path_esc, short_path(filename), rc);
    darkmach_log(MOD, "sqlite", data);
    fprintf(stderr, "[darkmach-db] sqlite3_open %s rc=%d\n", short_path(filename), rc);

    return rc;
}

static int hooked_sqlite3_open_v2(const char *filename, sqlite3 **ppDb,
                                    int flags, const char *zVfs) {
    int rc = orig_sqlite3_open_v2(filename, ppDb, flags, zVfs);

    if (rc == SQLITE_OK && ppDb && *ppDb) {
        db_map_set(*ppDb, filename);
    }

    char path_esc[1024];
    json_escape(filename, path_esc, sizeof(path_esc));

    const char *mode = "unknown";
    if (flags & SQLITE_OPEN_READONLY) mode = "readonly";
    else if (flags & SQLITE_OPEN_READWRITE) {
        if (flags & SQLITE_OPEN_CREATE) mode = "readwrite+create";
        else mode = "readwrite";
    }

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"open_v2\",\"path\":%s,\"file\":\"%s\",\"mode\":\"%s\",\"flags\":%d,\"rc\":%d",
             path_esc, short_path(filename), mode, flags, rc);
    darkmach_log(MOD, "sqlite", data);
    fprintf(stderr, "[darkmach-db] sqlite3_open_v2 %s [%s] rc=%d\n",
            short_path(filename), mode, rc);

    return rc;
}

static int hooked_sqlite3_close(sqlite3 *db) {
    const char *path = db_map_get(db);
    char data[1024];
    snprintf(data, sizeof(data),
             "\"op\":\"close\",\"file\":\"%s\"", short_path(path));
    darkmach_log(MOD, "sqlite", data);

    db_map_remove(db);
    return orig_sqlite3_close(db);
}

static int hooked_sqlite3_close_v2(sqlite3 *db) {
    const char *path = db_map_get(db);
    char data[1024];
    snprintf(data, sizeof(data),
             "\"op\":\"close_v2\",\"file\":\"%s\"", short_path(path));
    darkmach_log(MOD, "sqlite", data);

    db_map_remove(db);
    return orig_sqlite3_close_v2(db);
}

static int hooked_sqlite3_exec(sqlite3 *db, const char *sql,
                                int (*callback)(void *, int, char **, char **),
                                void *arg, char **errmsg) {
    const char *path = db_map_get(db);

    char sql_esc[4096];
    json_escape(sql, sql_esc, sizeof(sql_esc));

    int rc = orig_sqlite3_exec(db, sql, callback, arg, errmsg);

    char err_esc[1024] = "null";
    if (errmsg && *errmsg) {
        json_escape(*errmsg, err_esc, sizeof(err_esc));
    }

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"exec\",\"file\":\"%s\",\"sql\":%s,\"rc\":%d,\"error\":%s",
             short_path(path), sql_esc, rc, err_esc);
    darkmach_log(MOD, "query", data);

    if (sql && strlen(sql) > 0) {
        char sql_short[120];
        strncpy(sql_short, sql, sizeof(sql_short) - 1);
        sql_short[sizeof(sql_short) - 1] = '\0';
        for (char *p = sql_short; *p; p++) if (*p == '\n' || *p == '\r') *p = ' ';
        fprintf(stderr, "[darkmach-db] exec [%s] %s rc=%d\n",
                short_path(path), sql_short, rc);
    }

    return rc;
}

static int hooked_sqlite3_prepare_v2(sqlite3 *db, const char *sql, int nByte,
                                       sqlite3_stmt **ppStmt, const char **pzTail) {
    int rc = orig_sqlite3_prepare_v2(db, sql, nByte, ppStmt, pzTail);

    if (rc == SQLITE_OK && ppStmt && *ppStmt) {
        stmt_map_set(*ppStmt, sql, db);
    }

    const char *path = db_map_get(db);
    char sql_esc[4096];
    json_escape(sql, sql_esc, sizeof(sql_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"prepare\",\"file\":\"%s\",\"sql\":%s,\"rc\":%d",
             short_path(path), sql_esc, rc);
    darkmach_log(MOD, "query", data);

    return rc;
}

static int hooked_sqlite3_prepare_v3(sqlite3 *db, const char *sql, int nByte,
                                       unsigned int prepFlags,
                                       sqlite3_stmt **ppStmt, const char **pzTail) {
    int rc = orig_sqlite3_prepare_v3(db, sql, nByte, prepFlags, ppStmt, pzTail);

    if (rc == SQLITE_OK && ppStmt && *ppStmt) {
        stmt_map_set(*ppStmt, sql, db);
    }

    const char *path = db_map_get(db);
    char sql_esc[4096];
    json_escape(sql, sql_esc, sizeof(sql_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"prepare_v3\",\"file\":\"%s\",\"sql\":%s,\"rc\":%d",
             short_path(path), sql_esc, rc);
    darkmach_log(MOD, "query", data);

    return rc;
}

static int hooked_sqlite3_step(sqlite3_stmt *stmt) {
    int rc = orig_sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        sqlite3 *db = NULL;
        const char *sql = stmt_map_get_sql(stmt, &db);
        const char *path = db ? db_map_get(db) : "(unknown)";

        int colCount = sqlite3_column_count(stmt);

        char columns[16384];
        size_t pos = 0;
        pos += snprintf(columns + pos, sizeof(columns) - pos, "[");

        for (int i = 0; i < colCount && pos < sizeof(columns) - 200; i++) {
            const char *colName = sqlite3_column_name(stmt, i);
            int colType = sqlite3_column_type(stmt, i);

            if (i > 0) pos += snprintf(columns + pos, sizeof(columns) - pos, ",");
            pos += snprintf(columns + pos, sizeof(columns) - pos, "{\"name\":\"%s\",",
                           colName ? colName : "?");

            switch (colType) {
                case SQLITE_INTEGER:
                    pos += snprintf(columns + pos, sizeof(columns) - pos,
                                   "\"type\":\"int\",\"value\":%lld}",
                                   sqlite3_column_int64(stmt, i));
                    break;
                case SQLITE_FLOAT:
                    pos += snprintf(columns + pos, sizeof(columns) - pos,
                                   "\"type\":\"float\",\"value\":%f}",
                                   sqlite3_column_double(stmt, i));
                    break;
                case SQLITE_TEXT: {
                    const char *text = (const char *)sqlite3_column_text(stmt, i);
                    char text_esc[1024];
                    char text_trunc[512];
                    if (text) {
                        strncpy(text_trunc, text, sizeof(text_trunc) - 1);
                        text_trunc[sizeof(text_trunc) - 1] = '\0';
                    }
                    json_escape(text ? text_trunc : "(null)", text_esc, sizeof(text_esc));
                    pos += snprintf(columns + pos, sizeof(columns) - pos,
                                   "\"type\":\"text\",\"value\":%s}", text_esc);
                    break;
                }
                case SQLITE_BLOB: {
                    int blobLen = sqlite3_column_bytes(stmt, i);
                    pos += snprintf(columns + pos, sizeof(columns) - pos,
                                   "\"type\":\"blob\",\"size\":%d}", blobLen);
                    break;
                }
                case SQLITE_NULL:
                    pos += snprintf(columns + pos, sizeof(columns) - pos,
                                   "\"type\":\"null\",\"value\":null}");
                    break;
            }
        }
        snprintf(columns + pos, sizeof(columns) - pos, "]");

        char sql_esc[4096];
        json_escape(sql, sql_esc, sizeof(sql_esc));

        char data[24576];
        snprintf(data, sizeof(data),
                 "\"op\":\"row\",\"file\":\"%s\",\"sql\":%s,\"cols\":%d,\"data\":%s",
                 short_path(path), sql_esc, colCount, columns);
        darkmach_log(MOD, "row", data);
    }

    return rc;
}

static int hooked_sqlite3_finalize(sqlite3_stmt *stmt) {
    stmt_map_remove(stmt);
    return orig_sqlite3_finalize(stmt);
}

struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_sqlite3_open,        (const void *)sqlite3_open },
    { (const void *)hooked_sqlite3_open_v2,     (const void *)sqlite3_open_v2 },
    { (const void *)hooked_sqlite3_close,       (const void *)sqlite3_close },
    { (const void *)hooked_sqlite3_close_v2,    (const void *)sqlite3_close_v2 },
    { (const void *)hooked_sqlite3_exec,        (const void *)sqlite3_exec },
    { (const void *)hooked_sqlite3_prepare_v2,  (const void *)sqlite3_prepare_v2 },
    { (const void *)hooked_sqlite3_prepare_v3,  (const void *)sqlite3_prepare_v3 },
    { (const void *)hooked_sqlite3_step,        (const void *)sqlite3_step },
    { (const void *)hooked_sqlite3_finalize,    (const void *)sqlite3_finalize },
};

__attribute__((constructor))
static void darkmach_db_init(void) {
    fprintf(stderr, "[darkmach-db] initializing database interceptor\n");
    darkmach_log_init(MOD);

    memset(db_map, 0, sizeof(db_map));
    memset(stmt_map, 0, sizeof(stmt_map));

    orig_sqlite3_open = sqlite3_open;
    orig_sqlite3_open_v2 = sqlite3_open_v2;
    orig_sqlite3_close = sqlite3_close;
    orig_sqlite3_close_v2 = sqlite3_close_v2;
    orig_sqlite3_exec = sqlite3_exec;
    orig_sqlite3_prepare_v2 = sqlite3_prepare_v2;
    orig_sqlite3_prepare_v3 = sqlite3_prepare_v3;
    orig_sqlite3_step = sqlite3_step;
    orig_sqlite3_finalize = sqlite3_finalize;

    darkmach_log(MOD, "init",
               "\"hooks\":[\"sqlite3_open\",\"sqlite3_open_v2\","
               "\"sqlite3_close\",\"sqlite3_close_v2\","
               "\"sqlite3_exec\",\"sqlite3_prepare_v2\",\"sqlite3_prepare_v3\","
               "\"sqlite3_step\",\"sqlite3_finalize\"]");
    fprintf(stderr, "[darkmach-db] ready — sqlite3 API fully hooked (9 functions)\n");
}
