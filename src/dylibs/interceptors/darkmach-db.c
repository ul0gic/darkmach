/* Database interceptor: SQLite C API via DYLD interpose. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <sqlite3.h>
#include <stdarg.h>

#define MOD "db"

/* Read by darkmach-bridge's db_queries to tell "no queries" from "nothing watched". */
int darkmach_db_hooks_installed = 0;

static void db_report_query(const char *op, unsigned long sid, const char *path,
                            const char *sql, int rc) {
    static void (*record)(const char *, unsigned long, const char *,
                          const char *, int) = NULL;
    if (!record)
        record = (void (*)(const char *, unsigned long, const char *, const char *, int))
            dlsym(RTLD_DEFAULT, "darkmach_db_record_query");
    if (record) record(op, sid, path, sql, rc);
}

static void db_report_rows(unsigned long sid, long rows, long total) {
    static void (*record)(unsigned long, long, long) = NULL;
    if (!record)
        record = (void (*)(unsigned long, long, long))
            dlsym(RTLD_DEFAULT, "darkmach_db_record_rows");
    if (record) record(sid, rows, total);
}

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
static int (*orig_sqlite3_reset)(sqlite3_stmt *) = NULL;
static int (*orig_sqlite3_finalize)(sqlite3_stmt *) = NULL;

#define MAX_STMT_TRACK 256
#define DEFAULT_ROW_MAX 32

static struct {
    sqlite3_stmt *stmt;
    sqlite3 *db;
    unsigned long id;
    int rows_logged;
    long rows_exec;
    long rows_total;
} stmt_map[MAX_STMT_TRACK];
static pthread_mutex_t stmt_map_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long stmt_id_next = 1;
static int row_max = DEFAULT_ROW_MAX;
static int untracked_rows_logged = 0;

typedef struct {
    unsigned long id;
    long rows;
    long total;
    int logged;
    sqlite3 *db;
} stmt_result_t;

/* Always issues a fresh id, even reusing a slot: SQLite recycles freed
 * sqlite3_stmt pointers, and a stale id would misattribute rows. */
static unsigned long stmt_map_set(sqlite3_stmt *stmt, sqlite3 *db) {
    pthread_mutex_lock(&stmt_map_mutex);
    int slot = -1;
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt == stmt) { slot = i; break; }
        if (!stmt_map[i].stmt && slot == -1) slot = i;
    }
    unsigned long id = 0;
    if (slot >= 0) {
        memset(&stmt_map[slot], 0, sizeof(stmt_map[slot]));
        id = stmt_id_next++;
        stmt_map[slot].stmt = stmt;
        stmt_map[slot].db = db;
        stmt_map[slot].id = id;
    }
    pthread_mutex_unlock(&stmt_map_mutex);
    return id;
}

static int stmt_row_seen(sqlite3_stmt *stmt, unsigned long *out_id, sqlite3 **out_db) {
    *out_id = 0;
    *out_db = NULL;
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt != stmt) continue;
        stmt_map[i].rows_exec++;
        stmt_map[i].rows_total++;
        *out_id = stmt_map[i].id;
        *out_db = stmt_map[i].db;
        int log_row = stmt_map[i].rows_logged < row_max;
        if (log_row) stmt_map[i].rows_logged++;
        pthread_mutex_unlock(&stmt_map_mutex);
        return log_row;
    }
    int log_row = untracked_rows_logged < row_max;
    if (log_row) untracked_rows_logged++;
    pthread_mutex_unlock(&stmt_map_mutex);
    return log_row;
}

static int stmt_take_result(sqlite3_stmt *stmt, stmt_result_t *out) {
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt != stmt) continue;
        int pending = stmt_map[i].rows_exec > 0;
        out->id = stmt_map[i].id;
        out->rows = stmt_map[i].rows_exec;
        out->total = stmt_map[i].rows_total;
        out->logged = stmt_map[i].rows_logged;
        out->db = stmt_map[i].db;
        stmt_map[i].rows_exec = 0;
        pthread_mutex_unlock(&stmt_map_mutex);
        return pending;
    }
    pthread_mutex_unlock(&stmt_map_mutex);
    return 0;
}

static void stmt_map_remove(sqlite3_stmt *stmt) {
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt == stmt) {
            memset(&stmt_map[i], 0, sizeof(stmt_map[i]));
            break;
        }
    }
    pthread_mutex_unlock(&stmt_map_mutex);
}

/* Closing a connection finalizes its statements without calling sqlite3_finalize. */
static void stmt_map_remove_db(sqlite3 *db) {
    pthread_mutex_lock(&stmt_map_mutex);
    for (int i = 0; i < MAX_STMT_TRACK; i++) {
        if (stmt_map[i].stmt && stmt_map[i].db == db) {
            memset(&stmt_map[i], 0, sizeof(stmt_map[i]));
        }
    }
    pthread_mutex_unlock(&stmt_map_mutex);
}

/* Only worth a line once rows are being dropped — while every row is still
 * logged the operator can count the row events for that sid. */
static void log_result(sqlite3_stmt *stmt) {
    stmt_result_t r;
    if (!stmt_take_result(stmt, &r)) return;

    db_report_rows(r.id, r.rows, r.total);
    if (r.total <= r.logged) return;

    const char *path = r.db ? db_map_get(r.db) : "(unknown)";
    char data[512];
    snprintf(data, sizeof(data),
             "\"op\":\"result\",\"sid\":%lu,\"file\":\"%s\",\"rows\":%ld,"
             "\"total\":%ld,\"logged\":%d,\"truncated\":true",
             r.id, short_path(path), r.rows, r.total, r.logged);
    darkmach_log(MOD, "result", data);
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

    stmt_map_remove_db(db);
    db_map_remove(db);
    return orig_sqlite3_close(db);
}

static int hooked_sqlite3_close_v2(sqlite3 *db) {
    const char *path = db_map_get(db);
    char data[1024];
    snprintf(data, sizeof(data),
             "\"op\":\"close_v2\",\"file\":\"%s\"", short_path(path));
    darkmach_log(MOD, "sqlite", data);

    stmt_map_remove_db(db);
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
    db_report_query("exec", 0, short_path(path), sql, rc);

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

    unsigned long sid = 0;
    if (rc == SQLITE_OK && ppStmt && *ppStmt) {
        sid = stmt_map_set(*ppStmt, db);
    }

    const char *path = db_map_get(db);
    char sql_esc[4096];
    json_escape(sql, sql_esc, sizeof(sql_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"prepare\",\"sid\":%lu,\"file\":\"%s\",\"sql\":%s,\"rc\":%d",
             sid, short_path(path), sql_esc, rc);
    darkmach_log(MOD, "query", data);
    db_report_query("prepare", sid, short_path(path), sql, rc);

    return rc;
}

static int hooked_sqlite3_prepare_v3(sqlite3 *db, const char *sql, int nByte,
                                       unsigned int prepFlags,
                                       sqlite3_stmt **ppStmt, const char **pzTail) {
    int rc = orig_sqlite3_prepare_v3(db, sql, nByte, prepFlags, ppStmt, pzTail);

    unsigned long sid = 0;
    if (rc == SQLITE_OK && ppStmt && *ppStmt) {
        sid = stmt_map_set(*ppStmt, db);
    }

    const char *path = db_map_get(db);
    char sql_esc[4096];
    json_escape(sql, sql_esc, sizeof(sql_esc));

    char data[8192];
    snprintf(data, sizeof(data),
             "\"op\":\"prepare_v3\",\"sid\":%lu,\"file\":\"%s\",\"sql\":%s,\"rc\":%d",
             sid, short_path(path), sql_esc, rc);
    darkmach_log(MOD, "query", data);
    db_report_query("prepare_v3", sid, short_path(path), sql, rc);

    return rc;
}

/* snprintf returns the length it wanted, so an unclamped pos walks past out_size
 * and the next call writes out of bounds with an underflowed size. */
static void col_append(char *out, size_t out_size, size_t *pos, const char *fmt, ...) {
    if (*pos + 1 >= out_size) return;

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *pos, out_size - *pos, fmt, ap);
    va_end(ap);

    if (n < 0) return;
    *pos += (size_t)n;
    if (*pos >= out_size) *pos = out_size - 1;
}

static void format_columns(sqlite3_stmt *stmt, int colCount, char *out, size_t out_size) {
    size_t pos = 0;
    col_append(out, out_size, &pos, "[");

    for (int i = 0; i < colCount && pos < out_size - 2; i++) {
        const char *colName = sqlite3_column_name(stmt, i);
        int colType = sqlite3_column_type(stmt, i);

        if (i > 0) col_append(out, out_size, &pos, ",");
        col_append(out, out_size, &pos, "{\"name\":\"%s\",", colName ? colName : "?");

        switch (colType) {
            case SQLITE_INTEGER:
                col_append(out, out_size, &pos, "\"type\":\"int\",\"value\":%lld}",
                           sqlite3_column_int64(stmt, i));
                break;
            case SQLITE_FLOAT:
                col_append(out, out_size, &pos, "\"type\":\"float\",\"value\":%f}",
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
                col_append(out, out_size, &pos, "\"type\":\"text\",\"value\":%s}", text_esc);
                break;
            }
            case SQLITE_BLOB:
                col_append(out, out_size, &pos, "\"type\":\"blob\",\"size\":%d}",
                           sqlite3_column_bytes(stmt, i));
                break;
            case SQLITE_NULL:
                col_append(out, out_size, &pos, "\"type\":\"null\",\"value\":null}");
                break;
        }
    }
    col_append(out, out_size, &pos, "]");
}

static int hooked_sqlite3_step(sqlite3_stmt *stmt) {
    int rc = orig_sqlite3_step(stmt);

    if (rc == SQLITE_DONE) {
        log_result(stmt);
        return rc;
    }
    if (rc != SQLITE_ROW) return rc;

    unsigned long sid = 0;
    sqlite3 *db = NULL;
    if (!stmt_row_seen(stmt, &sid, &db)) return rc;

    const char *path = db ? db_map_get(db) : "(unknown)";
    int colCount = sqlite3_column_count(stmt);

    char columns[16384];
    format_columns(stmt, colCount, columns, sizeof(columns));

    char data[17408];
    snprintf(data, sizeof(data),
             "\"op\":\"row\",\"sid\":%lu,\"file\":\"%s\",\"cols\":%d,\"data\":%s",
             sid, short_path(path), colCount, columns);
    darkmach_log(MOD, "row", data);

    return rc;
}

static int hooked_sqlite3_reset(sqlite3_stmt *stmt) {
    log_result(stmt);
    return orig_sqlite3_reset(stmt);
}

static int hooked_sqlite3_finalize(sqlite3_stmt *stmt) {
    log_result(stmt);
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
    { (const void *)hooked_sqlite3_reset,       (const void *)sqlite3_reset },
    { (const void *)hooked_sqlite3_finalize,    (const void *)sqlite3_finalize },
};

__attribute__((constructor))
static void darkmach_db_init(void) {
    fprintf(stderr, "[darkmach-db] initializing database interceptor\n");
    darkmach_log_init(MOD);

    memset(db_map, 0, sizeof(db_map));
    memset(stmt_map, 0, sizeof(stmt_map));

    const char *row_max_env = getenv("DARKMACH_DB_ROW_MAX");
    if (row_max_env && row_max_env[0]) {
        row_max = atoi(row_max_env);
        if (row_max < 0) row_max = 0;
    }

    orig_sqlite3_open = sqlite3_open;
    orig_sqlite3_open_v2 = sqlite3_open_v2;
    orig_sqlite3_close = sqlite3_close;
    orig_sqlite3_close_v2 = sqlite3_close_v2;
    orig_sqlite3_exec = sqlite3_exec;
    orig_sqlite3_prepare_v2 = sqlite3_prepare_v2;
    orig_sqlite3_prepare_v3 = sqlite3_prepare_v3;
    orig_sqlite3_step = sqlite3_step;
    orig_sqlite3_reset = sqlite3_reset;
    orig_sqlite3_finalize = sqlite3_finalize;

    darkmach_db_hooks_installed =
        (orig_sqlite3_prepare_v2 && orig_sqlite3_prepare_v3 &&
         orig_sqlite3_exec && orig_sqlite3_step) ? 1 : 0;

    char init[256];
    snprintf(init, sizeof(init),
             "\"hooks\":[\"sqlite3_open\",\"sqlite3_open_v2\","
             "\"sqlite3_close\",\"sqlite3_close_v2\","
             "\"sqlite3_exec\",\"sqlite3_prepare_v2\",\"sqlite3_prepare_v3\","
             "\"sqlite3_step\",\"sqlite3_reset\",\"sqlite3_finalize\"],"
             "\"row_max\":%d,\"installed\":%s",
             row_max, darkmach_db_hooks_installed ? "true" : "false");
    darkmach_log(MOD, "init", init);
    fprintf(stderr, "[darkmach-db] ready — sqlite3 API %s (10 functions), "
                    "row_max=%d per statement\n",
            darkmach_db_hooks_installed ? "fully hooked" : "NOT hooked", row_max);
}
