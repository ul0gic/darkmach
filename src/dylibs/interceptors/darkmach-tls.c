/* Hooks BoringSSL below the framework layer, so plaintext is seen even where
 * NSURLSession hooks do not reach. Env vars documented in docs/interceptors.md. */
#include "darkmach-core.h"
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MOD "tls"

static int tls_verbose = 0;
static size_t tls_body_max = 4096;

typedef struct ssl_st SSL;
typedef struct bio_st BIO;

/* These are resolved at link time from libboringssl.dylib */
extern int SSL_read(SSL *ssl, void *buf, int num);
extern int SSL_write(SSL *ssl, const void *buf, int num);
extern int SSL_get_ex_data_X509_STORE_CTX_idx(void);
extern void *SSL_get_ex_data(const SSL *ssl, int idx);
extern int SSL_set_ex_data(SSL *ssl, int idx, void *data);
extern const char *SSL_get_servername(const SSL *ssl, int type);
extern int BIO_get_fd(BIO *b, int *fd);

/* TLSEXT_NAMETYPE_host_name = 0 in BoringSSL */
#define DARKMACH_TLSEXT_NAMETYPE_host_name 0

/* Track HTTP stream state for each SSL* connection, reassembling HTTP
 * messages that may span multiple SSL_write/SSL_read calls. */

#define MAX_TRACKED_CONNECTIONS 512
#define HEADER_BUF_SIZE 16384
#define BODY_PREVIEW_SIZE 4096

typedef enum {
    STREAM_IDLE = 0,
    STREAM_IN_HEADERS,
    STREAM_IN_BODY,
    STREAM_DONE
} stream_state_t;

typedef struct {
    SSL *ssl;
    int active;

    char peer_host[256];
    int peer_port;
    int fd;

    stream_state_t req_state;
    char req_headers[HEADER_BUF_SIZE];
    size_t req_headers_len;
    size_t req_content_length;
    size_t req_body_received;
    char req_body_preview[BODY_PREVIEW_SIZE + 1];
    size_t req_body_preview_len;

    char req_method[16];
    char req_path[2048];
    char req_host[256];
    char req_auth[1024];
    char req_content_type[256];
    int req_logged;

    stream_state_t resp_state;
    char resp_headers[HEADER_BUF_SIZE];
    size_t resp_headers_len;
    size_t resp_content_length;
    size_t resp_body_received;
    char resp_body_preview[BODY_PREVIEW_SIZE + 1];
    size_t resp_body_preview_len;

    int resp_status;
    char resp_content_type[256];
    int resp_logged;

    int req_chunked;
    int resp_chunked;
} tls_conn_t;

static tls_conn_t connections[MAX_TRACKED_CONNECTIONS];
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;


static tls_conn_t *find_or_create_conn(SSL *ssl) {
    tls_conn_t *free_slot = NULL;

    pthread_mutex_lock(&conn_mutex);
    for (int i = 0; i < MAX_TRACKED_CONNECTIONS; i++) {
        if (connections[i].active && connections[i].ssl == ssl) {
            pthread_mutex_unlock(&conn_mutex);
            return &connections[i];
        }
        if (!free_slot && !connections[i].active) {
            free_slot = &connections[i];
        }
    }

    if (free_slot) {
        memset(free_slot, 0, sizeof(tls_conn_t));
        free_slot->ssl = ssl;
        free_slot->active = 1;
        free_slot->fd = -1;
        free_slot->req_state = STREAM_IDLE;
        free_slot->resp_state = STREAM_IDLE;

        const char *sni = SSL_get_servername(ssl, DARKMACH_TLSEXT_NAMETYPE_host_name);
        if (sni) {
            strncpy(free_slot->peer_host, sni, sizeof(free_slot->peer_host) - 1);
        }
    }

    if (!free_slot) {
        fprintf(stderr, "[darkmach-tls] WARNING: connection tracking full (%d slots) — new connection untracked\n",
                MAX_TRACKED_CONNECTIONS);
    }
    pthread_mutex_unlock(&conn_mutex);

    return free_slot;
}

static void release_conn(SSL *ssl) {
    pthread_mutex_lock(&conn_mutex);
    for (int i = 0; i < MAX_TRACKED_CONNECTIONS; i++) {
        if (connections[i].active && connections[i].ssl == ssl) {
            connections[i].active = 0;
            break;
        }
    }
    pthread_mutex_unlock(&conn_mutex);
}


static const char *find_header_end(const char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i <= len - 4; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static int extract_header(const char *headers, size_t headers_len,
                          const char *name, char *value, size_t value_size) {
    size_t name_len = strlen(name);
    const char *p = headers;
    const char *end = headers + headers_len;

    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\r' && *line_end != '\n') line_end++;

        size_t line_len = (size_t)(line_end - p);

        if (line_len > name_len + 1) {
            int match = 1;
            for (size_t i = 0; i < name_len; i++) {
                char a = p[i];
                char b = name[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { match = 0; break; }
            }
            if (match && p[name_len] == ':') {
                const char *val_start = p + name_len + 1;
                while (val_start < line_end && *val_start == ' ') val_start++;
                size_t val_len = (size_t)(line_end - val_start);
                if (val_len >= value_size) val_len = value_size - 1;
                memcpy(value, val_start, val_len);
                value[val_len] = '\0';
                return 1;
            }
        }

        if (line_end < end && *line_end == '\r') line_end++;
        if (line_end < end && *line_end == '\n') line_end++;
        p = line_end;
    }
    return 0;
}

static int parse_request_line(const char *buf, size_t len,
                               char *method, size_t method_size,
                               char *path, size_t path_size) {
    const char *sp1 = memchr(buf, ' ', len);
    if (!sp1) return 0;

    size_t method_len = (size_t)(sp1 - buf);
    if (method_len >= method_size) method_len = method_size - 1;
    memcpy(method, buf, method_len);
    method[method_len] = '\0';

    const char *path_start = sp1 + 1;
    size_t remaining = len - (size_t)(path_start - buf);
    const char *sp2 = memchr(path_start, ' ', remaining);
    if (!sp2) return 0;

    size_t path_len = (size_t)(sp2 - path_start);
    if (path_len >= path_size) path_len = path_size - 1;
    memcpy(path, path_start, path_len);
    path[path_len] = '\0';

    return 1;
}

static int parse_status_line(const char *buf, size_t len, int *status) {
    if (len < 12) return 0;
    if (memcmp(buf, "HTTP/", 5) != 0) return 0;

    const char *sp = memchr(buf, ' ', len);
    if (!sp) return 0;

    *status = 0;
    const char *p = sp + 1;
    while (p < buf + len && *p >= '0' && *p <= '9') {
        *status = *status * 10 + (*p - '0');
        p++;
    }
    return (*status >= 100 && *status <= 599);
}

static int is_http_request(const char *buf, size_t len) {
    if (len < 4) return 0;
    return (memcmp(buf, "GET ", 4) == 0 ||
            memcmp(buf, "POST", 4) == 0 ||
            memcmp(buf, "PUT ", 4) == 0 ||
            memcmp(buf, "HEAD", 4) == 0 ||
            memcmp(buf, "DELE", 4) == 0 ||
            memcmp(buf, "PATC", 4) == 0 ||
            memcmp(buf, "OPTI", 4) == 0 ||
            memcmp(buf, "CONN", 4) == 0);
}

static int is_http_response(const char *buf, size_t len) {
    if (len < 9) return 0;
    return (memcmp(buf, "HTTP/1.", 7) == 0 || memcmp(buf, "HTTP/2", 6) == 0);
}

static void headers_to_json_str(const char *headers, size_t headers_len,
                                 char *json_buf, size_t json_buf_size) {
    size_t pos = 0;
    pos += snprintf(json_buf + pos, json_buf_size - pos, "{");

    const char *p = headers;
    const char *end = headers + headers_len;
    int first = 1;

    while (p < end && *p != '\r' && *p != '\n') p++;
    if (p < end && *p == '\r') p++;
    if (p < end && *p == '\n') p++;

    while (p < end) {
        const char *line_end = p;
        while (line_end < end && *line_end != '\r' && *line_end != '\n') line_end++;

        size_t line_len = (size_t)(line_end - p);
        if (line_len == 0) break;

        const char *colon = memchr(p, ':', line_len);
        if (colon && colon > p) {
            size_t name_len = (size_t)(colon - p);
            const char *val = colon + 1;
            while (val < line_end && *val == ' ') val++;
            size_t val_len = (size_t)(line_end - val);

            char name_raw[512], val_raw[2048];
            if (name_len >= sizeof(name_raw)) name_len = sizeof(name_raw) - 1;
            if (val_len >= sizeof(val_raw)) val_len = sizeof(val_raw) - 1;
            memcpy(name_raw, p, name_len);
            name_raw[name_len] = '\0';
            memcpy(val_raw, val, val_len);
            val_raw[val_len] = '\0';

            char name_esc[1024], val_esc[4096];
            json_escape(name_raw, name_esc, sizeof(name_esc));
            json_escape(val_raw, val_esc, sizeof(val_esc));

            if (!first && pos < json_buf_size - 1)
                pos += snprintf(json_buf + pos, json_buf_size - pos, ",");
            pos += snprintf(json_buf + pos, json_buf_size - pos, "%s:%s",
                            name_esc, val_esc);
            first = 0;
        }

        if (line_end < end && *line_end == '\r') line_end++;
        if (line_end < end && *line_end == '\n') line_end++;
        p = line_end;

        if (pos >= json_buf_size - 10) break;
    }

    snprintf(json_buf + pos, json_buf_size - pos, "}");
}


static void log_request_complete(tls_conn_t *conn) {
    if (conn->req_logged) return;
    conn->req_logged = 1;

    char url[4096];
    if (conn->req_host[0] && conn->req_path[0]) {
        snprintf(url, sizeof(url), "https://%s%s", conn->req_host, conn->req_path);
    } else if (conn->peer_host[0] && conn->req_path[0]) {
        snprintf(url, sizeof(url), "https://%s%s", conn->peer_host, conn->req_path);
    } else if (conn->req_path[0]) {
        snprintf(url, sizeof(url), "%s", conn->req_path);
    } else {
        snprintf(url, sizeof(url), "(unknown)");
    }

    char url_esc[8192];
    json_escape(url, url_esc, sizeof(url_esc));

    char method_esc[32];
    json_escape(conn->req_method, method_esc, sizeof(method_esc));

    char host_esc[512];
    json_escape(conn->req_host[0] ? conn->req_host : conn->peer_host, host_esc, sizeof(host_esc));

    char auth_esc[2048] = "null";
    if (conn->req_auth[0]) {
        json_escape(conn->req_auth, auth_esc, sizeof(auth_esc));
    }

    char ct_esc[512] = "null";
    if (conn->req_content_type[0]) {
        json_escape(conn->req_content_type, ct_esc, sizeof(ct_esc));
    }

    char headers_json[8192];
    headers_to_json_str(conn->req_headers, conn->req_headers_len,
                        headers_json, sizeof(headers_json));

    char body_esc[BODY_PREVIEW_SIZE * 3] = "null";
    if (conn->req_body_preview_len > 0) {
        conn->req_body_preview[conn->req_body_preview_len] = '\0';
        json_escape(conn->req_body_preview, body_esc, sizeof(body_esc));
    }

    char data[32768];
    snprintf(data, sizeof(data),
             "\"dir\":\"request\","
             "\"method\":%s,"
             "\"url\":%s,"
             "\"host\":%s,"
             "\"authorization\":%s,"
             "\"contentType\":%s,"
             "\"contentLength\":%zu,"
             "\"headers\":%s,"
             "\"body\":%s,"
             "\"ssl\":\"%p\","
             "\"fd\":%d",
             method_esc, url_esc, host_esc, auth_esc, ct_esc,
             conn->req_content_length, headers_json, body_esc,
             (void *)conn->ssl, conn->fd);

    darkmach_log(MOD, "request", data);

    fprintf(stderr, "[darkmach-tls] >> %s %s",
            conn->req_method, url);
    if (conn->req_auth[0]) {
        fprintf(stderr, " [Auth: %.40s%s]",
                conn->req_auth, strlen(conn->req_auth) > 40 ? "..." : "");
    }
    fprintf(stderr, "\n");
}

static void log_response_complete(tls_conn_t *conn) {
    if (conn->resp_logged) return;
    conn->resp_logged = 1;

    char host_esc[512];
    json_escape(conn->req_host[0] ? conn->req_host :
                (conn->peer_host[0] ? conn->peer_host : "(unknown)"),
                host_esc, sizeof(host_esc));

    char url_esc[8192];
    char url[4096];
    if (conn->req_host[0] && conn->req_path[0]) {
        snprintf(url, sizeof(url), "https://%s%s", conn->req_host, conn->req_path);
    } else if (conn->peer_host[0] && conn->req_path[0]) {
        snprintf(url, sizeof(url), "https://%s%s", conn->peer_host, conn->req_path);
    } else {
        snprintf(url, sizeof(url), "(unknown)");
    }
    json_escape(url, url_esc, sizeof(url_esc));

    char ct_esc[512] = "null";
    if (conn->resp_content_type[0]) {
        json_escape(conn->resp_content_type, ct_esc, sizeof(ct_esc));
    }

    char headers_json[8192];
    headers_to_json_str(conn->resp_headers, conn->resp_headers_len,
                        headers_json, sizeof(headers_json));

    char body_esc[BODY_PREVIEW_SIZE * 3] = "null";
    if (conn->resp_body_preview_len > 0) {
        conn->resp_body_preview[conn->resp_body_preview_len] = '\0';
        json_escape(conn->resp_body_preview, body_esc, sizeof(body_esc));
    }

    char data[32768];
    snprintf(data, sizeof(data),
             "\"dir\":\"response\","
             "\"status\":%d,"
             "\"url\":%s,"
             "\"host\":%s,"
             "\"contentType\":%s,"
             "\"contentLength\":%zu,"
             "\"bodySize\":%zu,"
             "\"headers\":%s,"
             "\"body\":%s,"
             "\"ssl\":\"%p\","
             "\"fd\":%d",
             conn->resp_status, url_esc, host_esc, ct_esc,
             conn->resp_content_length, conn->resp_body_received,
             headers_json, body_esc,
             (void *)conn->ssl, conn->fd);

    darkmach_log(MOD, "response", data);

    fprintf(stderr, "[darkmach-tls] << %d %s (%zu bytes)\n",
            conn->resp_status, url, conn->resp_body_received);
}


/* Process SSL_write data (outgoing = HTTP requests) */
static void process_write_data(tls_conn_t *conn, const char *buf, int len) {
    if (len <= 0) return;

    if (conn->req_state == STREAM_IDLE || conn->req_state == STREAM_DONE) {
        if (is_http_request(buf, (size_t)len)) {
            conn->req_state = STREAM_IN_HEADERS;
            conn->req_headers_len = 0;
            conn->req_content_length = 0;
            conn->req_body_received = 0;
            conn->req_body_preview_len = 0;
            conn->req_method[0] = '\0';
            conn->req_path[0] = '\0';
            conn->req_host[0] = '\0';
            conn->req_auth[0] = '\0';
            conn->req_content_type[0] = '\0';
            conn->req_logged = 0;
            conn->req_chunked = 0;

            conn->resp_state = STREAM_IDLE;
            conn->resp_headers_len = 0;
            conn->resp_content_length = 0;
            conn->resp_body_received = 0;
            conn->resp_body_preview_len = 0;
            conn->resp_status = 0;
            conn->resp_content_type[0] = '\0';
            conn->resp_logged = 0;
            conn->resp_chunked = 0;
        } else {
            if (tls_verbose) {
                fprintf(stderr, "[darkmach-tls] write: non-HTTP data (%d bytes)\n", len);
            }
            return;
        }
    }

    if (conn->req_state == STREAM_IN_HEADERS) {
        size_t space = sizeof(conn->req_headers) - conn->req_headers_len;
        size_t copy = (size_t)len < space ? (size_t)len : space;
        memcpy(conn->req_headers + conn->req_headers_len, buf, copy);
        conn->req_headers_len += copy;

        const char *hdr_end = find_header_end(conn->req_headers, conn->req_headers_len);
        if (hdr_end) {
            size_t headers_size = (size_t)(hdr_end - conn->req_headers);

            parse_request_line(conn->req_headers, conn->req_headers_len,
                               conn->req_method, sizeof(conn->req_method),
                               conn->req_path, sizeof(conn->req_path));

            extract_header(conn->req_headers, headers_size,
                           "Host", conn->req_host, sizeof(conn->req_host));
            extract_header(conn->req_headers, headers_size,
                           "Authorization", conn->req_auth, sizeof(conn->req_auth));
            extract_header(conn->req_headers, headers_size,
                           "Content-Type", conn->req_content_type, sizeof(conn->req_content_type));

            char cl_buf[32] = {0};
            if (extract_header(conn->req_headers, headers_size,
                               "Content-Length", cl_buf, sizeof(cl_buf))) {
                conn->req_content_length = (size_t)atol(cl_buf);
            }

            char te_buf[64] = {0};
            if (extract_header(conn->req_headers, headers_size,
                               "Transfer-Encoding", te_buf, sizeof(te_buf))) {
                for (char *c = te_buf; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
                if (strstr(te_buf, "chunked")) conn->req_chunked = 1;
            }

            const char *body_start = hdr_end + 4;
            size_t body_in_this_chunk = conn->req_headers_len - (size_t)(body_start - conn->req_headers);

            if (conn->req_content_length > 0 || conn->req_chunked) {
                conn->req_state = STREAM_IN_BODY;
                if (body_in_this_chunk > 0) {
                    size_t preview = body_in_this_chunk;
                    if (preview > tls_body_max) preview = tls_body_max;
                    memcpy(conn->req_body_preview, body_start, preview);
                    conn->req_body_preview_len = preview;
                    conn->req_body_received = body_in_this_chunk;
                }

                if (!conn->req_chunked &&
                    conn->req_body_received >= conn->req_content_length) {
                    conn->req_state = STREAM_DONE;
                    log_request_complete(conn);
                }
            } else {
                conn->req_state = STREAM_DONE;
                log_request_complete(conn);
            }
        }
    } else if (conn->req_state == STREAM_IN_BODY) {
        conn->req_body_received += (size_t)len;

        if (conn->req_body_preview_len < tls_body_max) {
            size_t space = tls_body_max - conn->req_body_preview_len;
            size_t copy = (size_t)len < space ? (size_t)len : space;
            memcpy(conn->req_body_preview + conn->req_body_preview_len, buf, copy);
            conn->req_body_preview_len += copy;
        }

        if (!conn->req_chunked &&
            conn->req_body_received >= conn->req_content_length) {
            conn->req_state = STREAM_DONE;
            log_request_complete(conn);
        }
    }
}

/* Process SSL_read data (incoming = HTTP responses) */
static void process_read_data(tls_conn_t *conn, const char *buf, int len) {
    if (len <= 0) return;

    if (conn->resp_state == STREAM_IDLE || conn->resp_state == STREAM_DONE) {
        if (is_http_response(buf, (size_t)len)) {
            conn->resp_state = STREAM_IN_HEADERS;
            conn->resp_headers_len = 0;
            conn->resp_content_length = 0;
            conn->resp_body_received = 0;
            conn->resp_body_preview_len = 0;
            conn->resp_status = 0;
            conn->resp_content_type[0] = '\0';
            conn->resp_logged = 0;
            conn->resp_chunked = 0;
        } else {
            if (tls_verbose) {
                fprintf(stderr, "[darkmach-tls] read: non-HTTP data (%d bytes)\n", len);
            }
            return;
        }
    }

    if (conn->resp_state == STREAM_IN_HEADERS) {
        size_t space = sizeof(conn->resp_headers) - conn->resp_headers_len;
        size_t copy = (size_t)len < space ? (size_t)len : space;
        memcpy(conn->resp_headers + conn->resp_headers_len, buf, copy);
        conn->resp_headers_len += copy;

        const char *hdr_end = find_header_end(conn->resp_headers, conn->resp_headers_len);
        if (hdr_end) {
            size_t headers_size = (size_t)(hdr_end - conn->resp_headers);

            parse_status_line(conn->resp_headers, conn->resp_headers_len,
                              &conn->resp_status);

            extract_header(conn->resp_headers, headers_size,
                           "Content-Type", conn->resp_content_type, sizeof(conn->resp_content_type));

            char cl_buf[32] = {0};
            if (extract_header(conn->resp_headers, headers_size,
                               "Content-Length", cl_buf, sizeof(cl_buf))) {
                conn->resp_content_length = (size_t)atol(cl_buf);
            }

            char te_buf[64] = {0};
            if (extract_header(conn->resp_headers, headers_size,
                               "Transfer-Encoding", te_buf, sizeof(te_buf))) {
                for (char *c = te_buf; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
                if (strstr(te_buf, "chunked")) conn->resp_chunked = 1;
            }

            /* Log a not-yet-logged request (e.g. chunked body) now that its
             * response has arrived */
            if (!conn->req_logged && conn->req_method[0]) {
                log_request_complete(conn);
            }

            const char *body_start = hdr_end + 4;
            size_t body_in_this_chunk = conn->resp_headers_len - (size_t)(body_start - conn->resp_headers);

            if (conn->resp_content_length > 0 || conn->resp_chunked) {
                conn->resp_state = STREAM_IN_BODY;
                if (body_in_this_chunk > 0) {
                    size_t preview = body_in_this_chunk;
                    if (preview > tls_body_max) preview = tls_body_max;
                    memcpy(conn->resp_body_preview, body_start, preview);
                    conn->resp_body_preview_len = preview;
                    conn->resp_body_received = body_in_this_chunk;
                }

                if (!conn->resp_chunked &&
                    conn->resp_body_received >= conn->resp_content_length) {
                    conn->resp_state = STREAM_DONE;
                    log_response_complete(conn);
                }
            } else {
                conn->resp_state = STREAM_DONE;
                log_response_complete(conn);
            }
        }
    } else if (conn->resp_state == STREAM_IN_BODY) {
        conn->resp_body_received += (size_t)len;

        if (conn->resp_body_preview_len < tls_body_max) {
            size_t space = tls_body_max - conn->resp_body_preview_len;
            size_t copy = (size_t)len < space ? (size_t)len : space;
            memcpy(conn->resp_body_preview + conn->resp_body_preview_len, buf, copy);
            conn->resp_body_preview_len += copy;
        }

        if (!conn->resp_chunked &&
            conn->resp_body_received >= conn->resp_content_length) {
            conn->resp_state = STREAM_DONE;
            log_response_complete(conn);
        }
    }
}


static int interposed_SSL_write(SSL *ssl, const void *buf, int num) {
    /* Always call the real function first to avoid breaking behavior */
    int ret = SSL_write(ssl, buf, num);

    if (ret > 0 && buf) {
        tls_conn_t *conn = find_or_create_conn(ssl);
        if (conn) {
            process_write_data(conn, (const char *)buf, ret);
        }
    }

    if (tls_verbose && ret > 0) {
        fprintf(stderr, "[darkmach-tls] SSL_write: %d bytes (ssl=%p)\n", ret, (void *)ssl);
    }

    return ret;
}


static int interposed_SSL_read(SSL *ssl, void *buf, int num) {
    int ret = SSL_read(ssl, buf, num);

    if (ret > 0 && buf) {
        tls_conn_t *conn = find_or_create_conn(ssl);
        if (conn) {
            process_read_data(conn, (const char *)buf, ret);
        }
    }

    if (tls_verbose && ret > 0) {
        fprintf(stderr, "[darkmach-tls] SSL_read: %d bytes (ssl=%p)\n", ret, (void *)ssl);
    }

    return ret;
}


struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)interposed_SSL_write, (const void *)SSL_write },
    { (const void *)interposed_SSL_read,  (const void *)SSL_read },
};

__attribute__((constructor))
static void darkmach_tls_init(void) {
    fprintf(stderr, "[darkmach-tls] initializing BoringSSL plaintext interceptor\n");
    darkmach_log_init(MOD);

    const char *verbose_env = getenv("DARKMACH_TLS_VERBOSE");
    if (verbose_env && verbose_env[0] == '1') {
        tls_verbose = 1;
        fprintf(stderr, "[darkmach-tls] verbose mode enabled\n");
    }

    const char *body_max_env = getenv("DARKMACH_TLS_BODY_MAX");
    if (body_max_env) {
        size_t val = (size_t)atol(body_max_env);
        if (val > 0 && val <= BODY_PREVIEW_SIZE) {
            tls_body_max = val;
        }
    }

    memset(connections, 0, sizeof(connections));

    char data[512];
    snprintf(data, sizeof(data),
             "\"hooks\":[\"SSL_read\",\"SSL_write\"],"
             "\"bodyMax\":%zu,"
             "\"verbose\":%s,"
             "\"maxConnections\":%d",
             tls_body_max,
             tls_verbose ? "true" : "false",
             MAX_TRACKED_CONNECTIONS);
    darkmach_log(MOD, "init", data);

    fprintf(stderr, "[darkmach-tls] ready -- SSL_read + SSL_write hooked (bodyMax=%zu)\n",
            tls_body_max);
    fprintf(stderr, "[darkmach-tls] captures ALL HTTPS traffic: "
            "NSURLSession, React Native, Flutter, Cordova, WKWebView\n");
}
