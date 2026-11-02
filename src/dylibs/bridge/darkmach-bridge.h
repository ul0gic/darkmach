/* Shared types and helpers for the bridge; included by every cmd-*.c module. */
#ifndef DARKMACH_BRIDGE_H
#define DARKMACH_BRIDGE_H

#include "../darkmach-core.h"
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <dispatch/dispatch.h>
#include <Security/Security.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>

#define MOD "bridge"
#define BRIDGE_SOCKET_PATH "/tmp/darkmach-bridge.sock"
#define BRIDGE_MAX_REQUEST 65536
#define BRIDGE_MAX_RESPONSE (1024 * 1024)


typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    const char *error;
} resp_t;

static resp_t resp_new(void) {
    resp_t r;
    r.cap = 8192;
    r.buf = malloc(r.cap);
    r.len = 0;
    r.error = NULL;
    if (!r.buf) {
        r.error = "Cannot allocate bridge response";
        return r;
    }
    r.buf[0] = '\0';
    return r;
}

static void resp_append(resp_t *r, const char *fmt, ...) {
    if (r->error) return;
    if (!r->buf || r->len >= r->cap || r->cap > BRIDGE_MAX_RESPONSE) {
        r->error = "Invalid bridge response buffer state";
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (needed < 0) {
        r->error = "Cannot format bridge response";
        return;
    }
    if ((size_t)needed > BRIDGE_MAX_RESPONSE - r->len - 1) {
        r->error = "Response exceeds 1 MiB; request a smaller result limit";
        return;
    }
    size_t required = r->len + (size_t)needed + 1;
    size_t cap = r->cap;
    while (required > cap) {
        cap *= 2;
        if (cap > BRIDGE_MAX_RESPONSE) cap = BRIDGE_MAX_RESPONSE;
    }
    if (cap != r->cap) {
        char *buf = realloc(r->buf, cap);
        if (!buf) {
            r->error = "Cannot allocate bridge response";
            return;
        }
        r->buf = buf;
        r->cap = cap;
    }

    va_start(ap, fmt);
    int written = vsnprintf(r->buf + r->len, r->cap - r->len, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= r->cap - r->len) {
        r->error = "Cannot format complete bridge response";
        return;
    }
    r->len += (size_t)written;
}

static void resp_free(resp_t *r) {
    free(r->buf);
    r->buf = NULL;
    r->len = r->cap = 0;
    r->error = NULL;
}


static void resp_append_json_str(resp_t *r, const char *s) {
    if (!s) { resp_append(r, "null"); return; }
    char esc[4096];
    json_escape(s, esc, sizeof(esc));
    resp_append(r, "%s", esc);
}

static void resp_append_json_data(resp_t *r, NSData *data) {
    if (r->error) return;
    if (!data) {
        r->error = "Cannot serialize JSON value";
        return;
    }
    NSUInteger length = [data length];
    if (length >= BRIDGE_MAX_RESPONSE) {
        r->error = "Response exceeds 1 MiB; request a smaller result limit";
        return;
    }
    resp_append(r, "%.*s", (int)length, (const char *)[data bytes]);
}


/* Find value for a key in JSON. Returns pointer into the string. */
static const char *json_get_string(const char *json, const char *key, char *out, size_t outsz) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) { out[0] = '\0'; return NULL; }
    p += strlen(search);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < outsz - 1) {
            if (*p == '\\' && *(p+1)) { p++; }
            out[i++] = *p++;
        }
        out[i] = '\0';
        return out;
    }
    size_t i = 0;
    while (*p && *p != ',' && *p != '}' && *p != ' ' && i < outsz - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return out;
}

static long json_get_long(const char *json, const char *key) {
    char val[64];
    if (json_get_string(json, key, val, sizeof(val))) return atol(val);
    return 0;
}

#endif /* DARKMACH_BRIDGE_H */
