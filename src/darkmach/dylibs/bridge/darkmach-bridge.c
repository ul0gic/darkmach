/* Runtime bridge dylib: UDS/JSON-lines server inside the target app. See docs/bridge.md.
 * Unity build -- all cmd-*.c modules are #included below into one translation unit. */

#include "darkmach-bridge.h"

typedef void (*bridge_handler_t)(const char *request, resp_t *r);

typedef struct {
    const char *name;
    bridge_handler_t handler;
    const char *args;
} bridge_command_t;

static void bridge_append_command_list(resp_t *r);

/* Order matters: cmd-trace.c defines hook_count used by cmd-recon.c (cmd_info) */
#include "cmd-trace.c"
#include "cmd-recon.c"
#include "cmd-events.c"
#include "cmd-network.c"
#include "cmd-ui.c"
#include "cmd-analysis.c"
#include "cmd-forensics.c"
#include "cmd-inject.c"


static int bridge_server_fd = -1;
static dispatch_queue_t bridge_queue = NULL;


/* The single source of truth for which commands exist: routing, the `info` list,
 * the ready banner and the init log all derive from this. */
static const bridge_command_t bridge_commands[] = {
    { "info",                  cmd_info,                  "" },
    { "enumerate_classes",     cmd_enumerate_classes,     "[filter]" },
    { "get_methods",           cmd_get_methods,           "<class>" },
    { "get_properties",        cmd_get_properties,        "<class>" },
    { "get_ivars",             cmd_get_ivars,             "<class>" },
    { "read_property",         cmd_read_property,         "<address> <property>" },
    { "call_method",           cmd_call_method,           "<address> <method>" },
    { "view_hierarchy",        cmd_view_hierarchy,        "" },
    { "keychain_dump",         cmd_keychain_dump,         "" },
    { "userdefaults_dump",     cmd_userdefaults_dump,     "" },
    { "cookies_dump",          cmd_cookies_dump,          "" },
    { "heap_search",           cmd_heap_search,           "<class>" },
    { "read_memory",           cmd_read_memory,           "<address> [size]" },
    { "hook_method",           cmd_hook_method,           "<class> <method>" },
    { "unhook_method",         cmd_unhook_method,         "<index>" },
    { "db_dump",               cmd_db_dump,               "[table_filter]" },
    { "fs_scan",               cmd_fs_scan,               "[path]" },
    { "memory_scan",           cmd_memory_scan,           "[pattern]" },
    { "heap_dump",             cmd_heap_dump,             "[class=<name>] [limit=N] [offset=N]" },
    { "event_tap",             cmd_event_tap,             "action=<enable|disable|recent> [name_filter=<str>] [limit=N]" },
    { "env_dump",              cmd_env_dump,              "" },
    { "db_query",              cmd_db_query,              "path=<db_path> sql=<statement>" },
    { "db_queries",            cmd_db_queries,            "[limit=N] [path_filter=<str>]" },
    { "net_tap",               cmd_net_tap,               "[limit=N]" },
    { "net_filter",            cmd_net_filter,            "[host=<str>] [path=<str>] [method=<str>] [status=N] [limit=N]" },
    { "crypto_tap",            cmd_crypto_tap,            "[limit=N]" },
    { "crypto_keys",           cmd_crypto_keys,           "" },
    { "auth_tap",              cmd_auth_tap,              "[limit=N]" },
    { "auth_tokens",           cmd_auth_tokens,           "" },
    { "trace",                 cmd_trace,                 "class=<name> method=<sel>" },
    { "trace_class",           cmd_trace_class,           "class=<name>" },
    { "trace_log",             cmd_trace_log,             "[limit=N] [class=<name>] [method=<sel>]" },
    { "untrace",               cmd_untrace,               "class=<name> method=<sel> | slot=<N>" },
    { "trace_verbose",         cmd_trace_verbose,         "verbose=<0|1> [slot=N]" },
    { "ui_tap",                cmd_ui_tap,                "[label=<str>] [x=<N> y=<N>] [class=<str>] [text=<str>] [index=N]" },
    { "ui_type",               cmd_ui_type,               "text=<str> [address=<hex>] [clear=true]" },
    { "ui_scroll",             cmd_ui_scroll,             "[dx=<N>] [dy=<N>] [address=<hex>]" },
    { "ui_back",               cmd_ui_back,               "" },
    { "ui_alert_dismiss",      cmd_ui_alert_dismiss,      "[button_index=N]" },
    { "webview_list",          cmd_webview_list,          "" },
    { "webview_eval",          cmd_webview_eval,          "address=<hex> js=<code>" },
    { "webview_content",       cmd_webview_content,       "address=<hex>" },
    { "webview_bridge_map",    cmd_webview_bridge_map,    "" },
    { "inject_class",          cmd_inject_class,          "name=<str> [superclass=<str>]" },
    { "inject_method",         cmd_inject_method,         "class=<str> selector=<sel> implementation=<type>" },
    { "replace_delegate",      cmd_replace_delegate,      "object_address=<hex> [new_class=<str>]" },
    { "deeplink",              cmd_deeplink,              "url=<url>" },
    { "entitlement_scan",      cmd_entitlement_scan,      "" },
    { "shared_container_scan", cmd_shared_container_scan, "" },
    { "pin_analyze",           cmd_pin_analyze,           "[limit=N]" },
    { "pin_extract",           cmd_pin_extract,           "[host=<str>] [limit=N]" },
    { "block_inspect",         cmd_block_inspect,         "address=<hex>" },
    { "block_invoke",          cmd_block_invoke,          "address=<hex> [args=<json>]" },
    { "proto_decode",          cmd_proto_decode,          "hex=<data> | base64=<data>" },
    { "proto_schema",          cmd_proto_schema,          "" },
    { "sdk_map",               cmd_sdk_map,               "" },
    { "sdk_keys",              cmd_sdk_keys,              "" },
    { "mem_forensics",         cmd_mem_forensics,         "" },
    { "mem_snapshot",          cmd_mem_snapshot,          "" },
    { "mem_diff",              cmd_mem_diff,              "snapshot_a=<id> snapshot_b=<id>" },
    { "timing_probe",          cmd_timing_probe,          "class=<name> method=<sel> [iterations=N]" },
    { "timing_compare",        cmd_timing_compare,        "class=<name> method=<sel> args_a=<json> args_b=<json>" },
};

static const size_t bridge_command_count =
    sizeof(bridge_commands) / sizeof(bridge_commands[0]);


static bridge_handler_t bridge_find_handler(const char *name) {
    for (size_t i = 0; i < bridge_command_count; i++) {
        if (strcmp(bridge_commands[i].name, name) == 0)
            return bridge_commands[i].handler;
    }
    return NULL;
}

/* Flat string array: darkmach bridge's client columnizes it. Argument hints live
 * in the table and are published once in the init log. */
static void bridge_append_command_list(resp_t *r) {
    resp_append(r, "\"commands\":[");
    for (size_t i = 0; i < bridge_command_count; i++)
        resp_append(r, "%s\"%s\"", i ? "," : "", bridge_commands[i].name);
    resp_append(r, "]");
}


/* Stealth lives in darkmach-stealth.dylib, absent from the default injection set,
 * so it resolves by dlsym rather than sitting in the table. */
static int bridge_dispatch_stealth(const char *cmd, const char *request,
                                   const char *id_str, resp_t *r) {
    if (strcmp(cmd, "stealth_scan") != 0 && strcmp(cmd, "stealth_enable") != 0 &&
        strcmp(cmd, "stealth_status") != 0)
        return 0;

    char sym[64];
    snprintf(sym, sizeof(sym), "darkmach_%s", cmd);
    typedef void (*stealth_fn)(const char *, void *);
    stealth_fn fn = (stealth_fn)dlsym(RTLD_DEFAULT, sym);
    if (fn) {
        fn(request, r);
    } else {
        r->len = 0;
        resp_append(r, "{\"id\":%s,\"ok\":false,"
                    "\"error\":\"darkmach-stealth.dylib not loaded\"", id_str);
    }
    return 1;
}


static void dispatch_command(const char *request, int client_fd) {
    char cmd[64] = "";
    char id_str[32] = "0";
    json_get_string(request, "cmd", cmd, sizeof(cmd));
    json_get_string(request, "id", id_str, sizeof(id_str));
    /* A miss clears the buffer, and a bare "id": is unparseable for the client. */
    if (!id_str[0]) strlcpy(id_str, "0", sizeof(id_str));

    resp_t r = resp_new();
    resp_append(&r, "{\"id\":%s,\"ok\":true,", id_str);

    bridge_handler_t handler = bridge_find_handler(cmd);
    if (handler) {
        handler(request, &r);
    } else if (!bridge_dispatch_stealth(cmd, request, id_str, &r)) {
        r.len = 0;
        resp_append(&r, "{\"id\":%s,\"ok\":false,\"error\":\"unknown command: %s\"",
                    id_str, cmd);
    }

    resp_append(&r, "}\n");

    write(client_fd, r.buf, r.len);
    resp_free(&r);
}


static void handle_client(int client_fd) {
    fprintf(stderr, "[darkmach-bridge] client connected (fd=%d)\n", client_fd);
    { char lb[64]; snprintf(lb, sizeof(lb), "\"fd\":%d", client_fd);
      darkmach_log(MOD, "client_connected", lb); }

    char buf[BRIDGE_MAX_REQUEST];
    ssize_t total = 0;

    while (1) {
        ssize_t n = read(client_fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        char *line_start = buf;
        char *newline;
        while ((newline = strchr(line_start, '\n')) != NULL) {
            *newline = '\0';
            if (strlen(line_start) > 0) {
                dispatch_command(line_start, client_fd);
            }
            line_start = newline + 1;
        }

        size_t remaining = total - (line_start - buf);
        if (remaining > 0 && line_start != buf) {
            memmove(buf, line_start, remaining);
        }
        total = remaining;
    }

    fprintf(stderr, "[darkmach-bridge] client disconnected (fd=%d)\n", client_fd);
    { char lb[64]; snprintf(lb, sizeof(lb), "\"fd\":%d", client_fd);
      darkmach_log(MOD, "client_disconnected", lb); }
    close(client_fd);
}

static void start_server(void) {
    unlink(BRIDGE_SOCKET_PATH);

    bridge_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bridge_server_fd < 0) {
        fprintf(stderr, "[darkmach-bridge] ERROR: socket() failed: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BRIDGE_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(bridge_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[darkmach-bridge] ERROR: bind() failed: %s\n", strerror(errno));
        close(bridge_server_fd);
        bridge_server_fd = -1;
        return;
    }

    if (listen(bridge_server_fd, 2) < 0) {
        fprintf(stderr, "[darkmach-bridge] ERROR: listen() failed: %s\n", strerror(errno));
        close(bridge_server_fd);
        bridge_server_fd = -1;
        return;
    }

    fprintf(stderr, "[darkmach-bridge] listening on %s\n", BRIDGE_SOCKET_PATH);

    bridge_queue = dispatch_queue_create("darkmach.bridge.accept", DISPATCH_QUEUE_SERIAL);
    dispatch_async(bridge_queue, ^{
        while (1) {
            int client_fd = accept(bridge_server_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EBADF) break;  /* Server shut down */
                fprintf(stderr, "[darkmach-bridge] accept error: %s\n", strerror(errno));
                continue;
            }

            dispatch_queue_t client_queue = dispatch_queue_create(
                "darkmach.bridge.client", DISPATCH_QUEUE_SERIAL);
            dispatch_async(client_queue, ^{
                handle_client(client_fd);
            });
        }
    });
}


__attribute__((constructor))
static void darkmach_bridge_init(void) {
    fprintf(stderr, "[darkmach-bridge] initializing LLM runtime bridge\n");
    darkmach_log_init(MOD);

    memset(hooks, 0, sizeof(hooks));

    start_server();

    { resp_t log = resp_new();
      resp_append(&log, "\"socket\":\"%s\",\"command_count\":%zu,\"commands\":[",
                  BRIDGE_SOCKET_PATH, bridge_command_count);
      for (size_t i = 0; i < bridge_command_count; i++)
          resp_append(&log, "%s{\"name\":\"%s\",\"args\":\"%s\"}",
                      i ? "," : "", bridge_commands[i].name, bridge_commands[i].args);
      resp_append(&log, "]");
      darkmach_log(MOD, "init", log.buf);
      resp_free(&log); }

    fprintf(stderr, "[darkmach-bridge] ready -- %zu commands available on %s\n",
            bridge_command_count, BRIDGE_SOCKET_PATH);
}
