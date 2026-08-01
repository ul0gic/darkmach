/* Runtime bridge dylib: UDS/JSON-lines server inside the target app. See docs/bridge.md.
 * Unity build -- all cmd-*.c modules are #included below into one translation unit. */

#include "darkmach-bridge.h"

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


static void dispatch_command(const char *request, int client_fd) {
    char cmd[64] = "";
    char id_str[32] = "0";
    json_get_string(request, "cmd", cmd, sizeof(cmd));
    json_get_string(request, "id", id_str, sizeof(id_str));
    /* A miss clears the buffer, and a bare "id": is unparseable for the client. */
    if (!id_str[0]) strlcpy(id_str, "0", sizeof(id_str));

    resp_t r = resp_new();
    resp_append(&r, "{\"id\":%s,\"ok\":true,", id_str);

    if (strcmp(cmd, "info") == 0)                    cmd_info(request, &r);
    else if (strcmp(cmd, "enumerate_classes") == 0)   cmd_enumerate_classes(request, &r);
    else if (strcmp(cmd, "get_methods") == 0)         cmd_get_methods(request, &r);
    else if (strcmp(cmd, "get_properties") == 0)      cmd_get_properties(request, &r);
    else if (strcmp(cmd, "get_ivars") == 0)           cmd_get_ivars(request, &r);
    else if (strcmp(cmd, "read_property") == 0)       cmd_read_property(request, &r);
    else if (strcmp(cmd, "call_method") == 0)         cmd_call_method(request, &r);
    else if (strcmp(cmd, "view_hierarchy") == 0)      cmd_view_hierarchy(request, &r);
    else if (strcmp(cmd, "keychain_dump") == 0)       cmd_keychain_dump(request, &r);
    else if (strcmp(cmd, "userdefaults_dump") == 0)   cmd_userdefaults_dump(request, &r);
    else if (strcmp(cmd, "cookies_dump") == 0)        cmd_cookies_dump(request, &r);
    else if (strcmp(cmd, "heap_search") == 0)         cmd_heap_search(request, &r);
    else if (strcmp(cmd, "read_memory") == 0)         cmd_read_memory(request, &r);
    else if (strcmp(cmd, "hook_method") == 0)         cmd_hook_method(request, &r);
    else if (strcmp(cmd, "unhook_method") == 0)       cmd_unhook_method(request, &r);
    else if (strcmp(cmd, "db_dump") == 0)             cmd_db_dump(request, &r);
    else if (strcmp(cmd, "fs_scan") == 0)             cmd_fs_scan(request, &r);
    else if (strcmp(cmd, "memory_scan") == 0)         cmd_memory_scan(request, &r);
    else if (strcmp(cmd, "heap_dump") == 0)           cmd_heap_dump(request, &r);
    else if (strcmp(cmd, "event_tap") == 0)           cmd_event_tap(request, &r);
    else if (strcmp(cmd, "env_dump") == 0)            cmd_env_dump(request, &r);
    else if (strcmp(cmd, "db_query") == 0)            cmd_db_query(request, &r);
    else if (strcmp(cmd, "db_queries") == 0)          cmd_db_queries(request, &r);
    else if (strcmp(cmd, "net_tap") == 0)             cmd_net_tap(request, &r);
    else if (strcmp(cmd, "net_filter") == 0)          cmd_net_filter(request, &r);
    else if (strcmp(cmd, "crypto_tap") == 0)          cmd_crypto_tap(request, &r);
    else if (strcmp(cmd, "crypto_keys") == 0)         cmd_crypto_keys(request, &r);
    else if (strcmp(cmd, "auth_tap") == 0)            cmd_auth_tap(request, &r);
    else if (strcmp(cmd, "auth_tokens") == 0)         cmd_auth_tokens(request, &r);
    else if (strcmp(cmd, "trace") == 0)              cmd_trace(request, &r);
    else if (strcmp(cmd, "trace_class") == 0)        cmd_trace_class(request, &r);
    else if (strcmp(cmd, "trace_log") == 0)          cmd_trace_log(request, &r);
    else if (strcmp(cmd, "untrace") == 0)            cmd_untrace(request, &r);
    else if (strcmp(cmd, "trace_verbose") == 0)     cmd_trace_verbose(request, &r);
    else if (strcmp(cmd, "ui_tap") == 0)             cmd_ui_tap(request, &r);
    else if (strcmp(cmd, "ui_type") == 0)            cmd_ui_type(request, &r);
    else if (strcmp(cmd, "ui_scroll") == 0)          cmd_ui_scroll(request, &r);
    else if (strcmp(cmd, "ui_back") == 0)            cmd_ui_back(request, &r);
    else if (strcmp(cmd, "ui_alert_dismiss") == 0)   cmd_ui_alert_dismiss(request, &r);
    else if (strcmp(cmd, "webview_list") == 0)        cmd_webview_list(request, &r);
    else if (strcmp(cmd, "webview_eval") == 0)        cmd_webview_eval(request, &r);
    else if (strcmp(cmd, "webview_content") == 0)     cmd_webview_content(request, &r);
    else if (strcmp(cmd, "webview_bridge_map") == 0)  cmd_webview_bridge_map(request, &r);
    else if (strcmp(cmd, "inject_class") == 0)        cmd_inject_class(request, &r);
    else if (strcmp(cmd, "inject_method") == 0)       cmd_inject_method(request, &r);
    else if (strcmp(cmd, "replace_delegate") == 0)    cmd_replace_delegate(request, &r);
    else if (strcmp(cmd, "deeplink") == 0)            cmd_deeplink(request, &r);
    else if (strcmp(cmd, "entitlement_scan") == 0)    cmd_entitlement_scan(request, &r);
    else if (strcmp(cmd, "shared_container_scan") == 0) cmd_shared_container_scan(request, &r);
    else if (strcmp(cmd, "pin_analyze") == 0)         cmd_pin_analyze(request, &r);
    else if (strcmp(cmd, "pin_extract") == 0)         cmd_pin_extract(request, &r);
    else if (strcmp(cmd, "block_inspect") == 0)       cmd_block_inspect(request, &r);
    else if (strcmp(cmd, "block_invoke") == 0)        cmd_block_invoke(request, &r);
    else if (strcmp(cmd, "proto_decode") == 0)        cmd_proto_decode(request, &r);
    else if (strcmp(cmd, "proto_schema") == 0)        cmd_proto_schema(request, &r);
    else if (strcmp(cmd, "sdk_map") == 0)             cmd_sdk_map(request, &r);
    else if (strcmp(cmd, "sdk_keys") == 0)            cmd_sdk_keys(request, &r);
    else if (strcmp(cmd, "mem_forensics") == 0)      cmd_mem_forensics(request, &r);
    else if (strcmp(cmd, "mem_snapshot") == 0)       cmd_mem_snapshot(request, &r);
    else if (strcmp(cmd, "mem_diff") == 0)           cmd_mem_diff(request, &r);
    else if (strcmp(cmd, "timing_probe") == 0)       cmd_timing_probe(request, &r);
    else if (strcmp(cmd, "timing_compare") == 0)     cmd_timing_compare(request, &r);
    else if (strcmp(cmd, "stealth_scan") == 0 || strcmp(cmd, "stealth_enable") == 0 || strcmp(cmd, "stealth_status") == 0) {
        /* Stealth commands — dispatch to darkmach-stealth.dylib via dlsym */
        char sym[64];
        snprintf(sym, sizeof(sym), "darkmach_%s", cmd);
        typedef void (*stealth_fn)(const char *, void *);
        stealth_fn fn = (stealth_fn)dlsym(RTLD_DEFAULT, sym);
        if (fn) fn(request, &r);
        else { r.len = 0; resp_append(&r, "{\"id\":%s,\"ok\":false,\"error\":\"darkmach-stealth.dylib not loaded\"", id_str); }
    }
    else {
        r.len = 0;
        resp_append(&r, "{\"id\":%s,\"ok\":false,\"error\":\"unknown command: %s\"", id_str, cmd);
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

    { char init_log[3072];
      snprintf(init_log, sizeof(init_log),
               "\"socket\":\"%s\","
               "\"commands\":[\"info\",\"enumerate_classes\",\"get_methods\","
               "\"get_properties\",\"get_ivars\",\"read_property\",\"call_method\","
               "\"view_hierarchy\",\"keychain_dump\",\"userdefaults_dump\","
               "\"cookies_dump\",\"heap_search\",\"read_memory\","
               "\"hook_method\",\"unhook_method\","
               "\"db_dump\",\"fs_scan\",\"memory_scan\","
               "\"heap_dump\",\"event_tap\",\"env_dump\","
               "\"db_query\",\"db_queries\","
               "\"net_tap\",\"net_filter\",\"crypto_tap\",\"crypto_keys\","
               "\"auth_tap\",\"auth_tokens\","
               "\"trace\",\"trace_class\",\"trace_log\",\"untrace\","
               "\"ui_tap\",\"ui_type\",\"ui_scroll\",\"ui_back\",\"ui_alert_dismiss\","
               "\"webview_list\",\"webview_eval\",\"webview_content\",\"webview_bridge_map\","
               "\"inject_class\",\"inject_method\",\"replace_delegate\","
               "\"entitlement_scan\",\"shared_container_scan\","
               "\"pin_analyze\",\"pin_extract\","
               "\"block_inspect\",\"block_invoke\","
               "\"proto_decode\",\"proto_schema\","
               "\"sdk_map\",\"sdk_keys\","
               "\"mem_forensics\",\"mem_snapshot\",\"mem_diff\","
               "\"timing_probe\",\"timing_compare\"]",
               BRIDGE_SOCKET_PATH);
      darkmach_log(MOD, "init", init_log); }

    fprintf(stderr, "[darkmach-bridge] ready -- 60 commands available on %s\n",
            BRIDGE_SOCKET_PATH);
}
