from __future__ import annotations

import contextlib
import json
import readline  # noqa: F401 — enables line editing in interactive_mode

from darkmach.bridge.client import SOCKET_PATH, send_command
from darkmach.bridge.render import _render_help, format_response


def parse_cli_args(argv):
    if not argv:
        return None, None

    cmd = argv[0]
    args = {}

    i = 1
    while i < len(argv):
        if argv[i].startswith("--"):
            key = argv[i][2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                val = argv[i + 1]
                if key in ("address", "size", "index", "limit", "offset", "status", "slot"):
                    with contextlib.suppress(ValueError):
                        val = int(val, 0)  # supports 0x prefix
                args[key] = val
                i += 2
            else:
                args[key] = True
                i += 1
        else:
            i += 1

    return cmd, args or None


def interactive_mode():
    print("darkmach-bridge client — type 'help' for commands, 'quit' to exit")
    print(f"Connecting to {SOCKET_PATH}...")

    r = send_command("info")
    if r.get("ok"):
        print(format_response(r, "info"))
    else:
        print(f"WARNING: {r.get('error', 'cannot connect')}")

    print()

    while True:
        try:
            line = input("darkmach> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue
        if line in ("quit", "exit", "q"):
            break
        if line == "help":
            print(_render_help())
            continue

        parts = line.split()
        cmd = parts[0]

        if cmd == "raw":
            raw_args = " ".join(parts[1:]) if len(parts) > 1 else "{}"
            try:
                parsed = json.loads(raw_args)
                r = send_command(parsed.get("cmd", "info"), parsed.get("args"))
                print(json.dumps(r, indent=2))
            except json.JSONDecodeError:
                print("Invalid JSON")
            continue

        args = {}

        kv_cmds = {
            "heap_dump",
            "event_tap",
            "env_dump",
            "db_query",
            "db_inject",
            "db_queries",
            "net_tap",
            "net_filter",
            "crypto_tap",
            "crypto_keys",
            "auth_tap",
            "auth_tokens",
            "trace",
            "trace_class",
            "trace_log",
            "untrace",
            "ui_tap",
            "ui_type",
            "ui_scroll",
            "ui_back",
            "ui_alert_dismiss",
            "stealth_scan",
            "stealth_enable",
            "stealth_status",
            "webview_list",
            "webview_eval",
            "webview_content",
            "webview_bridge_map",
            "inject_class",
            "inject_method",
            "replace_delegate",
            "deeplink",
            "entitlement_scan",
            "shared_container_scan",
            "pin_analyze",
            "pin_extract",
            "block_inspect",
            "block_invoke",
            "proto_decode",
            "proto_schema",
            "mem_forensics",
            "mem_snapshot",
            "mem_diff",
            "timing_probe",
            "timing_compare",
            "sdk_map",
            "sdk_keys",
        }
        int_keys = {"limit", "offset", "status", "slot", "button_index"}
        float_keys = {"x", "y", "dx", "dy"}

        if cmd in kv_cmds and len(parts) > 1:
            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k in int_keys:
                        with contextlib.suppress(ValueError):
                            v = int(v, 0)
                    elif k in float_keys:
                        with contextlib.suppress(ValueError):
                            v = float(v)
                    args[k] = v

        elif cmd == "enumerate_classes" and len(parts) > 1:
            args["filter"] = " ".join(parts[1:])
        elif cmd in ("get_methods", "get_properties", "get_ivars") and len(parts) > 1:
            args["class"] = parts[1]
        elif cmd == "read_property" and len(parts) >= 3:
            args["address"] = int(parts[1], 0)
            args["property"] = parts[2]
        elif cmd == "call_method" and len(parts) >= 3:
            args["address"] = int(parts[1], 0)
            args["method"] = parts[2]
        elif cmd == "heap_search" and len(parts) > 1:
            args["class"] = parts[1]
        elif cmd == "read_memory" and len(parts) >= 2:
            args["address"] = int(parts[1], 0)
            if len(parts) >= 3:
                args["size"] = int(parts[2], 0)
        elif cmd == "hook_method" and len(parts) >= 3:
            args["class"] = parts[1]
            args["method"] = " ".join(parts[2:])
        elif cmd == "unhook_method" and len(parts) >= 2:
            args["index"] = int(parts[1])
        elif cmd == "db_dump" and len(parts) > 1:
            args["table"] = parts[1]
        elif cmd == "fs_scan" and len(parts) > 1:
            args["path"] = parts[1]
        elif cmd == "memory_scan" and len(parts) > 1:
            args["pattern"] = " ".join(parts[1:])

        r = send_command(cmd, args or None)
        print(format_response(r, cmd))
        print()
