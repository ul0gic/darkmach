"""Bridge client — connects to darkmach-bridge.dylib via Unix domain socket.

Provides both a Python API (send_command) and an interactive REPL.
Used by the CLI (darkmach bridge) and available for LLM tool integration.
"""

from __future__ import annotations

import contextlib
import json
import readline  # noqa: F401 — enables line editing in interactive_mode
import socket
import sys
import textwrap

from darkmach._paths import BRIDGE_SOCKET
from darkmach.typeenc import TypeInfo, format_type_value, parse_method_signature

SOCKET_PATH = BRIDGE_SOCKET
RECV_BUF = 1 << 20  # 1MB max response

_req_id = 0


def send_command(cmd, args=None, socket_path=SOCKET_PATH):
    """Send a command to the bridge and return the parsed response."""
    global _req_id
    _req_id += 1

    msg = {"id": _req_id, "cmd": cmd}
    if args:
        msg["args"] = args

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(socket_path)
    except (FileNotFoundError, ConnectionRefusedError):
        return {"ok": False, "error": f"Cannot connect to {socket_path} — is the bridge running?"}

    s.sendall((json.dumps(msg) + "\n").encode())
    s.settimeout(30)

    data = b""
    while True:
        try:
            chunk = s.recv(RECV_BUF)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        except TimeoutError:
            break
    s.close()

    if not data:
        return {"ok": False, "error": "No response from bridge"}

    try:
        # Parse only the first newline-delimited JSON message (bridge protocol is JSON-lines)
        line = data.split(b"\n", 1)[0]
        return json.loads(line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raw_preview = data.decode("utf-8", errors="replace")[:500]
        return {"ok": False, "error": f"Invalid JSON: {e}", "raw": raw_preview}


def _ns_fmt(ns):
    """Format nanoseconds as human-readable duration."""
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.2f}s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f}ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.1f}us"
    return f"{ns}ns"


def format_response(resp, cmd):
    """Pretty-print a bridge response based on command type."""
    if not resp.get("ok", False) or "error" in resp:
        err = resp.get("error", "unknown error")
        return f"ERROR: {err}"

    lines = []

    if cmd == "info":
        lines.append(f"Bridge: {resp.get('bridge')} v{resp.get('version')}")
        app_name = resp.get("appName")
        app_ver = resp.get("appVersion")
        app_build = resp.get("appBuild")
        lines.append(f"App: {app_name} {app_ver} (build {app_build})")
        lines.append(f"Bundle: {resp.get('bundleId')}")
        lines.append(f"PID: {resp.get('pid')}")
        lines.append(f"Classes: {resp.get('totalClasses')}")
        lines.append(f"Active hooks: {resp.get('activeHooks')}")
        lines.append(f"Commands: {', '.join(resp.get('commands', []))}")

    elif cmd == "enumerate_classes":
        classes = resp.get("classes", [])
        lines.append(f"Found {resp.get('count', len(classes))} classes:")
        lines.extend(f"  {c}" for c in classes)

    elif cmd in ("get_methods", "get_properties", "get_ivars"):
        key = cmd.replace("get_", "")
        items = resp.get(key, [])
        lines.append(f"{len(items)} {key}:")
        for item in items:
            if isinstance(item, dict):
                name = item.get("name", str(item))
                attrs = item.get("attributes", item.get("type", ""))
                lines.append(f"  {name}  {attrs}")
            else:
                lines.append(f"  {item}")

    elif cmd == "read_property":
        lines.append(f"Property: {resp.get('property')}")
        lines.append(f"Value: {resp.get('value')}")
        lines.append(f"Class: {resp.get('valueClass')}")

    elif cmd == "call_method":
        lines.append(f"Result: {resp.get('result')}")
        lines.append(f"Class: {resp.get('resultClass')}")
        if resp.get("resultAddress"):
            lines.append(f"Address: {resp.get('resultAddress')}")

    elif cmd == "view_hierarchy":
        views = resp.get("views", [])

        def print_tree(node, indent=0):
            cls = node.get("class", "?")
            frame = node.get("frame", {})
            label = node.get("accessibilityLabel", "")
            text = node.get("text", "")
            hidden = node.get("hidden", False)
            prefix = "  " * indent
            line = f"{prefix}{cls}"
            if frame:
                fx, fy = frame.get("x", 0), frame.get("y", 0)
                fw, fh = frame.get("w", 0), frame.get("h", 0)
                line += f" ({fx:.0f},{fy:.0f} {fw:.0f}x{fh:.0f})"
            if label:
                line += f' label="{label}"'
            if text:
                line += f' text="{text[:60]}"'
            if hidden:
                line += " [HIDDEN]"
            lines.append(line)
            for child in node.get("subviews", []):
                print_tree(child, indent + 1)

        for v in views:
            print_tree(v)

    elif cmd == "keychain_dump":
        items = resp.get("items", [])
        lines.append(f"Keychain items: {len(items)}")
        lines.extend(
            f"  [{item.get('class', '?')}] {json.dumps(item.get('data', item), indent=2)[:200]}"
            for item in items
        )

    elif cmd == "userdefaults_dump":
        entries = resp.get("entries", [])
        lines.append(f"UserDefaults entries: {resp.get('count', len(entries))}")
        for e in entries:
            key = e.get("key", "?")
            val = str(e.get("value", ""))[:100]
            lines.append(f"  {key}: {val}")

    elif cmd == "cookies_dump":
        cookies = resp.get("cookies", [])
        lines.append(f"Cookies: {len(cookies)}")
        lines.extend(
            f"  {c.get('name', '?')}={str(c.get('value', ''))[:60]} ({c.get('domain', '?')})"
            for c in cookies
        )

    elif cmd == "heap_search":
        instances = resp.get("instances", [])
        lines.append(f"Found {resp.get('found', len(instances))} instances:")
        for inst in instances:
            lines.append(f"  {inst.get('address')} via {inst.get('via', '?')}")
            lines.append(f"    {inst.get('description', '')[:150]}")

    elif cmd == "read_memory":
        lines.append(f"Address: {resp.get('address')}")
        lines.append(f"Size: {resp.get('size')} bytes")
        hex_str = resp.get("hex", "")
        # Format as hex dump
        for i in range(0, len(hex_str), 32):
            chunk = hex_str[i : i + 32]
            hex_part = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
            ascii_part = resp.get("ascii", "")[i // 2 : (i + 32) // 2] if resp.get("ascii") else ""
            lines.append(f"  {i // 2:04x}: {hex_part:<48s} {ascii_part}")

    elif cmd in ("hook_method", "unhook_method"):
        lines.append(json.dumps(resp, indent=2))

    elif cmd == "db_dump":
        databases = resp.get("databases", [])
        lines.append(f"Home: {resp.get('home', '?')}")
        lines.append(f"Databases found: {len(databases)}")
        for db in databases:
            lines.append(f"\n  === {db.get('path', '?')} ===")
            if "error" in db:
                lines.append(f"    ERROR: {db['error']}")
                continue
            for tbl in db.get("tables", []):
                cols = ", ".join(
                    f"{c['name']} ({c.get('type', '?')})" for c in tbl.get("columns", [])
                )
                lines.append(f"    {tbl['name']} [{tbl.get('row_count', '?')} rows]: {cols}")
                for row in tbl.get("rows", [])[:5]:
                    row_str = json.dumps(row, default=str)
                    lines.append(f"      {row_str[:200]}")
                remaining = tbl.get("row_count", 0) - len(tbl.get("rows", []))
                if remaining > 0:
                    lines.append(f"      ... {remaining} more rows")

    elif cmd == "fs_scan":
        lines.append(f"Root: {resp.get('root', '?')}")
        lines.append(f"Total files: {resp.get('total_files', '?')}")

        def print_files(items, indent=0):
            for item in items:
                prefix = "  " * indent
                if item.get("type") == "dir":
                    lines.append(f"{prefix}[DIR] {item.get('path', '?')}")
                    print_files(item.get("children", []), indent + 1)
                else:
                    size = item.get("size", 0)
                    sz_str = f"{size:,}" if size < 1048576 else f"{size / 1048576:.1f}MB"
                    line = f"{prefix}{item.get('name', '?')} ({sz_str})"
                    if item.get("content"):
                        line += f"\n{prefix}  >>> {item['content'][:200]}"
                    lines.append(line)

        print_files(resp.get("files", []))

    elif cmd == "memory_scan":
        matches = resp.get("matches", [])
        lines.append(f"Regions scanned: {resp.get('regions_scanned', '?')}")
        lines.append(f"Matches found: {resp.get('match_count', len(matches))}")
        for m in matches:
            lines.append(f"  [{m.get('pattern', '?')}] @ {m.get('address', '?')}")
            lines.append(f"    {m.get('context', '')[:150]}")

    # ── Sprint 13.1: Foundation commands ─────────────────────────

    elif cmd == "heap_dump":
        instances = resp.get("instances", [])
        total_scanned = resp.get("total_scanned", 0)
        total_matched = resp.get("total_matched", len(instances))
        returned = resp.get("returned", len(instances))
        time_ms = resp.get("time_ms", 0)
        lines.append(
            f"Found {total_matched} instances "
            f"(scanned {total_scanned} objects in {time_ms}ms)"
        )
        if instances:
            lines.append(f"{'ADDRESS':<20s} {'CLASS':<40s} {'SIZE':>6s}")
            lines.append("-" * 68)
            for inst in instances:
                addr = inst.get("addr", "?")
                cls = inst.get("class", "?")
                size = str(inst.get("size", "?"))
                lines.append(f"{addr:<20s} {cls:<40s} {size:>6s}")
        if returned < total_matched:
            lines.append(f"... {total_matched - returned} more (use offset/limit)")

    elif cmd == "event_tap":
        # action=enable / action=disable
        if resp.get("enabled"):
            filt = resp.get("name_filter", "")
            lines.append(f"Event tap enabled{f' (filter: {filt})' if filt else ''}")
            return "\n".join(lines)
        if resp.get("disabled"):
            lines.append(f"Event tap disabled (captured {resp.get('total_captured', 0)} events)")
            return "\n".join(lines)
        # action=recent
        events = resp.get("events", [])
        total = resp.get("total_captured", len(events))
        lines.append(f"Events captured: {total} (showing {len(events)})")
        for ev in events:
            ts = ev.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            name = ev.get("name", "?")
            obj_cls = ev.get("object_class", "")
            keys = ", ".join(ev.get("user_info_keys", []))
            line = f"  [{ts_short}] {name}"
            if obj_cls:
                line += f"  from={obj_cls}"
            if keys:
                line += f"  keys=[{keys}]"
            lines.append(line)

    elif cmd == "env_dump":
        # Environment Variables
        env = resp.get("env", {})
        lines.append(f"=== Environment Variables ({len(env)}) ===")
        for k, v in sorted(env.items()):
            lines.append(f"  {k}={v[:120]}")
        # Launch Arguments
        launch_args = resp.get("args", [])
        lines.append(f"\n=== Launch Arguments ({len(launch_args)}) ===")
        lines.extend(f"  {a}" for a in launch_args)
        # Loaded Images
        images = resp.get("images", [])
        lines.append(f"\n=== Loaded Images ({len(images)}) ===")
        for img in images:
            name = img.get("name", "?")
            slide = img.get("slide", "0x0")
            lines.append(f"  {name:<40s} slide={slide}")
        # Open File Descriptors
        fds = resp.get("fds", [])
        lines.append(f"\n=== Open File Descriptors ({len(fds)}) ===")
        for fd in fds:
            fd_num = fd.get("fd", "?")
            path = fd.get("path", "?")
            lines.append(f"  fd {fd_num:<4} {path}")
        # PID
        pid = resp.get("pid")
        if pid:
            lines.append(f"\nPID: {pid}")

    elif cmd in ("db_inject", "db_query"):
        # SELECT results
        columns = resp.get("columns")
        if columns:
            rows = resp.get("rows", [])
            row_count = resp.get("row_count", len(rows))
            col_header = " | ".join(str(c) for c in columns)
            lines.append(col_header)
            lines.append("-" * len(col_header))
            lines.extend(" | ".join(str(v) for v in row) for row in rows)
            lines.append(f"({row_count} row{'s' if row_count != 1 else ''})")
            if resp.get("truncated"):
                lines.append("... results truncated")
        else:
            # INSERT/UPDATE/DELETE
            affected = resp.get("affected", 0)
            last_id = resp.get("last_insert_id", 0)
            lines.append(f"Affected rows: {affected}")
            if last_id:
                lines.append(f"Last insert ID: {last_id}")

    elif cmd == "db_queries":
        queries = resp.get("queries", [])
        total = resp.get("total_captured", len(queries))
        lines.append(f"Intercepted queries: {total} (showing {len(queries)})")
        for q in queries:
            ts = q.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            sql = q.get("sql", "?")[:80]
            path = q.get("path", "")
            dur = q.get("duration_us", 0)
            line = f"  [{ts_short}] {sql}"
            if dur:
                line += f"  ({dur}us)"
            if path:
                line += f"  [{path.rsplit('/', 1)[-1]}]"
            lines.append(line)

    # ── Sprint 13.2: Network Intelligence commands ───────────────

    elif cmd in ("net_tap", "net_filter"):
        requests = resp.get("requests", [])
        total = resp.get("total_captured", len(requests))
        lines.append(f"HTTP traffic: {total} captured (showing {len(requests)})")
        for req in requests:
            ts = req.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            method = req.get("method", "?")
            url = req.get("url", "?")
            if len(url) > 80:
                url = url[:77] + "..."
            status = req.get("status", "?")
            dur = req.get("duration_ms", "?")
            lines.append(f"  [{ts_short}] {method} {url} -> {status} ({dur}ms)")

    elif cmd == "crypto_tap":
        ops = resp.get("operations", [])
        total = resp.get("total_captured", len(ops))
        lines.append(f"Crypto operations: {total} captured (showing {len(ops)})")
        for op in ops:
            ts = op.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            op_type = op.get("op", "?")
            algo = op.get("algorithm", "?")
            key_hex = op.get("key_hex", "")
            key_preview = key_hex[:16] + "..." if len(key_hex) > 16 else key_hex
            direction = "ENC" if op.get("encrypt") else "DEC"
            lines.append(
                f"  [{ts_short}] {op_type} {algo} {direction} "
                f"key={key_preview}"
            )

    elif cmd == "crypto_keys":
        keys = resp.get("keys", [])
        total = resp.get("total_unique", len(keys))
        lines.append(f"Unique keys extracted: {total}")
        if keys:
            lines.append(f"{'ALGORITHM':<20s} {'KEY (hex)':<40s} {'USES':>5s}")
            lines.append("-" * 67)
            for k in keys:
                algo = k.get("algorithm", "?")
                key_hex = k.get("key_hex", "?")
                if len(key_hex) > 36:
                    key_hex = key_hex[:33] + "..."
                count = str(k.get("use_count", "?"))
                lines.append(f"  {algo:<18s} {key_hex:<40s} {count:>5s}")
                first = k.get("first_seen", "")
                last = k.get("last_seen", "")
                if first:
                    lines.append(f"    first: {first}  last: {last}")

    elif cmd == "auth_tap":
        events = resp.get("events", [])
        total = resp.get("total_captured", len(events))
        lines.append(f"Auth events: {total} captured (showing {len(events)})")
        for ev in events:
            ts = ev.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            ev_type = ev.get("type", "?")
            provider = ev.get("provider", "")
            url = ev.get("url", "")
            token_preview = ev.get("token_preview", "")
            line = f"  [{ts_short}] {ev_type}"
            if provider:
                line += f"  provider={provider}"
            if url:
                display_url = url[:60] + "..." if len(url) > 60 else url
                line += f"  {display_url}"
            if token_preview:
                tp = token_preview[:32] + "..." if len(token_preview) > 32 else token_preview
                line += f"\n    token: {tp}"
            claims = ev.get("claims", {})
            if claims:
                claim_parts = [f"{ck}={cv}" for ck, cv in list(claims.items())[:6]]
                lines.append(line)
                lines.append(f"    claims: {', '.join(claim_parts)}")
                continue
            lines.append(line)

    elif cmd == "auth_tokens":
        tokens = resp.get("tokens", [])
        total = resp.get("total_unique", len(tokens))
        lines.append(f"Extracted tokens: {total}")
        for tok in tokens:
            tok_type = tok.get("type", "?")
            preview = tok.get("value_preview", "?")
            if len(preview) > 40:
                preview = preview[:37] + "..."
            source = tok.get("source", "?")
            full_len = tok.get("full_value_len", 0)
            lines.append(f"  [{tok_type}] {preview} ({full_len} chars)")
            lines.append(f"    source: {source}")
            claims = tok.get("claims", {})
            if claims:
                claim_parts = [f"{ck}={cv}" for ck, cv in list(claims.items())[:6]]
                lines.append(f"    claims: {', '.join(claim_parts)}")
            first = tok.get("first_seen", "")
            last = tok.get("last_seen", "")
            if first:
                lines.append(f"    first: {first}  last: {last}")

    # ── Sprint 13.3: Trace commands ─────────────────────────────────

    elif cmd == "trace":
        cls = resp.get("class", "?")
        method = resp.get("method", "?")
        slot = resp.get("slot", "?")
        enc = resp.get("type_encoding", "")
        types = parse_method_signature(enc)
        ret_name = types[0].name if types else "?"
        # User args start at index 3 (after return, self, _cmd)
        user_types = types[3:] if len(types) > 3 else []
        arg_count = len(user_types)
        arg_desc = ", ".join(f"{t.name}" for t in user_types) if user_types else "none"
        lines.append(
            f"Hooked -[{cls} {method}] at slot {slot} "
            f"({ret_name} method, {arg_count} arg{'s' if arg_count != 1 else ''}: {arg_desc})"
        )

    elif cmd == "trace_class":
        cls = resp.get("class", "?")
        hooked = resp.get("hooked", 0)
        methods = resp.get("methods", [])
        skipped = resp.get("skipped", 0)
        lines.append(f"Hooked {hooked} methods on {cls}:")
        lines.extend(f"  - {m}" for m in methods)
        if skipped:
            reasons = resp.get("skipped_reasons", [])
            lines.append(f"Skipped {skipped}: {', '.join(reasons)}")

    elif cmd == "trace_log":
        entries = resp.get("entries", [])
        total = resp.get("total_entries", len(entries))
        returned = resp.get("returned", len(entries))
        lines.append(f"Trace log: {total} total, showing {returned}")
        for entry in entries:
            ts = entry.get("timestamp", "?")
            ts_short = ts[11:23] if len(ts) >= 23 else ts
            cls = entry.get("class", "?")
            method = entry.get("method", "?")
            call_count = entry.get("call_count", entry.get("slot", "?"))
            dur_ns = entry.get("duration_ns", 0)
            dur_ms = dur_ns / 1_000_000
            lines.append(f"\n[{ts_short}] -[{cls} {method}] #{call_count}")
            # Format args using typeenc
            args = entry.get("args", {})
            for arg_key in sorted(args.keys()):
                arg_info = args[arg_key]
                if isinstance(arg_info, dict):
                    type_name = arg_info.get("type", "?")
                    value = str(arg_info.get("value", ""))
                    # Build a TypeInfo for format_type_value
                    ti = TypeInfo(
                        encoding="@", name=type_name,
                        is_object="*" in type_name and type_name not in ("char *", "const char *"),
                        is_pointer="*" in type_name and type_name in ("char *", "const char *"),
                        is_struct=False, is_block=type_name == "block",
                    )
                    formatted = format_type_value(ti, value)
                    lines.append(f"  ({type_name}){arg_key} = {formatted}")
                else:
                    lines.append(f"  {arg_key} = {arg_info}")
            # Return value
            ret_info = entry.get("return_value", {})
            if isinstance(ret_info, dict):
                ret_val = ret_info.get("value")
                ret_str = str(ret_val) if ret_val is not None else "void"
            else:
                ret_str = str(ret_info) if ret_info else "void"
            lines.append(f"  -> {ret_str}  ({dur_ms:.1f}ms)")

    elif cmd == "untrace":
        cls = resp.get("class", "?")
        method = resp.get("method", "?")
        slot = resp.get("slot")
        if cls != "?" and method != "?":
            lines.append(f"Unhooked -[{cls} {method}]")
        elif slot is not None:
            lines.append(f"Unhooked slot {slot}")
        else:
            lines.append("Unhooked")

    # ── Sprint 13.4: UI Interact + Stealth commands ─────────────────

    elif cmd == "ui_tap":
        target_cls = resp.get("target_class", "")
        label = resp.get("target_label", "")
        frame = resp.get("target_frame", {})
        if label:
            line = f"Tapped {target_cls or 'view'} with label '{label}'"
        elif frame:
            fx = frame.get("x", 0)
            fy = frame.get("y", 0)
            line = f"Tapped {target_cls or 'view'} at ({fx:.0f}, {fy:.0f})"
        else:
            line = f"Tapped {target_cls or 'view'}"
        if frame:
            fx = frame.get("x", 0)
            fy = frame.get("y", 0)
            fw = frame.get("w", 0)
            fh = frame.get("h", 0)
            line += f" frame={{{fx:.1f}, {fy:.1f}, {fw:.1f}, {fh:.1f}}}"
        lines.append(line)

    elif cmd == "ui_type":
        field_cls = resp.get("field_class", "UITextField")
        new_text = resp.get("new_text", "")
        lines.append(f"Typed '{new_text}' into {field_cls}")
        prev = resp.get("previous_text")
        if prev:
            lines.append(f"  (was: '{prev}')")

    elif cmd == "ui_scroll":
        sv_cls = resp.get("scroll_view_class", "UIScrollView")
        offset = resp.get("content_offset", {})
        ox = offset.get("x", 0)
        oy = offset.get("y", 0)
        lines.append(f"Scrolled {sv_cls} to offset ({ox:.0f}, {oy:.0f})")
        size = resp.get("content_size", {})
        if size:
            sw = size.get("w", 0)
            sh = size.get("h", 0)
            lines.append(f"  content size: {sw:.0f} x {sh:.0f}")

    elif cmd == "ui_back":
        action = resp.get("action", "none")
        from_cls = resp.get("from_class", "?")
        to_cls = resp.get("to_class", "")
        if action == "pop":
            line = f"Navigated back (pop from {from_cls})"
            if to_cls:
                line += f" to {to_cls}"
            lines.append(line)
        elif action == "dismiss":
            lines.append(f"Dismissed {from_cls}")
        else:
            lines.append("No back action available")

    elif cmd == "ui_alert_dismiss":
        title = resp.get("title", "")
        button = resp.get("button", "")
        if title and button:
            lines.append(f"Dismissed alert '{title}' via button '{button}'")
        elif title:
            lines.append(f"Dismissed alert '{title}'")
        else:
            lines.append("Dismissed alert")

    elif cmd == "stealth_scan":
        detections = resp.get("detections", [])
        total = resp.get("total_detections", len(detections))
        risk = resp.get("risk_level", "unknown")
        if detections:
            lines.append(
                f"{'TECHNIQUE':<30s} {'LIBRARY':<20s} {'CONFIDENCE':<12s}"
            )
            lines.append("-" * 64)
            for d in detections:
                tech = d.get("technique", "?")
                lib = d.get("library", "?")
                conf = d.get("confidence", "?")
                lines.append(f"  {tech:<28s} {lib:<20s} {conf:<12s}")
                desc = d.get("description", "")
                if desc:
                    lines.append(f"    {desc}")
                cls = d.get("class", "")
                method = d.get("method", "")
                if cls or method:
                    loc = f"-[{cls} {method}]" if cls and method else cls or method
                    lines.append(f"    location: {loc}")
        suffix = "s" if total != 1 else ""
        lines.append(f"\nFound {total} anti-analysis technique{suffix} (risk: {risk})")

    elif cmd == "stealth_enable":
        bypasses = resp.get("active_bypasses", [])
        total = resp.get("total_active", len(bypasses))
        suffix = "es" if total != 1 else ""
        lines.append(f"Enabled {total} bypass{suffix}:")
        lines.extend(f"  - {b}" for b in bypasses)

    elif cmd == "stealth_status":
        bypasses = resp.get("bypasses", [])
        lines.append(f"{'TECHNIQUE':<20s} {'ACTIVE':<8s} {'INTERCEPTS':>10s}")
        lines.append("-" * 40)
        for b in bypasses:
            tech = b.get("technique", "?")
            active = "yes" if b.get("active") else "no"
            count = str(b.get("intercept_count", 0))
            lines.append(f"  {tech:<18s} {active:<8s} {count:>10s}")

    # ── Sprint 13.5: Deep Analysis commands ─────────────────────────

    elif cmd == "webview_list":
        webviews = resp.get("webviews", [])
        lines.append(f"WebViews found: {len(webviews)}")
        if webviews:
            lines.append(
                f"{'ADDRESS':<20s} {'URL':<50s} {'HANDLERS':>8s}"
            )
            lines.append("-" * 80)
            for wv in webviews:
                addr = wv.get("address", "?")
                url = wv.get("url", "(no URL)")
                if len(url) > 48:
                    url = url[:45] + "..."
                handlers = str(wv.get("handler_count", 0))
                lines.append(f"  {addr:<18s} {url:<50s} {handlers:>8s}")
                scripts = wv.get("user_scripts", 0)
                js_enabled = wv.get("js_enabled", True)
                if scripts or not js_enabled:
                    notes = []
                    if scripts:
                        notes.append(f"{scripts} user scripts")
                    if not js_enabled:
                        notes.append("JS disabled")
                    lines.append(f"    {', '.join(notes)}")

    elif cmd == "webview_eval":
        lines.append(f"WebView: {resp.get('address', '?')}")
        result = resp.get("result", "")
        lines.append(f"Result: {result}")
        if resp.get("error"):
            lines.append(f"JS Error: {resp['error']}")

    elif cmd == "webview_content":
        addr = resp.get("address", "?")
        length = resp.get("content_length", 0)
        lines.append(f"WebView: {addr} ({length} chars)")
        content = resp.get("content", "")
        # Show preview, full content available in raw response
        preview = content[:500]
        if len(content) > 500:
            preview += "\n... (truncated)"
        lines.append(preview)

    elif cmd == "webview_bridge_map":
        handlers = resp.get("handlers", [])
        lines.append(f"Script message handlers: {len(handlers)}")
        if handlers:
            lines.append(
                f"{'HANDLER NAME':<30s} {'NATIVE CLASS':<30s}"
            )
            lines.append("-" * 62)
            for h in handlers:
                name = h.get("name", "?")
                native_cls = h.get("native_class", "?")
                lines.append(f"  {name:<28s} {native_cls:<30s}")
                if h.get("webview_address"):
                    lines.append(f"    webview: {h['webview_address']}")

    elif cmd == "inject_class":
        name = resp.get("name", "?")
        superclass = resp.get("superclass", "NSObject")
        protocols = resp.get("protocols", [])
        lines.append(f"Created class: {name} : {superclass}")
        if protocols:
            lines.append(f"  protocols: {', '.join(protocols)}")
        lines.append(f"  address: {resp.get('class_address', '?')}")

    elif cmd == "inject_method":
        cls = resp.get("class", "?")
        selector = resp.get("selector", "?")
        impl = resp.get("implementation", "?")
        lines.append(f"Added -[{cls} {selector}]")
        lines.append(f"  implementation: {impl}")

    elif cmd == "replace_delegate":
        obj_addr = resp.get("object_address", "?")
        prop = resp.get("delegate_property", "delegate")
        old_cls = resp.get("original_class", "?")
        new_cls = resp.get("new_class", "?")
        lines.append(f"Replaced {prop} on {obj_addr}")
        lines.append(f"  {old_cls} -> {new_cls}")
        if resp.get("chained"):
            lines.append("  (chained to original)")

    elif cmd == "entitlement_scan":
        images = resp.get("images", [])
        total_ents = resp.get("total_entitlements", 0)
        risk_count = resp.get("risk_count", 0)
        lines.append(
            f"Scanned {len(images)} images, "
            f"{total_ents} entitlements ({risk_count} flagged)"
        )
        for img in images:
            img_name = img.get("name", "?")
            ents = img.get("entitlements", {})
            risks = img.get("risks", [])
            lines.append(f"\n  === {img_name} ({len(ents)} entitlements) ===")
            for key, val in ents.items():
                val_str = str(val) if not isinstance(val, list) else ", ".join(str(v) for v in val)
                if len(val_str) > 80:
                    val_str = val_str[:77] + "..."
                lines.append(f"    {key}: {val_str}")
            lines.extend(
                f"    ** {r.get('level', 'RISK')}: {r.get('description', '?')}"
                for r in risks
            )

    elif cmd == "shared_container_scan":
        containers = resp.get("containers", [])
        lines.append(f"Shared containers: {len(containers)}")
        for ctr in containers:
            group_id = ctr.get("group_id", "?")
            path = ctr.get("path", "?")
            file_count = ctr.get("file_count", 0)
            lines.append(f"\n  [{group_id}]")
            lines.append(f"    path: {path}")
            lines.append(f"    files: {file_count}")
            for f in ctr.get("files", [])[:20]:
                fname = f.get("name", "?")
                fsize = f.get("size", 0)
                sz = f"{fsize:,}" if fsize < 1048576 else f"{fsize / 1048576:.1f}MB"
                lines.append(f"      {fname} ({sz})")

    elif cmd == "pin_analyze":
        data = resp.get("data", resp)
        evals = data.get("evaluations", [])
        total = data.get("total_captured", len(evals))
        returned = data.get("returned", len(evals))
        pinned_hosts = data.get("pinned_hosts", [])
        lines.append(
            f"Trust evaluations: {total} captured (showing {returned})"
        )
        if evals:
            lines.append(
                f"{'HOST':<30s} {'TRUSTED':<9s} {'BYPASS':<8s} {'CERTS':>5s}"
            )
            lines.append("-" * 54)
            for ev in evals:
                host = ev.get("host", "?")
                if len(host) > 28:
                    host = host[:25] + "..."
                trusted = "yes" if ev.get("trusted") else "no"
                bypassed = "YES" if ev.get("bypassed") else "no"
                cert_count = str(ev.get("cert_count", 0))
                lines.append(
                    f"  {host:<28s} {trusted:<9s} {bypassed:<8s} {cert_count:>5s}"
                )
                for cert in ev.get("certs", [])[:3]:
                    subj = cert.get("subject", "?")
                    sha = cert.get("pubkey_sha256", "")
                    sha_short = sha[:16] + "..." if len(sha) > 16 else sha
                    lines.append(f"    {subj}  key={sha_short}")
        # TrustKit
        tk = data.get("trustkit", {})
        if tk.get("detected"):
            lines.append("\nTrustKit: detected")
            if tk.get("validator"):
                lines.append(f"  validator: {str(tk['validator'])[:120]}")
        else:
            lines.append("\nTrustKit: not detected")
        # ATS
        ats = data.get("ats", {})
        if ats.get("configured"):
            arb = ats.get("allows_arbitrary_loads", False)
            arb_web = ats.get("allows_arbitrary_loads_web", False)
            line = "ATS: configured"
            if arb:
                line += " (allows arbitrary loads)"
            if arb_web:
                line += " (allows arbitrary web loads)"
            lines.append(line)
            for exc in ats.get("exception_domains", []):
                domain = exc.get("domain", "?")
                notes = []
                if exc.get("allows_insecure_http"):
                    notes.append("insecure HTTP")
                if exc.get("includes_subdomains"):
                    notes.append("incl. subdomains")
                tls = exc.get("min_tls_version")
                if tls:
                    notes.append(f"TLS>={tls}")
                suffix = f"  ({', '.join(notes)})" if notes else ""
                lines.append(f"  {domain}{suffix}")
        else:
            lines.append("ATS: not configured")
        # Unique pinned hosts
        if pinned_hosts:
            lines.append(f"\nPinned hosts ({len(pinned_hosts)}):")
            lines.extend(f"  {h}" for h in pinned_hosts)

    elif cmd == "pin_extract":
        data = resp.get("data", resp)
        certs = data.get("certificates", [])
        returned = data.get("returned", len(certs))
        lines.append(f"Certificates extracted: {returned}")
        for cert in certs:
            host = cert.get("host", "?")
            subject = cert.get("subject", "?")
            der_size = cert.get("der_size", 0)
            trusted = "yes" if cert.get("trusted") else "no"
            lines.append(f"\n  [{host}] trusted={trusted}")
            lines.append(f"    subject: {subject}")
            lines.append(f"    DER: {der_size} bytes")
            sha = cert.get("pubkey_sha256", "")
            if sha:
                lines.append(f"    pubkey SHA-256: {sha}")
            b64 = cert.get("der_base64", "")
            if b64:
                preview = b64[:64] + "..." if len(b64) > 64 else b64
                lines.append(f"    base64: {preview}")

    # ── Sprint 13.6: Advanced commands ────────────────────────────

    elif cmd == "block_inspect":
        block_type = resp.get("block_type", "?")
        addr = resp.get("address", "?")
        invoke = resp.get("invoke_address", "?")
        sig = resp.get("signature", "")
        size = resp.get("descriptor_size", 0)
        lines.append(f"Block at {addr} ({block_type})")
        lines.append(f"  invoke: {invoke}")
        if sig:
            lines.append(f"  signature: {sig}")
        lines.append(f"  descriptor size: {size}")
        captured = resp.get("captured_vars", [])
        if captured:
            lines.append(f"  captured variables ({len(captured)}):")
            for v in captured:
                offset = v.get("offset", "?")
                vtype = v.get("type", "?")
                value = str(v.get("value", ""))[:80]
                lines.append(f"    +{offset} ({vtype}): {value}")

    elif cmd == "block_invoke":
        addr = resp.get("address", "?")
        result = resp.get("result", "void")
        result_class = resp.get("result_class", "")
        lines.append(f"Invoked block at {addr}")
        lines.append(f"  result: {result}")
        if result_class:
            lines.append(f"  class: {result_class}")

    elif cmd == "proto_decode":
        fields = resp.get("fields", [])
        source = resp.get("source", "")
        if source:
            lines.append(f"Source: {source}")
        lines.append(f"Decoded {len(fields)} field(s):")

        def render_proto_tree(flds, indent=1):
            for f in flds:
                prefix = "  " * indent
                num = f.get("field_number", "?")
                wire = f.get("wire_type", "?")
                name = f.get("name", "")
                name_part = f" ({name})" if name else ""
                nested = f.get("nested", [])
                if nested:
                    lines.append(f"{prefix}field {num}{name_part} {{")
                    render_proto_tree(nested, indent + 1)
                    lines.append(f"{prefix}}}")
                else:
                    val_str = str(f.get("value", ""))[:100]
                    lines.append(f"{prefix}field {num}{name_part} [{wire}]: {val_str}")

        render_proto_tree(fields)

    elif cmd == "proto_schema":
        schemas = resp.get("schemas", [])
        lines.append(f"Reconstructed schemas: {len(schemas)}")
        for schema in schemas:
            url = schema.get("url", "?")
            msg_type = schema.get("message_type", "unknown")
            sfields = schema.get("fields", [])
            lines.append(f"\n  [{msg_type}] from {url}")
            for sf in sfields:
                num = sf.get("number", "?")
                name = sf.get("name", f"field_{num}")
                ftype = sf.get("type", "?")
                lines.append(f"    {num}: {name} ({ftype})")

    elif cmd == "mem_forensics":
        findings = resp.get("findings", [])
        regions = resp.get("regions_scanned", 0)
        time_ms = resp.get("time_ms", 0)
        lines.append(f"Scanned {regions} freed regions in {time_ms}ms")
        lines.append(f"Recovered {len(findings)} sensitive item(s):")
        if findings:
            lines.append(f"  {'TYPE':<16s} {'ADDRESS':<20s} {'VALUE'}")
            lines.append("  " + "-" * 58)
            for finding in findings:
                ftype = finding.get("type", "?")
                addr = finding.get("address", "?")
                val = str(finding.get("value", ""))[:60]
                lines.append(f"  {ftype:<16s} {addr:<20s} {val}")

    elif cmd == "mem_snapshot":
        snap_id = resp.get("snapshot_id", "?")
        total_obj = resp.get("total_objects", 0)
        total_sz = resp.get("total_size", 0)
        sz_str = f"{total_sz / 1048576:.1f}MB" if total_sz >= 1048576 else f"{total_sz:,}"
        ts = resp.get("timestamp", "")
        line = f"Snapshot {snap_id}: {total_obj} objects ({sz_str})"
        if ts:
            line += f" at {ts}"
        lines.append(line)

    elif cmd == "mem_diff":
        added = resp.get("added", [])
        removed = resp.get("removed", [])
        changed = resp.get("changed", [])
        lines.append(f"Heap diff: +{len(added)} -{len(removed)} ~{len(changed)}")
        if added:
            lines.append("\n  Added:")
            for a in added:
                cls = a.get("class", "?")
                count = a.get("count", 0)
                size = a.get("total_size", 0)
                lines.append(f"    +{count} {cls} ({size:,} bytes)")
        if removed:
            lines.append("\n  Removed:")
            for rm in removed:
                cls = rm.get("class", "?")
                count = rm.get("count", 0)
                size = rm.get("total_size", 0)
                lines.append(f"    -{count} {cls} ({size:,} bytes)")
        if changed:
            lines.append("\n  Changed:")
            for ch in changed:
                cls = ch.get("class", "?")
                delta = ch.get("count_delta", 0)
                sign = "+" if delta >= 0 else ""
                lines.append(f"    {sign}{delta} {cls}")

    elif cmd == "timing_probe":
        cls = resp.get("class", "?")
        method = resp.get("method", "?")
        iters = resp.get("iterations", 0)
        lines.append(f"Timing: -[{cls} {method}] x{iters}")
        lines.append(f"  {'STAT':<10s} {'VALUE':>12s}")
        lines.append(f"  {'-' * 24}")
        for stat in ("mean", "median", "stddev", "min", "max"):
            val = resp.get(f"{stat}_ns", 0)
            lines.append(f"  {stat:<10s} {_ns_fmt(val):>12s}")
        if resp.get("constant_time") is not None:
            ct = "yes" if resp["constant_time"] else "no"
            lines.append(f"  Constant-time: {ct}")

    elif cmd == "timing_compare":
        cls = resp.get("class", "?")
        method = resp.get("method", "?")
        iters = resp.get("iterations", 0)
        lines.append(f"Timing comparison: -[{cls} {method}] x{iters}")
        for label in ("variant_a", "variant_b"):
            v = resp.get(label, {})
            mean = v.get("mean_ns", 0)
            stddev = v.get("stddev_ns", 0)
            tag = label.replace("variant_", "").upper()
            lines.append(f"  {tag}: mean={_ns_fmt(mean)}  stddev={_ns_fmt(stddev)}")
        diff = resp.get("difference_ns", 0)
        sig = resp.get("significant", False)
        sig_mark = " ***" if sig else ""
        lines.append(f"  Difference: {_ns_fmt(diff)}{sig_mark}")

    elif cmd == "sdk_map":
        sdks = resp.get("sdks", [])
        lines.append(f"SDKs detected: {len(sdks)}")
        if sdks:
            lines.append(
                f"  {'SDK':<25s} {'VERSION':<15s} {'CONFIDENCE':<12s} {'CLASSES':>8s}"
            )
            lines.append("  " + "-" * 62)
            for sdk in sdks:
                name = sdk.get("name", "?")
                ver = sdk.get("version", "?")
                conf = sdk.get("confidence", "?")
                cls_count = str(len(sdk.get("classes", [])))
                lines.append(f"  {name:<25s} {ver:<15s} {conf:<12s} {cls_count:>8s}")
                image = sdk.get("image", "")
                if image:
                    lines.append(f"    image: {image}")

    elif cmd == "sdk_keys":
        sdks = resp.get("sdks", [])
        total = sum(len(s.get("keys", [])) for s in sdks)
        suffix = "s" if total != 1 else ""
        lines.append(f"Extracted {total} credential{suffix} from {len(sdks)} SDK(s):")
        for sdk in sdks:
            name = sdk.get("name", "?")
            keys = sdk.get("keys", [])
            if keys:
                ks = "s" if len(keys) != 1 else ""
                lines.append(f"\n  === {name} ({len(keys)} key{ks}) ===")
                for k in keys:
                    kname = k.get("key_name", "?")
                    kval = str(k.get("key_value", ""))
                    if len(kval) > 60:
                        kval = kval[:57] + "..."
                    source = k.get("source", "")
                    lines.append(f"    {kname}: {kval}")
                    if source:
                        lines.append(f"      source: {source}")

    else:
        lines.append(json.dumps(resp, indent=2))

    return "\n".join(lines)


def parse_cli_args(argv):
    """Parse CLI arguments into (cmd, args_dict)."""
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
                # Try to parse as int (for address, size, index, limit, offset, status)
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
    """Run interactive REPL."""
    print("darkmach-bridge client — type 'help' for commands, 'quit' to exit")
    print(f"Connecting to {SOCKET_PATH}...")

    # Test connection
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
            print(
                textwrap.dedent("""
                Commands:
                  info
                  enumerate_classes [filter]
                  get_methods <class>
                  get_properties <class>
                  get_ivars <class>
                  read_property <address> <property>
                  call_method <address> <method>
                  view_hierarchy
                  keychain_dump
                  userdefaults_dump
                  cookies_dump
                  heap_search <class>
                  read_memory <address> [size]
                  hook_method <class> <method>
                  unhook_method <index>
                  db_dump [table_filter]
                  fs_scan [path]
                  memory_scan [pattern]

                Sprint 13.1 — Foundation:
                  heap_dump [class=<name>] [limit=N] [offset=N]
                  event_tap action=<enable|disable|recent> [name_filter=<str>] [limit=N]
                  env_dump
                  db_query path=<db_path> sql=<statement>
                  db_queries [limit=N] [path_filter=<str>]

                Sprint 13.2 — Network:
                  net_tap [limit=N]
                  net_filter [host=<str>] [path=<str>] [method=<str>] [status=N] [limit=N]
                  crypto_tap [limit=N]
                  crypto_keys
                  auth_tap [limit=N]
                  auth_tokens

                Sprint 13.3 — Trace:
                  trace class=<name> method=<sel>
                  trace_class class=<name>
                  trace_log [limit=N] [class=<name>] [method=<sel>]
                  untrace class=<name> method=<sel>
                  untrace slot=<N>

                Sprint 13.4 — UI Interact + Stealth:
                  ui_tap [label=<str>] [x=<N> y=<N>] [class=<str>] [text=<str>] [index=N]
                  ui_type text=<str> [address=<hex>] [clear=true]
                  ui_scroll [dx=<N>] [dy=<N>] [address=<hex>]
                  ui_back
                  ui_alert_dismiss [button_index=N]
                  stealth_scan
                  stealth_enable [techniques=<list>]
                  stealth_status

                Sprint 13.5 — Deep Analysis:
                  webview_list
                  webview_eval address=<hex> js=<code>
                  webview_content address=<hex>
                  webview_bridge_map
                  inject_class name=<str> [superclass=<str>]
                  inject_method class=<str> selector=<sel> implementation=<type>
                  replace_delegate object_address=<hex> [new_class=<str>]
                  entitlement_scan
                  shared_container_scan
                  pin_analyze [limit=N]
                  pin_extract [host=<str>] [limit=N]

                Sprint 13.6 — Advanced:
                  block_inspect address=<hex>
                  block_invoke address=<hex> [args=<json>]
                  proto_decode hex=<data> | base64=<data>
                  proto_schema
                  mem_forensics
                  mem_snapshot
                  mem_diff snapshot_a=<id> snapshot_b=<id>
                  timing_probe class=<name> method=<sel> [iterations=N]
                  timing_compare class=<name> method=<sel> args_a=<json> args_b=<json>
                  sdk_map
                  sdk_keys

                Addresses can be hex (0x...) or decimal.
                Use key=value for named args. Use 'raw <cmd> [args_json]' for raw JSON.
            """).strip()
            )
            continue

        parts = line.split()
        cmd = parts[0]

        # Raw JSON mode
        if cmd == "raw":
            raw_args = " ".join(parts[1:]) if len(parts) > 1 else "{}"
            try:
                parsed = json.loads(raw_args)
                r = send_command(parsed.get("cmd", "info"), parsed.get("args"))
                print(json.dumps(r, indent=2))
            except json.JSONDecodeError:
                print("Invalid JSON")
            continue

        # Build args from positional params or key=value pairs
        args = {}

        # New commands use key=value syntax
        kv_cmds = {
            "heap_dump", "event_tap", "env_dump", "db_query", "db_inject",
            "db_queries", "net_tap", "net_filter", "crypto_tap", "crypto_keys",
            "auth_tap", "auth_tokens",
            "trace", "trace_class", "trace_log", "untrace",
            "ui_tap", "ui_type", "ui_scroll", "ui_back", "ui_alert_dismiss",
            "stealth_scan", "stealth_enable", "stealth_status",
            "webview_list", "webview_eval", "webview_content", "webview_bridge_map",
            "inject_class", "inject_method", "replace_delegate",
            "entitlement_scan", "shared_container_scan", "pin_analyze", "pin_extract",
            "block_inspect", "block_invoke", "proto_decode", "proto_schema",
            "mem_forensics", "mem_snapshot", "mem_diff",
            "timing_probe", "timing_compare", "sdk_map", "sdk_keys",
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

        # Legacy positional commands
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


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd, args = parse_cli_args(sys.argv[1:])
        r = send_command(cmd, args)
        print(format_response(r, cmd))
    else:
        interactive_mode()
