from __future__ import annotations

import json
import socket

from darkmach._paths import BRIDGE_SOCKET

SOCKET_PATH = BRIDGE_SOCKET
RECV_BUF = 1 << 20  # 1MB max response

_req_id = 0
_bridge_req_id = 0


def exchange(message: dict, *, socket_path: str) -> bytes:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(message) + "\n").encode())
        sock.settimeout(30)

        data = b""
        while True:
            try:
                chunk = sock.recv(RECV_BUF)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            except TimeoutError:
                break
        return data
    finally:
        sock.close()


def send_command(cmd, args=None, socket_path=SOCKET_PATH):
    global _req_id
    _req_id += 1

    msg = {"id": _req_id, "cmd": cmd}
    if args:
        msg["args"] = args

    try:
        data = exchange(msg, socket_path=socket_path)
    except (FileNotFoundError, ConnectionRefusedError):
        return {"ok": False, "error": f"Cannot connect to {socket_path} — is the bridge running?"}

    if not data:
        return {"ok": False, "error": "No response from bridge"}

    try:
        # Parse only the first newline-delimited JSON message (bridge protocol is JSON-lines)
        line = data.split(b"\n", 1)[0]
        return json.loads(line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raw_preview = data.decode("utf-8", errors="replace")[:500]
        return {"ok": False, "error": f"Invalid JSON: {e}", "raw": raw_preview}


def bridge_command(cmd: str, args: dict | None = None) -> dict:
    """Send a single command to the bridge and return the response."""
    global _bridge_req_id
    _bridge_req_id += 1

    msg = {"id": _bridge_req_id, "cmd": cmd}
    if args:
        msg["args"] = args

    data = exchange(msg, socket_path=BRIDGE_SOCKET)

    if not data:
        return {"ok": False, "error": "No response from bridge"}
    # Parse only the first newline-delimited JSON message (bridge protocol is JSON-lines)
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8", errors="replace"))
