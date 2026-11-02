from __future__ import annotations

import json
import socket
import time

from darkmach._paths import BRIDGE_SOCKET

SOCKET_PATH = BRIDGE_SOCKET
RECV_BUF = 1 << 20  # 1MB max response

_req_id = 0
_bridge_req_id = 0


def exchange(message: dict, *, socket_path: str, timeout: float = 30) -> bytes:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + timeout
    try:
        sock.settimeout(timeout)
        sock.connect(socket_path)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Bridge command timed out before sending")
        sock.settimeout(remaining)
        sock.sendall((json.dumps(message) + "\n").encode())

        data = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
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


def bridge_command(
    cmd: str,
    args: dict | None = None,
    *,
    socket_path: str = BRIDGE_SOCKET,
    timeout: float = 30,
) -> dict:
    """Send a single command to the bridge and return the response."""
    global _bridge_req_id
    _bridge_req_id += 1

    msg = {"id": _bridge_req_id, "cmd": cmd}
    if args:
        msg["args"] = args

    data = exchange(msg, socket_path=socket_path, timeout=timeout)

    if not data:
        return {"ok": False, "error": "No response from bridge"}
    # Parse only the first newline-delimited JSON message (bridge protocol is JSON-lines)
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8", errors="replace"))
