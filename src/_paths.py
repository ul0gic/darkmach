"""`DARKMACH_OUTPUT` overrides OUTPUT_DIR here; the similarly named
`DARKMACH_OUTPUT_DIR` is unrelated — the CLI sets it per-launch for dylib logs."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from darkmach.pipeline.process import DarkmachError

_PACKAGE_DIR = Path(__file__).resolve().parent

DYLIB_DIR = _PACKAGE_DIR / "dylibs" / "build"
PATCH_DIR = _PACKAGE_DIR / "patch"


def _resolve_output_dir() -> Path:
    override = os.environ.get("DARKMACH_OUTPUT")
    if override:
        return Path(override).resolve()
    return Path.cwd() / "output"


OUTPUT_DIR = _resolve_output_dir()
CRYPT_CACHE = OUTPUT_DIR / ".cache" / "crypt"
BRIDGE_SOCKET = "/tmp/darkmach-bridge.sock"


def resolve_bridge_socket(udid: str | None = None, socket_path: str | None = None) -> str:
    if socket_path is None:
        if udid is None:
            return BRIDGE_SOCKET
        try:
            device_id = str(uuid.UUID(udid)).upper()
        except ValueError as error:
            raise DarkmachError(f"Invalid Simulator UDID: {udid}") from error
        socket_path = f"/tmp/darkmach-bridge-{device_id}.sock"
    if "\0" in socket_path or not Path(socket_path).is_absolute():
        raise DarkmachError("Bridge socket path must be absolute and contain no NUL bytes")
    try:
        encoded_path = socket_path.encode("utf-8")
    except UnicodeEncodeError as error:
        raise DarkmachError("Bridge socket path must be valid UTF-8") from error
    # Darwin sockaddr_un.sun_path is 104 bytes, including the terminating NUL.
    if len(encoded_path) >= 104:
        raise DarkmachError("Bridge socket path must be shorter than 104 UTF-8 bytes")
    return socket_path


def app_output_dir(app_name: str) -> Path:
    slug = app_name.lower().replace(" ", "-").replace(".app", "").replace("_", "-")
    return OUTPUT_DIR / slug


def app_static_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "static"


def app_dynamic_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "dynamic"


def app_bundle_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "bundle"


INTERCEPTOR_DYLIBS = [
    "darkmach-metal-fix.dylib",
    "darkmach-net.dylib",
    "darkmach-keychain.dylib",
    "darkmach-crypto.dylib",
    "darkmach-storage.dylib",
    "darkmach-ssl.dylib",
    "darkmach-db.dylib",
    "darkmach-bridge.dylib",
]

DECRYPT_DYLIB = DYLIB_DIR / "darkmach-decrypt.dylib"
SURVIVAL_DYLIB = DYLIB_DIR / "darkmach-survival.dylib"

# Strategy A writes this marker; launch uses it to inject the survival dylib.
STRATEGY_MARKER = ".darkmach-strategy"
