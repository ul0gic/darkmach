"""`DARKMACH_OUTPUT` overrides OUTPUT_DIR here; the similarly named
`DARKMACH_OUTPUT_DIR` is unrelated — the CLI sets it per-launch for dylib logs."""

from __future__ import annotations

import os
from pathlib import Path

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


def app_output_dir(app_name: str) -> Path:
    slug = app_name.lower().replace(" ", "-").replace(".app", "").replace("_", "-")
    return OUTPUT_DIR / slug


def app_static_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "static"


def app_dynamic_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "dynamic"


def app_bundle_dir(app_name: str) -> Path:
    return app_output_dir(app_name) / "bundle"
