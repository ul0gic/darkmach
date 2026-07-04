"""Resolve package directories (dylibs, patch scripts) and OUTPUT_DIR.

OUTPUT_DIR defaults to `$PWD/output`, overridable via `DARKMACH_OUTPUT`.
Distinct from `DARKMACH_OUTPUT_DIR`, which the CLI sets per-launch to point
the dylibs' JSONL logs at a per-app `dynamic/` subdir.
"""

from __future__ import annotations

import os
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent  # …/darkmach/

DYLIB_DIR = _PACKAGE_DIR / "dylibs" / "build"
PATCH_DIR = _PACKAGE_DIR / "patch"


def _resolve_output_dir() -> Path:
    """Default to $PWD/output, overridable via DARKMACH_OUTPUT env var."""
    override = os.environ.get("DARKMACH_OUTPUT")
    if override:
        return Path(override).resolve()
    return Path.cwd() / "output"


OUTPUT_DIR = _resolve_output_dir()
CRYPT_CACHE = OUTPUT_DIR / ".cache" / "crypt"
BRIDGE_SOCKET = "/tmp/darkmach-bridge.sock"


def app_output_dir(app_name: str) -> Path:
    """Return output/<app_name>/ — the per-app output root."""
    slug = app_name.lower().replace(" ", "-").replace(".app", "").replace("_", "-")
    return OUTPUT_DIR / slug


def app_static_dir(app_name: str) -> Path:
    """output/<app>/static/ — static analysis results."""
    return app_output_dir(app_name) / "static"


def app_dynamic_dir(app_name: str) -> Path:
    """output/<app>/dynamic/ — runtime interceptor logs."""
    return app_output_dir(app_name) / "dynamic"


def app_bundle_dir(app_name: str) -> Path:
    """output/<app>/bundle/ — patched app copy."""
    return app_output_dir(app_name) / "bundle"
