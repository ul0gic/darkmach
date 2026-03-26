"""Resolve project root and key directories.

When installed via pipx, the package lives in a venv but the project
root (dylibs, scripts, patch) must be found. We walk up from the
package file to find the marker (pyproject.toml).

For development (pip install -e .), __file__ is inside src/darkmach/
and the root is two levels up.
"""

from __future__ import annotations

from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent  # src/darkmach/
_SRC_DIR = _THIS_DIR.parent  # src/


def _find_root() -> Path:
    """Walk up from package dir looking for pyproject.toml."""
    candidate = _THIS_DIR
    for _ in range(5):
        if (candidate / "pyproject.toml").exists():
            return candidate
        candidate = candidate.parent
    # Fallback: assume src/darkmach/ layout → root is ../../
    return _THIS_DIR.parent.parent


ROOT = _find_root()
SRC_DIR = ROOT / "src"
DYLIB_DIR = SRC_DIR / "dylibs" / "build"
PATCH_DIR = SRC_DIR / "patch"
OUTPUT_DIR = ROOT / "output"
CRYPT_CACHE = OUTPUT_DIR / ".cache" / "crypt"
BRIDGE_SOCKET = "/tmp/darkmach-bridge.sock"


def app_output_dir(app_name: str) -> Path:
    """Return output/<app_name>/ — the per-app output root."""
    # Normalize: lowercase, strip common suffixes, replace spaces
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
