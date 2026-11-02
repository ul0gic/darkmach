from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class DarkmachError(Exception):
    """Raised when a pipeline step fails."""


def log(msg: str) -> None:
    print(f"[darkmach] {msg}", flush=True)


def log_step(step: int, total: int, msg: str) -> None:
    print(f"[darkmach] [{step}/{total}] {msg}", flush=True)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with consistent error handling."""
    if not quiet:
        log(f"  $ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        stderr = result.stderr if capture else ""
        raise DarkmachError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{stderr}")
    return result


def plist_read(plist_path: Path, key: str) -> str | None:
    """Read a single key from a plist file."""
    result = subprocess.run(
        ["plutil", "-extract", key, "raw", str(plist_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None
