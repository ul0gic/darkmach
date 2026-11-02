from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from darkmach.pipeline.process import DarkmachError

if TYPE_CHECKING:
    from pathlib import Path


def validate_app_path(app_path: Path) -> None:
    """Validate an app path before starting the pipeline."""
    if not app_path.exists():
        raise DarkmachError(f"Path does not exist: {app_path}")
    if not app_path.is_dir():
        raise DarkmachError(f"Not a directory: {app_path}")
    if app_path.suffix != ".app":
        raise DarkmachError(f"Not an .app bundle: {app_path}")
    has_wrapper = (app_path / "Wrapper").is_dir()
    has_plist = (app_path / "Info.plist").exists()
    if not has_wrapper and not has_plist:
        raise DarkmachError(f"Not a valid app bundle (no Wrapper/ or Info.plist): {app_path}")


def find_ios_app_bundle(app_path: Path) -> Path:
    """Mac App Store iOS apps nest the real bundle at `Name.app/Wrapper/Name.app`;
    a manually placed bundle is the `.app` itself."""
    wrapper = app_path / "Wrapper"
    if wrapper.is_dir():
        inner_apps = list(wrapper.glob("*.app"))
        if inner_apps:
            return inner_apps[0]
    info_plist = app_path / "Info.plist"
    if info_plist.exists():
        result = subprocess.run(
            ["plutil", "-p", str(info_plist)],
            capture_output=True,
            text=True,
            check=False,
        )
        if "UIDeviceFamily" in result.stdout:
            return app_path
    raise DarkmachError(f"Cannot find iOS app bundle in {app_path}")
