from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from darkmach._paths import BRIDGE_SOCKET
from darkmach.bridge.client import bridge_command
from darkmach.pipeline.process import DarkmachError, log, plist_read


def simctl(*args: str, capture: bool = True, check: bool = True) -> str:
    result = subprocess.run(
        ["xcrun", "simctl", *args],
        capture_output=capture,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise DarkmachError(f"simctl {args[0]} failed: {result.stderr}")
    return result.stdout.strip() if capture else ""


def get_booted_device() -> str | None:
    raw = simctl("list", "devices", "booted", "-j")
    data = json.loads(raw)
    for devices in data.get("devices", {}).values():
        for dev in devices:
            if dev.get("state") == "Booted":
                return dev["udid"]
    return None


def boot_simulator() -> str:
    udid = get_booted_device()
    if udid:
        log(f"Simulator already booted: {udid}")
        return udid

    log("No booted Simulator — finding available device...")
    raw = simctl("list", "devices", "available", "-j")
    data = json.loads(raw)

    for runtime in sorted(data.get("devices", {}).keys(), reverse=True):
        if "iOS" not in runtime:
            continue
        for dev in data["devices"][runtime]:
            if dev.get("isAvailable") and "iPhone" in dev.get("name", ""):
                udid = dev["udid"]
                log(f"Booting {dev['name']} ({udid})...")
                simctl("boot", udid, check=False)
                subprocess.run(["open", "-a", "Simulator"], check=False)
                log("Waiting for Simulator to be fully ready...")
                subprocess.run(
                    ["xcrun", "simctl", "bootstatus", udid, "-b"],
                    check=False,
                    timeout=60,
                )
                return udid

    raise DarkmachError("No available iPhone Simulator device found")


def stage_install(ios_bundle: Path, udid: str) -> str:
    """Install a patched bundle into the Simulator. Returns bundle ID."""
    info_plist = ios_bundle / "Info.plist"
    bundle_id = plist_read(info_plist, "CFBundleIdentifier")
    if not bundle_id:
        raise DarkmachError(f"Cannot read CFBundleIdentifier from {info_plist}")

    log(f"Installing {bundle_id} to Simulator {udid}...")
    simctl("install", udid, str(ios_bundle))
    return bundle_id


def stage_launch(
    bundle_id: str,
    udid: str,
    *,
    dylibs: list[Path] | None = None,
    env: dict[str, str] | None = None,
) -> int:
    """Returns the PID of the launched process."""
    simctl("terminate", udid, bundle_id, check=False)
    time.sleep(0.5)

    sock_path = Path(BRIDGE_SOCKET)
    if sock_path.exists():
        sock_path.unlink()

    launch_env = dict(os.environ)
    if dylibs:
        missing = [d for d in dylibs if not d.exists()]
        if missing:
            raise DarkmachError(f"Missing dylibs: {[str(m) for m in missing]}")
        libs_str = ":".join(str(d) for d in dylibs)
        launch_env["SIMCTL_CHILD_DYLD_INSERT_LIBRARIES"] = libs_str

    if env:
        for key, val in env.items():
            launch_env[f"SIMCTL_CHILD_{key}"] = val

    result = subprocess.run(
        ["xcrun", "simctl", "launch", udid, bundle_id],
        capture_output=True,
        text=True,
        env=launch_env,
        check=False,
    )
    if result.returncode != 0:
        raise DarkmachError(f"Launch failed: {result.stderr}")

    output = result.stdout.strip()
    parts = output.split(":")
    if len(parts) >= 2:
        pid = int(parts[-1].strip())
        log(f"Launched {bundle_id} (PID {pid})")
        return pid

    raise DarkmachError(f"Cannot parse PID from simctl output: {output}")


def stage_bridge_wait(timeout: int = 15) -> bool:
    """Wait for the bridge socket to appear and verify connectivity."""
    log("Waiting for bridge socket...")
    sock_path = Path(BRIDGE_SOCKET)

    for _i in range(timeout * 2):
        if sock_path.exists():
            time.sleep(0.3)
            try:
                resp = bridge_command("info")
                if resp.get("ok"):
                    app_name = resp.get("appName", "?")
                    version = resp.get("appVersion", "?")
                    classes = resp.get("totalClasses", 0)
                    log(f"Bridge connected: {app_name} {version} ({classes} classes)")
                    return True
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                pass
        time.sleep(0.5)

    log("WARNING: Bridge socket did not appear within timeout")
    return False
