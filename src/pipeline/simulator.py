from __future__ import annotations

import errno
import json
import os
import socket
import stat
import subprocess
import time
import uuid
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


def _ios_devices() -> list[dict]:
    try:
        data = json.loads(simctl("list", "devices", "available", "-j"))
    except json.JSONDecodeError as error:
        raise DarkmachError("simctl returned invalid device JSON") from error
    if not isinstance(data, dict) or not isinstance(data.get("devices"), dict):
        raise DarkmachError("simctl returned an invalid device inventory")
    return [
        device
        for runtime, devices in data["devices"].items()
        if "iOS" in runtime
        for device in devices
        if device.get("isAvailable")
    ]


def _device_by_udid(devices: list[dict], udid: str) -> dict:
    try:
        identifier = str(uuid.UUID(udid)).upper()
    except ValueError as error:
        raise DarkmachError(f"Invalid Simulator UDID: {udid}") from error
    for device in devices:
        if device["udid"].upper() == identifier:
            return device
    raise DarkmachError(f"Simulator {identifier} is unavailable or is not an iOS device")


def get_booted_device(udid: str | None = None) -> str | None:
    devices = _ios_devices()
    if udid is not None:
        selected = _device_by_udid(devices, udid)
        return selected["udid"] if selected.get("state") == "Booted" else None
    booted = [device for device in devices if device.get("state") == "Booted"]
    if len(booted) > 1:
        raise DarkmachError("Multiple iOS Simulators are booted; select one with --udid")
    return booted[0]["udid"] if booted else None


def boot_simulator(udid: str | None = None) -> str:
    devices = _ios_devices()
    if udid is not None:
        selected = _device_by_udid(devices, udid)
    else:
        booted = [device for device in devices if device.get("state") == "Booted"]
        if len(booted) > 1:
            raise DarkmachError("Multiple iOS Simulators are booted; select one with --udid")
        candidates = booted or [device for device in devices if "iPhone" in device["name"]]
        if len(candidates) != 1:
            raise DarkmachError("Select an available iOS Simulator with --udid")
        selected = candidates[0]

    identifier = selected["udid"]
    if selected.get("state") == "Booted":
        log(f"Simulator already booted: {selected['name']} ({identifier})")
        return identifier

    log(f"Booting {selected['name']} ({identifier})...")
    simctl("boot", identifier)
    subprocess.run(["open", "-a", "Simulator"], check=False)
    log("Waiting for Simulator to be fully ready...")
    try:
        subprocess.run(
            ["xcrun", "simctl", "bootstatus", identifier, "-b"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        raise DarkmachError(
            f"Simulator {identifier} did not finish booting within 60 seconds"
        ) from error
    except subprocess.CalledProcessError as error:
        raise DarkmachError(f"Simulator {identifier} failed to boot: {error.stderr}") from error
    return identifier


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
    socket_path: str = BRIDGE_SOCKET,
) -> int:
    """Returns the PID of the launched process."""
    simctl("terminate", udid, bundle_id, check=False)
    time.sleep(0.5)

    sock_path = Path(socket_path)
    try:
        previous = sock_path.lstat()
    except FileNotFoundError:
        previous = None
    if previous is not None:
        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid():
            raise DarkmachError(f"Refusing to replace unowned or non-socket path: {sock_path}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.setblocking(False)
            status = probe.connect_ex(socket_path)
        if status == errno.ECONNREFUSED:
            try:
                current = sock_path.lstat()
            except FileNotFoundError:
                current = None
            if current is not None:
                if (current.st_dev, current.st_ino) != (previous.st_dev, previous.st_ino):
                    raise DarkmachError(f"Bridge socket changed during preparation: {sock_path}")
                sock_path.unlink()
        elif status != errno.ENOENT:
            raise DarkmachError(
                f"Bridge socket is live or unavailable; choose another --socket: {sock_path}"
            )

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
    launch_env["SIMCTL_CHILD_DARKMACH_BRIDGE_SOCKET"] = socket_path

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


def stage_bridge_wait(
    timeout: int = 15,
    *,
    socket_path: str = BRIDGE_SOCKET,
    expected_bundle_id: str | None = None,
    expected_pid: int | None = None,
) -> bool:
    """Wait for the bridge socket to appear and verify connectivity."""
    log("Waiting for bridge socket...")
    sock_path = Path(socket_path)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if sock_path.exists():
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                resp = bridge_command("info", socket_path=socket_path, timeout=remaining)
                if not isinstance(resp, dict):
                    raise DarkmachError("Bridge info reply is not a JSON object")
                if resp.get("ok"):
                    if (
                        expected_bundle_id is not None
                        and resp.get("bundleId") != expected_bundle_id
                    ):
                        raise DarkmachError("Connected bridge belongs to a different app")
                    if expected_pid is not None and resp.get("pid") != expected_pid:
                        raise DarkmachError("Connected bridge belongs to a different process")
                    app_name = resp.get("appName", "?")
                    version = resp.get("appVersion", "?")
                    classes = resp.get("totalClasses", 0)
                    log(f"Bridge connected: {app_name} {version} ({classes} classes)")
                    return True
            except (ConnectionRefusedError, FileNotFoundError, TimeoutError):
                pass
            except (OSError, json.JSONDecodeError) as error:
                raise DarkmachError(f"Cannot verify bridge at {socket_path}: {error}") from error
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.5, remaining))

    log("WARNING: Bridge socket did not appear within timeout")
    return False
