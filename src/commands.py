from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from darkmach._paths import (
    DYLIB_DIR,
    INTERCEPTOR_DYLIBS,
    STRATEGY_MARKER,
    SURVIVAL_DYLIB,
    app_bundle_dir,
    app_dynamic_dir,
    app_output_dir,
    app_static_dir,
    resolve_bridge_socket,
)
from darkmach.bridge.client import bridge_command
from darkmach.pipeline.bundles import find_ios_app_bundle, validate_app_path
from darkmach.pipeline.patching import _read_crypt_info, stage_patch
from darkmach.pipeline.process import DarkmachError, log, log_step, plist_read
from darkmach.pipeline.provenance import atomic_write_json, hash_file
from darkmach.pipeline.simulator import (
    boot_simulator,
    get_booted_device,
    simctl,
    stage_bridge_wait,
    stage_launch,
)

if TYPE_CHECKING:
    import argparse


def stage_analyze(ios_bundle: Path, output_dir: Path) -> None:
    """Run static analysis on a decrypted iOS bundle."""
    from darkmach.analysis.bundle import analyze_bundle

    output_dir.mkdir(parents=True, exist_ok=True)
    analyze_bundle(ios_bundle, output_dir)
    log(f"Analysis output: {output_dir}")


def _new_run_record(command: str, label: str) -> tuple[Path, dict]:
    if not label or label in {".", ".."} or Path(label).name != label:
        raise DarkmachError("An app name must be a single bundle name")
    now = datetime.now(UTC)
    run_id = f"{now.strftime('%Y%m%dT%H%M%S.%fZ')}-{os.getpid()}"
    path = app_output_dir(label) / "runs" / f"{run_id}.json"
    receipt = {
        "schema_version": 1,
        "run_id": run_id,
        "command": command,
        "status": "running",
        "started_at": now.isoformat(),
        "finished_at": None,
        "target": {"name": label, "bundle_id": None, "version": None},
        "input_main_sha256": None,
        "environment": {
            "python": platform.python_version(),
            "macos": platform.mac_ver()[0],
            "architecture": platform.machine(),
        },
        "device": None,
        "bridge": None,
        "stages": {
            name: {"status": "not-run", "started_at": None, "finished_at": None}
            for name in (
                "locate",
                "copy",
                "analyze",
                "device",
                "patch",
                "install",
                "launch",
                "bridge",
            )
        },
        "patch": None,
        "injected_artifacts": [],
        "validation": {"ui": "not-checked", "capture_events": "not-checked"},
    }
    try:
        atomic_write_json(path, receipt)
    except OSError as error:
        raise DarkmachError(f"Cannot create run receipt: {path}") from error
    return path, receipt


def _record_stage(record: tuple[Path, dict], name: str, *, completed: bool = False) -> None:
    path, receipt = record
    stage = receipt["stages"][name]
    if completed:
        stage.update(status="completed", finished_at=datetime.now(UTC).isoformat())
    else:
        stage.update(status="running", started_at=datetime.now(UTC).isoformat())
    atomic_write_json(path, receipt)


def _finish_run_record(record: tuple[Path, dict], error: BaseException | None = None) -> None:
    path, receipt = record
    now = datetime.now(UTC).isoformat()
    receipt.update(status="failed" if error else "completed", finished_at=now)
    if error:
        for stage in receipt["stages"].values():
            if stage["status"] == "running":
                stage.update(status="failed", finished_at=now)
        receipt["error"] = {"type": type(error).__name__}
    try:
        atomic_write_json(path, receipt)
    except OSError as write_error:
        raise DarkmachError(f"Cannot write run receipt: {path}") from write_error
    log(f"Run receipt: {path}")


def _bundle_identity(bundle: Path) -> tuple[str, str, str]:
    name = plist_read(bundle / "Info.plist", "CFBundleExecutable") or bundle.stem
    bundle_id = plist_read(bundle / "Info.plist", "CFBundleIdentifier")
    if not name or Path(name).name != name or name in {".", ".."}:
        raise DarkmachError("CFBundleExecutable must be a single filename")
    if not bundle_id:
        raise DarkmachError("App is missing CFBundleIdentifier")
    version = plist_read(bundle / "Info.plist", "CFBundleShortVersionString") or "?"
    return name, bundle_id, version


def _device_record(udid: str) -> dict:
    data = json.loads(simctl("list", "devices", "-j"))
    for runtime, devices in data.get("devices", {}).items():
        for device in devices:
            if device.get("udid") == udid:
                return {"udid": udid, "runtime": runtime, "name": device.get("name")}
    raise DarkmachError(f"Selected Simulator disappeared: {udid}")


def _injected_artifacts(bundle: Path) -> list[Path]:
    paths = [DYLIB_DIR / name for name in INTERCEPTOR_DYLIBS]
    if (bundle / STRATEGY_MARKER).is_file():
        paths.insert(0, SURVIVAL_DYLIB)
    missing = [path.name for path in paths if not path.is_file()]
    if missing:
        raise DarkmachError(f"Build missing interceptor dylibs first: {', '.join(missing)}")
    return paths


def _record_entitlement_readback(receipt: dict, socket_path: str) -> None:
    response = bridge_command("entitlement_scan", socket_path=socket_path)
    if not response.get("ok"):
        raise DarkmachError("Bridge could not inspect the app entitlement payload")
    readback = response.get("os_readback", {})
    status = readback.get("status", "unavailable")
    receipt["validation"]["entitlements"] = {
        "encoded_status": response.get("main_encoded_status"),
        "os_readback": status,
        "expected_keys": readback.get("expected_keys", []),
        "reported_keys": readback.get("reported_keys", []),
        "missing_keys": readback.get("missing_keys", []),
        "mismatched_keys": readback.get("mismatched_keys", []),
        "universal_capability_grants_verified": False,
    }
    patch = receipt.get("patch")
    if patch and patch["entitlements"]["status"] == "preserved":
        if status == "unavailable":
            log("WARNING: entitlement payload preserved; OS readback is unavailable")
        elif status != "reported_values_match":
            raise DarkmachError(
                f"OS entitlement readback did not match preserved payload: {status}"
            )
        elif set(readback.get("expected_keys", [])) != set(patch["entitlements"]["kept_keys"]):
            raise DarkmachError("Runtime entitlement keys do not match the preserved original set")
    log(f"Entitlement OS readback: {status}; universal capability grants are not asserted")


def cmd_run(args: argparse.Namespace) -> int:
    app_path = Path(args.app).resolve()
    record = _new_run_record("run", app_path.stem)
    receipt = record[1]
    try:
        _record_stage(record, "locate")
        validate_app_path(app_path)
        ios_bundle = find_ios_app_bundle(app_path)
        app_name, bundle_id, version = _bundle_identity(ios_bundle)
        receipt["target"] = {"name": app_name, "bundle_id": bundle_id, "version": version}
        receipt["input_basename"] = app_path.name
        receipt["input_main_sha256"] = hash_file(ios_bundle / app_name)
        _record_stage(record, "locate", completed=True)
        log_step(1, 7, f"Located {app_name} ({bundle_id}) v{version}")

        _record_stage(record, "copy")
        work_bundle = app_bundle_dir(app_name) / f"{app_name}.app"
        if work_bundle.exists():
            shutil.rmtree(work_bundle)
        work_bundle.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ios_bundle, work_bundle, symlinks=True)
        _record_stage(record, "copy", completed=True)
        log_step(2, 7, f"Copied to {work_bundle}")

        _record_stage(record, "analyze")
        static_dir = app_static_dir(app_name)
        stage_analyze(work_bundle, static_dir)
        _record_stage(record, "analyze", completed=True)
        log_step(3, 7, "Static analysis complete")

        _record_stage(record, "device")
        udid = boot_simulator(getattr(args, "udid", None))
        socket_path = resolve_bridge_socket(udid, getattr(args, "socket", None))
        receipt["device"] = _device_record(udid)
        receipt["bridge"] = {"socket": socket_path, "pid": None, "connected": False}
        _record_stage(record, "device", completed=True)
        log_step(4, 7, f"Selected Simulator: {udid}")

        _record_stage(record, "patch")
        result = stage_patch(work_bundle, udid=udid, strip_entitlements=args.strip_entitlements)
        receipt["patch"] = asdict(result)
        if result.input_sha256 != receipt["input_main_sha256"]:
            raise DarkmachError("Input executable changed between copying and patching")
        _record_stage(record, "patch", completed=True)
        log_step(5, 7, "Patching complete")

        _record_stage(record, "install")
        dylibs = _injected_artifacts(work_bundle)
        receipt["injected_artifacts"] = [
            {"name": path.name, "sha256": hash_file(path)} for path in dylibs
        ]
        simctl("uninstall", udid, bundle_id, check=False)
        simctl("install", udid, str(work_bundle))
        _record_stage(record, "install", completed=True)

        _record_stage(record, "launch")
        dynamic_dir = app_dynamic_dir(app_name)
        dynamic_dir.mkdir(parents=True, exist_ok=True)
        pid = stage_launch(
            bundle_id,
            udid,
            dylibs=dylibs,
            env={"DARKMACH_OUTPUT_DIR": str(dynamic_dir)},
            socket_path=socket_path,
        )
        receipt["bridge"]["pid"] = pid
        _record_stage(record, "launch", completed=True)
        log_step(6, 7, f"Installed and launched PID {pid}")

        _record_stage(record, "bridge")
        connected = stage_bridge_wait(
            socket_path=socket_path, expected_bundle_id=bundle_id, expected_pid=pid
        )
        if not connected:
            raise DarkmachError("Expected bridge did not connect; run is incomplete")
        receipt["bridge"]["connected"] = True
        _record_entitlement_readback(receipt, socket_path)
        _record_stage(record, "bridge", completed=True)
        log_step(7, 7, "Target bridge connected")
    except KeyboardInterrupt as error:
        _finish_run_record(record, error)
        raise
    except (DarkmachError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        _finish_run_record(record, error)
        if isinstance(error, DarkmachError):
            raise
        raise DarkmachError(str(error)) from error
    _finish_run_record(record)
    print()
    print("=" * 60)
    print("  Darkmach Pipeline Complete")
    for label, value in [
        ("App", f"{app_name} ({bundle_id}) v{version}"),
        ("PID", pid),
        ("Device", udid),
        ("Bridge", "CONNECTED"),
        ("Socket", socket_path),
        ("Static", static_dir),
        ("Dynamic", dynamic_dir),
    ]:
        print(f"  {label:<10} {value}")
    print("  UI and capture-event validation: not checked by run")
    print("=" * 60)
    print(f"Connect: darkmach bridge --socket {shlex.quote(socket_path)}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Static analysis only."""
    app_path = Path(args.app).resolve()
    validate_app_path(app_path)

    ios_bundle = find_ios_app_bundle(app_path)
    app_name = plist_read(ios_bundle / "Info.plist", "CFBundleExecutable") or ios_bundle.stem

    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = app_static_dir(app_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    stage_analyze(ios_bundle, output_dir)
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    app_path = Path(args.app).resolve()
    record = _new_run_record("patch", app_path.stem)
    receipt = record[1]
    try:
        _record_stage(record, "locate")
        validate_app_path(app_path)
        ios_bundle = find_ios_app_bundle(app_path)
        app_name, bundle_id, version = _bundle_identity(ios_bundle)
        receipt["target"] = {"name": app_name, "bundle_id": bundle_id, "version": version}
        receipt["input_basename"] = app_path.name
        receipt["input_main_sha256"] = hash_file(ios_bundle / app_name)
        _record_stage(record, "locate", completed=True)
        if ios_bundle.is_relative_to(Path("/Applications")):
            _record_stage(record, "copy")
            work_bundle = app_bundle_dir(app_name) / f"{app_name}.app"
            if work_bundle.exists():
                shutil.rmtree(work_bundle)
            work_bundle.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(ios_bundle, work_bundle, symlinks=True)
            ios_bundle = work_bundle
            _record_stage(record, "copy", completed=True)
        cryptoff, cryptsize = _read_crypt_info(ios_bundle / app_name)
        udid = None
        if (cryptoff and cryptsize) or getattr(args, "udid", None):
            _record_stage(record, "device")
            udid = boot_simulator(getattr(args, "udid", None))
            receipt["device"] = _device_record(udid)
            _record_stage(record, "device", completed=True)
        _record_stage(record, "patch")
        result = stage_patch(ios_bundle, udid=udid, strip_entitlements=args.strip_entitlements)
        receipt["patch"] = asdict(result)
        _record_stage(record, "patch", completed=True)
    except KeyboardInterrupt as error:
        _finish_run_record(record, error)
        raise
    except (DarkmachError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        _finish_run_record(record, error)
        if isinstance(error, DarkmachError):
            raise
        raise DarkmachError(str(error)) from error
    _finish_run_record(record)
    print(f"Patched: {ios_bundle}")
    if udid:
        print(f"Device:  {udid}")
        print(f"Launch after install: darkmach launch {bundle_id} --udid {udid}")
    else:
        print("No Simulator was required for this unencrypted input.")
    return 0


def cmd_launch(args: argparse.Namespace) -> int:
    bundle_id = args.bundle_id
    record = _new_run_record("launch", bundle_id.rsplit(".", 1)[-1])
    receipt = record[1]
    receipt["target"]["bundle_id"] = bundle_id
    try:
        _record_stage(record, "device")
        udid = boot_simulator(getattr(args, "udid", None))
        socket_path = resolve_bridge_socket(udid, getattr(args, "socket", None))
        receipt["device"] = _device_record(udid)
        receipt["bridge"] = {"socket": socket_path, "pid": None, "connected": False}
        _record_stage(record, "device", completed=True)
        _record_stage(record, "locate")
        bundle = Path(simctl("get_app_container", udid, bundle_id, "app").strip())
        app_name, actual_bundle_id, version = _bundle_identity(bundle)
        if actual_bundle_id != bundle_id:
            raise DarkmachError("Installed app identity does not match requested bundle")
        receipt["target"] = {"name": app_name, "bundle_id": bundle_id, "version": version}
        _record_stage(record, "locate", completed=True)
        _record_stage(record, "launch")
        dylibs = _injected_artifacts(bundle)
        receipt["injected_artifacts"] = [
            {"name": path.name, "sha256": hash_file(path)} for path in dylibs
        ]
        dynamic_dir = app_dynamic_dir(app_name)
        dynamic_dir.mkdir(parents=True, exist_ok=True)
        launch_env = {"DARKMACH_OUTPUT_DIR": str(dynamic_dir)}
        if args.ssl_bypass:
            launch_env["DARKMACH_SSL_BYPASS"] = "1"
        pid = stage_launch(bundle_id, udid, dylibs=dylibs, env=launch_env, socket_path=socket_path)
        receipt["bridge"]["pid"] = pid
        _record_stage(record, "launch", completed=True)
        _record_stage(record, "bridge")
        if not stage_bridge_wait(
            socket_path=socket_path, expected_bundle_id=bundle_id, expected_pid=pid
        ):
            raise DarkmachError("Expected bridge did not connect; launch is incomplete")
        receipt["bridge"]["connected"] = True
        _record_entitlement_readback(receipt, socket_path)
        _record_stage(record, "bridge", completed=True)
    except KeyboardInterrupt as error:
        _finish_run_record(record, error)
        raise
    except (DarkmachError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        _finish_run_record(record, error)
        if isinstance(error, DarkmachError):
            raise
        raise DarkmachError(str(error)) from error
    _finish_run_record(record)
    print(f"PID: {pid}  Device: {udid}  Bridge: CONNECTED")
    print(f"Connect: darkmach bridge --socket {shlex.quote(socket_path)}")
    return 0


def cmd_bridge(args: argparse.Namespace) -> int:
    """Connect to a running bridge and run interactive client."""
    if getattr(args, "commands", False):
        from darkmach.bridge.render import _render_help

        print(_render_help())
        return 0

    from darkmach.bridge.shell import interactive_mode

    selected = getattr(args, "udid", None)
    explicit_socket = getattr(args, "socket", None)
    if selected is None and explicit_socket is None:
        selected = get_booted_device()
    endpoint = resolve_bridge_socket(selected, explicit_socket)
    interactive_mode(socket_path=endpoint)
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    """Find iOS apps available on Mac via App Store."""
    from darkmach.discover import run_discover

    ids = args.ids.split(",") if args.ids else None
    return run_discover(
        search=args.search,
        category=args.category,
        ids=ids,
        limit=args.limit,
        output=args.output,
        token=getattr(args, "token", None),
    )


def cmd_hermes(args: argparse.Namespace) -> int:
    """Extract secrets from Hermes bytecode."""
    from darkmach.analysis.hermes import main as hermes_main

    app_path = Path(args.app).resolve()
    app_name = app_path.stem.replace(".app", "")
    output = getattr(args, "output", None) or str(app_static_dir(app_name) / "hermes")

    argv = [args.app, "--output", output]
    if getattr(args, "json", False):
        argv.append("--json")
    old_argv = sys.argv
    sys.argv = ["darkmach hermes", *argv]
    try:
        hermes_main()
    finally:
        sys.argv = old_argv
    return 0


def cmd_keychain(args: argparse.Namespace) -> int:
    """Read Simulator keychain from host filesystem."""
    from darkmach.analysis.keychain import main as keychain_main

    argv = []
    if getattr(args, "udid", None):
        argv.extend(["--udid", args.udid])
    if getattr(args, "json", False):
        argv.append("--json")
    old_argv = sys.argv
    sys.argv = ["darkmach keychain", *argv]
    try:
        keychain_main()
    finally:
        sys.argv = old_argv
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    """List installed iOS apps."""
    apps_dir = Path("/Applications")
    found = []

    for app in sorted(apps_dir.iterdir()):
        if app.suffix != ".app":
            continue
        wrapper = app / "Wrapper"
        if not wrapper.is_dir():
            continue
        inner_apps = list(wrapper.glob("*.app"))
        if not inner_apps:
            continue
        inner = inner_apps[0]
        info = inner / "Info.plist"
        if not info.exists():
            continue

        name = plist_read(info, "CFBundleExecutable") or inner.stem
        bid = plist_read(info, "CFBundleIdentifier") or "?"
        ver = plist_read(info, "CFBundleShortVersionString") or "?"
        found.append((name, bid, ver, str(app)))

    if not found:
        log("No iOS apps found in /Applications")
        return 0

    print(f"{'Name':<30} {'Bundle ID':<40} {'Version':<10}")
    print("-" * 80)
    for name, bid, ver, _path in found:
        print(f"{name:<30} {bid:<40} {ver:<10}")
    print(f"\n{len(found)} iOS apps found")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """System pre-flight check."""
    ok = True

    arch = subprocess.run(
        ["uname", "-m"], capture_output=True, text=True, check=False
    ).stdout.strip()
    status = "OK" if arch == "arm64" else "FAIL"
    if status == "FAIL":
        ok = False
    print(f"  [{status}] Architecture: {arch}")

    sip = subprocess.run(
        ["csrutil", "status"], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"  [INFO] {sip}")

    for tool in ["xcrun", "otool", "vtool", "codesign", "plutil", "clang"]:
        path = shutil.which(tool)
        status = "OK" if path else "MISSING"
        if not path:
            ok = False
        print(f"  [{status}] {tool}: {path or 'not found'}")

    try:
        sdk = subprocess.run(
            ["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"],
            capture_output=True,
            text=True,
            check=False,
        )
        if sdk.returncode == 0:
            print(f"  [OK] Simulator SDK: {sdk.stdout.strip()}")
        else:
            print("  [FAIL] Simulator SDK not found")
            ok = False
    except FileNotFoundError:
        print("  [FAIL] xcrun not found")
        ok = False

    udid = get_booted_device(getattr(args, "udid", None))
    if udid:
        print(f"  [OK] Simulator booted: {udid}")
    else:
        print("  [INFO] No Simulator booted (will auto-boot on launch)")

    all_present = True
    for name in INTERCEPTOR_DYLIBS:
        path = DYLIB_DIR / name
        if not path.exists():
            print(f"  [MISSING] {name}")
            all_present = False
    if all_present:
        print(f"  [OK] All {len(INTERCEPTOR_DYLIBS)} interceptor dylibs present")

    ios_count = 0
    for app in Path("/Applications").iterdir():
        if app.suffix == ".app" and (app / "Wrapper").is_dir():
            ios_count += 1
    print(f"  [INFO] {ios_count} iOS apps in /Applications")

    print()
    print("  System ready." if ok else "  System has issues — check above.")
    return 0 if ok else 1
