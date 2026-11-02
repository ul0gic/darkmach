from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from darkmach._paths import (
    BRIDGE_SOCKET,
    DYLIB_DIR,
    INTERCEPTOR_DYLIBS,
    STRATEGY_MARKER,
    SURVIVAL_DYLIB,
    app_bundle_dir,
    app_dynamic_dir,
    app_static_dir,
)
from darkmach.pipeline.bundles import find_ios_app_bundle, validate_app_path
from darkmach.pipeline.patching import stage_patch
from darkmach.pipeline.process import log, log_step, plist_read
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


def cmd_run(args: argparse.Namespace) -> int:
    """Full pipeline: analyze → patch → install → launch → bridge."""
    app_path = Path(args.app).resolve()
    validate_app_path(app_path)

    total_steps = 7

    log_step(1, total_steps, "Locating iOS app bundle...")
    ios_bundle = find_ios_app_bundle(app_path)
    app_name = plist_read(ios_bundle / "Info.plist", "CFBundleExecutable") or ios_bundle.stem
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier") or "unknown"
    version = plist_read(ios_bundle / "Info.plist", "CFBundleShortVersionString") or "?"
    log(f"Found: {app_name} ({bundle_id}) v{version}")

    log_step(2, total_steps, "Copying to output directory...")
    bundle_dir = app_bundle_dir(app_name)
    work_bundle = bundle_dir / f"{app_name}.app"
    if work_bundle.exists():
        shutil.rmtree(work_bundle)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(str(ios_bundle), str(work_bundle), symlinks=True)
    log(f"Copied to {work_bundle}")

    log_step(3, total_steps, "Running static analysis...")
    static_dir = app_static_dir(app_name)
    static_dir.mkdir(parents=True, exist_ok=True)
    stage_analyze(work_bundle, static_dir)

    # Booted ahead of patching: crypt region extraction spawns into the Simulator.
    log_step(4, total_steps, "Booting Simulator...")
    udid = boot_simulator()

    log_step(5, total_steps, "Patching for iOS Simulator...")
    stage_patch(work_bundle, udid=udid, strip_entitlements=args.strip_entitlements)

    log_step(6, total_steps, "Installing and launching with interceptors...")
    simctl("uninstall", udid, bundle_id, check=False)  # remove stale install
    simctl("install", udid, str(work_bundle))

    dynamic_dir = app_dynamic_dir(app_name)
    dynamic_dir.mkdir(parents=True, exist_ok=True)

    dylib_paths = [DYLIB_DIR / name for name in INTERCEPTOR_DYLIBS]
    # Inserted at index 0: survival's constructor must fix up ObjC metadata before the
    # interceptors load, or dyld aborts on the cryptid=1 frameworks Strategy A leaves.
    if (work_bundle / STRATEGY_MARKER).is_file() and SURVIVAL_DYLIB.exists():
        log("[strategy_a] Adding darkmach-survival.dylib to injection list")
        dylib_paths.insert(0, SURVIVAL_DYLIB)
    pid = stage_launch(
        bundle_id,
        udid,
        dylibs=dylib_paths,
        env={"DARKMACH_OUTPUT_DIR": str(dynamic_dir)},
    )

    log_step(7, total_steps, "Connecting to bridge...")
    bridge_ok = stage_bridge_wait()

    print()
    print("=" * 60)
    print("  Darkmach Pipeline Complete")
    print(f"  App:       {app_name} ({bundle_id}) v{version}")
    print(f"  PID:       {pid}")
    print(f"  Device:    {udid}")
    print(f"  Bridge:    {'CONNECTED' if bridge_ok else 'NOT CONNECTED'}")
    print(f"  Socket:    {BRIDGE_SOCKET}")
    print(f"  Static:    {static_dir}")
    print(f"  Dynamic:   {dynamic_dir}")
    print("=" * 60)
    print()
    if bridge_ok:
        print("  Bridge is ready. Connect with:")
        print("    darkmach bridge")
    print()
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
    """Patch a bundle for Simulator."""
    app_path = Path(args.app).resolve()
    validate_app_path(app_path)

    ios_bundle = find_ios_app_bundle(app_path)

    if str(ios_bundle).startswith("/Applications"):
        app_name = ios_bundle.stem
        bundle_dir = app_bundle_dir(app_name)
        work_bundle = bundle_dir / f"{app_name}.app"
        if work_bundle.exists():
            shutil.rmtree(work_bundle)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(str(ios_bundle), str(work_bundle), symlinks=True)
        log(f"Copied to {work_bundle}")
        ios_bundle = work_bundle

    # auto-boots Simulator if needed for crypt extraction
    stage_patch(ios_bundle, strip_entitlements=args.strip_entitlements)
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier")
    print()
    print(f"Patched: {ios_bundle}")
    print(f"Install: xcrun simctl install booted {ios_bundle}")
    print(f"Launch:  xcrun simctl launch booted {bundle_id}")
    return 0


def cmd_launch(args: argparse.Namespace) -> int:
    """Launch an already-installed app with interceptors."""
    bundle_id = args.bundle_id
    app_slug = bundle_id.rsplit(".", 1)[-1] if "." in bundle_id else bundle_id
    udid = get_booted_device()
    if not udid:
        log("No booted Simulator. Booting one...")
        udid = boot_simulator()

    dylib_paths = [DYLIB_DIR / name for name in INTERCEPTOR_DYLIBS]
    missing = [d for d in dylib_paths if not d.exists()]
    if missing:
        log(f"WARNING: Missing dylibs: {[d.name for d in missing]}")
        dylib_paths = [d for d in dylib_paths if d.exists()]

    dynamic_dir = app_dynamic_dir(app_slug)
    dynamic_dir.mkdir(parents=True, exist_ok=True)

    env = {"DARKMACH_OUTPUT_DIR": str(dynamic_dir)}
    if args.ssl_bypass:
        env["DARKMACH_SSL_BYPASS"] = "1"

    pid = stage_launch(bundle_id, udid, dylibs=dylib_paths, env=env)
    bridge_ok = stage_bridge_wait()

    print()
    print(f"  PID: {pid}  Bridge: {'OK' if bridge_ok else 'NO'}  Socket: {BRIDGE_SOCKET}")
    return 0


def cmd_bridge(args: argparse.Namespace) -> int:
    """Connect to a running bridge and run interactive client."""
    from darkmach.bridge.shell import interactive_mode

    interactive_mode()
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


def cmd_status(_args: argparse.Namespace) -> int:
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

    udid = get_booted_device()
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
