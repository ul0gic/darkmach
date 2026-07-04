#!/usr/bin/env python3
"""Darkmach — iOS reverse engineering pipeline CLI.

Automates the full pipeline from App Store app to instrumented Simulator
session with LLM bridge. Runs on any Apple Silicon Mac.

Usage:
    darkmach run   /Applications/AppName.app   # full pipeline
    darkmach analyze /Applications/AppName.app  # static analysis only
    darkmach patch /path/to/App.app             # patch for simulator only
    darkmach launch com.bundle.id               # launch with interceptors
    darkmach bridge                             # connect to running bridge
    darkmach list                               # list installed iOS apps
    darkmach status                             # system pre-flight check
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from darkmach._paths import (
    BRIDGE_SOCKET,
    CRYPT_CACHE,
    DYLIB_DIR,
    PATCH_DIR,
    app_bundle_dir,
    app_dynamic_dir,
    app_static_dir,
)

# ── Constants ──────────────────────────────────────────────────────────

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

SURGICAL_PATCHER = PATCH_DIR / "patch-macho-surgical.py"
MAIN_PATCHER = PATCH_DIR / "make-main-patch.py"
OBJC_METADATA_PATCHER = PATCH_DIR / "patch-objc-metadata.py"
DECRYPT_DYLIB = DYLIB_DIR / "darkmach-decrypt.dylib"
SURVIVAL_DYLIB = DYLIB_DIR / "darkmach-survival.dylib"

# Marker file written into a bundle when stage_patch routed it through Strategy A.
# stage_launch reads this to know whether to inject darkmach-survival.dylib.
STRATEGY_MARKER = ".darkmach-strategy"


# ── Utilities ──────────────────────────────────────────────────────────


class DarkmachError(Exception):
    """Raised when a pipeline step fails."""


def validate_app_path(app_path: Path) -> None:
    """Validate an app path before starting the pipeline."""
    if not app_path.exists():
        raise DarkmachError(f"Path does not exist: {app_path}")
    if not app_path.is_dir():
        raise DarkmachError(f"Not a directory: {app_path}")
    if app_path.suffix != ".app":
        raise DarkmachError(f"Not an .app bundle: {app_path}")
    # Must have either Wrapper/ (Mac App Store iOS app) or Info.plist (direct bundle)
    has_wrapper = (app_path / "Wrapper").is_dir()
    has_plist = (app_path / "Info.plist").exists()
    if not has_wrapper and not has_plist:
        raise DarkmachError(f"Not a valid app bundle (no Wrapper/ or Info.plist): {app_path}")


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


def find_ios_app_bundle(app_path: Path) -> Path:
    """Resolve to the actual iOS .app bundle.

    Mac App Store iOS apps live at:
        /Applications/Name.app/Wrapper/Name.app  (inner = real iOS bundle)
    Manually placed bundles may be the .app itself.
    """
    wrapper = app_path / "Wrapper"
    if wrapper.is_dir():
        inner_apps = list(wrapper.glob("*.app"))
        if inner_apps:
            return inner_apps[0]
    # Check if this is already an iOS bundle (has UIDeviceFamily)
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


# ── Simulator Helpers ──────────────────────────────────────────────────


def simctl(*args: str, capture: bool = True, check: bool = True) -> str:
    """Run xcrun simctl and return stdout."""
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
    """Return the UDID of the first booted Simulator, or None."""
    raw = simctl("list", "devices", "booted", "-j")
    data = json.loads(raw)
    for devices in data.get("devices", {}).values():
        for dev in devices:
            if dev.get("state") == "Booted":
                return dev["udid"]
    return None


def boot_simulator() -> str:
    """Boot a Simulator device. Returns UDID."""
    udid = get_booted_device()
    if udid:
        log(f"Simulator already booted: {udid}")
        return udid

    log("No booted Simulator — finding available device...")
    raw = simctl("list", "devices", "available", "-j")
    data = json.loads(raw)

    # Prefer iPhone with latest iOS runtime
    for runtime in sorted(data.get("devices", {}).keys(), reverse=True):
        if "iOS" not in runtime:
            continue
        for dev in data["devices"][runtime]:
            if dev.get("isAvailable") and "iPhone" in dev.get("name", ""):
                udid = dev["udid"]
                log(f"Booting {dev['name']} ({udid})...")
                simctl("boot", udid, check=False)
                # Open Simulator.app so user can see it
                subprocess.run(["open", "-a", "Simulator"], check=False)
                # Wait until device is fully booted (services ready)
                log("Waiting for Simulator to be fully ready...")
                subprocess.run(
                    ["xcrun", "simctl", "bootstatus", udid, "-b"],
                    check=False,
                    timeout=60,
                )
                return udid

    raise DarkmachError("No available iPhone Simulator device found")


# ── Pipeline Stages ────────────────────────────────────────────────────


def stage_analyze(ios_bundle: Path, output_dir: Path) -> None:
    """Run static analysis on a decrypted iOS bundle."""
    from darkmach.analyze import analyze_bundle

    output_dir.mkdir(parents=True, exist_ok=True)
    analyze_bundle(ios_bundle, output_dir)
    log(f"Analysis output: {output_dir}")


def _read_crypt_info(binary: Path) -> tuple[int, int]:
    """Read cryptoff and cryptsize from a Mach-O binary before patching."""
    import struct

    with binary.open("rb") as f:
        data = f.read()

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        return 0, 0

    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            cryptoff = struct.unpack_from("<I", data, offset + 8)[0]
            cryptsize = struct.unpack_from("<I", data, offset + 12)[0]
            cryptid = struct.unpack_from("<I", data, offset + 16)[0]
            if cryptid != 0 and cryptoff != 0:
                return cryptoff, cryptsize
        offset += cmdsize
    return 0, 0


def _has_encryption(binary: Path) -> bool:
    """True if the binary has LC_ENCRYPTION_INFO_64 with cryptid=1 and a non-zero region."""
    cryptoff, cryptsize = _read_crypt_info(binary)
    return cryptoff != 0 and cryptsize != 0


def _iter_bundle_binaries(ios_bundle: Path) -> list[tuple[Path, str]]:
    """Walk every Mach-O in a bundle (main + Frameworks/ + PlugIns/[*.appex/Frameworks/]).

    Returns list of (binary_path, label) tuples in the same traversal order
    that patch_bundle uses, so callers can apply per-binary work alongside it.
    """
    out: list[tuple[Path, str]] = []
    info_plist = ios_bundle / "Info.plist"
    main_exe = plist_read(info_plist, "CFBundleExecutable")
    if main_exe:
        main_bin = ios_bundle / main_exe
        if main_bin.is_file():
            out.append((main_bin, main_exe))

    fw_dir = ios_bundle / "Frameworks"
    if fw_dir.is_dir():
        for fw in sorted(fw_dir.iterdir()):
            if fw.suffix == ".framework" and fw.is_dir():
                fw_binary = fw / fw.stem
                if fw_binary.is_file():
                    out.append((fw_binary, fw.stem))
            elif fw.suffix == ".dylib" and fw.is_file():
                out.append((fw, fw.name))

    plugins_dir = ios_bundle / "PlugIns"
    if plugins_dir.is_dir():
        for appex in sorted(plugins_dir.iterdir()):
            if appex.suffix != ".appex" or not appex.is_dir():
                continue
            appex_exec = plist_read(appex / "Info.plist", "CFBundleExecutable") or appex.stem
            appex_binary = appex / appex_exec
            if appex_binary.is_file():
                out.append((appex_binary, appex.stem))
            appex_fw_dir = appex / "Frameworks"
            if appex_fw_dir.is_dir():
                for fw in sorted(appex_fw_dir.iterdir()):
                    if fw.suffix == ".framework" and fw.is_dir():
                        fw_binary = fw / fw.stem
                        if fw_binary.is_file():
                            out.append((fw_binary, f"{appex.stem}/{fw.stem}"))
    return out


def _detect_strategy(ios_bundle: Path) -> str:
    """Pick a patching strategy by counting FairPlay-encrypted Mach-Os in the bundle.

    Returns:
        "extract"     — exactly one encrypted Mach-O (Mac App Store opted-in app:
                        the main binary is FairPlay-encrypted, frameworks ship in
                        the clear). Use the existing extract-via-page-in path.
        "strategy_a"  — two or more encrypted Mach-Os (iOS-channel IPA:
                        every Mach-O including frameworks has cryptid=1). The
                        existing extract path can't load this — frameworks would
                        be cryptid=0 with ciphertext bytes. Use the Strategy A
                        toolchain (shellcode entry + ObjC neutralization +
                        survival dylib at runtime; encryption headers retained
                        so the kernel page-in mechanism decrypts on demand).
        "none"        — zero encrypted Mach-Os (already-decrypted bundle). The
                        existing path is a no-op for crypto, just patches platform.
    """
    encrypted_count = sum(
        1 for binary, _label in _iter_bundle_binaries(ios_bundle) if _has_encryption(binary)
    )
    if encrypted_count >= 2:
        return "strategy_a"
    return "extract"


def _restore_crypt_header(binary: Path, cryptoff: int, cryptsize: int, cryptid: int = 1) -> None:
    """Rewrite LC_ENCRYPTION_INFO_64 fields after the surgical patcher zeroed them.

    The surgical patcher always zeros cryptoff/cryptsize/cryptid. For Strategy A
    we need cryptid=1 (and the original cryptoff/cryptsize) to remain so the
    macOS kernel keeps decrypting FairPlay pages during page-in.
    """
    import struct

    with binary.open("r+b") as f:
        data = bytearray(f.read())
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != 0xFEEDFACF:
            return
        ncmds = struct.unpack_from("<I", data, 16)[0]
        offset = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
                struct.pack_into("<I", data, offset + 8, cryptoff)
                struct.pack_into("<I", data, offset + 12, cryptsize)
                struct.pack_into("<I", data, offset + 16, cryptid)
                break
            offset += cmdsize
        f.seek(0)
        f.write(data)
        f.truncate()


def _extract_crypt_region(
    ios_bundle: Path,
    binary: Path,
    cryptoff: int,
    cryptsize: int,
    udid: str,
) -> Path:
    """Extract decrypted FairPlay crypt region bytes via Simulator spawn.

    Creates a platform-only patched copy (cryptid=1 intact), spawns it in the
    Simulator with darkmach-decrypt.dylib. The kernel decrypts FairPlay pages during
    page-in; the dylib reads the decrypted bytes and writes them to a file.

    Returns the path to the extracted bytes file.
    """
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier") or "unknown"
    cache_file = CRYPT_CACHE / f"{bundle_id}.bin"

    if cache_file.exists() and cache_file.stat().st_size == cryptsize:
        log(f"Using cached crypt dump: {cache_file}")
        return cache_file

    if not DECRYPT_DYLIB.exists():
        raise DarkmachError(f"darkmach-decrypt.dylib not found: {DECRYPT_DYLIB}")

    # Create a temporary copy, run the full bundle patcher (patches ALL binaries —
    # main, frameworks, extensions — for platform + encryption + plists + signing),
    # then restore cryptid=1 on the main binary so kernel decrypts during page-in.
    import struct

    exe_name = binary.name
    tmp_dir = Path("/tmp/darkmach-decrypt")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir()
    tmp_bundle = tmp_dir / ios_bundle.name
    shutil.copytree(str(ios_bundle), str(tmp_bundle), symlinks=True)
    tmp_binary = tmp_bundle / exe_name

    # Run full bundle patcher (platform flags, encryption zeros, plists, signing)
    patch_bundle(tmp_bundle)

    # Restore cryptid=1 so kernel decrypts during page-in
    with tmp_binary.open("r+b") as f:
        data = bytearray(f.read())
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            struct.pack_into("<I", data, offset + 8, cryptoff)
            struct.pack_into("<I", data, offset + 12, cryptsize)
            struct.pack_into("<I", data, offset + 16, 1)  # cryptid = 1
            break
        offset += cmdsize
    with tmp_binary.open("wb") as f:
        f.write(data)

    # Re-sign the temp binary
    subprocess.run(
        ["codesign", "-s", "-", "--force", str(tmp_binary)],
        capture_output=True,
        check=True,
    )

    # Spawn in Simulator with decrypt dylib — simctl spawn bypasses SpringBoard
    CRYPT_CACHE.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SIMCTL_CHILD_DYLD_INSERT_LIBRARIES"] = str(DECRYPT_DYLIB)
    env["SIMCTL_CHILD_DARKMACH_CRYPTOFF"] = hex(cryptoff)
    env["SIMCTL_CHILD_DARKMACH_CRYPTSIZE"] = hex(cryptsize)
    env["SIMCTL_CHILD_DARKMACH_DECRYPT_OUT"] = str(cache_file)

    log("Extracting decrypted crypt region via simctl spawn...")
    result = subprocess.run(
        ["xcrun", "simctl", "spawn", udid, str(tmp_binary)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    # Clean up temp bundle
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if not cache_file.exists() or cache_file.stat().st_size != cryptsize:
        stderr_tail = result.stderr[-500:] if result.stderr else ""
        raise DarkmachError(
            f"Crypt region extraction failed (exit {result.returncode})\n{stderr_tail}"
        )

    log(f"Extracted {cryptsize} bytes to {cache_file}")
    return cache_file


def _write_crypt_bytes(binary: Path, cryptoff: int, dump_file: Path) -> None:
    """Write decrypted bytes into the binary at the crypt region offset."""
    decrypted = dump_file.read_bytes()
    with binary.open("r+b") as f:
        f.seek(cryptoff)
        f.write(decrypted)
    log(f"Wrote {len(decrypted)} decrypted bytes at offset 0x{cryptoff:x}")


def _patch_binary(binary: Path, label: str) -> None:
    """Patch a single Mach-O binary: vtool conversion + surgical platform/encryption patch."""
    # Check for legacy LC_VERSION_MIN_IPHONEOS that needs vtool conversion
    result = subprocess.run(
        ["otool", "-l", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if "LC_VERSION_MIN_IPHONEOS" in result.stdout:
        log(f"    {label}: converting LC_VERSION_MIN_IPHONEOS -> LC_BUILD_VERSION (vtool)")
        run(
            [
                "vtool",
                "-set-build-version",
                "iossim",
                "17.0",
                "17.0",
                "-replace",
                "-output",
                str(binary),
                str(binary),
            ],
            quiet=True,
        )

    # Import and call the surgical patcher directly
    import importlib.util

    spec = importlib.util.spec_from_file_location("patch_macho_surgical", str(SURGICAL_PATCHER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.patch_file(str(binary))


def _patch_plist(plist: Path, label: str) -> None:
    """Patch an Info.plist for Simulator platform."""
    subprocess.run(
        [
            "plutil",
            "-replace",
            "CFBundleSupportedPlatforms.0",
            "-string",
            "iPhoneSimulator",
            str(plist),
        ],
        capture_output=True,
        check=False,
    )
    subprocess.run(
        ["plutil", "-replace", "DTPlatformName", "-string", "iphonesimulator", str(plist)],
        capture_output=True,
        check=False,
    )

    # Rewrite DTSDKName: iphoneos16.4 -> iphonesimulator16.4
    sdk_result = subprocess.run(
        ["plutil", "-extract", "DTSDKName", "raw", str(plist)],
        capture_output=True,
        text=True,
        check=False,
    )
    if sdk_result.returncode == 0:
        sdk_ver = sdk_result.stdout.strip().replace("iphoneos", "")
        if sdk_ver:
            subprocess.run(
                [
                    "plutil",
                    "-replace",
                    "DTSDKName",
                    "-string",
                    f"iphonesimulator{sdk_ver}",
                    str(plist),
                ],
                capture_output=True,
                check=False,
            )

    # Remove device restrictions
    subprocess.run(
        ["plutil", "-remove", "UISupportedDevices", str(plist)],
        capture_output=True,
        check=False,
    )
    subprocess.run(
        ["plutil", "-remove", "UIRequiredDeviceCapabilities", str(plist)],
        capture_output=True,
        check=False,
    )
    log(f"    {label}: plist patched")


def _sign_item(item: Path, label: str) -> None:
    """Ad-hoc codesign a single item."""
    subprocess.run(
        ["codesign", "-s", "-", "--force", str(item)],
        capture_output=True,
        check=False,
    )
    log(f"    {label}: signed")


def patch_bundle(ios_bundle: Path, *, keep_framework_crypt: bool = False) -> None:
    """Patch an entire .app bundle for iOS Simulator.

    1. Patches all Mach-O binaries (main + frameworks + extensions)
    2. Patches all Info.plists for simulator platform
    3. Re-signs inside-out (frameworks -> extensions -> main)
    4. Verifies codesign and platform flag

    This is the Python replacement for patch-for-simulator.sh.

    Args:
        ios_bundle: path to the .app bundle to patch in place.
        keep_framework_crypt: when True, the LC_ENCRYPTION_INFO_64 fields
            (cryptoff, cryptsize, cryptid) on EVERY binary in the bundle are
            restored after the surgical patcher zeroes them. Required for
            Strategy A bundles (iOS-channel IPAs where every Mach-O is
            FairPlay-encrypted) — the kernel needs cryptid=1 to keep
            decrypting pages during page-in. Defaults to False so all
            existing callers (Mac App Store extract path) get the
            cryptid=0 behavior they always had.
    """
    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")

    binary = ios_bundle / exe_name

    # Snapshot pre-patch crypt info for every binary EXCEPT the main executable,
    # so we can restore cryptid=1 after the surgical patcher zeroes them.
    # Empty when keep_framework_crypt=False (no-op for the default path).
    #
    # Why exclude the main binary: the iOS Simulator kernel's exec_mach_imgact
    # rejects cryptid=1 on the executable image (no FairPlay handler in the sim
    # kernel for spawned processes). The symptom is launchd posix_spawn returning
    # error 153 ("Completely unexpected error"), which surfaces in SpringBoard
    # logs as the misleading "RequestDenied by SBMainWorkspace". Frameworks and
    # extension inner frameworks are mmap'd (not exec'd) and so go through the
    # macOS kernel's page-in path — there cryptid=1 is exactly what we want, so
    # the kernel keeps decrypting FairPlay pages on demand. The main binary's
    # crypt region is replaced wholesale by make-main-patch.py shellcode in
    # Strategy A step 3a, so cryptid=0 there is safe.
    crypt_snapshot: dict[Path, tuple[int, int]] = {}
    if keep_framework_crypt:
        main_binary_path = binary.resolve()
        for bin_path, _label in _iter_bundle_binaries(ios_bundle):
            if bin_path.resolve() == main_binary_path:
                continue
            cryptoff, cryptsize = _read_crypt_info(bin_path)
            if cryptoff and cryptsize:
                crypt_snapshot[bin_path] = (cryptoff, cryptsize)

    log(f"=== Patching {exe_name} for iOS Simulator ===")

    # ── Step 1: Patch all binaries ──────────────────────────────────
    log("[1/4] Patching binaries...")
    log("  Main binary:")
    _patch_binary(binary, exe_name)

    # Embedded frameworks
    log("  Embedded frameworks:")
    fw_dir = ios_bundle / "Frameworks"
    if fw_dir.is_dir():
        for fw in sorted(fw_dir.iterdir()):
            if fw.suffix == ".framework" and fw.is_dir():
                fw_name = fw.stem
                fw_binary = fw / fw_name
                if fw_binary.is_file():
                    _patch_binary(fw_binary, fw_name)
            elif fw.suffix == ".dylib" and fw.is_file():
                _patch_binary(fw, fw.name)
    else:
        log("    No Frameworks directory")

    # App extensions
    log("  App extensions:")
    plugins_dir = ios_bundle / "PlugIns"
    if plugins_dir.is_dir():
        for appex in sorted(plugins_dir.iterdir()):
            if appex.suffix != ".appex" or not appex.is_dir():
                continue
            appex_name = appex.stem
            appex_exec = plist_read(appex / "Info.plist", "CFBundleExecutable") or appex_name
            appex_binary = appex / appex_exec
            if appex_binary.is_file():
                _patch_binary(appex_binary, appex_name)

            # Frameworks inside extensions
            appex_fw_dir = appex / "Frameworks"
            if appex_fw_dir.is_dir():
                for fw in sorted(appex_fw_dir.iterdir()):
                    if fw.suffix == ".framework" and fw.is_dir():
                        fw_name = fw.stem
                        fw_binary = fw / fw_name
                        if fw_binary.is_file():
                            _patch_binary(fw_binary, f"{appex_name}/{fw_name}")
    else:
        log("    No PlugIns directory")

    # Restore LC_ENCRYPTION_INFO_64 fields if Strategy A asked us to keep
    # FairPlay decryption active. The surgical patcher always zeroes
    # cryptid/cryptoff/cryptsize; we put them back so the kernel page-in
    # mechanism continues to decrypt these binaries at load time.
    if keep_framework_crypt and crypt_snapshot:
        log(f"  Restoring cryptid=1 on {len(crypt_snapshot)} binaries (Strategy A)")
        for bin_path, (cryptoff, cryptsize) in crypt_snapshot.items():
            _restore_crypt_header(bin_path, cryptoff, cryptsize, cryptid=1)

    # ── Step 2: Patch all plists ────────────────────────────────────
    log("[2/4] Patching plists...")
    _patch_plist(info_plist, "Main")

    if plugins_dir.is_dir():
        for appex in sorted(plugins_dir.iterdir()):
            if appex.suffix != ".appex" or not appex.is_dir():
                continue
            appex_plist = appex / "Info.plist"
            if appex_plist.is_file():
                _patch_plist(appex_plist, appex.stem)

    # ── Step 3: Re-sign inside-out ──────────────────────────────────
    log("[3/4] Re-signing (inside-out)...")

    log("  Frameworks:")
    if fw_dir.is_dir():
        for fw in sorted(fw_dir.iterdir()):
            is_framework = fw.suffix == ".framework" and fw.is_dir()
            is_dylib = fw.suffix == ".dylib" and fw.is_file()
            if is_framework or is_dylib:
                _sign_item(fw, fw.name)

    log("  Extensions:")
    if plugins_dir.is_dir():
        for appex in sorted(plugins_dir.iterdir()):
            if appex.suffix != ".appex" or not appex.is_dir():
                continue
            # Sign frameworks inside extensions first
            appex_fw_dir = appex / "Frameworks"
            if appex_fw_dir.is_dir():
                for fw in sorted(appex_fw_dir.iterdir()):
                    if fw.suffix == ".framework" and fw.is_dir():
                        _sign_item(fw, f"{appex.stem}/{fw.name}")
            _sign_item(appex, appex.name)

    log("  Main bundle:")
    _sign_item(ios_bundle, exe_name)

    # ── Step 4: Verify ──────────────────────────────────────────────
    log("[4/4] Verifying...")
    verify = subprocess.run(
        ["codesign", "-v", str(ios_bundle)],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode == 0:
        log("    Signature valid")
    else:
        log("    WARNING: Signature verification failed")

    # Check platform flag
    otool_result = subprocess.run(
        ["otool", "-l", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    platform = None
    lines = otool_result.stdout.splitlines()
    for i, line in enumerate(lines):
        if "LC_BUILD_VERSION" in line:
            for j in range(i, min(i + 5, len(lines))):
                if "platform" in lines[j]:
                    platform = lines[j].strip().split()[-1]
                    break
            break

    if platform == "7":
        log("    Platform: iOSSimulator (correct)")
    else:
        log(f"    WARNING: Platform is {platform}, expected 7 (iOSSimulator)")

    bundle_id = plist_read(info_plist, "CFBundleIdentifier")
    print()
    log("=== Done ===")
    log(f"Install: xcrun simctl install booted {ios_bundle}")
    log(f"Launch:  xcrun simctl launch booted {bundle_id}")


def _patch_strategy_a(ios_bundle: Path) -> None:
    """Strategy A pipeline for iOS-channel IPAs (every Mach-O FairPlay-encrypted).

    Order matters — see agent-memory/exploit-engineer/strategy_a_patch_order.md.

    1. Snapshot main-binary cryptoff/cryptsize (the surgical patcher will zero them).
    2. Run patch_bundle(keep_framework_crypt=True): patches platform flag iOS->iOSSimulator
       on every binary, runs surgical patcher, then restores cryptid=1 + cryptoff +
       cryptsize on every binary. Also patches plists and re-signs inside-out.
       The kernel page-in mechanism keeps decrypting these binaries at load time.
    3. On main binary only, install Strategy A specials:
       - make-main-patch.py — GOT-based shellcode entry replacing the encrypted main()
       - patch-objc-metadata.py — neutralize ObjC class_ro_t.baseMethods pointers
         that reach into the crypt region (otherwise libobjc fixupMethodList aborts
         during dyld init).
    4. Re-sign the main binary, then re-sign the bundle inside-out.
    5. Drop a marker file so stage_launch knows to inject darkmach-survival.dylib.
    """
    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")
    binary = ios_bundle / exe_name

    # Capture original crypt geometry before any patcher touches it.
    cryptoff, cryptsize = _read_crypt_info(binary)
    if not (cryptoff and cryptsize):
        raise DarkmachError(
            f"Strategy A requires LC_ENCRYPTION_INFO_64 with cryptid=1 on {binary}, "
            "but none was found"
        )
    log(f"Strategy A: main cryptoff=0x{cryptoff:x} cryptsize=0x{cryptsize:x}")

    # Snapshot crypt geometry for every embedded Mach-O too (frameworks, appex,
    # appex frameworks). After patch_bundle(keep_framework_crypt=True) runs
    # below, these binaries still carry cryptid=1 + the same cryptoff/cryptsize
    # — but reading them up front guarantees we have a consistent record even
    # if a future patch_bundle change perturbs the load command. The Round 7
    # cache-coherent neutralizer must be invoked per-framework with that
    # framework's own crypt window, otherwise libobjc fixupMethodList SIGABRTs
    # in the first framework whose method_list_t pointer reaches into its own
    # un-decrypted ciphertext (Round 8 wall: PodMerged.framework + 0xafb180).
    embedded_crypt: list[tuple[Path, str, int, int]] = []
    for fw_binary, fw_label in _iter_bundle_binaries(ios_bundle):
        if fw_binary == binary:
            continue
        fw_cryptoff, fw_cryptsize = _read_crypt_info(fw_binary)
        if fw_cryptoff and fw_cryptsize:
            embedded_crypt.append((fw_binary, fw_label, fw_cryptoff, fw_cryptsize))
    log(
        f"[strategy_a] Found {len(embedded_crypt)} embedded encrypted Mach-O(s) "
        "to neutralize after main"
    )

    # Step 0: Strip FairPlay SC_Info/ artifacts. iOS-channel IPAs ship
    # SC_Info/<name>.{sinf,supf,supp,supx} + Manifest.plist alongside the main
    # bundle, every framework, and every appex. Apple's storefront delivery
    # treats SC_Info/ as a sealed-resource exception; ad-hoc re-signing does
    # not — codesign verification fails with "a sealed resource is missing or
    # invalid" and SpringBoard rejects launch as Invalid (FBSOpenApplication
    # ServiceErrorDomain code=1, denied by SBMainWorkspace). The kernel
    # page-in decryption path doesn't need these files in Simulator. Mac App
    # Store opted-in apps don't ship SC_Info/, so this is a no-op for them.
    sc_info_dirs = [d for d in ios_bundle.rglob("SC_Info") if d.is_dir()]
    if sc_info_dirs:
        log(f"[strategy_a] Removing {len(sc_info_dirs)} SC_Info/ directories")
        for sc_info in sc_info_dirs:
            shutil.rmtree(sc_info)

    # Step 1+2: bundle patch with crypt headers preserved.
    patch_bundle(ios_bundle, keep_framework_crypt=True)

    # Step 3a: Install GOT-based shellcode entry on main binary.
    if not MAIN_PATCHER.is_file():
        raise DarkmachError(f"make-main-patch.py not found: {MAIN_PATCHER}")
    log("[strategy_a] Installing shellcode entry (make-main-patch.py)...")
    run(
        [
            sys.executable,
            str(MAIN_PATCHER),
            str(binary),
            "--app",
            str(ios_bundle),
            "--cryptoff",
            hex(cryptoff),
            "--cryptsize",
            hex(cryptsize),
        ]
    )

    # Step 3b: Neutralize ObjC method-list pointers that reach into crypt.
    if not OBJC_METADATA_PATCHER.is_file():
        raise DarkmachError(f"patch-objc-metadata.py not found: {OBJC_METADATA_PATCHER}")
    log("[strategy_a] Neutralizing ObjC method lists (patch-objc-metadata.py)...")
    run(
        [
            sys.executable,
            str(OBJC_METADATA_PATCHER),
            str(binary),
            "--cryptoff",
            hex(cryptoff),
            "--cryptsize",
            hex(cryptsize),
        ]
    )

    # Step 3c: Neutralize ObjC method-list pointers in EVERY embedded Mach-O.
    # Round 8 wall: framework method_list_t pointers reach into their own crypt
    # regions. iOS-channel IPAs have no FairPlay key on this Mac, so
    # the kernel page-in path can't decrypt them at runtime — libobjc reads
    # ciphertext garbage and SIGABRTs in fixupMethodList. The patcher itself
    # is binary-agnostic: per-framework cryptoff/cryptsize is enough.
    fw_processed = 0
    for fw_binary, fw_label, fw_cryptoff, fw_cryptsize in embedded_crypt:
        log(
            f"[strategy_a]   neutralizing {fw_label} "
            f"(cryptoff=0x{fw_cryptoff:x} cryptsize=0x{fw_cryptsize:x})"
        )
        run(
            [
                sys.executable,
                str(OBJC_METADATA_PATCHER),
                str(fw_binary),
                "--cryptoff",
                hex(fw_cryptoff),
                "--cryptsize",
                hex(fw_cryptsize),
            ]
        )
        # Re-sign each modified binary in place so the final bundle re-sign
        # below can re-seal it. Without an inline re-sign the framework's
        # signature would mismatch its bytes when codesign walks the bundle.
        run(["codesign", "-s", "-", "--force", str(fw_binary)], quiet=True)
        fw_processed += 1
    log(f"[strategy_a] Neutralized ObjC method lists in {fw_processed} framework/appex binaries")

    # Step 4: Marker file for stage_launch to know it needs survival.dylib.
    # MUST be written BEFORE the final re-sign — codesign seals every file
    # present at sign time. A marker added after re-sign would be reported as
    # "a sealed resource is missing or invalid" and SpringBoard would refuse
    # the launch as Invalid (FBSOpenApplicationServiceErrorDomain code=1).
    (ios_bundle / STRATEGY_MARKER).write_text("strategy_a\n")
    log("[strategy_a] Wrote marker — stage_launch will inject darkmach-survival.dylib")

    # Step 5: Re-sign main binary then bundle (inside-out). The bundle re-sign
    # walks frameworks first via codesign's own logic when given the bundle.
    log("[strategy_a] Re-signing main binary + bundle...")
    run(["codesign", "-s", "-", "--force", str(binary)], quiet=True)
    run(["codesign", "-s", "-", "--force", str(ios_bundle)], quiet=True)


def stage_patch(ios_bundle: Path, udid: str | None = None) -> None:
    """Patch an iOS bundle for Simulator execution.

    Auto-detects which strategy this bundle needs:

      - "extract"    — Mac App Store opted-in app: only the main binary is FairPlay-
                       encrypted, frameworks ship in the clear. Use the existing
                       page-in extract path (cryptid=0 on disk after patching).

      - "strategy_a" — iOS-channel IPA: EVERY Mach-O including frameworks
                       has cryptid=1. The extract path can't survive this — page-in
                       can't decrypt these (sinf is bound to the download client's GUID,
                       not this Mac's FairPlay identity: fairplayOpen fails -42110),
                       and zeroing cryptid to 0 while ciphertext stays on disk makes
                       dyld_sim map raw ciphertext as code and crash instantly.
                       _patch_strategy_a instead keeps cryptid=1 + cryptoff + cryptsize
                       intact — cryptid=1 makes dyld_sim skip the crypt region rather
                       than execute its ciphertext — then replaces the encrypted entry
                       point with GOT-based shellcode and neutralizes ObjC method-list
                       pointers so libobjc never dereferences into un-decrypted bytes.
                       The real app code stays ciphertext and never runs; this yields
                       an injectable but hollow process, not decrypted app logic.
    """
    strategy = _detect_strategy(ios_bundle)
    log(f"[strategy] detected: {strategy}")

    if strategy == "strategy_a":
        _patch_strategy_a(ios_bundle)
        return

    # ── extract path (default — Mac App Store opted-in apps) ──────────────
    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")

    binary = ios_bundle / exe_name

    # Step 1: Capture crypt info BEFORE the patcher zeros it
    cryptoff, cryptsize = _read_crypt_info(binary)
    has_encryption = cryptoff != 0 and cryptsize != 0
    if has_encryption:
        log(f"FairPlay encryption: cryptoff=0x{cryptoff:x} cryptsize=0x{cryptsize:x}")

    # Step 2: Extract decrypted crypt region BEFORE patching (needs original binary)
    crypt_dump = None
    if has_encryption:
        if not udid:
            udid = get_booted_device()
            if not udid:
                udid = boot_simulator()
        crypt_dump = _extract_crypt_region(ios_bundle, binary, cryptoff, cryptsize, udid)

    # Step 3: Run bundle patcher (platform flags, encryption headers, plists, re-sign)
    patch_bundle(ios_bundle)

    # Step 4: Write decrypted bytes into the crypt region (cryptid is now 0)
    if crypt_dump:
        _write_crypt_bytes(binary, cryptoff, crypt_dump)
        # Re-sign after modifying the binary (inside-out: binary then bundle)
        run(["codesign", "-s", "-", "--force", str(binary)], quiet=True)
        run(["codesign", "-s", "-", "--force", str(ios_bundle)], quiet=True)


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
    """Launch an app in the Simulator with optional dylib injection.

    Returns the PID of the launched process.
    """
    # Terminate any existing instance
    simctl("terminate", udid, bundle_id, check=False)
    time.sleep(0.5)

    # Remove old bridge socket
    sock_path = Path(BRIDGE_SOCKET)
    if sock_path.exists():
        sock_path.unlink()

    # Build environment
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

    # Parse PID from "com.bundle.id: 12345"
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


# ── Bridge Client ──────────────────────────────────────────────────────

_bridge_req_id = 0


def bridge_command(cmd: str, args: dict | None = None) -> dict:
    """Send a single command to the bridge and return the response."""
    global _bridge_req_id
    _bridge_req_id += 1

    msg = {"id": _bridge_req_id, "cmd": cmd}
    if args:
        msg["args"] = args

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(BRIDGE_SOCKET)
    sock.sendall((json.dumps(msg) + "\n").encode())
    sock.settimeout(30)

    data = b""
    while True:
        try:
            chunk = sock.recv(1 << 20)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        except TimeoutError:
            break
    sock.close()

    if not data:
        return {"ok": False, "error": "No response from bridge"}
    # Parse only the first newline-delimited JSON message (bridge protocol is JSON-lines)
    line = data.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8", errors="replace"))


# ── CLI Commands ───────────────────────────────────────────────────────


def cmd_run(args: argparse.Namespace) -> int:
    """Full pipeline: analyze → patch → install → launch → bridge."""
    app_path = Path(args.app).resolve()
    validate_app_path(app_path)

    total_steps = 7

    # Step 1: Locate the iOS bundle
    log_step(1, total_steps, "Locating iOS app bundle...")
    ios_bundle = find_ios_app_bundle(app_path)
    app_name = plist_read(ios_bundle / "Info.plist", "CFBundleExecutable") or ios_bundle.stem
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier") or "unknown"
    version = plist_read(ios_bundle / "Info.plist", "CFBundleShortVersionString") or "?"
    log(f"Found: {app_name} ({bundle_id}) v{version}")

    # Step 2: Copy to output/<app>/bundle/
    log_step(2, total_steps, "Copying to output directory...")
    bundle_dir = app_bundle_dir(app_name)
    work_bundle = bundle_dir / f"{app_name}.app"
    if work_bundle.exists():
        shutil.rmtree(work_bundle)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(str(ios_bundle), str(work_bundle), symlinks=True)
    log(f"Copied to {work_bundle}")

    # Step 3: Static analysis → output/<app>/static/
    log_step(3, total_steps, "Running static analysis...")
    static_dir = app_static_dir(app_name)
    static_dir.mkdir(parents=True, exist_ok=True)
    stage_analyze(work_bundle, static_dir)

    # Step 4: Boot Simulator (needed for crypt region extraction during patching)
    log_step(4, total_steps, "Booting Simulator...")
    udid = boot_simulator()

    # Step 5: Patch for Simulator (includes FairPlay decryption via simctl spawn)
    log_step(5, total_steps, "Patching for iOS Simulator...")
    stage_patch(work_bundle, udid=udid)

    # Step 6: Install and launch with interceptors
    log_step(6, total_steps, "Installing and launching with interceptors...")
    simctl("uninstall", udid, bundle_id, check=False)  # remove stale install
    simctl("install", udid, str(work_bundle))

    dynamic_dir = app_dynamic_dir(app_name)
    dynamic_dir.mkdir(parents=True, exist_ok=True)

    dylib_paths = [DYLIB_DIR / name for name in INTERCEPTOR_DYLIBS]
    # Strategy A bundles need darkmach-survival.dylib loaded BEFORE the
    # interceptors — its constructor walks ObjC metadata to keep dyld from
    # aborting on the cryptid=1 frameworks left behind by _patch_strategy_a.
    if (work_bundle / STRATEGY_MARKER).is_file() and SURVIVAL_DYLIB.exists():
        log("[strategy_a] Adding darkmach-survival.dylib to injection list")
        dylib_paths.insert(0, SURVIVAL_DYLIB)
    pid = stage_launch(
        bundle_id,
        udid,
        dylibs=dylib_paths,
        env={"DARKMACH_OUTPUT_DIR": str(dynamic_dir)},
    )

    # Step 7: Wait for bridge
    log_step(7, total_steps, "Connecting to bridge...")
    bridge_ok = stage_bridge_wait()

    # Summary
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

    # If pointing at an installed app, copy first
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

    stage_patch(ios_bundle)  # auto-boots Simulator if needed for crypt extraction
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier")
    print()
    print(f"Patched: {ios_bundle}")
    print(f"Install: xcrun simctl install booted {ios_bundle}")
    print(f"Launch:  xcrun simctl launch booted {bundle_id}")
    return 0


def cmd_launch(args: argparse.Namespace) -> int:
    """Launch an already-installed app with interceptors."""
    bundle_id = args.bundle_id
    # Derive app name from bundle_id for output dir (last component)
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
    from darkmach.bridge import interactive_mode

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
    from darkmach.hermes import main as hermes_main

    # Default output to output/<app>/static/hermes/
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
    from darkmach.keychain import main as keychain_main

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

    # Architecture
    arch = subprocess.run(
        ["uname", "-m"], capture_output=True, text=True, check=False
    ).stdout.strip()
    status = "OK" if arch == "arm64" else "FAIL"
    if status == "FAIL":
        ok = False
    print(f"  [{status}] Architecture: {arch}")

    # SIP
    sip = subprocess.run(
        ["csrutil", "status"], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"  [INFO] {sip}")

    # Xcode
    for tool in ["xcrun", "otool", "vtool", "codesign", "plutil", "clang"]:
        path = shutil.which(tool)
        status = "OK" if path else "MISSING"
        if not path:
            ok = False
        print(f"  [{status}] {tool}: {path or 'not found'}")

    # Simulator SDK
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

    # Simulator
    udid = get_booted_device()
    if udid:
        print(f"  [OK] Simulator booted: {udid}")
    else:
        print("  [INFO] No Simulator booted (will auto-boot on launch)")

    # Dylibs
    all_present = True
    for name in INTERCEPTOR_DYLIBS:
        path = DYLIB_DIR / name
        if not path.exists():
            print(f"  [MISSING] {name}")
            all_present = False
    if all_present:
        print(f"  [OK] All {len(INTERCEPTOR_DYLIBS)} interceptor dylibs present")

    # iOS apps
    ios_count = 0
    for app in Path("/Applications").iterdir():
        if app.suffix == ".app" and (app / "Wrapper").is_dir():
            ios_count += 1
    print(f"  [INFO] {ios_count} iOS apps in /Applications")

    print()
    print("  System ready." if ok else "  System has issues — check above.")
    return 0 if ok else 1


# ── Main ───────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="darkmach",
        description="iOS reverse engineering pipeline for Apple Silicon",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # run
    p_run = sub.add_parser("run", help="Full pipeline: analyze → patch → install → launch → bridge")
    p_run.add_argument("app", help="Path to .app (e.g., /Applications/AppName.app)")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Static analysis only")
    p_analyze.add_argument("app", help="Path to .app")
    p_analyze.add_argument("-o", "--output", help="Output directory")

    # patch
    p_patch = sub.add_parser("patch", help="Patch bundle for Simulator")
    p_patch.add_argument("app", help="Path to .app")

    # launch
    p_launch = sub.add_parser("launch", help="Launch installed app with interceptors")
    p_launch.add_argument("bundle_id", help="Bundle ID (e.g., com.oddsjam.app)")
    p_launch.add_argument("--ssl-bypass", action="store_true", help="Bypass SSL pinning")

    # bridge
    sub.add_parser("bridge", help="Connect to running bridge (interactive)")

    # discover
    p_discover = sub.add_parser("discover", help="Find iOS apps available on Mac")
    p_discover.add_argument("search", nargs="?", help="Search term")
    p_discover.add_argument("--category", help="Category ID or 'all'")
    p_discover.add_argument("--ids", help="Comma-separated app IDs")
    p_discover.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    p_discover.add_argument("-o", "--output", help="Output file path")
    p_discover.add_argument(
        "--token", help="amp-api Bearer token (overrides DARKMACH_AMP_TOKEN env var)"
    )

    # hermes
    p_hermes = sub.add_parser("hermes", help="Extract secrets from Hermes bytecode")
    p_hermes.add_argument("app", help="Path to .app or .jsbundle")
    p_hermes.add_argument("-o", "--output", help="Output directory")
    p_hermes.add_argument("--json", action="store_true", help="JSON output")

    # keychain
    p_keychain = sub.add_parser("keychain", help="Read Simulator keychain (host-side)")
    p_keychain.add_argument("--udid", help="Simulator UDID (auto-detects booted)")
    p_keychain.add_argument("--json", action="store_true", help="JSON output")

    # list
    sub.add_parser("list", help="List installed iOS apps")

    # status
    sub.add_parser("status", help="System pre-flight check")

    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "analyze": cmd_analyze,
        "patch": cmd_patch,
        "launch": cmd_launch,
        "bridge": cmd_bridge,
        "discover": cmd_discover,
        "hermes": cmd_hermes,
        "keychain": cmd_keychain,
        "list": cmd_list,
        "status": cmd_status,
    }

    try:
        return commands[args.command](args)
    except DarkmachError as e:
        log(f"ERROR: {e}")
        return 1
    except KeyboardInterrupt:
        print()
        return 130


def entrypoint() -> None:
    """Entry point for pipx/console_scripts."""
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
