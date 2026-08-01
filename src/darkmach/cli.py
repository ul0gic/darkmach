#!/usr/bin/env python3
"""Darkmach iOS reverse engineering pipeline CLI. See docs/cli-reference.md."""

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

# An allowlist, not a droplist: an entitlement the Simulator refuses fails the launch
# outright, while a dropped one is only reported — so unrecognized keys must not pass through.
SIMULATOR_ENTITLEMENTS = frozenset(
    {
        "application-identifier",
        "com.apple.developer.applesignin",
        "com.apple.developer.associated-domains",
        "com.apple.developer.team-identifier",
        "com.apple.security.application-groups",
        "keychain-access-groups",
    }
)


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
    """Ordered to match patch_bundle's own traversal, so callers can pair
    per-binary work against it."""
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
    """Pick a patching strategy from which binaries carry FairPlay encryption.

    Returns "extract" or "strategy_a" — decision tree in `docs/patching.md`.
    """
    fw_dir = ios_bundle / "Frameworks"
    for binary, _label in _iter_bundle_binaries(ios_bundle):
        if fw_dir in binary.parents and _has_encryption(binary):
            return "strategy_a"
    return "extract"


def _restore_crypt_header(binary: Path, cryptoff: int, cryptsize: int, cryptid: int = 1) -> None:
    """Undoes the surgical patcher's unconditional zeroing — Strategy A needs
    cryptid=1 for the kernel to keep decrypting FairPlay pages during page-in."""
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
    """Spawns a cryptid=1 copy under darkmach-decrypt.dylib so the kernel decrypts
    FairPlay pages during page-in; the dylib dumps them. See `docs/patching.md`."""
    bundle_id = plist_read(ios_bundle / "Info.plist", "CFBundleIdentifier") or "unknown"
    cache_file = CRYPT_CACHE / f"{bundle_id}.bin"

    if cache_file.exists() and cache_file.stat().st_size == cryptsize:
        log(f"Using cached crypt dump: {cache_file}")
        return cache_file

    if not DECRYPT_DYLIB.exists():
        raise DarkmachError(f"darkmach-decrypt.dylib not found: {DECRYPT_DYLIB}")

    import struct

    exe_name = binary.name
    tmp_dir = Path("/tmp/darkmach-decrypt")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir()
    tmp_bundle = tmp_dir / ios_bundle.name
    shutil.copytree(str(ios_bundle), str(tmp_bundle), symlinks=True)
    tmp_binary = tmp_bundle / exe_name

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


def _read_signed_entitlements(binary: Path) -> dict[str, object]:
    """Read the entitlement plist out of a binary's code signature."""
    import plistlib
    from xml.parsers.expat import ExpatError

    result = subprocess.run(
        ["codesign", "-d", "--entitlements", "-", "--xml", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        parsed = plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, ValueError, ExpatError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _filter_entitlements(entitlements: dict[str, object]) -> tuple[dict[str, object], list[str]]:
    """Split entitlements into the Simulator-compatible set and the dropped keys."""
    kept = {k: v for k, v in entitlements.items() if k in SIMULATOR_ENTITLEMENTS}
    dropped = sorted(k for k in entitlements if k not in SIMULATOR_ENTITLEMENTS)
    return kept, dropped


def _inject_entitlements(binary: Path, entitlements: dict[str, object]) -> None:
    """Simulator launchd rejects entitlements in an ad-hoc signature (error 163) and
    reads a __TEXT,__entitlements section instead; it fits in the header padding."""
    import plistlib
    import struct

    blob = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
    data = bytearray(binary.read_bytes())

    if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        raise DarkmachError(f"not a 64-bit Mach-O: {binary}")

    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    text_off = text_cmdsize = None
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x19 and data[offset + 8 : offset + 24].rstrip(b"\0") == b"__TEXT":
            text_off, text_cmdsize = offset, cmdsize
            break
        offset += cmdsize
    if text_off is None:
        raise DarkmachError(f"no __TEXT segment in {binary}")

    text_vmaddr = struct.unpack_from("<Q", data, text_off + 24)[0]
    nsects = struct.unpack_from("<I", data, text_off + 64)[0]

    first_section = len(data)
    for i in range(nsects):
        sect = text_off + 72 + i * 80
        if data[sect : sect + 16].rstrip(b"\0") == b"__entitlements":
            raise DarkmachError(f"__entitlements already present in {binary}")
        sect_size = struct.unpack_from("<Q", data, sect + 40)[0]
        sect_off = struct.unpack_from("<I", data, sect + 48)[0]
        if sect_size and sect_off < first_section:
            first_section = sect_off

    header_end = 32 + sizeofcmds
    blob_off = (header_end + 80 + 15) & ~15
    if blob_off + len(blob) > first_section:
        raise DarkmachError(
            f"only {first_section - header_end} bytes of header padding in {binary.name}, "
            f"need {blob_off + len(blob) - header_end}"
        )

    sect_insert = text_off + 72 + nsects * 80
    trailing_commands = bytes(data[sect_insert:header_end])
    data[sect_insert : sect_insert + 80] = (
        b"__entitlements".ljust(16, b"\0")
        + b"__TEXT".ljust(16, b"\0")
        + struct.pack("<QQ", text_vmaddr + blob_off, len(blob))
        + struct.pack("<8I", blob_off, 0, 0, 0, 0, 0, 0, 0)
    )
    data[sect_insert + 80 : header_end + 80] = trailing_commands
    data[blob_off : blob_off + len(blob)] = blob

    struct.pack_into("<I", data, 20, sizeofcmds + 80)
    struct.pack_into("<I", data, text_off + 4, text_cmdsize + 80)
    struct.pack_into("<I", data, text_off + 64, nsects + 1)

    binary.write_bytes(data)


def _install_entitlements(binary: Path, entitlements: dict[str, object] | None) -> bool:
    """None means the caller deliberately stripped them; True means the binary
    changed and the caller must re-sign it."""
    if entitlements is None:
        return False
    if not entitlements:
        log("  Entitlements: none on the original binary")
        return False

    kept, dropped = _filter_entitlements(entitlements)
    if dropped:
        log(f"  Entitlements: dropped {len(dropped)} — {', '.join(dropped)}")
    if not kept:
        log("  Entitlements: kept 0 (none are Simulator-compatible)")
        return False

    try:
        _inject_entitlements(binary, kept)
    except DarkmachError as e:
        log(f"  WARNING: entitlements NOT applied, app runs unprivileged — {e}")
        return False

    log(f"  Entitlements: kept {len(kept)} — {', '.join(sorted(kept))}")
    return True


def _sign_item(item: Path, label: str) -> None:
    subprocess.run(
        ["codesign", "-s", "-", "--force", str(item)],
        capture_output=True,
        check=False,
    )
    log(f"    {label}: signed")


def patch_bundle(ios_bundle: Path, *, keep_framework_crypt: bool = False) -> None:
    """`keep_framework_crypt` restores cryptid=1 so the kernel keeps decrypting pages."""
    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")

    binary = ios_bundle / exe_name

    # The main executable is excluded: exec of a cryptid=1 image fails posix_spawn
    # with error 153, while mmap'd frameworks still decrypt on page-in.
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

    log("[1/4] Patching binaries...")
    log("  Main binary:")
    _patch_binary(binary, exe_name)

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

    if keep_framework_crypt and crypt_snapshot:
        log(f"  Restoring cryptid=1 on {len(crypt_snapshot)} binaries (Strategy A)")
        for bin_path, (cryptoff, cryptsize) in crypt_snapshot.items():
            _restore_crypt_header(bin_path, cryptoff, cryptsize, cryptid=1)

    log("[2/4] Patching plists...")
    _patch_plist(info_plist, "Main")

    if plugins_dir.is_dir():
        for appex in sorted(plugins_dir.iterdir()):
            if appex.suffix != ".appex" or not appex.is_dir():
                continue
            appex_plist = appex / "Info.plist"
            if appex_plist.is_file():
                _patch_plist(appex_plist, appex.stem)

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


def _patch_strategy_a(ios_bundle: Path, entitlements: dict[str, object] | None) -> None:
    """Step order is load-bearing — see
    `agent-memory/exploit-engineer/strategy_a_patch_order.md`."""
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

    # Captured up front because the ObjC neutralizer needs each framework's own crypt
    # window; the wrong one leaves ciphertext that SIGABRTs libobjc fixupMethodList.
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

    # Ad-hoc re-signing has no SC_Info/ sealed-resource exception, so leaving these
    # fails codesign and SpringBoard refuses the launch.
    sc_info_dirs = [d for d in ios_bundle.rglob("SC_Info") if d.is_dir()]
    if sc_info_dirs:
        log(f"[strategy_a] Removing {len(sc_info_dirs)} SC_Info/ directories")
        for sc_info in sc_info_dirs:
            shutil.rmtree(sc_info)

    patch_bundle(ios_bundle, keep_framework_crypt=True)

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

    # Every embedded Mach-O, not just the main one: framework method_list_t pointers
    # reach into crypt regions the page-in path cannot decrypt without a FairPlay key.
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
        # Without this inline re-sign the framework's signature mismatches its bytes
        # when codesign later walks the bundle.
        run(["codesign", "-s", "-", "--force", str(fw_binary)], quiet=True)
        fw_processed += 1
    log(f"[strategy_a] Neutralized ObjC method lists in {fw_processed} framework/appex binaries")

    # Must land before the final re-sign — codesign seals the files present at sign
    # time, and a later addition breaks the seal, which SpringBoard rejects.
    (ios_bundle / STRATEGY_MARKER).write_text("strategy_a\n")
    log("[strategy_a] Wrote marker — stage_launch will inject darkmach-survival.dylib")

    _install_entitlements(binary, entitlements)

    # Inside-out: the binary must be sealed before the bundle re-sign walks it.
    log("[strategy_a] Re-signing main binary + bundle...")
    run(["codesign", "-s", "-", "--force", str(binary)], quiet=True)
    run(["codesign", "-s", "-", "--force", str(ios_bundle)], quiet=True)


def stage_patch(
    ios_bundle: Path, udid: str | None = None, *, strip_entitlements: bool = False
) -> None:
    """Strategy selection and both pipelines are documented in `docs/patching.md`."""
    strategy = _detect_strategy(ios_bundle)
    log(f"[strategy] detected: {strategy}")

    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")

    binary = ios_bundle / exe_name

    # Must be read before any patcher runs — re-signing discards the original blob.
    entitlements: dict[str, object] | None = None
    if strip_entitlements:
        log("Entitlements: stripping (--strip-entitlements)")
    else:
        entitlements = _read_signed_entitlements(binary)

    if strategy == "strategy_a":
        _patch_strategy_a(ios_bundle, entitlements)
        return

    # Read before the patcher zeros it.
    cryptoff, cryptsize = _read_crypt_info(binary)
    has_encryption = cryptoff != 0 and cryptsize != 0
    if has_encryption:
        log(f"FairPlay encryption: cryptoff=0x{cryptoff:x} cryptsize=0x{cryptsize:x}")

    # Extraction needs the original binary, so it must precede patching.
    crypt_dump = None
    if has_encryption:
        if not udid:
            udid = get_booted_device()
            if not udid:
                udid = boot_simulator()
        crypt_dump = _extract_crypt_region(ios_bundle, binary, cryptoff, cryptsize, udid)

    patch_bundle(ios_bundle)

    modified = bool(crypt_dump)
    if crypt_dump:
        _write_crypt_bytes(binary, cryptoff, crypt_dump)
    if _install_entitlements(binary, entitlements):
        modified = True

    if modified:
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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="darkmach",
        description="iOS reverse engineering pipeline for Apple Silicon",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    strip_help = "Re-sign with no entitlements (unprivileged control baseline)"

    p_run = sub.add_parser("run", help="Full pipeline: analyze → patch → install → launch → bridge")
    p_run.add_argument("app", help="Path to .app (e.g., /Applications/AppName.app)")
    p_run.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_analyze = sub.add_parser("analyze", help="Static analysis only")
    p_analyze.add_argument("app", help="Path to .app")
    p_analyze.add_argument("-o", "--output", help="Output directory")

    p_patch = sub.add_parser("patch", help="Patch bundle for Simulator")
    p_patch.add_argument("app", help="Path to .app")
    p_patch.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_launch = sub.add_parser("launch", help="Launch installed app with interceptors")
    p_launch.add_argument("bundle_id", help="Bundle ID (e.g., com.oddsjam.app)")
    p_launch.add_argument("--ssl-bypass", action="store_true", help="Bypass SSL pinning")

    sub.add_parser("bridge", help="Connect to running bridge (interactive)")

    p_discover = sub.add_parser("discover", help="Find iOS apps available on Mac")
    p_discover.add_argument("search", nargs="?", help="Search term")
    p_discover.add_argument("--category", help="Category ID or 'all'")
    p_discover.add_argument("--ids", help="Comma-separated app IDs")
    p_discover.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    p_discover.add_argument("-o", "--output", help="Output file path")
    p_discover.add_argument(
        "--token", help="amp-api Bearer token (overrides DARKMACH_AMP_TOKEN env var)"
    )

    p_hermes = sub.add_parser("hermes", help="Extract secrets from Hermes bytecode")
    p_hermes.add_argument("app", help="Path to .app or .jsbundle")
    p_hermes.add_argument("-o", "--output", help="Output directory")
    p_hermes.add_argument("--json", action="store_true", help="JSON output")

    p_keychain = sub.add_parser("keychain", help="Read Simulator keychain (host-side)")
    p_keychain.add_argument("--udid", help="Simulator UDID (auto-detects booted)")
    p_keychain.add_argument("--json", action="store_true", help="JSON output")

    sub.add_parser("list", help="List installed iOS apps")

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
