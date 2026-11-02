from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from darkmach._paths import CRYPT_CACHE, DECRYPT_DYLIB, PATCH_DIR, STRATEGY_MARKER
from darkmach.patch.surgical import patch_file
from darkmach.pipeline.process import DarkmachError, log, plist_read, run
from darkmach.pipeline.signing import _install_entitlements, _read_signed_entitlements, _sign_item
from darkmach.pipeline.simulator import boot_simulator, get_booted_device

MAIN_PATCHER = PATCH_DIR / "make-main-patch.py"
OBJC_METADATA_PATCHER = PATCH_DIR / "patch-objc-metadata.py"


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

    patch_file(str(binary))


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
