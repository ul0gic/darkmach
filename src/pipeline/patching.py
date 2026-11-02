from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from darkmach._paths import CRYPT_CACHE, DECRYPT_DYLIB, PATCH_DIR, STRATEGY_MARKER
from darkmach.patch.surgical import patch_file
from darkmach.pipeline.process import DarkmachError, log, plist_read, run
from darkmach.pipeline.provenance import (
    CryptDump,
    EntitlementResult,
    PatchResult,
    atomic_write_json,
    hash_file,
)
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
    *,
    input_sha256: str,
) -> CryptDump:
    cache_key = f"{input_sha256}/{cryptoff:x}-{cryptsize:x}"
    cache_file = CRYPT_CACHE / f"{cache_key}.bin"
    receipt_file = cache_file.with_suffix(".json")
    identity = {
        "schema_version": 1,
        "input_sha256": input_sha256,
        "cryptoff": cryptoff,
        "cryptsize": cryptsize,
        "length": cryptsize,
    }
    try:
        receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        receipt = None
    except (json.JSONDecodeError, UnicodeDecodeError):
        receipt = None
        log("Crypt cache receipt is malformed; extracting a fresh region")
    if (
        isinstance(receipt, dict)
        and type(receipt.get("schema_version")) is int
        and all(receipt.get(k) == v for k, v in identity.items())
    ):
        try:
            size_matches = cache_file.stat().st_size == cryptsize
            dump_hash = hash_file(cache_file) if size_matches else None
        except FileNotFoundError:
            dump_hash = None
        if dump_hash is not None and dump_hash == receipt.get("dump_sha256"):
            log(f"Using verified cached crypt dump: {cache_file}")
            return CryptDump(cache_file, "hit", cache_key, dump_hash)
        log("Crypt cache data does not match its receipt; extracting a fresh region")
    elif receipt is not None:
        log("Crypt cache identity does not match the input; extracting a fresh region")

    if not DECRYPT_DYLIB.exists():
        raise DarkmachError(f"darkmach-decrypt.dylib not found: {DECRYPT_DYLIB}")

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=cache_file.parent, prefix=".crypt-", delete=False
    ) as target:
        temporary_dump = Path(target.name)
    try:
        with tempfile.TemporaryDirectory(prefix="darkmach-decrypt-", dir="/tmp") as workspace:
            tmp_bundle = Path(workspace) / ios_bundle.name
            shutil.copytree(str(ios_bundle), str(tmp_bundle), symlinks=True)
            # launchd_sim rejected a 0700 executable parent; crypt dumps stay 0600.
            Path(workspace).chmod(0o755)
            tmp_binary = tmp_bundle / binary.name
            patch_bundle(tmp_bundle)
            _restore_crypt_header(tmp_binary, cryptoff, cryptsize)
            subprocess.run(
                ["codesign", "-s", "-", "--force", str(tmp_binary)],
                capture_output=True,
                check=True,
            )

            env = dict(os.environ)
            env["SIMCTL_CHILD_DYLD_INSERT_LIBRARIES"] = str(DECRYPT_DYLIB)
            env["SIMCTL_CHILD_DARKMACH_CRYPTOFF"] = hex(cryptoff)
            env["SIMCTL_CHILD_DARKMACH_CRYPTSIZE"] = hex(cryptsize)
            env["SIMCTL_CHILD_DARKMACH_DECRYPT_OUT"] = str(temporary_dump)
            log("Extracting decrypted crypt region via simctl spawn...")
            try:
                result = subprocess.run(
                    ["xcrun", "simctl", "spawn", udid, str(tmp_binary)],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise DarkmachError("Crypt region extraction exceeded 30 seconds") from error

            if temporary_dump.stat().st_size != cryptsize:
                stderr_tail = result.stderr[-500:] if result.stderr else ""
                raise DarkmachError(
                    f"Crypt region extraction failed (exit {result.returncode})\n{stderr_tail}"
                )
            dump_hash = hash_file(temporary_dump)
            temporary_dump.replace(cache_file)
            atomic_write_json(receipt_file, {**identity, "dump_sha256": dump_hash})
        log(f"Extracted {cryptsize} bytes to {cache_file}")
        return CryptDump(cache_file, "miss", cache_key, dump_hash)
    finally:
        temporary_dump.unlink(missing_ok=True)


def _write_crypt_bytes(
    binary: Path, cryptoff: int, dump_file: Path, *, expected_sha256: str
) -> None:
    decrypted = dump_file.read_bytes()
    if hashlib.sha256(decrypted).hexdigest() != expected_sha256:
        raise DarkmachError("Crypt dump changed after validation; refusing to patch")
    with binary.open("r+b") as target:
        size = os.fstat(target.fileno()).st_size
        if cryptoff < 0 or cryptoff > size or len(decrypted) > size - cryptoff:
            raise DarkmachError("Decrypted region is outside the patched executable")
        target.seek(cryptoff)
        target.write(decrypted)
    log(f"Wrote {len(decrypted)} verified decrypted bytes at offset 0x{cryptoff:x}")


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
    log(f"Patched bundle: {ios_bundle}")
    log(f"Bundle ID: {bundle_id}")


def _patch_strategy_a(
    ios_bundle: Path, entitlements: dict[str, object] | None
) -> EntitlementResult:
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

    entitlement_result = _install_entitlements(binary, entitlements)

    # Inside-out: the binary must be sealed before the bundle re-sign walks it.
    log("[strategy_a] Re-signing main binary + bundle...")
    run(["codesign", "-s", "-", "--force", str(binary)], quiet=True)
    run(["codesign", "-s", "-", "--force", str(ios_bundle)], quiet=True)
    return entitlement_result


def stage_patch(
    ios_bundle: Path, udid: str | None = None, *, strip_entitlements: bool = False
) -> PatchResult:
    """Strategy selection and both pipelines are documented in `docs/patching.md`."""
    strategy = _detect_strategy(ios_bundle)
    log(f"[strategy] detected: {strategy}")

    info_plist = ios_bundle / "Info.plist"
    exe_name = plist_read(info_plist, "CFBundleExecutable")
    if not exe_name:
        raise DarkmachError(f"Cannot read CFBundleExecutable from {info_plist}")

    binary = ios_bundle / exe_name
    input_sha256 = hash_file(binary)
    cryptoff, cryptsize = _read_crypt_info(binary)
    file_size = binary.stat().st_size
    if (
        bool(cryptoff) != bool(cryptsize)
        or cryptoff > file_size
        or cryptsize > file_size - cryptoff
    ):
        raise DarkmachError("Encrypted region is outside the original executable")

    # Must be read before any patcher runs — re-signing discards the original blob.
    entitlements: dict[str, object] | None = None
    if strip_entitlements:
        log("Entitlements: stripping (--strip-entitlements)")
    else:
        entitlements = _read_signed_entitlements(binary)

    if strategy == "strategy_a":
        entitlement_result = _patch_strategy_a(ios_bundle, entitlements)
        return PatchResult(
            strategy,
            input_sha256,
            cryptoff,
            cryptsize,
            "not-needed",
            None,
            None,
            entitlement_result,
        )

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
        crypt_dump = _extract_crypt_region(
            ios_bundle, binary, cryptoff, cryptsize, udid, input_sha256=input_sha256
        )

    patch_bundle(ios_bundle)

    modified = bool(crypt_dump)
    if crypt_dump:
        _write_crypt_bytes(
            binary, cryptoff, crypt_dump.path, expected_sha256=crypt_dump.dump_sha256
        )
    entitlement_result = _install_entitlements(binary, entitlements)
    if entitlement_result.status == "preserved":
        modified = True

    if modified:
        # Re-sign after modifying the binary (inside-out: binary then bundle)
        run(["codesign", "-s", "-", "--force", str(binary)], quiet=True)
        run(["codesign", "-s", "-", "--force", str(ios_bundle)], quiet=True)

    return PatchResult(
        strategy,
        input_sha256,
        cryptoff,
        cryptsize,
        crypt_dump.cache_status if crypt_dump else "not-needed",
        crypt_dump.cache_key if crypt_dump else None,
        crypt_dump.dump_sha256 if crypt_dump else None,
        entitlement_result,
    )
