from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from darkmach.pipeline.process import DarkmachError, log, run
from darkmach.pipeline.provenance import EntitlementResult

if TYPE_CHECKING:
    from pathlib import Path

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


def _read_signed_entitlements(binary: Path) -> dict[str, object]:
    """Read the entitlement plist out of a binary's code signature."""
    import plistlib
    from xml.parsers.expat import ExpatError

    result = subprocess.run(
        ["codesign", "-d", "--entitlements", "-", "--xml", str(binary)],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise DarkmachError(f"Cannot read signed entitlements from {binary.name}")
    if not result.stdout.strip():
        return {}
    try:
        parsed = plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, ValueError, ExpatError) as error:
        raise DarkmachError(f"Invalid signed entitlement plist in {binary.name}") from error
    if not isinstance(parsed, dict):
        raise DarkmachError(f"Signed entitlements in {binary.name} are not a dictionary")
    return parsed


def _filter_entitlements(entitlements: dict[str, object]) -> tuple[dict[str, object], list[str]]:
    """Split entitlements into the Simulator-compatible set and the dropped keys."""
    kept = {k: v for k, v in entitlements.items() if k in SIMULATOR_ENTITLEMENTS}
    dropped = sorted(k for k in entitlements if k not in SIMULATOR_ENTITLEMENTS)
    return kept, dropped


def _inject_entitlements(binary: Path, entitlements: dict[str, object]) -> str:
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
    encoding = "xml"
    if blob_off + len(blob) > first_section:
        blob = plistlib.dumps(entitlements, fmt=plistlib.FMT_BINARY)
        encoding = "binary"
    if blob_off + len(blob) > first_section:
        raise DarkmachError(
            f"Cannot preserve entitlements in {binary.name}: "
            f"{first_section - header_end} bytes of header space available, "
            f"{blob_off + len(blob) - header_end} required even with a binary plist. "
            "Use --strip-entitlements only to explicitly omit these app capabilities."
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
    return encoding


def _install_entitlements(
    binary: Path, entitlements: dict[str, object] | None
) -> EntitlementResult:
    if entitlements is None:
        log("  Entitlements: explicitly omitted (--strip-entitlements)")
        return EntitlementResult("stripped", (), (), None)
    if not entitlements:
        log("  Entitlements: none on the original binary")
        return EntitlementResult("absent", (), (), None)

    kept, dropped = _filter_entitlements(entitlements)
    if dropped:
        log(f"  Entitlements: dropped {len(dropped)} unsupported keys — {', '.join(dropped)}")
    if not kept:
        log("  Entitlements: no Simulator-compatible keys on the original binary")
        return EntitlementResult("none-compatible", (), tuple(dropped), None)

    encoding = _inject_entitlements(binary, kept)
    log(
        f"  Entitlements: preserved {len(kept)} compatible keys ({encoding}) — "
        f"{', '.join(sorted(kept))}"
    )
    return EntitlementResult("preserved", tuple(sorted(kept)), tuple(dropped), encoding)


def _sign_item(item: Path, label: str) -> None:
    run(["codesign", "-s", "-", "--force", str(item)], quiet=True)
    log(f"    {label}: signed")
