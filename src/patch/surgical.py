#!/usr/bin/env python3
"""Byte-level Mach-O patcher: LC_BUILD_VERSION platform iOS -> iOSSimulator, and
LC_ENCRYPTION_INFO_64 cryptoff/cryptsize/cryptid zeroed.
"""

import struct
import sys
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM = 0xBEBAFECA
FAT_CIGAM_64 = 0xBFBAFECA

LC_BUILD_VERSION = 0x32
LC_ENCRYPTION_INFO_64 = 0x2C

CPU_TYPE_ARM64 = 0x0100000C

PLATFORM_IOS = 2
PLATFORM_IOS_SIMULATOR = 7


def patch_thin(data, base_offset, label=""):
    """Patch a single Mach-O slice starting at base_offset."""
    prefix = f"  [{label}] " if label else "  "

    magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags, _reserved = (
        struct.unpack_from("<IIIIIIII", data, base_offset)
    )

    if magic != MH_MAGIC_64:
        print(f"{prefix}Not a 64-bit Mach-O (magic=0x{magic:08X}), skipping")
        return data, False

    header_size = 32  # mach_header_64
    offset = base_offset + header_size
    patched = False

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)

        if cmd == LC_BUILD_VERSION:
            # Layout: cmd(4) cmdsize(4) platform(4) minos(4) sdk(4) ntools(4)
            platform_offset = offset + 8
            old_platform = struct.unpack_from("<I", data, platform_offset)[0]
            if old_platform == PLATFORM_IOS:
                struct.pack_into("<I", data, platform_offset, PLATFORM_IOS_SIMULATOR)
                print(
                    f"{prefix}LC_BUILD_VERSION: platform {old_platform} -> {PLATFORM_IOS_SIMULATOR}"
                )
                patched = True
            elif old_platform == PLATFORM_IOS_SIMULATOR:
                print(f"{prefix}LC_BUILD_VERSION: already simulator ({old_platform})")
            else:
                print(f"{prefix}LC_BUILD_VERSION: unexpected platform {old_platform}, skipping")

        elif cmd == LC_ENCRYPTION_INFO_64:
            # Layout: cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) pad(4)
            cryptoff_offset = offset + 8
            cryptsize_offset = offset + 12
            cryptid_offset = offset + 16

            old_cryptoff = struct.unpack_from("<I", data, cryptoff_offset)[0]
            old_cryptsize = struct.unpack_from("<I", data, cryptsize_offset)[0]
            old_cryptid = struct.unpack_from("<I", data, cryptid_offset)[0]

            struct.pack_into("<I", data, cryptoff_offset, 0)
            struct.pack_into("<I", data, cryptsize_offset, 0)
            struct.pack_into("<I", data, cryptid_offset, 0)

            print(
                f"{prefix}LC_ENCRYPTION_INFO_64: cryptoff={old_cryptoff}->0, "
                f"cryptsize={old_cryptsize}->0, cryptid={old_cryptid}->0"
            )
            patched = True

        offset += cmdsize

    if not patched:
        print(f"{prefix}No changes needed")

    return data, patched


def patch_file(filepath):
    """Patch a Mach-O file (thin or FAT)."""
    print(f"Patching: {filepath}")

    with Path(filepath).open("rb") as f:
        data = bytearray(f.read())

    magic = struct.unpack_from(">I", data, 0)[0]  # FAT headers are big-endian

    changed = False

    if magic in (FAT_MAGIC, FAT_CIGAM):
        nfat_arch = struct.unpack_from(">I", data, 4)[0]
        for i in range(nfat_arch):
            # fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
            arch_offset = 8 + (i * 20)
            cputype, _cpusubtype, slice_offset, _slice_size, _align = struct.unpack_from(
                ">IIIII", data, arch_offset
            )
            arch_name = "arm64" if cputype == CPU_TYPE_ARM64 else f"cpu_{cputype}"
            data, did_patch = patch_thin(data, slice_offset, label=arch_name)
            changed = changed or did_patch

    elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
        nfat_arch = struct.unpack_from(">I", data, 4)[0]
        for i in range(nfat_arch):
            # fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4)
            arch_offset = 8 + (i * 32)
            cputype, _cpusubtype = struct.unpack_from(">II", data, arch_offset)
            slice_offset = struct.unpack_from(">Q", data, arch_offset + 8)[0]
            arch_name = "arm64" if cputype == CPU_TYPE_ARM64 else f"cpu_{cputype}"
            data, did_patch = patch_thin(data, slice_offset, label=arch_name)
            changed = changed or did_patch

    else:
        le_magic = struct.unpack_from("<I", data, 0)[0]
        if le_magic == MH_MAGIC_64:
            data, changed = patch_thin(data, 0)
        else:
            print(f"  Unknown format (magic=0x{magic:08X}), skipping")
            return False

    if changed:
        with Path(filepath).open("wb") as f:
            f.write(data)
        print("  Written successfully")
    else:
        print("  No changes written")

    return changed


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mach-o-file> [mach-o-file ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        if Path(path).is_file():
            patch_file(path)
        else:
            print(f"Not a file: {path}")


if __name__ == "__main__":
    main()
