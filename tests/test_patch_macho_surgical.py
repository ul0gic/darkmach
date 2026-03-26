"""Tests for src/patch/patch-macho-surgical.py -- Mach-O binary patcher.

Covers:
  - patch_thin: LC_BUILD_VERSION platform patching (iOS -> iOSSimulator)
  - patch_thin: LC_ENCRYPTION_INFO_64 zeroing (cryptoff, cryptsize, cryptid)
  - patch_file: thin binary, FAT binary (32-bit and 64-bit), unknown format
  - Edge cases: already patched, unexpected platform, missing load commands
  - Binary round-trip: construct -> patch -> verify
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the standalone script via importlib (filename contains hyphens)
# ---------------------------------------------------------------------------

_PATCH_SCRIPT = (
    Path(__file__).resolve().parent.parent / "src" / "patch" / "patch-macho-surgical.py"
)


@pytest.fixture(scope="module")
def pms():
    """Import patch-macho-surgical.py as a module."""
    spec = importlib.util.spec_from_file_location("patch_macho_surgical", str(_PATCH_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers: Build synthetic Mach-O binaries from raw bytes
# ---------------------------------------------------------------------------

# Mach-O constants (duplicated here for self-contained test readability)
MH_MAGIC_64 = 0xFEEDFACF
LC_BUILD_VERSION = 0x32
LC_ENCRYPTION_INFO_64 = 0x2C
PLATFORM_IOS = 2
PLATFORM_IOS_SIMULATOR = 7
CPU_TYPE_ARM64 = 0x0100000C


def _build_mach_header_64(ncmds, sizeofcmds, cputype=CPU_TYPE_ARM64):
    """Build a raw mach_header_64 (32 bytes)."""
    return struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cputype,
        0,  # cpusubtype
        0x00000002,  # filetype MH_EXECUTE
        ncmds,
        sizeofcmds,
        0,  # flags
        0,  # reserved
    )


def _build_lc_build_version(platform=PLATFORM_IOS, minos=0x110000, sdk=0x110000):
    """Build LC_BUILD_VERSION load command (24 bytes, ntools=0)."""
    # cmd(4) cmdsize(4) platform(4) minos(4) sdk(4) ntools(4) = 24
    return struct.pack("<IIIIII", LC_BUILD_VERSION, 24, platform, minos, sdk, 0)


def _build_lc_encryption_info_64(cryptoff=0x4000, cryptsize=0x1000, cryptid=1):
    """Build LC_ENCRYPTION_INFO_64 load command (24 bytes)."""
    # cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) pad(4) = 24
    return struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, cryptoff, cryptsize, cryptid, 0)


def _build_thin_macho(platform=PLATFORM_IOS, cryptoff=0x4000, cryptsize=0x1000, cryptid=1,
                      include_build_version=True, include_encryption=True):
    """Build a complete thin Mach-O binary with optional load commands."""
    cmds = b""
    ncmds = 0

    if include_build_version:
        cmds += _build_lc_build_version(platform=platform)
        ncmds += 1

    if include_encryption:
        cmds += _build_lc_encryption_info_64(
            cryptoff=cryptoff, cryptsize=cryptsize, cryptid=cryptid
        )
        ncmds += 1

    header = _build_mach_header_64(ncmds, len(cmds))
    # Pad to cover the crypt region so it's a valid file
    binary = header + cmds
    needed = cryptoff + cryptsize if include_encryption else 0x1000
    if len(binary) < needed:
        binary += b"\x00" * (needed - len(binary))
    return binary


def _build_fat_macho(slices, fat64=False):
    """Build a FAT binary wrapping one or more thin Mach-O slices.

    slices: list of (cputype, cpusubtype, thin_bytes)
    """
    nfat_arch = len(slices)
    alignment = 14  # 2^14 = 16384
    align_size = 1 << alignment

    if fat64:
        fat_magic = 0xCAFEBABF
        arch_entry_size = 32
    else:
        fat_magic = 0xCAFEBABE
        arch_entry_size = 20

    header_size = 8 + nfat_arch * arch_entry_size

    # Pre-calculate slice offsets (each aligned to align_size)
    offsets = []
    current = (header_size + align_size - 1) & ~(align_size - 1)
    for _, _, thin_bytes in slices:
        offsets.append(current)
        current = ((current + len(thin_bytes)) + align_size - 1) & ~(align_size - 1)

    # Build the FAT header (big-endian)
    result = struct.pack(">II", fat_magic, nfat_arch)
    for i, (cputype, cpusubtype, thin_bytes) in enumerate(slices):
        if fat64:
            result += struct.pack(
                ">IIQQII",
                cputype, cpusubtype,
                offsets[i], len(thin_bytes),
                alignment, 0,
            )
        else:
            result += struct.pack(
                ">IIIII",
                cputype, cpusubtype,
                offsets[i], len(thin_bytes),
                alignment,
            )

    # Pad to first slice and write all slices at their offsets
    total_size = offsets[-1] + len(slices[-1][2])
    fat_data = bytearray(total_size)
    fat_data[:len(result)] = result
    for i, (_, _, thin_bytes) in enumerate(slices):
        fat_data[offsets[i]: offsets[i] + len(thin_bytes)] = thin_bytes

    return bytes(fat_data)


# ===================================================================
# patch_thin tests
# ===================================================================


class TestPatchThin:
    """Test the patch_thin function on raw Mach-O bytes."""

    def test_patches_platform_ios_to_simulator(self, pms):
        """LC_BUILD_VERSION platform should change from iOS(2) to iOSSimulator(7)."""
        data = bytearray(_build_thin_macho(platform=PLATFORM_IOS))
        data, changed = pms.patch_thin(data, 0)

        assert changed is True
        # Find the platform field in LC_BUILD_VERSION
        # header=32 bytes, LC_BUILD_VERSION starts at 32, platform at 32+8=40
        platform = struct.unpack_from("<I", data, 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

    def test_patches_encryption_to_zero(self, pms):
        """LC_ENCRYPTION_INFO_64 cryptoff/cryptsize/cryptid should all be zeroed."""
        data = bytearray(_build_thin_macho(cryptoff=0x4000, cryptsize=0x1000, cryptid=1))
        data, changed = pms.patch_thin(data, 0)

        assert changed is True
        # LC_ENCRYPTION_INFO_64 is the second load command (after LC_BUILD_VERSION at +32)
        # LC_BUILD_VERSION is 24 bytes, so encryption starts at 32 + 24 = 56
        enc_offset = 32 + 24
        cryptoff = struct.unpack_from("<I", data, enc_offset + 8)[0]
        cryptsize = struct.unpack_from("<I", data, enc_offset + 12)[0]
        cryptid = struct.unpack_from("<I", data, enc_offset + 16)[0]
        assert cryptoff == 0
        assert cryptsize == 0
        assert cryptid == 0

    def test_already_simulator_no_change(self, pms):
        """If already iOSSimulator, platform should not be changed."""
        data = bytearray(_build_thin_macho(
            platform=PLATFORM_IOS_SIMULATOR, include_encryption=False
        ))
        data, changed = pms.patch_thin(data, 0)
        # No encryption to patch, platform already correct
        assert changed is False

    def test_unexpected_platform_skipped(self, pms):
        """Platform values other than iOS(2) or iOSSimulator(7) should be skipped."""
        data = bytearray(_build_thin_macho(platform=1, include_encryption=False))  # macOS = 1
        data, changed = pms.patch_thin(data, 0)
        assert changed is False
        # Platform should remain macOS(1)
        platform = struct.unpack_from("<I", data, 40)[0]
        assert platform == 1

    def test_no_load_commands_no_change(self, pms):
        """Binary with no relevant load commands should report no changes."""
        data = bytearray(_build_thin_macho(
            include_build_version=False, include_encryption=False
        ))
        data, changed = pms.patch_thin(data, 0)
        assert changed is False

    def test_bad_magic_returns_false(self, pms):
        """Non-Mach-O data should be rejected."""
        data = bytearray(b"\x00" * 1024)
        data, changed = pms.patch_thin(data, 0)
        assert changed is False

    def test_with_base_offset(self, pms):
        """patch_thin should work with a non-zero base offset (FAT slice)."""
        thin = _build_thin_macho(platform=PLATFORM_IOS)
        padding = b"\x00" * 0x4000
        data = bytearray(padding + thin)

        data, changed = pms.patch_thin(data, 0x4000)
        assert changed is True

        # Check platform at base_offset + 32 + 8
        platform = struct.unpack_from("<I", data, 0x4000 + 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

    def test_both_patches_applied(self, pms):
        """Both platform and encryption should be patched in a single pass."""
        data = bytearray(_build_thin_macho(
            platform=PLATFORM_IOS, cryptoff=0x4000, cryptsize=0x1000, cryptid=1
        ))
        data, changed = pms.patch_thin(data, 0)

        assert changed is True
        # Verify platform changed
        platform = struct.unpack_from("<I", data, 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR
        # Verify encryption zeroed
        enc_offset = 32 + 24
        cryptid = struct.unpack_from("<I", data, enc_offset + 16)[0]
        assert cryptid == 0

    def test_encryption_already_zero(self, pms):
        """If encryption is already zeroed, only platform should cause a change."""
        data = bytearray(_build_thin_macho(
            platform=PLATFORM_IOS, cryptoff=0, cryptsize=0, cryptid=0
        ))
        data, changed = pms.patch_thin(data, 0)

        # Platform should still be patched
        assert changed is True
        platform = struct.unpack_from("<I", data, 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

    def test_label_parameter_accepted(self, pms):
        """The label parameter should not affect functionality."""
        data = bytearray(_build_thin_macho())
        data, changed = pms.patch_thin(data, 0, label="arm64")
        assert changed is True


# ===================================================================
# patch_file tests
# ===================================================================


class TestPatchFile:
    """Test the patch_file function which handles thin and FAT binaries."""

    def test_thin_binary(self, tmp_path, pms):
        """patch_file should handle a thin arm64 Mach-O."""
        binary = _build_thin_macho(platform=PLATFORM_IOS, cryptid=1)
        path = tmp_path / "ThinApp"
        path.write_bytes(binary)

        result = pms.patch_file(str(path))
        assert result is True

        # Verify the file was written back
        data = bytearray(path.read_bytes())
        platform = struct.unpack_from("<I", data, 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

    def test_thin_binary_no_change(self, tmp_path, pms):
        """patch_file returns False when no changes needed."""
        binary = _build_thin_macho(
            platform=PLATFORM_IOS_SIMULATOR,
            include_encryption=False,
        )
        path = tmp_path / "AlreadyPatched"
        path.write_bytes(binary)

        result = pms.patch_file(str(path))
        assert result is False

    def test_unknown_format(self, tmp_path, pms):
        """patch_file returns False for unknown binary formats."""
        path = tmp_path / "mystery"
        path.write_bytes(b"\x7fELF" + b"\x00" * 1000)  # ELF header, not Mach-O

        result = pms.patch_file(str(path))
        assert result is False

    def test_fat_binary_32bit(self, tmp_path, pms):
        """patch_file should handle a FAT binary with 32-bit fat_arch entries."""
        thin = _build_thin_macho(platform=PLATFORM_IOS, cryptid=1)
        fat = _build_fat_macho([(CPU_TYPE_ARM64, 0, thin)])

        path = tmp_path / "FatApp"
        path.write_bytes(fat)

        result = pms.patch_file(str(path))
        assert result is True

        # Re-read and find the arm64 slice
        data = bytearray(path.read_bytes())
        # fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) at offset 8
        slice_offset = struct.unpack_from(">I", data, 8 + 8)[0]
        # Verify the thin Mach-O magic is at the slice offset
        magic = struct.unpack_from("<I", data, slice_offset)[0]
        assert magic == MH_MAGIC_64
        # Verify platform was patched
        platform = struct.unpack_from("<I", data, slice_offset + 40)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

    def test_fat_binary_64bit(self, tmp_path, pms):
        """patch_file should handle a FAT binary with 64-bit fat_arch_64 entries."""
        thin = _build_thin_macho(platform=PLATFORM_IOS, cryptid=1)
        fat = _build_fat_macho([(CPU_TYPE_ARM64, 0, thin)], fat64=True)

        path = tmp_path / "Fat64App"
        path.write_bytes(fat)

        result = pms.patch_file(str(path))
        assert result is True

    def test_file_size_preserved(self, tmp_path, pms):
        """Patching should not change the file size."""
        binary = _build_thin_macho(platform=PLATFORM_IOS, cryptid=1)
        path = tmp_path / "SizeApp"
        path.write_bytes(binary)
        original_size = path.stat().st_size

        pms.patch_file(str(path))

        assert path.stat().st_size == original_size

    def test_non_crypt_data_preserved(self, tmp_path, pms):
        """Data outside load commands should not be modified."""
        thin = _build_thin_macho(platform=PLATFORM_IOS)
        # Write a known pattern in the padding area
        data = bytearray(thin)
        marker_offset = 0x200
        marker = b"SPHINX_MARKER_DATA"
        data[marker_offset: marker_offset + len(marker)] = marker

        path = tmp_path / "MarkerApp"
        path.write_bytes(bytes(data))

        pms.patch_file(str(path))

        patched = path.read_bytes()
        assert patched[marker_offset: marker_offset + len(marker)] == marker


# ===================================================================
# Round-trip: construct, patch, verify load commands
# ===================================================================


class TestRoundTrip:
    """Full round-trip: build binary -> patch -> verify all fields."""

    def test_complete_roundtrip(self, tmp_path, pms):
        """Build a binary with iOS platform + encryption, patch it, verify all changes."""
        original_cryptoff = 0x4000
        original_cryptsize = 0x1000

        binary = _build_thin_macho(
            platform=PLATFORM_IOS,
            cryptoff=original_cryptoff,
            cryptsize=original_cryptsize,
            cryptid=1,
        )
        path = tmp_path / "RoundTrip"
        path.write_bytes(binary)

        # Patch
        result = pms.patch_file(str(path))
        assert result is True

        # Verify
        data = bytearray(path.read_bytes())

        # Header should be unchanged
        magic = struct.unpack_from("<I", data, 0)[0]
        assert magic == MH_MAGIC_64

        cputype = struct.unpack_from("<I", data, 4)[0]
        assert cputype == CPU_TYPE_ARM64

        ncmds = struct.unpack_from("<I", data, 16)[0]
        assert ncmds == 2  # LC_BUILD_VERSION + LC_ENCRYPTION_INFO_64

        # LC_BUILD_VERSION: platform should be iOSSimulator
        lc_offset = 32
        cmd = struct.unpack_from("<I", data, lc_offset)[0]
        assert cmd == LC_BUILD_VERSION
        platform = struct.unpack_from("<I", data, lc_offset + 8)[0]
        assert platform == PLATFORM_IOS_SIMULATOR

        # LC_ENCRYPTION_INFO_64: all zeros
        enc_offset = lc_offset + 24
        cmd = struct.unpack_from("<I", data, enc_offset)[0]
        assert cmd == LC_ENCRYPTION_INFO_64
        cryptoff = struct.unpack_from("<I", data, enc_offset + 8)[0]
        cryptsize = struct.unpack_from("<I", data, enc_offset + 12)[0]
        cryptid = struct.unpack_from("<I", data, enc_offset + 16)[0]
        assert cryptoff == 0
        assert cryptsize == 0
        assert cryptid == 0

    def test_idempotent_data(self, tmp_path, pms):
        """Patching twice should produce identical binary data even though patcher reports changes.

        Note: patch_macho_surgical always reports changed=True when LC_ENCRYPTION_INFO_64
        is present (it unconditionally zeros the fields and sets patched=True, even when
        values are already zero). This is a known behavior -- the data is identical after
        the second pass, but the return value is True.
        """
        binary = _build_thin_macho(platform=PLATFORM_IOS, cryptid=1)
        path = tmp_path / "Idempotent"
        path.write_bytes(binary)

        # First patch
        result1 = pms.patch_file(str(path))
        assert result1 is True
        data_after_first = path.read_bytes()

        # Second patch -- patcher still reports True (zeroes already-zero encryption),
        # but the actual file content should be unchanged
        pms.patch_file(str(path))
        data_after_second = path.read_bytes()

        assert data_after_first == data_after_second

    def test_no_encryption_truly_idempotent(self, tmp_path, pms):
        """Without LC_ENCRYPTION_INFO_64, second patch returns False (truly idempotent)."""
        binary = _build_thin_macho(
            platform=PLATFORM_IOS, include_encryption=False
        )
        path = tmp_path / "NoEncrypt"
        path.write_bytes(binary)

        result1 = pms.patch_file(str(path))
        assert result1 is True  # Platform changed

        result2 = pms.patch_file(str(path))
        assert result2 is False  # Platform already simulator, no encryption to touch


# ===================================================================
# Module constants
# ===================================================================


class TestModuleConstants:
    """Verify that module-level constants match expected Mach-O values."""

    def test_mh_magic_64(self, pms):
        assert pms.MH_MAGIC_64 == 0xFEEDFACF

    def test_fat_magic(self, pms):
        assert pms.FAT_MAGIC == 0xCAFEBABE

    def test_fat_magic_64(self, pms):
        assert pms.FAT_MAGIC_64 == 0xCAFEBABF

    def test_fat_cigam(self, pms):
        assert pms.FAT_CIGAM == 0xBEBAFECA

    def test_fat_cigam_64(self, pms):
        assert pms.FAT_CIGAM_64 == 0xBFBAFECA

    def test_lc_build_version(self, pms):
        assert pms.LC_BUILD_VERSION == 0x32

    def test_lc_encryption_info_64(self, pms):
        assert pms.LC_ENCRYPTION_INFO_64 == 0x2C

    def test_cpu_type_arm64(self, pms):
        assert pms.CPU_TYPE_ARM64 == 0x0100000C

    def test_platform_ios(self, pms):
        assert pms.PLATFORM_IOS == 2

    def test_platform_ios_simulator(self, pms):
        assert pms.PLATFORM_IOS_SIMULATOR == 7
