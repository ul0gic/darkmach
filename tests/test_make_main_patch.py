"""Tests for src/patch/make-main-patch.py -- ARM64 instruction encoders and shellcode generation.

Covers:
  - All 17 ARM64 instruction encoder functions with known-good expected values
  - Edge cases: max/min immediates, boundary registers (X0, X30, SP), negative offsets
  - find_load_commands: Mach-O parsing from raw bytes
  - generate_main_patch: end-to-end shellcode generation + binary patching
  - detect_delegate (embedded copy): AppDelegate auto-detection
"""

from __future__ import annotations

import importlib.util
import struct
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Import the standalone script via importlib (filename contains hyphens)
# ---------------------------------------------------------------------------

_PATCH_SCRIPT = (
    Path(__file__).resolve().parent.parent / "src" / "darkmach" / "patch" / "make-main-patch.py"
)


@pytest.fixture(scope="module")
def mmp():
    """Import make-main-patch.py as a module."""
    spec = importlib.util.spec_from_file_location("make_main_patch", str(_PATCH_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===================================================================
# ARM64 Instruction Encoder Tests
# ===================================================================


class TestEncodeRet:
    """RET -- return via X30."""

    def test_encoding(self, mmp):
        assert mmp.encode_ret() == 0xD65F03C0

    def test_is_32_bits(self, mmp):
        val = mmp.encode_ret()
        assert 0 <= val <= 0xFFFFFFFF


class TestEncodeNop:
    """NOP -- no operation."""

    def test_encoding(self, mmp):
        assert mmp.encode_nop() == 0xD503201F

    def test_is_32_bits(self, mmp):
        val = mmp.encode_nop()
        assert 0 <= val <= 0xFFFFFFFF


class TestEncodeBrk:
    """BRK #imm16 -- breakpoint."""

    def test_brk_0(self, mmp):
        assert mmp.encode_brk(0) == 0xD4200000

    def test_brk_1(self, mmp):
        assert mmp.encode_brk(1) == 0xD4200020

    def test_brk_default_arg(self, mmp):
        """BRK with no argument should default to imm16=0."""
        assert mmp.encode_brk() == 0xD4200000

    def test_brk_max_imm16(self, mmp):
        # BRK #0xFFFF -- maximum 16-bit immediate
        val = mmp.encode_brk(0xFFFF)
        # Extract imm16: bits [20:5]
        extracted_imm = (val >> 5) & 0xFFFF
        assert extracted_imm == 0xFFFF
        # Verify opcode bits: 11010100_001 in bits [31:21]
        assert (val >> 21) == 0b11010100_001

    def test_brk_preserves_opcode(self, mmp):
        for imm in [0, 1, 42, 255, 0xFFFF]:
            val = mmp.encode_brk(imm)
            assert (val >> 21) == 0b11010100_001
            assert (val & 0x1F) == 0  # Rd field = 0


class TestEncodeBlr:
    """BLR Xn -- branch with link to register."""

    def test_blr_x0(self, mmp):
        assert mmp.encode_blr(0) == 0xD63F0000

    def test_blr_x30(self, mmp):
        assert mmp.encode_blr(30) == 0xD63F03C0

    def test_blr_all_registers(self, mmp):
        """BLR should encode any register 0-30 in bits [9:5]."""
        for rn in range(31):
            val = mmp.encode_blr(rn)
            extracted_rn = (val >> 5) & 0x1F
            assert extracted_rn == rn
            # Rd field should be 0
            assert (val & 0x1F) == 0
            # Opcode: 1101011_0_0_01_11111_0000_0_0 in bits [31:10]
            assert (val >> 10) == 0b1101011_0_0_01_11111_0000_0_0


class TestEncodeBr:
    """BR Xn -- branch to register (no link)."""

    def test_br_x0(self, mmp):
        assert mmp.encode_br(0) == 0xD61F0000

    def test_br_x30(self, mmp):
        assert mmp.encode_br(30) == 0xD61F03C0

    def test_br_vs_blr_differ_only_in_opc(self, mmp):
        """BR and BLR differ only in the opc field (bit 21)."""
        for rn in [0, 1, 15, 29, 30]:
            br_val = mmp.encode_br(rn)
            blr_val = mmp.encode_blr(rn)
            # BR has opc=00, BLR has opc=01 at bits [22:21]
            assert br_val != blr_val
            # They should differ by exactly 1 bit (bit 21)
            diff = br_val ^ blr_val
            assert diff == (1 << 21)


class TestEncodeBl:
    """BL #offset -- PC-relative branch with link, +/- 128MB."""

    def test_bl_zero(self, mmp):
        assert mmp.encode_bl(0) == 0x94000000

    def test_bl_plus_4(self, mmp):
        # BL #4 -> imm26 = 1
        assert mmp.encode_bl(4) == 0x94000001

    def test_bl_plus_8(self, mmp):
        assert mmp.encode_bl(8) == 0x94000002

    def test_bl_large_positive(self, mmp):
        # BL #1024 -> imm26 = 256
        val = mmp.encode_bl(1024)
        assert (val >> 26) == 0b100101  # opcode
        assert (val & 0x3FFFFFF) == 256

    def test_bl_negative_offset(self, mmp):
        # BL #-4 -> imm26 should be sign-extended via masking
        val = mmp.encode_bl(-4)
        assert (val >> 26) == 0b100101
        # -4 / 4 = -1, masked to 26 bits = 0x3FFFFFF
        assert (val & 0x3FFFFFF) == 0x3FFFFFF

    def test_bl_requires_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_bl(3)  # Not 4-byte aligned

    def test_bl_opcode_preserved(self, mmp):
        for offset in [0, 4, 100, 1024, -8, -1024]:
            val = mmp.encode_bl(offset)
            assert (val >> 26) == 0b100101


class TestEncodeB:
    """B #offset -- unconditional branch."""

    def test_b_zero(self, mmp):
        assert mmp.encode_b(0) == 0x14000000

    def test_b_plus_8(self, mmp):
        assert mmp.encode_b(8) == 0x14000002

    def test_b_negative(self, mmp):
        val = mmp.encode_b(-4)
        assert (val >> 26) == 0b000101
        assert (val & 0x3FFFFFF) == 0x3FFFFFF

    def test_b_requires_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_b(2)

    def test_b_vs_bl_differ_in_opcode(self, mmp):
        """B and BL differ in bit 31 (link bit)."""
        b_val = mmp.encode_b(8)
        bl_val = mmp.encode_bl(8)
        # B = 000101, BL = 100101 -> differ in bit 31
        assert (b_val >> 26) == 0b000101
        assert (bl_val >> 26) == 0b100101


class TestEncodeCbz:
    """CBZ Xt, #offset -- compare and branch if zero (64-bit)."""

    def test_cbz_x0_plus_8(self, mmp):
        assert mmp.encode_cbz(0, 8) == 0xB4000040

    def test_cbz_register_encoding(self, mmp):
        """Rt is in bits [4:0]."""
        for rt in [0, 1, 19, 29, 30]:
            val = mmp.encode_cbz(rt, 8)
            assert (val & 0x1F) == rt

    def test_cbz_offset_encoding(self, mmp):
        """imm19 (offset/4) is in bits [23:5]."""
        # CBZ X0, #100 -> imm19 = 25
        val = mmp.encode_cbz(0, 100)
        extracted_imm19 = (val >> 5) & 0x7FFFF
        assert extracted_imm19 == 25

    def test_cbz_requires_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_cbz(0, 3)

    def test_cbz_opcode_64bit(self, mmp):
        """64-bit CBZ has sf=1 in bit 31 and opc bits."""
        val = mmp.encode_cbz(0, 8)
        # 1_011010_0 in bits [31:24]
        assert (val >> 24) == 0b1_011010_0


class TestEncodeMovReg:
    """MOV Xd, Xm -- register move (alias for ORR Xd, XZR, Xm)."""

    def test_mov_x0_x1(self, mmp):
        assert mmp.encode_mov_reg(0, 1) == 0xAA0103E0

    def test_mov_x29_sp(self, mmp):
        # MOV X29, XZR|SP (register 31) -- used for frame pointer init in some contexts
        assert mmp.encode_mov_reg(29, 31) == 0xAA1F03FD

    def test_rd_in_bits_4_0(self, mmp):
        for rd in [0, 1, 19, 29, 30]:
            val = mmp.encode_mov_reg(rd, 0)
            assert (val & 0x1F) == rd

    def test_rm_in_bits_20_16(self, mmp):
        for rm in [0, 1, 19, 29, 30]:
            val = mmp.encode_mov_reg(0, rm)
            assert ((val >> 16) & 0x1F) == rm

    def test_rn_is_xzr(self, mmp):
        """Rn field (bits [9:5]) should be 31 (XZR) for MOV alias."""
        for rd in range(31):
            val = mmp.encode_mov_reg(rd, 0)
            assert ((val >> 5) & 0x1F) == 31


class TestEncodeMovImm:
    """MOV Xd, #imm16 -- alias for MOVZ (64-bit)."""

    def test_mov_x0_0(self, mmp):
        assert mmp.encode_mov_imm(0, 0) == 0xD2800000

    def test_mov_x0_42(self, mmp):
        assert mmp.encode_mov_imm(0, 42) == 0xD2800540

    def test_imm16_encoding(self, mmp):
        """imm16 is in bits [20:5]."""
        for imm in [0, 1, 42, 255, 0xFFFF]:
            val = mmp.encode_mov_imm(0, imm)
            extracted = (val >> 5) & 0xFFFF
            assert extracted == imm

    def test_rd_encoding(self, mmp):
        for rd in [0, 1, 19, 29, 30]:
            val = mmp.encode_mov_imm(rd, 0)
            assert (val & 0x1F) == rd

    def test_opcode_movz_64bit(self, mmp):
        """MOVZ 64-bit: 110100101_00 in bits [31:21]."""
        val = mmp.encode_mov_imm(0, 0)
        assert (val >> 21) == 0b110100101_00


class TestEncodeMovn:
    """MOVN Xd, #imm16 -- move NOT (Xd = ~(imm16 << shift))."""

    def test_movn_rtld_default(self, mmp):
        # MOVN X0, #1 -> X0 = ~1 = -2 = 0xFFFFFFFFFFFFFFFE = RTLD_DEFAULT
        assert mmp.encode_movn(0, 1) == 0x92800020

    def test_movn_imm_encoding(self, mmp):
        """imm16 is in bits [20:5]."""
        val = mmp.encode_movn(0, 1)
        extracted = (val >> 5) & 0xFFFF
        assert extracted == 1

    def test_movn_rd_encoding(self, mmp):
        for rd in [0, 1, 19]:
            val = mmp.encode_movn(rd, 1)
            assert (val & 0x1F) == rd

    def test_movn_shift_0(self, mmp):
        """hw=0 (shift=0) should put 0 in bits [22:21]."""
        val = mmp.encode_movn(0, 1, shift=0)
        hw = (val >> 21) & 0x3
        assert hw == 0

    def test_movn_shift_16(self, mmp):
        """hw=1 (shift=16) should put 1 in bits [22:21]."""
        val = mmp.encode_movn(0, 1, shift=16)
        hw = (val >> 21) & 0x3
        assert hw == 1

    def test_movn_opcode(self, mmp):
        """MOVN 64-bit: 10010010_1 in bits [31:23]."""
        val = mmp.encode_movn(0, 0)
        assert (val >> 23) == 0b10010010_1


class TestEncodeAddImm:
    """ADD Xd, Xn, #imm12 -- 64-bit add immediate."""

    def test_mov_x29_sp(self, mmp):
        # ADD X29, SP, #0 = MOV X29, SP
        assert mmp.encode_add_imm(29, 31, 0) == 0x910003FD

    def test_add_max_imm(self, mmp):
        # ADD X0, X0, #4095 (max imm12)
        assert mmp.encode_add_imm(0, 0, 4095) == 0x913FFC00

    def test_imm12_encoding(self, mmp):
        """imm12 in bits [21:10]."""
        for imm in [0, 1, 100, 4095]:
            val = mmp.encode_add_imm(0, 0, imm)
            extracted = (val >> 10) & 0xFFF
            assert extracted == imm

    def test_rd_rn_encoding(self, mmp):
        val = mmp.encode_add_imm(5, 10, 0)
        assert (val & 0x1F) == 5  # Rd
        assert ((val >> 5) & 0x1F) == 10  # Rn

    def test_rejects_negative_imm(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_add_imm(0, 0, -1)

    def test_rejects_too_large_imm(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_add_imm(0, 0, 4096)

    def test_opcode(self, mmp):
        """64-bit ADD immediate: 1001000100 in bits [31:22]."""
        val = mmp.encode_add_imm(0, 0, 0)
        assert (val >> 22) == 0b1001000100


class TestEncodeAdr:
    """ADR Xd, #offset -- PC-relative address, +/- 1MB."""

    def test_adr_zero(self, mmp):
        assert mmp.encode_adr(0, 0) == 0x10000000

    def test_adr_x1_100(self, mmp):
        assert mmp.encode_adr(1, 100) == 0x10000321

    def test_rd_encoding(self, mmp):
        for rd in [0, 1, 19, 29, 30]:
            val = mmp.encode_adr(rd, 0)
            assert (val & 0x1F) == rd

    def test_offset_reconstruction(self, mmp):
        """Verify the split immlo/immhi fields reconstruct the correct offset."""
        for offset in [0, 4, 100, 1000, -4, -100, -1000]:
            val = mmp.encode_adr(0, offset)
            # Extract immlo (bits [30:29]) and immhi (bits [23:5])
            immlo = (val >> 29) & 0x3
            immhi = (val >> 5) & 0x7FFFF
            reconstructed = (immhi << 2) | immlo
            # Sign-extend from 21 bits
            if reconstructed & (1 << 20):
                reconstructed -= 1 << 21
            assert reconstructed == offset

    def test_rejects_out_of_range(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_adr(0, 1048576)  # > +1MB
        with pytest.raises(AssertionError):
            mmp.encode_adr(0, -1048577)  # < -1MB

    def test_accepts_boundary(self, mmp):
        # Exactly at +1MB-1 and -1MB boundaries
        mmp.encode_adr(0, 1048575)
        mmp.encode_adr(0, -1048576)

    def test_opcode_bit31_zero(self, mmp):
        """ADR has op=0 in bit 31 (vs ADRP which has op=1)."""
        val = mmp.encode_adr(0, 0)
        assert (val >> 31) == 0


class TestEncodeStpPre:
    """STP Xt, Xt2, [Xn, #imm]! -- pre-indexed store pair (64-bit)."""

    def test_stp_frame_setup(self, mmp):
        # STP X29, X30, [SP, #-80]! -- standard prologue
        assert mmp.encode_stp_pre(29, 30, 31, -80) == 0xA9BB7BFD

    def test_rt_rt2_rn_encoding(self, mmp):
        val = mmp.encode_stp_pre(19, 20, 31, -16)
        assert (val & 0x1F) == 19  # Rt
        assert ((val >> 10) & 0x1F) == 20  # Rt2
        assert ((val >> 5) & 0x1F) == 31  # Rn (SP)

    def test_imm_encoding(self, mmp):
        """imm7 (offset/8) in bits [21:15]."""
        # STP Xt, Xt2, [SP, #-80]! -> imm7 = -80/8 = -10 = 0x76 (7-bit 2's comp)
        val = mmp.encode_stp_pre(29, 30, 31, -80)
        imm7 = (val >> 15) & 0x7F
        # -10 in 7-bit 2's complement = 0x76 = 118
        assert imm7 == (-80 // 8) & 0x7F

    def test_requires_8byte_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_stp_pre(0, 1, 31, -7)

    def test_rejects_out_of_range(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_stp_pre(0, 1, 31, -520)  # < -512
        with pytest.raises(AssertionError):
            mmp.encode_stp_pre(0, 1, 31, 512)  # > 504

    def test_positive_offset(self, mmp):
        val = mmp.encode_stp_pre(0, 1, 31, 16)
        imm7 = (val >> 15) & 0x7F
        assert imm7 == 2  # 16/8 = 2

    def test_opcode_bits(self, mmp):
        """Pre-indexed STP 64-bit: 10_101_0_011_0 in bits [31:22]."""
        val = mmp.encode_stp_pre(0, 1, 31, -16)
        assert (val >> 22) == 0b10_101_0_011_0


class TestEncodeLdpPost:
    """LDP Xt, Xt2, [Xn], #imm -- post-indexed load pair (64-bit)."""

    def test_ldp_epilogue(self, mmp):
        # LDP X29, X30, [SP], #80 -- standard epilogue
        assert mmp.encode_ldp_post(29, 30, 31, 80) == 0xA8C57BFD

    def test_rt_rt2_rn_encoding(self, mmp):
        val = mmp.encode_ldp_post(19, 20, 31, 16)
        assert (val & 0x1F) == 19
        assert ((val >> 10) & 0x1F) == 20
        assert ((val >> 5) & 0x1F) == 31

    def test_requires_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_ldp_post(0, 1, 31, 5)

    def test_opcode_bits(self, mmp):
        """Post-indexed LDP 64-bit: 10_101_0_001_1 in bits [31:22]."""
        val = mmp.encode_ldp_post(0, 1, 31, 16)
        assert (val >> 22) == 0b10_101_0_001_1


class TestEncodeStpSigned:
    """STP Xt, Xt2, [Xn, #imm] -- signed offset store pair (64-bit)."""

    def test_stp_signed(self, mmp):
        assert mmp.encode_stp_signed(19, 20, 31, 16) == 0xA90153F3

    def test_opcode_bits(self, mmp):
        """Signed offset STP 64-bit: 10_101_0_010_0 in bits [31:22]."""
        val = mmp.encode_stp_signed(0, 1, 31, 16)
        assert (val >> 22) == 0b10_101_0_010_0

    def test_requires_alignment(self, mmp):
        with pytest.raises(AssertionError):
            mmp.encode_stp_signed(0, 1, 31, 3)


class TestEncodeLdpSigned:
    """LDP Xt, Xt2, [Xn, #imm] -- signed offset load pair (64-bit)."""

    def test_ldp_signed(self, mmp):
        assert mmp.encode_ldp_signed(19, 20, 31, 16) == 0xA94153F3

    def test_opcode_bits(self, mmp):
        """Signed offset LDP 64-bit: 10_101_0_010_1 in bits [31:22]."""
        val = mmp.encode_ldp_signed(0, 1, 31, 16)
        assert (val >> 22) == 0b10_101_0_010_1


# ===================================================================
# STP/LDP opcode distinguishing tests
# ===================================================================


class TestStpLdpOpcodeDistinction:
    """STP pre, STP signed, LDP post, LDP signed must have distinct opcodes."""

    def test_all_four_differ(self, mmp):
        stp_pre = mmp.encode_stp_pre(0, 1, 31, 16)
        stp_signed = mmp.encode_stp_signed(0, 1, 31, 16)
        ldp_post = mmp.encode_ldp_post(0, 1, 31, 16)
        ldp_signed = mmp.encode_ldp_signed(0, 1, 31, 16)

        opcodes = {
            stp_pre >> 22,
            stp_signed >> 22,
            ldp_post >> 22,
            ldp_signed >> 22,
        }
        assert len(opcodes) == 4


# ===================================================================
# All Instructions Are 32 Bits
# ===================================================================


class TestAllEncoders32Bit:
    """Every encoder must return a value that fits in 32 bits (ARM64 fixed-width)."""

    def test_all_encoders_fit_32_bits(self, mmp):
        values = [
            mmp.encode_ret(),
            mmp.encode_nop(),
            mmp.encode_brk(0),
            mmp.encode_brk(0xFFFF),
            mmp.encode_blr(0),
            mmp.encode_blr(30),
            mmp.encode_br(0),
            mmp.encode_bl(0),
            mmp.encode_bl(1024),
            mmp.encode_bl(-4),
            mmp.encode_b(0),
            mmp.encode_b(8),
            mmp.encode_cbz(0, 8),
            mmp.encode_mov_reg(0, 1),
            mmp.encode_mov_imm(0, 0),
            mmp.encode_mov_imm(0, 0xFFFF),
            mmp.encode_movn(0, 1),
            mmp.encode_add_imm(0, 0, 0),
            mmp.encode_adr(0, 0),
            mmp.encode_adr(0, -100),
            mmp.encode_stp_pre(29, 30, 31, -80),
            mmp.encode_ldp_post(29, 30, 31, 80),
            mmp.encode_stp_signed(19, 20, 31, 16),
            mmp.encode_ldp_signed(19, 20, 31, 16),
        ]
        for val in values:
            assert 0 <= val <= 0xFFFFFFFF, f"Value 0x{val:X} exceeds 32 bits"


# ===================================================================
# Struct Packing
# ===================================================================


class TestInstructionPacking:
    """Instructions must pack to exactly 4 bytes in little-endian."""

    def test_pack_ret(self, mmp):
        packed = struct.pack("<I", mmp.encode_ret())
        assert packed == b"\xc0\x03\x5f\xd6"
        assert len(packed) == 4

    def test_pack_nop(self, mmp):
        packed = struct.pack("<I", mmp.encode_nop())
        assert packed == b"\x1f\x20\x03\xd5"
        assert len(packed) == 4

    def test_pack_roundtrip(self, mmp):
        """Pack then unpack should recover the same value."""
        for val in [mmp.encode_ret(), mmp.encode_nop(), mmp.encode_brk(1)]:
            packed = struct.pack("<I", val)
            unpacked = struct.unpack("<I", packed)[0]
            assert unpacked == val


# ===================================================================
# find_load_commands
# ===================================================================


def _build_macho_bytes(
    entryoff=0x1000,
    cryptoff=0x1000,
    cryptsize=0x1000,
    cryptid=1,
    include_main=True,
    include_crypt=True,
):
    """Build a minimal Mach-O binary with LC_MAIN and LC_ENCRYPTION_INFO_64."""
    ncmds = int(include_main) + int(include_crypt)

    # LC_MAIN: cmd(4) + cmdsize(4) + entryoff(8) + stacksize(8) = 24
    lc_main = b""
    if include_main:
        lc_main = struct.pack("<IIqq", 0x80000028, 24, entryoff, 0)

    # LC_ENCRYPTION_INFO_64: cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4) pad(4)
    lc_crypt = b""
    if include_crypt:
        lc_crypt = struct.pack("<IIIIII", 0x2C, 24, cryptoff, cryptsize, cryptid, 0)

    sizeofcmds = len(lc_main) + len(lc_crypt)

    # mach_header_64: 32 bytes
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # magic
        0x0100000C,  # cputype ARM64
        0x00000000,  # cpusubtype
        0x00000002,  # filetype MH_EXECUTE
        ncmds,
        sizeofcmds,
        0,  # flags
        0,  # reserved
    )

    return header + lc_main + lc_crypt


class TestFindLoadCommands:
    """Tests for find_load_commands() Mach-O parser."""

    def test_basic_parse(self, mmp):
        data = _build_macho_bytes()
        info = mmp.find_load_commands(data)
        assert info is not None
        assert info["entryoff"] == 0x1000
        assert info["cryptoff"] == 0x1000
        assert info["cryptsize"] == 0x1000
        assert info["cryptid"] == 1

    def test_custom_values(self, mmp):
        data = _build_macho_bytes(entryoff=0x2000, cryptoff=0x3000, cryptsize=0x4000, cryptid=0)
        info = mmp.find_load_commands(data)
        assert info["entryoff"] == 0x2000
        assert info["cryptoff"] == 0x3000
        assert info["cryptsize"] == 0x4000
        assert info["cryptid"] == 0

    def test_no_crypt(self, mmp):
        data = _build_macho_bytes(include_crypt=False)
        info = mmp.find_load_commands(data)
        assert info is not None
        assert "entryoff" in info
        assert "cryptoff" not in info

    def test_no_main(self, mmp):
        data = _build_macho_bytes(include_main=False)
        info = mmp.find_load_commands(data)
        assert info is not None
        assert "entryoff" not in info
        assert "cryptoff" in info

    def test_bad_magic(self, mmp):
        data = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 100
        assert mmp.find_load_commands(data) is None

    def test_base_offset(self, mmp):
        """Parsing with a non-zero base offset (for FAT binary slices)."""
        padding = b"\x00" * 64
        macho_data = _build_macho_bytes()
        data = padding + macho_data
        info = mmp.find_load_commands(data, base=64)
        assert info is not None
        assert info["entryoff"] == 0x1000


# ===================================================================
# generate_main_patch (end-to-end)
# ===================================================================


class TestGenerateMainPatch:
    """End-to-end tests for the shellcode generation + binary patching pipeline."""

    def _make_test_binary(self, tmp_path, mmp, cryptoff=0x4000, cryptsize=0x1000, entryoff=0x4080):
        """Build a test Mach-O binary with enough data to patch."""
        data = _build_macho_bytes(
            entryoff=entryoff, cryptoff=cryptoff, cryptsize=cryptsize, cryptid=1
        )
        # Pad to cover the crypt region
        needed = cryptoff + cryptsize
        if len(data) < needed:
            data += b"\x00" * (needed - len(data))
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(data)
        return str(binary_path)

    def test_generates_patched_binary(self, tmp_path, mmp):
        """Shellcode generation should succeed and modify the binary."""
        binary_path = self._make_test_binary(tmp_path, mmp)

        output_path = str(tmp_path / "TestApp_patched")

        # Mock the GOT-slot lookup so no real __got section or otool is needed
        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            result = mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=output_path,
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
            )

        assert result is True
        assert Path(output_path).exists()

        patched_data = Path(output_path).read_bytes()
        # The crypt region should have been modified
        crypt_region = patched_data[0x4000 : 0x4000 + 0x1000]
        assert crypt_region != b"\x00" * 0x1000

    def test_fill_region_contains_brk(self, tmp_path, mmp):
        """Strategy A (default) should fill the padding after shellcode with BRK instructions.

        Note: The fill bytes may not start at a 4-byte-aligned offset relative to
        the region start (because string data can have non-multiple-of-4 length).
        We check for the raw BRK byte pattern appearing repeatedly in the region.
        """
        binary_path = self._make_test_binary(tmp_path, mmp)
        output_path = str(tmp_path / "TestApp_patched")

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=output_path,
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
            )

        patched_data = Path(output_path).read_bytes()
        crypt_region = patched_data[0x4000 : 0x4000 + 0x1000]

        brk_bytes = struct.pack("<I", mmp.encode_brk(1))
        ret_bytes = struct.pack("<I", mmp.encode_ret())

        # The fill region should contain many BRK byte patterns
        brk_count = crypt_region.count(brk_bytes)
        assert brk_count > 100, f"Expected 100+ BRK fills, got {brk_count}"

        # RET should only appear once (in the epilogue), not in the fill
        # (The epilogue RET is at a 4-byte-aligned offset, fill is at the string-end offset)
        ret_count = crypt_region.count(ret_bytes)
        assert ret_count < 5, f"Strategy A should not have many RETs, got {ret_count}"

    def test_bootstrap_mode_uses_ret(self, tmp_path, mmp):
        """Strategy B (bootstrap=True) should fill with RET instead of BRK."""
        binary_path = self._make_test_binary(tmp_path, mmp)
        output_path = str(tmp_path / "TestApp_patched")

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=output_path,
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
                bootstrap=True,
            )

        patched_data = Path(output_path).read_bytes()
        crypt_region = patched_data[0x4000 : 0x4000 + 0x1000]

        ret_bytes = struct.pack("<I", mmp.encode_ret())
        brk_bytes = struct.pack("<I", mmp.encode_brk(1))

        # The fill region should contain many RET byte patterns
        ret_count = crypt_region.count(ret_bytes)
        # The epilogue has 1 RET, and the fill should have hundreds more
        assert ret_count > 100, f"Expected 100+ RET fills, got {ret_count}"

        # BRK should NOT appear in bootstrap mode
        brk_count = crypt_region.count(brk_bytes)
        assert brk_count == 0, f"Strategy B should have no BRK, got {brk_count}"

    def test_nop_sled_before_entry(self, tmp_path, mmp):
        """Region before entry_in_crypt should be NOP sled."""
        cryptoff = 0x4000
        entryoff = 0x4080  # 0x80 bytes into crypt region
        binary_path = self._make_test_binary(
            tmp_path, mmp, cryptoff=cryptoff, cryptsize=0x1000, entryoff=entryoff
        )
        output_path = str(tmp_path / "TestApp_patched")

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=output_path,
                force_cryptoff=cryptoff,
                force_cryptsize=0x1000,
            )

        patched_data = Path(output_path).read_bytes()
        entry_in_crypt = entryoff - cryptoff  # 0x80

        # Every 4 bytes before the entry should be NOP
        for off in range(0, entry_in_crypt, 4):
            word = struct.unpack_from("<I", patched_data, cryptoff + off)[0]
            assert word == mmp.encode_nop(), (
                f"Expected NOP at offset 0x{cryptoff + off:x}, got 0x{word:08X}"
            )

    def test_region_exact_size(self, tmp_path, mmp):
        """Patched region must be exactly cryptsize bytes."""
        cryptsize = 0x2000
        binary_path = self._make_test_binary(
            tmp_path, mmp, cryptoff=0x4000, cryptsize=cryptsize, entryoff=0x4080
        )
        output_path = str(tmp_path / "TestApp_patched")

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=output_path,
                force_cryptoff=0x4000,
                force_cryptsize=cryptsize,
            )

        original_size = Path(binary_path).stat().st_size
        patched_size = Path(output_path).stat().st_size
        assert patched_size == original_size

    def test_delegate_string_embedded(self, tmp_path, mmp):
        """Only the delegate class name is embedded — no function-name strings remain."""
        binary_path = self._make_test_binary(tmp_path, mmp)
        output_path = str(tmp_path / "TestApp_patched")

        delegate = "_TtC7TestApp11AppDelegate"

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                binary_path,
                delegate,
                output_path=output_path,
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
            )

        patched_data = Path(output_path).read_bytes()
        crypt_region = patched_data[0x4000 : 0x4000 + 0x1000]

        # Only the delegate class name is embedded now
        assert delegate.encode("ascii") + b"\x00" in crypt_region

    def test_fails_without_got_slot(self, tmp_path, mmp):
        """Should return False if a required GOT slot cannot be found."""
        binary_path = self._make_test_binary(tmp_path, mmp)

        with patch.object(mmp, "find_got_address", return_value=None):
            result = mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
            )

        assert result is False

    def test_fails_without_lc_main(self, tmp_path, mmp):
        """Should return False if LC_MAIN is missing."""
        data = _build_macho_bytes(include_main=False)
        data += b"\x00" * 0x5000
        binary_path = tmp_path / "NoMain"
        binary_path.write_bytes(data)

        result = mmp.generate_main_patch(
            str(binary_path),
            "AppDelegate",
            force_cryptoff=0x1000,
            force_cryptsize=0x1000,
        )
        assert result is False

    def test_fails_on_bad_magic(self, tmp_path, mmp):
        """Should return False if binary is not Mach-O."""
        binary_path = tmp_path / "NotMachO"
        binary_path.write_bytes(b"\x00" * 0x5000)

        result = mmp.generate_main_patch(
            str(binary_path),
            "AppDelegate",
            force_cryptoff=0x1000,
            force_cryptsize=0x1000,
        )
        assert result is False

    def test_fails_without_crypt_info(self, tmp_path, mmp):
        """Should return False if cryptoff/cryptsize are zero and no override provided."""
        data = _build_macho_bytes(cryptoff=0, cryptsize=0, cryptid=0)
        data += b"\x00" * 0x5000
        binary_path = tmp_path / "NoCrypt"
        binary_path.write_bytes(data)

        result = mmp.generate_main_patch(str(binary_path), "AppDelegate")
        assert result is False

    def test_overwrite_in_place(self, tmp_path, mmp):
        """When output_path is None, the binary should be overwritten in place."""
        binary_path = self._make_test_binary(tmp_path, mmp)
        original_data = Path(binary_path).read_bytes()

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            result = mmp.generate_main_patch(
                binary_path,
                "AppDelegate",
                output_path=None,
                force_cryptoff=0x4000,
                force_cryptsize=0x1000,
            )

        assert result is True
        patched_data = Path(binary_path).read_bytes()
        assert patched_data != original_data


# ===================================================================
# Shellcode Structure Validation
# ===================================================================


class TestShellcodeStructure:
    """Validate the internal structure of the generated shellcode block."""

    def _generate_shellcode_region(self, tmp_path, mmp, delegate="AppDelegate", bootstrap=False):
        """Helper: generate a patched binary and return the crypt region bytes."""
        cryptoff = 0x4000
        cryptsize = 0x1000
        entryoff = 0x4000  # Entry at start of crypt region (no NOP sled)

        data = _build_macho_bytes(
            entryoff=entryoff, cryptoff=cryptoff, cryptsize=cryptsize, cryptid=1
        )
        needed = cryptoff + cryptsize
        data += b"\x00" * (needed - len(data))

        binary_path = tmp_path / "SC_TestApp"
        binary_path.write_bytes(data)
        output_path = tmp_path / "SC_TestApp_patched"

        with patch.object(mmp, "find_got_address", return_value=0x100104000):
            mmp.generate_main_patch(
                str(binary_path),
                delegate,
                output_path=str(output_path),
                force_cryptoff=cryptoff,
                force_cryptsize=cryptsize,
                bootstrap=bootstrap,
            )

        patched_data = output_path.read_bytes()
        return patched_data[cryptoff : cryptoff + cryptsize]

    def test_starts_with_stp_prologue(self, tmp_path, mmp):
        """First instruction should be STP X29, X30, [SP, #-64]!"""
        region = self._generate_shellcode_region(tmp_path, mmp)
        first_word = struct.unpack_from("<I", region, 0)[0]
        assert first_word == mmp.encode_stp_pre(29, 30, 31, -64)

    def test_second_is_mov_fp_sp(self, tmp_path, mmp):
        """Second instruction should be ADD X29, SP, #0 (MOV X29, SP)."""
        region = self._generate_shellcode_region(tmp_path, mmp)
        second_word = struct.unpack_from("<I", region, 4)[0]
        assert second_word == mmp.encode_add_imm(29, 31, 0)

    def test_no_movn_no_dlsym(self, tmp_path, mmp):
        """MOVN X0, #1 (RTLD_DEFAULT) is gone — GOT slots replaced the dlsym path."""
        region = self._generate_shellcode_region(tmp_path, mmp)
        movn_bytes = struct.pack("<I", mmp.encode_movn(0, 1))
        assert movn_bytes not in region

    def test_contains_blr_instructions(self, tmp_path, mmp):
        """Each resolved GOT pointer is called via BLR X16 — three times."""
        region = self._generate_shellcode_region(tmp_path, mmp)
        blr16 = struct.pack("<I", mmp.encode_blr(16))
        assert region.count(blr16) == 3

    def test_ends_with_ret(self, tmp_path, mmp):
        """The code section should end with RET before the string data."""
        region = self._generate_shellcode_region(tmp_path, mmp)
        # Find the first occurrence of the string data marker
        str_offset = region.find(b"AppDelegate\x00")
        assert str_offset > 0
        # The instruction just before the strings should be RET
        code_end = str_offset
        last_instr = struct.unpack_from("<I", region, code_end - 4)[0]
        assert last_instr == mmp.encode_ret()

    def test_no_bl_uses_blr_x16(self, tmp_path, mmp):
        """No BL instructions remain — the three GOT calls go through BLR X16."""
        region = self._generate_shellcode_region(tmp_path, mmp)
        # BL instructions have opcode 100101 in bits [31:26]
        bl_count = 0
        for off in range(0, len(region) - 3, 4):
            word = struct.unpack_from("<I", region, off)[0]
            if (word >> 26) == 0b100101:
                bl_count += 1
            # Stop scanning once the delegate string begins
            if region[off : off + 4] == b"AppD":
                break
        assert bl_count == 0
        blr16 = struct.pack("<I", mmp.encode_blr(16))
        assert region.count(blr16) == 3


# ===================================================================
# detect_delegate (embedded in make-main-patch.py)
# ===================================================================


class TestDetectDelegateEmbedded:
    """Test the detect_delegate function embedded in make-main-patch.py."""

    def test_swift_exact_match(self, tmp_path, mmp):
        """Strategy 1: exact Swift mangled name matching module."""
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(b"dummy")

        strings_output = "_TtC7TestApp11AppDelegate\nsome_other_string"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout=strings_output, stderr=""
            )
            name, method, confidence = mmp.detect_delegate(str(binary_path))

        assert name == "_TtC7TestApp11AppDelegate"
        assert "Swift mangled" in method
        assert confidence == "high"

    def test_objc_prefixed_appdelegate(self, tmp_path, mmp):
        """Strategy 3: prefixed ObjC AppDelegate (regex requires prefix)."""
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(b"dummy")

        strings_output = "MyAppDelegate\nsome_other_symbol"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout=strings_output, stderr=""
            )
            name, method, _confidence = mmp.detect_delegate(str(binary_path))

        assert name == "MyAppDelegate"
        assert "ObjC" in method

    def test_swiftui_detection(self, tmp_path, mmp):
        """Strategy 4: SwiftUI @main app has no AppDelegate."""
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(b"dummy")

        strings_output = "$s7SwiftUI3AppP\nsome_other_string"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout=strings_output, stderr=""
            )
            name, method, _confidence = mmp.detect_delegate(str(binary_path))

        assert name is None
        assert "SwiftUI" in method

    def test_no_delegate_found(self, tmp_path, mmp):
        """Returns None when nothing matches."""
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(b"dummy")

        strings_output = "random_string\nanother_string\n"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout=strings_output, stderr=""
            )
            name, _method, confidence = mmp.detect_delegate(str(binary_path))

        assert name is None
        assert confidence is None

    def test_sdk_delegate_filtered(self, tmp_path, mmp):
        """SDK delegates (GoogleUtilities, Firebase, etc.) should be filtered out."""
        binary_path = tmp_path / "TestApp"
        binary_path.write_bytes(b"dummy")

        strings_output = (
            "_TtC15GoogleUtilities28GULAppDelegateSwizzlerHelper\nGULAppDelegateSwizzler"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout=strings_output, stderr=""
            )
            name, _method, _confidence = mmp.detect_delegate(str(binary_path))

        # Should not return Google's delegate
        if name is not None:
            assert "GoogleUtilities" not in name
            assert "GULAppDelegateSwizzler" not in name
