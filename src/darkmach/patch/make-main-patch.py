#!/usr/bin/env python3
"""
Generate a replacement main() for an iOS app whose entry point
falls inside a FairPlay-encrypted region.

Strategy:
  - Write ARM64 shellcode that calls objc_getClass, NSStringFromClass,
    and UIApplicationMain by loading each function pointer directly from
    its __got/__auth_got slot (ADRP+LDR+BLR). Strategy A's BRK fill
    destroys __stubs (which lives inside the crypt region), so stub-based
    calls are impossible — __got in __DATA_CONST is unencrypted and
    populated by dyld at bind time.
  - The only embedded string constant is the AppDelegate class name,
    referenced PC-relative via ADR. No dlsym, no function-name strings.
  - Patch the shellcode into the binary at the encrypted region offset.

The result: the encrypted region is replaced with a working main()
that boots the app through the standard UIApplicationMain path.
"""

import contextlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ── ARM64 instruction encoders ──────────────────────────────────────


def encode_stp_pre(rt, rt2, rn, imm):
    """STP Xt, Xt2, [Xn, #imm]! (pre-indexed, 64-bit)"""
    assert imm % 8 == 0 and -512 <= imm <= 504
    imm7 = (imm // 8) & 0x7F
    return (0b10_101_0_011_0 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def encode_ldp_post(rt, rt2, rn, imm):
    """LDP Xt, Xt2, [Xn], #imm (post-indexed, 64-bit)"""
    assert imm % 8 == 0 and -512 <= imm <= 504
    imm7 = (imm // 8) & 0x7F
    return (0b10_101_0_001_1 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def encode_stp_signed(rt, rt2, rn, imm):
    """STP Xt, Xt2, [Xn, #imm] (signed offset, 64-bit)"""
    assert imm % 8 == 0 and -512 <= imm <= 504
    imm7 = (imm // 8) & 0x7F
    return (0b10_101_0_010_0 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def encode_ldp_signed(rt, rt2, rn, imm):
    """LDP Xt, Xt2, [Xn, #imm] (signed offset, 64-bit)"""
    assert imm % 8 == 0 and -512 <= imm <= 504
    imm7 = (imm // 8) & 0x7F
    return (0b10_101_0_010_1 << 22) | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt


def encode_mov_reg(rd, rm):
    """MOV Xd, Xm (alias for ORR Xd, XZR, Xm)"""
    return (0b10101010000 << 21) | (rm << 16) | (0b000000 << 10) | (31 << 5) | rd


def encode_mov_imm(rd, imm16):
    """MOV Xd, #imm16 (alias for MOVZ)"""
    return (0b110100101_00 << 21) | (imm16 << 5) | rd


def encode_movn(rd, imm16, shift=0):
    """MOVN Xd, #imm16 (Xd = ~(imm16 << shift))"""
    hw = shift // 16
    return (0b10010010_1 << 23) | (hw << 21) | (imm16 << 5) | rd


def encode_add_imm(rd, rn, imm12):
    """ADD Xd, Xn, #imm12 (64-bit). Register 31 = SP here."""
    assert 0 <= imm12 <= 4095
    return (0b1001000100 << 22) | (imm12 << 10) | (rn << 5) | rd


def encode_adr(rd, offset):
    """ADR Xd, #offset (PC-relative, ±1MB)"""
    assert -1048576 <= offset <= 1048575
    immlo = offset & 0x3
    immhi = (offset >> 2) & 0x7FFFF
    return (0b0 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd


def encode_bl(offset_bytes):
    """BL #offset (PC-relative, ±128MB, must be 4-byte aligned)"""
    assert offset_bytes % 4 == 0
    imm26 = (offset_bytes // 4) & 0x3FFFFFF
    return (0b100101 << 26) | imm26


def encode_blr(rn):
    """BLR Xn"""
    return (0b1101011_0_0_01_11111_0000_0_0 << 10) | (rn << 5) | 0b00000


def encode_br(rn):
    """BR Xn"""
    return (0b1101011_0_0_00_11111_0000_0_0 << 10) | (rn << 5) | 0b00000


def encode_cbz(rt, offset_bytes):
    """CBZ Xt, #offset (64-bit)"""
    assert offset_bytes % 4 == 0
    imm19 = (offset_bytes // 4) & 0x7FFFF
    return (0b1_011010_0 << 24) | (imm19 << 5) | rt


def encode_b(offset_bytes):
    """B #offset"""
    assert offset_bytes % 4 == 0
    imm26 = (offset_bytes // 4) & 0x3FFFFFF
    return (0b000101 << 26) | imm26


def encode_ret():
    """RET (return via X30)"""
    return 0xD65F03C0


def encode_nop():
    """NOP"""
    return 0xD503201F


def encode_brk(imm16=0):
    """BRK #imm16"""
    return (0b11010100_001 << 21) | (imm16 << 5) | 0b00000


def encode_adrp(rd, page_offset):
    """ADRP Xd, #page_offset

    page_offset is the difference between the target page and the instruction's
    page, in BYTES (must be 4KB-aligned). ADRP loads (PC[63:12]<<12) + page_offset
    into Xd, where PC[11:0] is implicitly 0.

    Encoding: op[31]=1 immlo[30:29] 10000[28:24] immhi[23:5] Rd[4:0]
    The encoded immediate is signed 21 bits = (page_offset >> 12).
    """
    assert page_offset % 4096 == 0, f"ADRP offset must be 4KB-aligned, got {page_offset}"
    imm = page_offset >> 12
    # Sign-check: 21-bit signed range
    assert -(1 << 20) <= imm < (1 << 20), f"ADRP imm out of range: {imm}"
    imm21 = imm & 0x1FFFFF
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    return (1 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd


def encode_ldr_imm_unsigned(rt, rn, imm):
    """LDR Xt, [Xn, #imm] (unsigned offset, 64-bit)

    imm must be a multiple of 8, 0..32760.
    Encoding: 11 111 0 01 01 imm12[21:10] Rn[9:5] Rt[4:0]
    where imm12 = imm / 8.
    """
    assert imm % 8 == 0 and 0 <= imm <= 32760, f"LDR imm out of range: {imm}"
    imm12 = imm // 8
    return (0b11_111_0_01_01 << 22) | (imm12 << 10) | (rn << 5) | rt


# ── Binary analysis helpers ──────────────────────────────────────────


def find_load_commands(data, base=0):
    """Parse Mach-O load commands, return dict of key values."""
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != 0xFEEDFACF:
        return None

    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    offset = base + 32  # past mach_header_64

    info = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)

        if cmd == 0x80000028:  # LC_MAIN
            info["entryoff"] = struct.unpack_from("<Q", data, offset + 8)[0]

        elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            info["cryptoff"] = struct.unpack_from("<I", data, offset + 8)[0]
            info["cryptsize"] = struct.unpack_from("<I", data, offset + 12)[0]
            info["cryptid"] = struct.unpack_from("<I", data, offset + 16)[0]

        offset += cmdsize

    return info


def _find_got_section_bounds(binary_path):
    """Return (addr, size) tuples for every __got-like section.
    Includes __got, __auth_got. Range checks across all of them."""
    lc_out = subprocess.check_output(["otool", "-l", binary_path], text=True)
    lines = lc_out.split("\n")
    bounds = []
    for i, line in enumerate(lines):
        sl = line.strip()
        if sl.startswith(("sectname __got", "sectname __auth_got")):
            addr = size = None
            for j in range(i, min(i + 10, len(lines))):
                t = lines[j].strip()
                if t.startswith("addr "):
                    addr = int(t.split()[-1], 16)
                elif t.startswith("size "):
                    val = t.split()[-1]
                    size = int(val, 16) if val.startswith("0x") else int(val)
                if addr is not None and size is not None:
                    break
            if addr is not None and size is not None:
                bounds.append((addr, size))
    return bounds


def find_got_address(binary_path, symbol_name):
    """Find the __got slot address for a given symbol using otool -Iv.

    The indirect symbol table lists each symbol multiple times if it has
    both a __stubs entry and a __got entry. We filter to the entry whose
    address falls within a __got/__auth_got section's range.
    """
    bounds = _find_got_section_bounds(binary_path)
    if not bounds:
        return None

    out = subprocess.check_output(["otool", "-Iv", binary_path], text=True)
    target = symbol_name
    # otool -Iv prints lines like "0x0000000103859790  7503 _objc_getClass"
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) < 3:
            continue
        # The symbol name is the last column; allow exact match for safety
        if parts[-1] != target:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        for got_addr, got_size in bounds:
            if got_addr <= addr < got_addr + got_size:
                return addr
    return None


# ── Main patch generation ────────────────────────────────────────────


def generate_main_patch(
    binary_path,
    delegate_class,
    output_path=None,
    force_cryptoff=None,
    force_cryptsize=None,
    bootstrap=False,
):
    """
    Generate a patched binary with the encrypted region replaced by
    a working main() function.

    If force_cryptoff/force_cryptsize are provided, use those instead
    of reading from the binary (needed when encryption fields are already zeroed).

    If bootstrap=True (Strategy B), fills the crypt region with RET
    instructions instead of BRK traps. This allows other functions in the
    crypt region to return harmlessly when called. The bootstrap dylib
    (darkmach-bootstrap.dylib) handles the actual UIApplicationMain call.
    """
    print(f"Analyzing: {binary_path}")

    with Path(binary_path).open("rb") as f:
        data = bytearray(f.read())

    info = find_load_commands(data)
    if not info:
        print("ERROR: Could not parse Mach-O")
        return False

    entryoff = info.get("entryoff")
    cryptoff = force_cryptoff if force_cryptoff is not None else info.get("cryptoff")
    cryptsize = force_cryptsize if force_cryptsize is not None else info.get("cryptsize")

    if entryoff is None:
        print("ERROR: Missing LC_MAIN")
        return False
    if (
        cryptoff is None or cryptoff == 0 or cryptsize is None or cryptsize == 0
    ) and force_cryptoff is None:
        print("ERROR: cryptoff/cryptsize are zero and no --cryptoff/--cryptsize provided")
        print("  Use --cryptoff and --cryptsize to specify the original values")
        return False

    print(f"  entryoff:  0x{entryoff:x}")
    print(f"  cryptoff:  0x{cryptoff:x}")
    print(f"  cryptsize: 0x{cryptsize:x}")

    # Find __TEXT segment vmaddr (always 0x100000000 for arm64, but let's verify)
    text_vmaddr = 0x100000000  # standard for arm64 main executable

    entry_vmaddr = text_vmaddr + entryoff
    entry_in_crypt = entryoff - cryptoff  # offset of entry within encrypted region
    print(f"  entry vmaddr:   0x{entry_vmaddr:x}")
    print(f"  entry in crypt: 0x{entry_in_crypt:x}")

    # ── Resolve GOT slots for the three functions we need ──
    #
    # Strategy A's BRK fill destroys __stubs (which lives inside the crypt
    # region), so calling functions via __stubs is impossible. Instead we
    # load function pointers directly from __got/__auth_got, which live in
    # __DATA_CONST (unencrypted, populated by dyld at bind time).
    #
    # Sequence per call:
    #   ADRP x16, _func@GOTPAGE        ; high 21 bits of GOT slot's page
    #   LDR  x16, [x16, #pageoff]      ; load real function pointer
    #   BLR  x16                        ; call resolved function
    got_objc_getClass = find_got_address(binary_path, "_objc_getClass")
    got_NSStringFromClass = find_got_address(binary_path, "_NSStringFromClass")
    got_UIApplicationMain = find_got_address(binary_path, "_UIApplicationMain")
    missing = [
        n
        for n, v in [
            ("_objc_getClass", got_objc_getClass),
            ("_NSStringFromClass", got_NSStringFromClass),
            ("_UIApplicationMain", got_UIApplicationMain),
        ]
        if v is None
    ]
    if missing:
        print(f"ERROR: Could not find GOT slot(s) for: {', '.join(missing)}")
        print("  These symbols must exist in __got or __auth_got. Check otool -Iv.")
        return False
    print(f"  GOT _objc_getClass:     0x{got_objc_getClass:x}")
    print(f"  GOT _NSStringFromClass: 0x{got_NSStringFromClass:x}")
    print(f"  GOT _UIApplicationMain: 0x{got_UIApplicationMain:x}")

    # ── Build the replacement main() shellcode ───────────────────────
    #
    # Register assignments:
    #   x19 = argc (saved across calls)
    #   x20 = argv (saved across calls)
    #   x21 = saved Class returned by objc_getClass (across NSStringFromClass)
    #   x16 = scratch — loaded with resolved function pointer per call
    #
    # Only one string constant remains (the delegate class name); all other
    # function lookup strings are gone since we no longer call dlsym.

    str_delegate = delegate_class.encode("ascii") + b"\x00"

    SP = 31
    X0, X1, X2, X3 = 0, 1, 2, 3
    X16 = 16
    X19, X20, X21, X22 = 19, 20, 21, 22
    X29, X30 = 29, 30

    instructions = []

    # Indexes of instructions whose encoding depends on knowing both the
    # instruction's vmaddr AND the target (GOT slot or string offset).
    # We emit placeholders, then fix up after layout.
    adrp_objc_idx = None
    ldr_objc_idx = None
    adrp_nsstr_idx = None
    ldr_nsstr_idx = None
    adrp_uiapp_idx = None
    ldr_uiapp_idx = None
    adr_delegate_idx = None
    cbz_idx = None
    b_idx = None
    use_nil_idx = None
    call_uiapp_idx = None

    # Prologue: save frame pointer, link register, and callee-saved regs we use
    # 4 register pairs * 16 bytes = 64 bytes of frame, but stp pre-indexed
    # requires multiples of 16 and we use 48 bytes for saves + 16 for fp/lr.
    # Total frame: 64 bytes.
    instructions.append(encode_stp_pre(X29, X30, SP, -64))  # stp x29, x30, [sp, #-64]!
    instructions.append(encode_add_imm(X29, SP, 0))  # mov x29, sp
    instructions.append(encode_stp_signed(X19, X20, SP, 16))  # stp x19, x20, [sp, #16]
    instructions.append(encode_stp_signed(X21, X22, SP, 32))  # stp x21, x22, [sp, #32]

    # Save argc/argv
    instructions.append(encode_mov_reg(X19, X0))  # mov x19, x0 (argc)
    instructions.append(encode_mov_reg(X20, X1))  # mov x20, x1 (argv)

    # ── objc_getClass(delegate_class) via GOT ──
    adrp_objc_idx = len(instructions)
    instructions.append(0)  # adrp x16, _objc_getClass@GOTPAGE
    ldr_objc_idx = len(instructions)
    instructions.append(0)  # ldr  x16, [x16, #pageoff]
    adr_delegate_idx = len(instructions)
    instructions.append(0)  # adr  x0, str_delegate (PC-relative within shellcode)
    instructions.append(encode_blr(X16))  # blr  x16

    # cbz x0, use_nil
    cbz_idx = len(instructions)
    instructions.append(0)  # cbz x0, use_nil
    instructions.append(encode_mov_reg(X21, X0))  # mov x21, x0 (save Class)

    # ── NSStringFromClass(cls) via GOT ──
    adrp_nsstr_idx = len(instructions)
    instructions.append(0)  # adrp x16, _NSStringFromClass@GOTPAGE
    ldr_nsstr_idx = len(instructions)
    instructions.append(0)  # ldr  x16, [x16, #pageoff]
    instructions.append(encode_mov_reg(X0, X21))  # mov x0, x21 (Class arg)
    instructions.append(encode_blr(X16))  # blr  x16
    # x0 now holds NSString* class name; fall through to call_uiapp with x0 = name
    b_idx = len(instructions)
    instructions.append(0)  # b call_uiapp

    # use_nil:
    use_nil_idx = len(instructions)
    instructions.append(encode_mov_imm(X0, 0))  # mov x0, #0 (nil delegate name)

    # call_uiapp:
    call_uiapp_idx = len(instructions)
    instructions.append(encode_mov_reg(X3, X0))  # mov x3, x0 (delegate class name or nil)
    instructions.append(encode_mov_reg(X0, X19))  # mov x0, x19 (argc)
    instructions.append(encode_mov_reg(X1, X20))  # mov x1, x20 (argv)
    instructions.append(encode_mov_imm(X2, 0))  # mov x2, #0 (principalClass = nil)
    adrp_uiapp_idx = len(instructions)
    instructions.append(0)  # adrp x16, _UIApplicationMain@GOTPAGE
    ldr_uiapp_idx = len(instructions)
    instructions.append(0)  # ldr  x16, [x16, #pageoff]
    instructions.append(encode_blr(X16))  # blr  x16 (UIApplicationMain)

    # Epilogue
    instructions.append(encode_ldp_signed(X21, X22, SP, 32))
    instructions.append(encode_ldp_signed(X19, X20, SP, 16))
    instructions.append(encode_ldp_post(X29, X30, SP, 64))
    instructions.append(encode_ret())

    # ── String data layout ──
    code_size = len(instructions) * 4
    str_offsets = {}
    string_data = bytearray()
    str_offsets["delegate"] = code_size + len(string_data)
    string_data += str_delegate

    # ── Fix up GOT-relative ADRP+LDR pairs ──
    # ADRP loads the page-base of the target GOT slot.
    # LDR loads the 64-bit pointer at slot.
    def emit_got_adrp_ldr(adrp_idx, ldr_idx, got_vmaddr):
        adrp_vmaddr = entry_vmaddr + adrp_idx * 4
        adrp_page = adrp_vmaddr & ~0xFFF
        target_page = got_vmaddr & ~0xFFF
        page_offset = target_page - adrp_page
        page_lo = got_vmaddr & 0xFFF
        instructions[adrp_idx] = encode_adrp(X16, page_offset)
        instructions[ldr_idx] = encode_ldr_imm_unsigned(X16, X16, page_lo)

    emit_got_adrp_ldr(adrp_objc_idx, ldr_objc_idx, got_objc_getClass)
    emit_got_adrp_ldr(adrp_nsstr_idx, ldr_nsstr_idx, got_NSStringFromClass)
    emit_got_adrp_ldr(adrp_uiapp_idx, ldr_uiapp_idx, got_UIApplicationMain)

    # ── ADR for delegate-class string (PC-relative within shellcode) ──
    instructions[adr_delegate_idx] = encode_adr(X0, str_offsets["delegate"] - adr_delegate_idx * 4)

    # ── CBZ + B fixups ──
    instructions[cbz_idx] = encode_cbz(X0, (use_nil_idx - cbz_idx) * 4)
    instructions[b_idx] = encode_b((call_uiapp_idx - b_idx) * 4)

    # ── Assemble the complete code block ──
    code_bytes = bytearray()
    for instr in instructions:
        code_bytes += struct.pack("<I", instr)
    code_bytes += string_data

    print(
        f"\n  Shellcode: {len(code_bytes)} bytes "
        f"({len(instructions)} instructions + {len(string_data)} string bytes)"
    )

    # ── Build the replacement region ──
    nop = struct.pack("<I", encode_nop())
    ret = struct.pack("<I", encode_ret())
    brk = struct.pack("<I", encode_brk(1))

    # Strategy B: fill with RETs so other functions in the crypt region
    # return harmlessly when called by the rest of the binary.
    # Strategy A: fill with BRKs to trap unexpected execution.
    fill = ret if bootstrap else brk
    fill_label = "RET" if bootstrap else "BRK"

    region = bytearray()
    # NOP sled before the entry point
    while len(region) < entry_in_crypt:
        region += nop
    # Main function code
    region += code_bytes
    # Padding after (RET for Strategy B, BRK for Strategy A)
    while len(region) < cryptsize:
        region += fill

    region = region[:cryptsize]

    strategy = "B (bootstrap — RETs for other functions)" if bootstrap else "A (shellcode only)"
    print(f"\n  Strategy: {strategy}")
    print(f"  Region layout ({cryptsize} bytes):")
    print(f"    NOPs:  0x000 - 0x{entry_in_crypt - 1:03x}")
    print(f"    main:  0x{entry_in_crypt:03x} - 0x{entry_in_crypt + len(code_bytes) - 1:03x}")
    print(f"    {fill_label}:   0x{entry_in_crypt + len(code_bytes):03x} - 0x{cryptsize - 1:03x}")

    # ── Patch the binary ──
    if output_path is None:
        output_path = binary_path

    # Replace the encrypted region
    data[cryptoff : cryptoff + cryptsize] = region

    with Path(output_path).open("wb") as f:
        f.write(data)

    print(f"\n  Patched region written at file offset 0x{cryptoff:x}")
    print(f"  Output: {output_path}")

    # ── Verify with disassembly ──
    print("\n  Disassembly of replacement main():")
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(bytes(code_bytes[: len(instructions) * 4]))
        tmp_path = tmp.name

    try:
        # Try xcrun llvm-objdump, then llvm-objdump, then hex fallback
        disasm_ok = False
        for cmd in [["xcrun", "llvm-objdump"], ["llvm-objdump"]]:
            try:
                result = subprocess.run(
                    [*cmd, "-d", "--triple=aarch64", "-b", "binary", tmp_path],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if (
                            line.strip()
                            and not line.startswith("Disassembly")
                            and not line.startswith(tmp_path)
                        ):
                            print(f"    {line}")
                    disasm_ok = True
                    break
            except FileNotFoundError:
                continue

        if not disasm_ok:
            for i in range(0, len(instructions) * 4, 4):
                word = struct.unpack_from("<I", code_bytes, i)[0]
                print(f"    0x{i:04x}: {word:08x}")
    finally:
        Path(tmp_path).unlink()

    return True


# ── AppDelegate auto-detection ──────────────────────────────────────


def detect_delegate(binary_path, app_path=None, force_cryptoff=None, force_cryptsize=None):
    """
    Auto-detect AppDelegate class name from an iOS binary.

    Returns (class_name, method, confidence) or (None, reason, None).

    force_cryptoff/force_cryptsize override the on-disk LC_ENCRYPTION_INFO_64
    fields. Required when the caller has already zeroed cryptid on disk (e.g.
    Strategy A's main-binary cryptid=0 fix) but still needs the tier-5
    classlist scanner to recognize the original encrypted region.
    """
    import re

    # Determine module name
    module_name = None
    if app_path:
        plist = Path(app_path) / "Info.plist"
        if plist.is_file():
            with contextlib.suppress(Exception):
                result = subprocess.run(
                    ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleExecutable", plist],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    module_name = result.stdout.strip()
    if not module_name:
        module_name = Path(binary_path).name

    # Get strings from binary
    try:
        result = subprocess.run(
            ["strings", binary_path], capture_output=True, text=True, check=False
        )
        all_strings = result.stdout.split("\n")
    except Exception:
        all_strings = []

    # Strategy 1: Swift mangled name matching module exactly
    expected = f"_TtC{len(module_name)}{module_name}11AppDelegate"
    for s in all_strings:
        if s.strip() == expected:
            return (expected, "Swift mangled (exact module match)", "high")

    # Strategy 1b: Module match with variant delegate name
    swift_module_re = re.compile(
        rf"^_TtC{len(module_name)}{re.escape(module_name)}\d+\w*AppDelegate\w*$"
    )
    for raw in all_strings:
        s = raw.strip()
        if swift_module_re.match(s):
            return (s, "Swift mangled (module match, variant)", "high")

    # Strategy 2: Any Swift mangled AppDelegate (filter SDK modules)
    swift_any_re = re.compile(r"^_TtC(\d+)(\w+?)(\d+)(.*AppDelegate.*)$")
    sdk_modules = {
        "GoogleUtilities",
        "Firebase",
        "AirshipCore",
        "AirshipAutomation",
        "Pulse",
        "PulseUI",
        "FBSDKCoreKit",
        "Branch",
        "Adjust",
        "AppsFlyerLib",
        "Singular",
        "Kochava",
        "MoEngage",
        "CleverTap",
        "OneSignal",
        "Braze",
        "Leanplum",
    }
    candidates = []
    for raw in all_strings:
        s = raw.strip()
        m = swift_any_re.match(s)
        if m:
            mod_name = m.group(2)
            if mod_name not in sdk_modules:
                candidates.append((s, mod_name))

    if len(candidates) == 1:
        return (candidates[0][0], f"Swift mangled (module: {candidates[0][1]})", "high")
    elif len(candidates) > 1:
        best = max(
            candidates,
            key=lambda c: sum(
                a == b for a, b in zip(c[1].lower(), module_name.lower(), strict=False)
            ),
        )
        return (best[0], f"Swift mangled (best of {len(candidates)} candidates)", "medium")

    # Strategy 3: ObjC-style AppDelegate
    objc_re = re.compile(r"^[A-Z][A-Za-z0-9]*AppDelegate$")
    objc_candidates = []
    for raw in all_strings:
        s = raw.strip()
        if objc_re.match(s) and len(s) < 60 and s != "GULAppDelegateSwizzler":
            objc_candidates.append(s)
    objc_candidates = list(dict.fromkeys(objc_candidates))

    for c in objc_candidates:
        if c == "AppDelegate":
            return (c, "ObjC class name (plain AppDelegate)", "high")
    if len(objc_candidates) == 1:
        return (objc_candidates[0], "ObjC class name (single match)", "medium")
    elif objc_candidates:
        return (objc_candidates[0], f"ObjC class name (first of {len(objc_candidates)})", "low")

    # Strategy 4: SwiftUI @main (no AppDelegate)
    has_swiftui = any("$s7SwiftUI3AppP" in s for s in all_strings)
    if has_swiftui:
        return (None, "SwiftUI @main app — no AppDelegate, needs alternative entry", None)

    # Strategy 5: __objc_classlist walk (Round 5 promotion).
    # When tiers 1-4 found nothing, the symbol table and __cstring/__objc_classname
    # are likely inside the FairPlay-encrypted region (iOS-channel IPAs).
    # Walk __DATA_CONST,__objc_classlist (unencrypted) and read class names whose
    # bytes happen to live OUTSIDE the crypt range. Mirrors the tier 6 logic in
    # detect-delegate.py — kept inline so make-main-patch.py stays self-contained.
    classlist_match, n_classes, names_in_crypt = _classlist_appdelegate_scan(
        binary_path,
        force_cryptoff=force_cryptoff,
        force_cryptsize=force_cryptsize,
    )
    if classlist_match:
        return (
            classlist_match,
            f"__objc_classlist walk ({n_classes} classes, {names_in_crypt} names in crypt)",
            "medium",
        )

    # All-names-in-crypt: fall back to convention. The shellcode's cbz check
    # already tolerates objc_getClass returning nil — UIApplicationMain with
    # nil delegate-class then asks UIKit to find the @main delegate via Info.plist
    # (UISceneDelegateClassName, NSPrincipalClass, or auto-detection). See
    # agent-memory/exploit-engineer/strategy_a_delegate_uncertainty.md.
    if n_classes > 0 and names_in_crypt == n_classes:
        guess = f"_TtC{len(module_name)}{module_name}11AppDelegate"
        reason = (
            f"convention guess (all {n_classes} class names in crypt; "
            "relies on cbz-to-nil fallback)"
        )
        return (guess, reason, "low")

    return (None, "No AppDelegate detected — manual --delegate required", None)


# ── __objc_classlist walk helpers (Round 5) ───────────────────────────
#
# Inline copy of detect-delegate.py's tier 6 helpers. Self-contained so
# make-main-patch.py keeps having no extra imports beyond stdlib + system
# tools. Only the AppDelegate-pattern scan is exposed.

_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_LC_ENCRYPTION_INFO_64 = 0x2C
_CLASS_RO_NAME_OFFSET = 0x18
_CLASS_T_BITS_OFFSET = 0x20

_CLASSLIST_BLOCKLIST = {
    "GULAppDelegateSwizzler",
    "FIRAppDelegateProxy",
    "FBSDKApplicationDelegate",
    "BNCAppDelegate",
    "AppsFlyerDelegate",
}


def _classlist_parse_macho(data):
    import struct as _s

    if len(data) < 32:
        raise ValueError("not a 64-bit Mach-O")
    if _s.unpack_from("<I", data, 0)[0] != _MH_MAGIC_64:
        raise ValueError("bad magic")
    ncmds = _s.unpack_from("<I", data, 16)[0]
    off = 32
    segments, sections, crypt = [], {}, None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, sz = _s.unpack_from("<II", data, off)
        if sz == 0:
            break
        if cmd == _LC_SEGMENT_64 and off + 72 <= len(data):
            segname = data[off + 8 : off + 24].split(b"\x00")[0].decode(errors="replace")
            vmaddr = _s.unpack_from("<Q", data, off + 24)[0]
            vmsize = _s.unpack_from("<Q", data, off + 32)[0]
            fileoff = _s.unpack_from("<Q", data, off + 40)[0]
            filesize = _s.unpack_from("<Q", data, off + 48)[0]
            nsects = _s.unpack_from("<I", data, off + 64)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            sec_off = off + 72
            for _i in range(nsects):
                if sec_off + 80 > len(data):
                    break
                sectname = data[sec_off : sec_off + 16].split(b"\x00")[0].decode(errors="replace")
                addr = _s.unpack_from("<Q", data, sec_off + 32)[0]
                size = _s.unpack_from("<Q", data, sec_off + 40)[0]
                sec_fileoff = _s.unpack_from("<I", data, sec_off + 48)[0]
                sections[(segname, sectname)] = (addr, size, sec_fileoff)
                sec_off += 80
        elif cmd == _LC_ENCRYPTION_INFO_64 and off + 20 <= len(data):
            crypt = (
                _s.unpack_from("<I", data, off + 8)[0],
                _s.unpack_from("<I", data, off + 12)[0],
                _s.unpack_from("<I", data, off + 16)[0],
            )
        off += sz
    return segments, sections, crypt


def _classlist_vm_to_file(va, segments):
    for segname, vmaddr, vmsize, fo, _fs in segments:
        if vmsize > 0 and vmaddr <= va < vmaddr + vmsize and segname != "__PAGEZERO":
            return fo + (va - vmaddr)
    return None


def _classlist_decode_ptr(p):
    return (p & 0xFFFFFFFFF, (p >> 36) & 0xFF, (p >> 51) & 0xFFF, (p >> 63) & 1)


def _classlist_appdelegate_scan(binary_path, force_cryptoff=None, force_cryptsize=None):
    """Return (best_match_or_None, total_classes, names_in_crypt).

    Only ObjC/Swift class names matching AppDelegate patterns are returned.
    Names whose bytes land inside the encrypted region are skipped.

    force_cryptoff/force_cryptsize override the on-disk LC_ENCRYPTION_INFO_64
    fields. Use when cryptid has been zeroed on disk but the bytes are still
    ciphertext (Strategy A main-binary fix).
    """
    import re as _re
    import struct as _s

    swift_re = _re.compile(r"^_TtC\d+\w+?\d+\w*AppDelegate\w*$")
    objc_re = _re.compile(r"^[A-Z][A-Za-z0-9_]*AppDelegate[A-Za-z0-9_]*$")

    try:
        with Path(binary_path).open("rb") as f:
            data = f.read()
    except OSError:
        return (None, 0, 0)

    try:
        segments, sections, crypt = _classlist_parse_macho(data)
    except ValueError:
        return (None, 0, 0)

    classlist = sections.get(("__DATA_CONST", "__objc_classlist")) or sections.get(
        ("__DATA", "__objc_classlist")
    )
    if classlist is None:
        return (None, 0, 0)
    _addr, size, fileoff = classlist
    if size == 0 or fileoff == 0:
        return (None, 0, 0)

    load_addr = next((s[1] for s in segments if s[0] == "__TEXT"), 0x100000000)
    cryptoff, cryptsize, cryptid = crypt or (0, 0, 0)
    if force_cryptoff is not None:
        cryptoff = force_cryptoff
    if force_cryptsize is not None:
        cryptsize = force_cryptsize
    crypt_lo, crypt_hi = cryptoff, cryptoff + cryptsize
    # When the caller forced a crypt range (Strategy A main-binary fix),
    # treat it as active even if cryptid is now 0 on disk — the bytes there
    # are still ciphertext until the kernel page-in handler decrypts them.
    crypt_active = cryptsize > 0 and (cryptid != 0 or force_cryptsize is not None)

    n_classes = size // 8
    matches = []
    seen = set()
    names_in_crypt = 0

    def _follow(file_off):
        if file_off + 8 > len(data):
            return None
        v = _s.unpack_from("<Q", data, file_off)[0]
        if v == 0:
            return None
        target, _, _, bind = _classlist_decode_ptr(v)
        if bind:
            return None
        return _classlist_vm_to_file(load_addr + target, segments)

    for i in range(n_classes):
        cls_file = _follow(fileoff + i * 8)
        if cls_file is None:
            continue
        bits_off = cls_file + _CLASS_T_BITS_OFFSET
        if bits_off + 8 > len(data):
            continue
        bits = _s.unpack_from("<Q", data, bits_off)[0]
        if bits == 0:
            continue
        bt, _, _, bind = _classlist_decode_ptr(bits)
        if bind:
            continue
        ro_file = _classlist_vm_to_file(load_addr + (bt & ~0x7), segments)
        if ro_file is None:
            continue
        name_field = ro_file + _CLASS_RO_NAME_OFFSET
        if name_field + 8 > len(data):
            continue
        nv = _s.unpack_from("<Q", data, name_field)[0]
        if nv == 0:
            continue
        nt, _, _, nbind = _classlist_decode_ptr(nv)
        if nbind:
            continue
        name_file = _classlist_vm_to_file(load_addr + nt, segments)
        if name_file is None:
            continue
        if crypt_active and crypt_lo <= name_file < crypt_hi:
            names_in_crypt += 1
            continue
        # Read C string.
        if name_file >= len(data):
            continue
        end = data.find(b"\x00", name_file)
        if end == -1 or end - name_file > 200 or end == name_file:
            continue
        try:
            s = data[name_file:end].decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s in seen or s in _CLASSLIST_BLOCKLIST:
            continue
        seen.add(s)
        if swift_re.match(s):
            matches.append((s, 2))
        elif objc_re.match(s) and len(s) < 60:
            matches.append((s, 1))

    if not matches:
        return (None, n_classes, names_in_crypt)
    matches.sort(key=lambda x: (x[1], -len(x[0])), reverse=True)
    return (matches[0][0], n_classes, names_in_crypt)


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Patch encrypted main() region in iOS binary")
    parser.add_argument("binary", help="Path to the Mach-O binary")
    parser.add_argument("--delegate", help="AppDelegate class name (auto-detected if omitted)")
    parser.add_argument("--app", help="Path to .app bundle (for auto-detection)")
    parser.add_argument("--output", "-o", help="Output path (default: overwrite input)")
    parser.add_argument(
        "--cryptoff", type=lambda x: int(x, 0), help="Override cryptoff (hex or decimal)"
    )
    parser.add_argument(
        "--cryptsize", type=lambda x: int(x, 0), help="Override cryptsize (hex or decimal)"
    )
    parser.add_argument(
        "--detect-only", action="store_true", help="Only detect delegate class, do not patch"
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Strategy B: fill crypt region with RETs (not BRKs) for multi-function crypt regions",
    )

    args = parser.parse_args()

    if not Path(args.binary).is_file():
        print(f"Not a file: {args.binary}")
        sys.exit(1)

    # Auto-detect .app path if not provided
    app_path = args.app
    if not app_path:
        path = str(Path(args.binary).resolve().parent)
        while path and path != "/":
            if path.endswith(".app"):
                app_path = path
                break
            path = str(Path(path).parent)

    # Resolve delegate class
    delegate = args.delegate
    if not delegate:
        print("Auto-detecting AppDelegate...")
        class_name, method, confidence = detect_delegate(
            args.binary,
            app_path,
            force_cryptoff=args.cryptoff,
            force_cryptsize=args.cryptsize,
        )
        if class_name:
            print(f"  Detected: {class_name}")
            print(f"  Method:   {method}")
            print(f"  Confidence: {confidence}")
            delegate = class_name
        else:
            print(f"  Detection failed: {method}")
            print("  Use --delegate to specify manually")
            sys.exit(1)

    if args.detect_only:
        sys.exit(0)

    success = generate_main_patch(
        args.binary,
        delegate,
        args.output,
        force_cryptoff=args.cryptoff,
        force_cryptsize=args.cryptsize,
        bootstrap=args.bootstrap,
    )
    sys.exit(0 if success else 1)
