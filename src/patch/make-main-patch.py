#!/usr/bin/env python3
"""
Generate a replacement main() for an iOS app whose entry point
falls inside a FairPlay-encrypted region.

Strategy:
  - Write ARM64 shellcode that calls dlsym(RTLD_DEFAULT, ...) to
    resolve UIApplicationMain, objc_getClass, NSStringFromClass
  - Use BL to the target binary's existing dlsym stub (the only
    external call needed — everything else is via BLR to resolved ptrs)
  - ADR instructions reference string constants embedded in the same
    code block (PC-relative, position-independent)
  - Patch the shellcode into the binary at the encrypted region offset

The result: the encrypted 4KB region is replaced with a working main()
that boots the app through the standard UIApplicationMain path.
"""
import struct
import sys
import os
import subprocess
import tempfile


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


# ── Binary analysis helpers ──────────────────────────────────────────

def find_load_commands(data, base=0):
    """Parse Mach-O load commands, return dict of key values."""
    magic = struct.unpack_from('<I', data, base)[0]
    if magic != 0xFEEDFACF:
        return None

    ncmds = struct.unpack_from('<I', data, base + 16)[0]
    offset = base + 32  # past mach_header_64

    info = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)

        if cmd == 0x80000028:  # LC_MAIN
            info['entryoff'] = struct.unpack_from('<Q', data, offset + 8)[0]

        elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            info['cryptoff'] = struct.unpack_from('<I', data, offset + 8)[0]
            info['cryptsize'] = struct.unpack_from('<I', data, offset + 12)[0]
            info['cryptid'] = struct.unpack_from('<I', data, offset + 16)[0]

        offset += cmdsize

    return info


def find_stub_address(binary_path, symbol_name):
    """Find the __stubs entry address for a given symbol using otool -Iv."""
    out = subprocess.check_output(
        ['otool', '-Iv', binary_path], text=True
    )

    # Get __stubs address range from load commands
    lc_out = subprocess.check_output(
        ['otool', '-l', binary_path], text=True
    )
    stubs_addr = None
    stubs_size = None
    lines = lc_out.split('\n')
    for i, line in enumerate(lines):
        if '__stubs' in line and 'sectname' in line:
            for j in range(i, min(i + 10, len(lines))):
                if 'addr' in lines[j] and 'sectname' not in lines[j]:
                    stubs_addr = int(lines[j].split()[-1], 16)
                if 'size' in lines[j] and 'sectname' not in lines[j]:
                    val = lines[j].split()[-1]
                    stubs_size = int(val, 16) if val.startswith('0x') else int(val)
            break

    if stubs_addr is None:
        return None

    stubs_end = stubs_addr + stubs_size

    # Find symbol in indirect symbol table within __stubs range
    for line in out.split('\n'):
        if symbol_name in line:
            parts = line.split()
            if parts:
                addr = int(parts[0], 16)
                if stubs_addr <= addr < stubs_end:
                    return addr

    return None


# ── Main patch generation ────────────────────────────────────────────

def generate_main_patch(binary_path, delegate_class, output_path=None,
                        force_cryptoff=None, force_cryptsize=None,
                        bootstrap=False):
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

    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())

    info = find_load_commands(data)
    if not info:
        print("ERROR: Could not parse Mach-O")
        return False

    entryoff = info.get('entryoff')
    cryptoff = force_cryptoff if force_cryptoff is not None else info.get('cryptoff')
    cryptsize = force_cryptsize if force_cryptsize is not None else info.get('cryptsize')

    if entryoff is None:
        print("ERROR: Missing LC_MAIN")
        return False
    if cryptoff is None or cryptoff == 0 or cryptsize is None or cryptsize == 0:
        if force_cryptoff is None:
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

    # Find dlsym stub in the binary
    dlsym_stub = find_stub_address(binary_path, '_dlsym')
    if dlsym_stub is None:
        print("ERROR: Could not find _dlsym stub in binary")
        return False
    print(f"  dlsym stub:     0x{dlsym_stub:x}")

    # ── Build the replacement main() shellcode ───────────────────────

    # String constants (will be appended after code)
    str_objc_getClass = b"objc_getClass\x00"
    str_NSStringFromClass = b"NSStringFromClass\x00"
    str_UIApplicationMain = b"UIApplicationMain\x00"
    str_delegate = delegate_class.encode('ascii') + b"\x00"

    # Register assignments:
    #   x19 = argc (saved)
    #   x20 = argv (saved)
    #   x21 = resolved objc_getClass ptr
    #   x22 = resolved NSStringFromClass ptr
    #   x23 = resolved UIApplicationMain ptr

    SP = 31
    X0, X1, X2, X3 = 0, 1, 2, 3
    X19, X20, X21, X22, X23, X24 = 19, 20, 21, 22, 23, 24
    X29, X30 = 29, 30

    instructions = []

    # Prologue: save frame pointer, link register, and callee-saved regs
    instructions.append(encode_stp_pre(X29, X30, SP, -80))   # stp x29, x30, [sp, #-80]!
    instructions.append(encode_add_imm(X29, SP, 0))           # mov x29, sp (ADD x29, sp, #0)
    instructions.append(encode_stp_signed(X19, X20, SP, 16))  # stp x19, x20, [sp, #16]
    instructions.append(encode_stp_signed(X21, X22, SP, 32))  # stp x21, x22, [sp, #32]
    instructions.append(encode_stp_signed(X23, X24, SP, 48))  # stp x23, x24, [sp, #48]

    # Save argc, argv
    instructions.append(encode_mov_reg(X19, X0))               # mov x19, x0 (argc)
    instructions.append(encode_mov_reg(X20, X1))               # mov x20, x1 (argv)

    # ── dlsym(RTLD_DEFAULT, "objc_getClass") ──
    instructions.append(encode_movn(X0, 1))                    # movn x0, #1 -> x0 = -2 = RTLD_DEFAULT
    adr_objc_idx = len(instructions)
    instructions.append(0)  # placeholder: adr x1, str_objc_getClass
    bl_1_idx = len(instructions)
    instructions.append(0)  # placeholder: bl dlsym_stub
    instructions.append(encode_mov_reg(X21, X0))               # mov x21, x0

    # ── dlsym(RTLD_DEFAULT, "NSStringFromClass") ──
    instructions.append(encode_movn(X0, 1))                    # movn x0, #1
    adr_nsstr_idx = len(instructions)
    instructions.append(0)  # placeholder: adr x1, str_NSStringFromClass
    bl_2_idx = len(instructions)
    instructions.append(0)  # placeholder: bl dlsym_stub
    instructions.append(encode_mov_reg(X22, X0))               # mov x22, x0

    # ── dlsym(RTLD_DEFAULT, "UIApplicationMain") ──
    instructions.append(encode_movn(X0, 1))                    # movn x0, #1
    adr_uiapp_idx = len(instructions)
    instructions.append(0)  # placeholder: adr x1, str_UIApplicationMain
    bl_3_idx = len(instructions)
    instructions.append(0)  # placeholder: bl dlsym_stub
    instructions.append(encode_mov_reg(X23, X0))               # mov x23, x0

    # ── objc_getClass(delegate_class) ──
    adr_delegate_idx = len(instructions)
    instructions.append(0)  # placeholder: adr x0, str_delegate
    instructions.append(encode_blr(X21))                       # blr x21 (objc_getClass)

    # Check if class was found
    cbz_idx = len(instructions)
    instructions.append(0)  # placeholder: cbz x0, use_nil

    # ── NSStringFromClass(cls) ──
    instructions.append(encode_blr(X22))                       # blr x22 (NSStringFromClass)
    b_idx = len(instructions)
    instructions.append(0)  # placeholder: b call_uiapp

    # use_nil:
    use_nil_idx = len(instructions)
    instructions.append(encode_mov_imm(X0, 0))                 # mov x0, #0

    # call_uiapp:
    call_uiapp_idx = len(instructions)
    instructions.append(encode_mov_reg(X3, X0))                # mov x3, x0 (clsName)
    instructions.append(encode_mov_reg(X0, X19))               # mov x0, x19 (argc)
    instructions.append(encode_mov_reg(X1, X20))               # mov x1, x20 (argv)
    instructions.append(encode_mov_imm(X2, 0))                 # mov x2, #0 (nil)
    instructions.append(encode_blr(X23))                       # blr x23 (UIApplicationMain)

    # Epilogue
    instructions.append(encode_ldp_signed(X23, X24, SP, 48))  # ldp x23, x24, [sp, #48]
    instructions.append(encode_ldp_signed(X21, X22, SP, 32))  # ldp x21, x22, [sp, #32]
    instructions.append(encode_ldp_signed(X19, X20, SP, 16))  # ldp x19, x20, [sp, #16]
    instructions.append(encode_ldp_post(X29, X30, SP, 80))    # ldp x29, x30, [sp], #80
    instructions.append(encode_ret())                           # ret

    # ── String data layout ──
    code_size = len(instructions) * 4
    str_offsets = {}

    string_data = bytearray()
    str_offsets['objc_getClass'] = code_size + len(string_data)
    string_data += str_objc_getClass

    str_offsets['NSStringFromClass'] = code_size + len(string_data)
    string_data += str_NSStringFromClass

    str_offsets['UIApplicationMain'] = code_size + len(string_data)
    string_data += str_UIApplicationMain

    str_offsets['delegate'] = code_size + len(string_data)
    string_data += str_delegate

    # ── Fix up ADR instructions ──
    # ADR offset = string_byte_offset - instruction_byte_offset
    instructions[adr_objc_idx] = encode_adr(
        X1, str_offsets['objc_getClass'] - adr_objc_idx * 4)
    instructions[adr_nsstr_idx] = encode_adr(
        X1, str_offsets['NSStringFromClass'] - adr_nsstr_idx * 4)
    instructions[adr_uiapp_idx] = encode_adr(
        X1, str_offsets['UIApplicationMain'] - adr_uiapp_idx * 4)
    instructions[adr_delegate_idx] = encode_adr(
        X0, str_offsets['delegate'] - adr_delegate_idx * 4)

    # ── Fix up BL instructions to dlsym stub ──
    # BL offset = dlsym_vmaddr - instruction_vmaddr
    for bl_idx in [bl_1_idx, bl_2_idx, bl_3_idx]:
        instr_vmaddr = entry_vmaddr + bl_idx * 4
        bl_offset = dlsym_stub - instr_vmaddr
        instructions[bl_idx] = encode_bl(bl_offset)

    # ── Fix up CBZ and B ──
    instructions[cbz_idx] = encode_cbz(
        X0, (use_nil_idx - cbz_idx) * 4)
    instructions[b_idx] = encode_b(
        (call_uiapp_idx - b_idx) * 4)

    # ── Assemble the complete code block ──
    code_bytes = bytearray()
    for instr in instructions:
        code_bytes += struct.pack('<I', instr)
    code_bytes += string_data

    print(f"\n  Shellcode: {len(code_bytes)} bytes ({len(instructions)} instructions + {len(string_data)} string bytes)")

    # ── Build the replacement region ──
    nop = struct.pack('<I', encode_nop())
    ret = struct.pack('<I', encode_ret())
    brk = struct.pack('<I', encode_brk(1))

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
    data[cryptoff:cryptoff + cryptsize] = region

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"\n  Patched region written at file offset 0x{cryptoff:x}")
    print(f"  Output: {output_path}")

    # ── Verify with disassembly ──
    print("\n  Disassembly of replacement main():")
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(bytes(code_bytes[:len(instructions) * 4]))
        tmp_path = tmp.name

    try:
        # Try xcrun llvm-objdump, then llvm-objdump, then hex fallback
        disasm_ok = False
        for cmd in [['xcrun', 'llvm-objdump'], ['llvm-objdump']]:
            try:
                result = subprocess.run(
                    cmd + ['-d', '--triple=aarch64', '-b', 'binary', tmp_path],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip() and not line.startswith('Disassembly') and not line.startswith(tmp_path):
                            print(f"    {line}")
                    disasm_ok = True
                    break
            except FileNotFoundError:
                continue

        if not disasm_ok:
            for i in range(0, len(instructions) * 4, 4):
                word = struct.unpack_from('<I', code_bytes, i)[0]
                print(f"    0x{i:04x}: {word:08x}")
    finally:
        os.unlink(tmp_path)

    return True


# ── AppDelegate auto-detection ──────────────────────────────────────

def detect_delegate(binary_path, app_path=None):
    """
    Auto-detect AppDelegate class name from an iOS binary.

    Returns (class_name, method, confidence) or (None, reason, None).
    """
    import re

    # Determine module name
    module_name = None
    if app_path:
        plist = os.path.join(app_path, "Info.plist")
        if os.path.isfile(plist):
            try:
                result = subprocess.run(
                    ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleExecutable", plist],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    module_name = result.stdout.strip()
            except Exception:
                pass
    if not module_name:
        module_name = os.path.basename(binary_path)

    # Get strings from binary
    try:
        result = subprocess.run(["strings", binary_path], capture_output=True, text=True)
        all_strings = result.stdout.split('\n')
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
    for s in all_strings:
        s = s.strip()
        if swift_module_re.match(s):
            return (s, "Swift mangled (module match, variant)", "high")

    # Strategy 2: Any Swift mangled AppDelegate (filter SDK modules)
    swift_any_re = re.compile(r"^_TtC(\d+)(\w+?)(\d+)(.*AppDelegate.*)$")
    sdk_modules = {
        'GoogleUtilities', 'Firebase', 'AirshipCore', 'AirshipAutomation',
        'Pulse', 'PulseUI', 'FBSDKCoreKit', 'Branch', 'Adjust',
        'AppsFlyerLib', 'Singular', 'Kochava', 'MoEngage',
        'CleverTap', 'OneSignal', 'Braze', 'Leanplum'
    }
    candidates = []
    for s in all_strings:
        s = s.strip()
        m = swift_any_re.match(s)
        if m:
            mod_name = m.group(2)
            if mod_name not in sdk_modules:
                candidates.append((s, mod_name))

    if len(candidates) == 1:
        return (candidates[0][0], f"Swift mangled (module: {candidates[0][1]})", "high")
    elif len(candidates) > 1:
        best = max(candidates, key=lambda c: sum(
            a == b for a, b in zip(c[1].lower(), module_name.lower())
        ))
        return (best[0], f"Swift mangled (best of {len(candidates)} candidates)", "medium")

    # Strategy 3: ObjC-style AppDelegate
    objc_re = re.compile(r"^[A-Z][A-Za-z0-9]*AppDelegate$")
    objc_candidates = []
    for s in all_strings:
        s = s.strip()
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

    return (None, "No AppDelegate detected — manual --delegate required", None)


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Patch encrypted main() region in iOS binary')
    parser.add_argument('binary', help='Path to the Mach-O binary')
    parser.add_argument('--delegate',
                        help='AppDelegate class name (auto-detected if omitted)')
    parser.add_argument('--app', help='Path to .app bundle (for auto-detection)')
    parser.add_argument('--output', '-o', help='Output path (default: overwrite input)')
    parser.add_argument('--cryptoff', type=lambda x: int(x, 0),
                        help='Override cryptoff (hex or decimal)')
    parser.add_argument('--cryptsize', type=lambda x: int(x, 0),
                        help='Override cryptsize (hex or decimal)')
    parser.add_argument('--detect-only', action='store_true',
                        help='Only detect delegate class, do not patch')
    parser.add_argument('--bootstrap', action='store_true',
                        help='Strategy B: fill crypt region with RETs (not BRKs) for multi-function crypt regions')

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Not a file: {args.binary}")
        sys.exit(1)

    # Auto-detect .app path if not provided
    app_path = args.app
    if not app_path:
        path = os.path.dirname(os.path.abspath(args.binary))
        while path and path != "/":
            if path.endswith(".app"):
                app_path = path
                break
            path = os.path.dirname(path)

    # Resolve delegate class
    delegate = args.delegate
    if not delegate:
        print("Auto-detecting AppDelegate...")
        class_name, method, confidence = detect_delegate(args.binary, app_path)
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
        args.binary, delegate, args.output,
        force_cryptoff=args.cryptoff, force_cryptsize=args.cryptsize,
        bootstrap=args.bootstrap
    )
    sys.exit(0 if success else 1)
