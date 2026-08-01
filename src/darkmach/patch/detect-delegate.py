#!/usr/bin/env python3
"""Auto-detect the AppDelegate class name from an iOS Mach-O binary, for
make-main-patch.py --delegate. The six detection tiers: `docs/patching.md`.
"""

import contextlib
import re
import struct
import subprocess
import sys
from pathlib import Path


def get_bundle_executable(app_path):
    """Get CFBundleExecutable from Info.plist."""
    plist = Path(app_path) / "Info.plist"
    if not plist.is_file():
        return None
    with contextlib.suppress(Exception):
        result = subprocess.run(
            ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleExecutable", plist],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    return None


def get_strings(binary_path):
    """Run strings on a binary, return as list."""
    try:
        result = subprocess.run(
            ["strings", binary_path], capture_output=True, text=True, check=False
        )
        return result.stdout.split("\n")
    except Exception:
        return []


def get_nm_symbols(binary_path):
    """Run nm on binary, return lines."""
    try:
        result = subprocess.run(["nm", binary_path], capture_output=True, text=True, check=False)
        return result.stdout.split("\n")
    except Exception:
        return []


# Reads class names straight off disk via chained fixups, because the symbol table
# cannot expose them when __cstring/__objc_classname is encrypted.
_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_LC_ENCRYPTION_INFO_64 = 0x2C
# class_ro_t layout offsets (from objc-runtime-new.h):
_CLASS_RO_NAME_OFFSET = 0x18
# class_t layout: { isa(8), super(8), cache(16), bits(8) }
_CLASS_T_BITS_OFFSET = 0x20

_CLASSLIST_OBJC_RE = re.compile(r"^[A-Z][A-Za-z0-9_]*AppDelegate[A-Za-z0-9_]*$")
_CLASSLIST_SWIFT_RE = re.compile(r"^_TtC\d+\w+?\d+\w*AppDelegate\w*$")
# Don't be fooled by SDK-supplied delegate-helper classes.
_CLASSLIST_BLOCKLIST = {
    "GULAppDelegateSwizzler",
    "FIRAppDelegateProxy",
    "FBSDKApplicationDelegate",
    "BNCAppDelegate",
    "AppsFlyerDelegate",
}


def _parse_macho(data):
    """Return (segments, sections, crypt); raises ValueError on bad magic."""
    if len(data) < 32:
        raise ValueError("not a 64-bit Mach-O (too short)")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != _MH_MAGIC_64:
        raise ValueError(f"not a 64-bit Mach-O (magic=0x{magic:08x})")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segments = []
    sections = {}
    crypt = None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, sz = struct.unpack_from("<II", data, off)
        if sz == 0:
            break
        if cmd == _LC_SEGMENT_64 and off + 72 <= len(data):
            segname = data[off + 8 : off + 24].split(b"\x00")[0].decode(errors="replace")
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            vmsize = struct.unpack_from("<Q", data, off + 32)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            sec_off = off + 72
            for _i in range(nsects):
                if sec_off + 80 > len(data):
                    break
                sectname = data[sec_off : sec_off + 16].split(b"\x00")[0].decode(errors="replace")
                addr = struct.unpack_from("<Q", data, sec_off + 32)[0]
                size = struct.unpack_from("<Q", data, sec_off + 40)[0]
                sec_fileoff = struct.unpack_from("<I", data, sec_off + 48)[0]
                sections[(segname, sectname)] = (addr, size, sec_fileoff)
                sec_off += 80
        elif cmd == _LC_ENCRYPTION_INFO_64 and off + 20 <= len(data):
            cryptoff = struct.unpack_from("<I", data, off + 8)[0]
            cryptsize = struct.unpack_from("<I", data, off + 12)[0]
            cryptid = struct.unpack_from("<I", data, off + 16)[0]
            crypt = (cryptoff, cryptsize, cryptid)
        off += sz
    return segments, sections, crypt


def _vm_to_file(vmaddr, segments):
    """Map a vmaddr to its on-disk file offset, skipping __PAGEZERO."""
    for segname, va, vs, fo, _fs in segments:
        if vs > 0 and va <= vmaddr < va + vs and segname != "__PAGEZERO":
            return fo + (vmaddr - va)
    return None


def _decode_chained_ptr64(p):
    """Decode a DYLD_CHAINED_PTR_64 word. Returns (target, high8, next, bind)."""
    target = p & 0xFFFFFFFFF
    high8 = (p >> 36) & 0xFF
    nxt = (p >> 51) & 0xFFF
    bind = (p >> 63) & 1
    return target, high8, nxt, bind


def _follow_chain_ptr(file_off, data, load_addr, segments):
    """Resolve the 8-byte chained pointer at file_off to a file offset, or None for a zero
    entry, an external bind, or an unresolvable target."""
    if file_off + 8 > len(data):
        return None
    v = struct.unpack_from("<Q", data, file_off)[0]
    if v == 0:
        return None
    target, _, _, bind = _decode_chained_ptr64(v)
    if bind:
        return None
    return _vm_to_file(load_addr + target, segments)


def _read_cstring(file_off, data, max_len=200):
    """Read a NUL-terminated C string. Returns the decoded string or None."""
    if file_off is None or file_off < 0 or file_off >= len(data):
        return None
    end = data.find(b"\x00", file_off)
    if end == -1:
        return None
    if end - file_off > max_len or end - file_off == 0:
        return None
    try:
        return data[file_off:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _walk_classlist_for_appdelegate(binary_path):
    """Tier 5: return ([(class_name, score)], total_classes, names_in_crypt) for AppDelegate
    classes resolving outside the crypt region. Score 2 is Swift-mangled, 1 is plain ObjC."""
    try:
        with Path(binary_path).open("rb") as f:
            data = f.read()
    except OSError:
        return ([], 0, 0)

    try:
        segments, sections, crypt = _parse_macho(data)
    except ValueError:
        return ([], 0, 0)

    classlist = sections.get(("__DATA_CONST", "__objc_classlist")) or sections.get(
        ("__DATA", "__objc_classlist")
    )
    if classlist is None:
        return ([], 0, 0)

    _cl_addr, cl_size, cl_fileoff = classlist
    if cl_size == 0 or cl_fileoff == 0:
        return ([], 0, 0)

    load_addr = next((s[1] for s in segments if s[0] == "__TEXT"), 0x100000000)

    cryptoff, cryptsize, cryptid = crypt or (0, 0, 0)
    crypt_lo, crypt_hi = cryptoff, cryptoff + cryptsize
    crypt_active = cryptid != 0 and cryptsize > 0

    matches = []
    seen_names = set()
    n_classes = cl_size // 8
    names_in_crypt = 0

    for i in range(n_classes):
        cls_file = _follow_chain_ptr(cl_fileoff + i * 8, data, load_addr, segments)
        if cls_file is None:
            continue
        # class_t.bits at +0x20 — pointer (low 3 bits are flags) to class_ro_t.
        bits_off = cls_file + _CLASS_T_BITS_OFFSET
        if bits_off + 8 > len(data):
            continue
        bits = struct.unpack_from("<Q", data, bits_off)[0]
        if bits == 0:
            continue
        bt, _, _, bind = _decode_chained_ptr64(bits)
        if bind:
            continue
        ro_vm = load_addr + (bt & ~0x7)  # mask the low 3 RW_REALIZED-style flag bits
        ro_file = _vm_to_file(ro_vm, segments)
        if ro_file is None:
            continue
        name_field = ro_file + _CLASS_RO_NAME_OFFSET
        if name_field + 8 > len(data):
            continue
        nv = struct.unpack_from("<Q", data, name_field)[0]
        if nv == 0:
            continue
        nt, _, _, nbind = _decode_chained_ptr64(nv)
        if nbind:
            continue
        name_file = _vm_to_file(load_addr + nt, segments)
        if name_file is None:
            continue
        # Skip names whose bytes live in the FairPlay region — reading them
        # yields garbage (or BRK fill after make-main-patch).
        if crypt_active and crypt_lo <= name_file < crypt_hi:
            names_in_crypt += 1
            continue
        s = _read_cstring(name_file, data)
        if s is None or s in seen_names:
            continue
        seen_names.add(s)
        if s in _CLASSLIST_BLOCKLIST:
            continue
        if _CLASSLIST_SWIFT_RE.match(s):
            matches.append((s, 2))
        elif _CLASSLIST_OBJC_RE.match(s) and len(s) < 60:
            matches.append((s, 1))

    return (matches, n_classes, names_in_crypt)


def detect_delegate(binary_path, app_path=None):
    """Detect the AppDelegate class name, returning (name, method, confidence), or
    (None, reason, None) when no delegate is found."""
    module_name = None
    if app_path:
        module_name = get_bundle_executable(app_path)
    if not module_name:
        module_name = Path(binary_path).name

    print(f"  Module name: {module_name}")

    all_strings = get_strings(binary_path)

    expected_swift = f"_TtC{len(module_name)}{module_name}11AppDelegate"
    for s in all_strings:
        if s.strip() == expected_swift:
            return (expected_swift, "Swift mangled (exact module match)", "high")

    swift_module_pattern = re.compile(
        rf"^_TtC{len(module_name)}{re.escape(module_name)}\d+\w*AppDelegate\w*$"
    )
    for raw in all_strings:
        s = raw.strip()
        if swift_module_pattern.match(s):
            return (s, "Swift mangled (module match, variant name)", "high")

    swift_any_pattern = re.compile(r"^_TtC(\d+)(\w+?)(\d+)(.*AppDelegate.*)$")
    candidates = []
    for raw in all_strings:
        s = raw.strip()
        m = swift_any_pattern.match(s)
        if m:
            _mod_len, mod_name, _cls_len, _cls_rest = m.groups()
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
            if mod_name not in sdk_modules:
                candidates.append((s, mod_name))

    if len(candidates) == 1:
        name, mod = candidates[0]
        return (name, f"Swift mangled (module: {mod})", "high")
    elif len(candidates) > 1:
        # Tiebreak: prefer the module name with the longest common prefix
        # against the binary name (case-insensitive).
        best = None
        best_score = -1
        for name, mod in candidates:
            score = 0
            for a, b in zip(mod.lower(), module_name.lower(), strict=False):
                if a == b:
                    score += 1
                else:
                    break
            if score > best_score:
                best_score = score
                best = name
        if best:
            return (best, f"Swift mangled (best match from {len(candidates)} candidates)", "medium")

    objc_pattern = re.compile(r"^[A-Z][A-Za-z0-9]*AppDelegate$")
    objc_candidates = []
    for raw in all_strings:
        s = raw.strip()
        if objc_pattern.match(s) and len(s) < 60 and s != "GULAppDelegateSwizzler":
            objc_candidates.append(s)

    objc_candidates = list(dict.fromkeys(objc_candidates))

    for c in objc_candidates:
        if c == "AppDelegate":
            return (c, "ObjC class name (plain AppDelegate)", "high")

    if len(objc_candidates) == 1:
        return (objc_candidates[0], "ObjC class name (single match)", "medium")
    elif len(objc_candidates) > 1:
        for c in objc_candidates:
            if c.startswith(module_name[:3]):
                return (
                    c,
                    f"ObjC class name (prefix match from {len(objc_candidates)} candidates)",
                    "medium",
                )
        return (
            objc_candidates[0],
            f"ObjC class name (first of {len(objc_candidates)} candidates)",
            "low",
        )

    nm_lines = get_nm_symbols(binary_path)
    for line in nm_lines:
        if "AppDelegate" in line and "_TtC" in line:
            parts = line.split()
            for p in parts:
                if p.startswith("_TtC") and "AppDelegate" in p:
                    return (p, "nm symbol table (Swift)", "high")

    for line in nm_lines:
        if "AppDelegate" in line:
            parts = line.split()
            for p in parts:
                if "AppDelegate" in p and not p.startswith("_OBJC"):
                    return (p, "nm symbol table", "medium")

    has_swiftui_app = False
    swiftui_main_symbol = None
    for raw in all_strings:
        s = raw.strip()
        if s == "$s7SwiftUI3AppP":
            has_swiftui_app = True
        # SwiftUI App.main() entry mangles as $s<N><Module><N><AppName>V5$mainyyFZ
        m = re.match(r"^\$s(\d+)(\w+?)(\d+)(\w+?)V5\$mainyyFZ$", s)
        if m:
            swiftui_main_symbol = s

    for line in nm_lines:
        m = re.search(r"(\$s\d+\w+\d+\w+V5\$mainyyFZ)", line)
        if m:
            swiftui_main_symbol = m.group(1)

    if has_swiftui_app and swiftui_main_symbol is None:
        return (
            None,
            "SwiftUI @main app detected but no App.main() symbol found — "
            "may need alternative entry strategy",
            None,
        )

    if swiftui_main_symbol:
        return (
            None,
            f"SwiftUI @main app — entry is {swiftui_main_symbol}, "
            "not UIApplicationMain. Need alternative shellcode path.",
            None,
        )

    # Tiers 1-5 fail when the symbol table and __cstring are themselves encrypted, so
    # fall back to class names reachable from __objc_classlist outside the crypt range.
    matches, n_classes, names_in_crypt = _walk_classlist_for_appdelegate(binary_path)
    if matches:
        # Tokenizing the module name lets "Coupang_New" match a class named "Coupang…".
        module_lower = module_name.lower()
        module_tokens = [t for t in re.split(r"[_\-.\s]+", module_lower) if t]

        def _rank(item):
            name, score = item
            name_lower = name.lower()
            module_bonus = 0
            if module_lower and module_lower in name_lower:
                module_bonus = 2
            else:
                for token in module_tokens:
                    if len(token) >= 3 and token in name_lower:
                        module_bonus = 1
                        break
            return (score, module_bonus, -len(name))

        matches.sort(key=_rank, reverse=True)
        best = matches[0][0]
        method = (
            f"__objc_classlist walk ({len(matches)} candidate"
            f"{'s' if len(matches) != 1 else ''} from {n_classes} classes; "
            f"{names_in_crypt} names skipped — in crypt)"
        )
        confidence = "medium" if len(matches) == 1 else "low"
        return (best, method, confidence)

    if n_classes > 0 and names_in_crypt == n_classes:
        # Every name is encrypted; the caller falls back to make-main-patch.py's
        # convention guess and its cbz-to-nil path.
        return (
            None,
            f"All {n_classes} ObjC class names fall inside the FairPlay-encrypted region — "
            f"manual --delegate required (try _TtC{len(module_name)}{module_name}11AppDelegate)",
            None,
        )

    return (None, "No AppDelegate or SwiftUI @main detected — manual investigation needed", None)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Auto-detect AppDelegate class name from iOS binary"
    )
    parser.add_argument("binary", help="Path to Mach-O binary")
    parser.add_argument("--app", help="Path to .app bundle (for Info.plist)")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only output the class name (for scripting)"
    )
    args = parser.parse_args()

    if not Path(args.binary).is_file():
        print(f"Not a file: {args.binary}", file=sys.stderr)
        sys.exit(1)

    app_path = args.app
    if not app_path:
        path = str(Path(args.binary).resolve().parent)
        while path and path != "/":
            if path.endswith(".app"):
                app_path = path
                break
            path = str(Path(path).parent)

    if not args.quiet:
        print(f"Detecting AppDelegate for: {args.binary}")
        if app_path:
            print(f"  App bundle: {app_path}")

    class_name, method, confidence = detect_delegate(args.binary, app_path)

    if args.quiet:
        if class_name:
            print(class_name)
            sys.exit(0)
        else:
            sys.exit(1)

    print()
    if class_name:
        print(f"  Detected: {class_name}")
        print(f"  Method:   {method}")
        print(f"  Confidence: {confidence}")
        print(f"\n  Use with: python3 make-main-patch.py <binary> --delegate '{class_name}'")
    else:
        print("  NOT FOUND")
        print(f"  Reason: {method}")
        sys.exit(1)


if __name__ == "__main__":
    main()
