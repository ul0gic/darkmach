#!/usr/bin/env python3
"""Splice class_ro_t list pointers that reach into the crypt region out of their chained-fixup
chain, so libobjc's init walk sees NULL instead of aborting on encrypted bytes.
"""

import argparse
import struct
import sys
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034
DYLD_CHAINED_PTR_64 = 6


def parse_segments_and_sections(data):
    """Return list of (segname, vmaddr, vmsize, fileoff, filesize) and
    a dict of (segname, sectname) -> (addr, size, fileoff)."""
    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        raise ValueError("not a 64-bit Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segments = []
    sections = {}
    chained_fixups = None
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8 : off + 24].split(b"\x00")[0].decode()
            vmaddr = struct.unpack_from("<Q", data, off + 24)[0]
            vmsize = struct.unpack_from("<Q", data, off + 32)[0]
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            sec_off = off + 72
            for _i in range(nsects):
                sectname = data[sec_off : sec_off + 16].split(b"\x00")[0].decode()
                addr = struct.unpack_from("<Q", data, sec_off + 32)[0]
                size = struct.unpack_from("<Q", data, sec_off + 40)[0]
                sec_fileoff = struct.unpack_from("<I", data, sec_off + 48)[0]
                sections[(segname, sectname)] = (addr, size, sec_fileoff)
                sec_off += 80
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff = struct.unpack_from("<I", data, off + 8)[0]
            datasize = struct.unpack_from("<I", data, off + 12)[0]
            chained_fixups = (dataoff, datasize)
        off += sz
    return segments, sections, chained_fixups


def load_addr(segments):
    """Return preferred load address (vmaddr of __TEXT)."""
    for s in segments:
        if s[0] == "__TEXT":
            return s[1]
    return 0x100000000


def vm_to_file(vmaddr, segments):
    for segname, va, vs, fo, _fs in segments:
        if vs > 0 and va <= vmaddr < va + vs and segname != "__PAGEZERO":
            return fo + (vmaddr - va)
    return None


def file_to_vm(fileoff, segments):
    for segname, va, _vs, fo, fs in segments:
        if fs > 0 and fo <= fileoff < fo + fs and segname != "__PAGEZERO":
            return va + (fileoff - fo)
    return None


def decode_ptr64(p):
    """Decode DYLD_CHAINED_PTR_64 word."""
    target = p & 0xFFFFFFFFF
    high8 = (p >> 36) & 0xFF
    nxt = (p >> 51) & 0xFFF
    bind = (p >> 63) & 1
    return target, high8, nxt, bind


def parse_chained_starts(data, fixups_off):
    """Parse chained fixups blob, return per-segment chain start info.
    Returns dict: seg_index -> {page_size, pointer_format, segment_offset, page_starts: [...] }"""
    starts_offset = struct.unpack_from("<I", data, fixups_off + 4)[0]
    starts_in_image = fixups_off + starts_offset
    seg_count = struct.unpack_from("<I", data, starts_in_image)[0]
    result = {}
    for i in range(seg_count):
        soff = struct.unpack_from("<I", data, starts_in_image + 4 + i * 4)[0]
        if soff == 0:
            continue
        seg_struct = starts_in_image + soff
        _size = struct.unpack_from("<I", data, seg_struct)[0]
        page_size = struct.unpack_from("<H", data, seg_struct + 4)[0]
        pointer_format = struct.unpack_from("<H", data, seg_struct + 6)[0]
        segment_offset = struct.unpack_from("<Q", data, seg_struct + 8)[0]
        page_count = struct.unpack_from("<H", data, seg_struct + 20)[0]
        page_starts = []
        for j in range(page_count):
            ps = struct.unpack_from("<H", data, seg_struct + 22 + j * 2)[0]
            page_starts.append(ps)
        result[i] = {
            "struct_offset": seg_struct,
            "page_size": page_size,
            "pointer_format": pointer_format,
            "segment_offset": segment_offset,
            "page_starts": page_starts,
            "page_starts_offset": seg_struct + 22,  # for in-place modification
        }
    return result


def find_chain_entry(target_file_offset, data, segments, chain_starts):
    """Return (chain_seg_idx, page_idx, prev_chain_file_offset, chain_file_offset, chain_value),
    with prev None for a page-start entry, or None when the offset is in no chained segment."""
    target_vmaddr = file_to_vm(target_file_offset, segments)
    if target_vmaddr is None:
        return None

    for seg_idx, info in chain_starts.items():
        _segname, va, vs, fo, _fs = segments[seg_idx]
        if not (va <= target_vmaddr < va + vs):
            continue
        page_size = info["page_size"]
        seg_offset_in_target = target_vmaddr - va
        page_idx = seg_offset_in_target // page_size
        if page_idx >= len(info["page_starts"]):
            return None
        page_start = info["page_starts"][page_idx]
        if page_start == 0xFFFF:  # DYLD_CHAINED_PTR_START_NONE
            return None
        page_file_off = fo + page_idx * page_size
        chain_off = page_file_off + page_start
        prev = None
        while True:
            v = struct.unpack_from("<Q", data, chain_off)[0]
            _target, _, nxt, _ = decode_ptr64(v)
            if chain_off == target_file_offset:
                return (seg_idx, page_idx, prev, chain_off, v)
            if nxt == 0:
                return None  # end of chain, didn't find
            prev = chain_off
            chain_off += nxt * 4
    return None


def neutralize_pointer(target_file_offset, data, segments, chain_starts):
    """Repoint the predecessor entry (or page_start[]) past this field and zero the 8 bytes, so
    dyld never writes here and the on-disk NULL survives fixup."""
    result = find_chain_entry(target_file_offset, data, segments, chain_starts)
    if result is None:
        # No chain entry means dyld will not write here, so an on-disk 0 is sufficient.
        v = struct.unpack_from("<Q", data, target_file_offset)[0]
        if v == 0:
            return False  # already zero
        # If it's a bind, leave it alone (binds reference imports, not crypt)
        _, _, _, bind = decode_ptr64(v)
        if bind:
            return False
        # Chain doesn't reach this offset; dyld won't fix it up. Writing 0 sticks.
        struct.pack_into("<Q", data, target_file_offset, 0)
        return True

    seg_idx, page_idx, prev_off, my_off, my_val = result
    _target, _high8, nxt, _bind = decode_ptr64(my_val)
    info = chain_starts[seg_idx]
    page_size = info["page_size"]
    _segname, _va, _vs, fo, _fs = segments[seg_idx]
    page_file_off = fo + page_idx * page_size

    if nxt == 0:
        # Last entry in this page's chain.
        if prev_off is None:
            # Only entry — mark the page as having no fixups (page_start = 0xFFFF).
            ps_off = info["page_starts_offset"] + page_idx * 2
            struct.pack_into("<H", data, ps_off, 0xFFFF)
            # Keep cached page_starts list coherent so subsequent find_chain_entry
            # calls see the updated value.
            info["page_starts"][page_idx] = 0xFFFF
        else:
            # Tell prev that it's the end of the chain.
            prev_val = struct.unpack_from("<Q", data, prev_off)[0]
            # Clear next field (bits 51..62)
            new_val = prev_val & ~(0xFFF << 51)
            struct.pack_into("<Q", data, prev_off, new_val)
    else:
        next_chain_off = my_off + nxt * 4
        if prev_off is None:
            # Target is the page-start. Point page_start[] at the next chain
            # entry's offset within the page.
            new_page_start = next_chain_off - page_file_off
            ps_off = info["page_starts_offset"] + page_idx * 2
            struct.pack_into("<H", data, ps_off, new_page_start)
            # Keep the cached page_starts list coherent — later find_chain_entry
            # calls otherwise walk from a stale offset and miss in-crypt pointers.
            info["page_starts"][page_idx] = new_page_start
        else:
            # Repoint prev's next field past this entry. New stride = old prev.next + nxt.
            prev_val = struct.unpack_from("<Q", data, prev_off)[0]
            new_next_stride = (next_chain_off - prev_off) // 4
            if new_next_stride > 0xFFF:
                # Stride overflow — chain entries too far apart to bypass cleanly.
                return False
            new_val = (prev_val & ~(0xFFF << 51)) | (new_next_stride << 51)
            struct.pack_into("<Q", data, prev_off, new_val)

    struct.pack_into("<Q", data, my_off, 0)
    return True


def patch_binary(path, original_cryptoff, original_cryptsize, dry_run=False):
    """Patch ObjC metadata pointers that reach into the original crypt region."""
    print(f"\n=== {path} ===")
    print(
        f"  Original crypt region: 0x{original_cryptoff:x} .. "
        f"0x{original_cryptoff + original_cryptsize:x}"
    )

    with Path(path).open("rb") as f:
        data = bytearray(f.read())

    segments, sections, chained_fixups = parse_segments_and_sections(data)
    if chained_fixups is None:
        print("  WARN: no LC_DYLD_CHAINED_FIXUPS — skipping (classic relocations unsupported)")
        return None

    fixups_off = chained_fixups[0]
    chain_starts = parse_chained_starts(data, fixups_off)

    la = load_addr(segments)

    crypt_lo = original_cryptoff
    crypt_hi = original_cryptoff + original_cryptsize

    def is_in_crypt_after_fixup(raw_word):
        """Check if a chained pointer's resolved value falls in the encrypted region."""
        if raw_word == 0:
            return False
        target, _, _, bind = decode_ptr64(raw_word)
        if bind:
            return False  # bind references imports, not file content
        resolved_vmaddr = la + target
        f = vm_to_file(resolved_vmaddr, segments)
        return f is not None and crypt_lo <= f < crypt_hi

    stats = {
        "classlist_classes": 0,
        "metaclasses": 0,
        "nlclslist_classes": 0,
        "catlist_categories": 0,
        "nlcatlist_categories": 0,
        "baseMethods_zeroed": 0,
        "metaclass_baseMethods_zeroed": 0,
        "baseProtocols_zeroed": 0,
        "ivars_zeroed": 0,
        "baseProperties_zeroed": 0,
        "cat_instanceMethods_zeroed": 0,
        "cat_classMethods_zeroed": 0,
        "cat_protocols_zeroed": 0,
        "cat_instanceProperties_zeroed": 0,
        "cat_classProperties_zeroed": 0,
    }

    def neutralize_class_ro(ro_file_offset, role):
        """Zero baseMethods/baseProtocols/ivars/baseProperties when they point into crypt; the
        class_ro_t name at 0x18 is left intact. On a metaclass 0x20 is the class-method list."""
        for fld_off, _fld_name, stat_key in [
            (
                0x20,
                "baseMethods",
                "metaclass_baseMethods_zeroed" if role == "metaclass" else "baseMethods_zeroed",
            ),
            (0x28, "baseProtocols", "baseProtocols_zeroed"),
            (0x30, "ivars", "ivars_zeroed"),
            (0x40, "baseProperties", "baseProperties_zeroed"),
        ]:
            field_off = ro_file_offset + fld_off
            if field_off + 8 > len(data):
                continue
            v = struct.unpack_from("<Q", data, field_off)[0]
            if is_in_crypt_after_fixup(v):
                if not dry_run:
                    if neutralize_pointer(field_off, data, segments, chain_starts):
                        stats[stat_key] += 1
                else:
                    stats[stat_key] += 1

    def follow_chain_ptr(file_off):
        """Read pointer at file_off and resolve to file offset of target struct."""
        if file_off + 8 > len(data):
            return None
        v = struct.unpack_from("<Q", data, file_off)[0]
        if v == 0:
            return None
        t, _, _, bind = decode_ptr64(v)
        if bind:
            return None
        resolved_vm = la + t
        return vm_to_file(resolved_vm, segments)

    if ("__DATA_CONST", "__objc_classlist") in sections:
        _addr, size, fileoff = sections[("__DATA_CONST", "__objc_classlist")]
    elif ("__DATA", "__objc_classlist") in sections:
        _addr, size, fileoff = sections[("__DATA", "__objc_classlist")]
    else:
        _addr = size = fileoff = 0

    if size > 0:
        n = size // 8
        print(f"  __objc_classlist: {n} classes")
        for i in range(n):
            cls_file = follow_chain_ptr(fileoff + i * 8)
            if cls_file is None:
                continue
            stats["classlist_classes"] += 1

            bits_off = cls_file + 32
            if bits_off + 8 > len(data):
                continue
            bits = struct.unpack_from("<Q", data, bits_off)[0]
            bt, _, _, bind = decode_ptr64(bits)
            if bind:
                continue
            ro_vm = la + (bt & ~0x7)
            ro_file = vm_to_file(ro_vm, segments)
            if ro_file is None:
                continue
            neutralize_class_ro(ro_file, "class")

            # Metaclass (class.isa)
            isa = struct.unpack_from("<Q", data, cls_file)[0]
            it, _, _, ibind = decode_ptr64(isa)
            if ibind:
                continue
            meta_vm = la + it
            meta_file = vm_to_file(meta_vm, segments)
            if meta_file is None:
                continue
            stats["metaclasses"] += 1
            meta_bits_off = meta_file + 32
            if meta_bits_off + 8 > len(data):
                continue
            meta_bits = struct.unpack_from("<Q", data, meta_bits_off)[0]
            mbt, _, _, mbind = decode_ptr64(meta_bits)
            if mbind:
                continue
            meta_ro_vm = la + (mbt & ~0x7)
            meta_ro_file = vm_to_file(meta_ro_vm, segments)
            if meta_ro_file is None:
                continue
            neutralize_class_ro(meta_ro_file, "metaclass")

    if ("__DATA_CONST", "__objc_nlclslist") in sections:
        _addr, size, fileoff = sections[("__DATA_CONST", "__objc_nlclslist")]
    elif ("__DATA", "__objc_nlclslist") in sections:
        _addr, size, fileoff = sections[("__DATA", "__objc_nlclslist")]
    else:
        size = 0
    if size > 0:
        n = size // 8
        print(f"  __objc_nlclslist: {n} non-lazy classes")
        # Re-walked in case the linker emitted an nlcls absent from classlist; repeating the
        # neutralization on an already-zeroed pointer is a no-op.
        for i in range(n):
            cls_file = follow_chain_ptr(fileoff + i * 8)
            if cls_file is None:
                continue
            stats["nlclslist_classes"] += 1

            bits_off = cls_file + 32
            if bits_off + 8 > len(data):
                continue
            bits = struct.unpack_from("<Q", data, bits_off)[0]
            bt, _, _, bbind = decode_ptr64(bits)
            if not bbind:
                ro_vm = la + (bt & ~0x7)
                ro_file = vm_to_file(ro_vm, segments)
                if ro_file is not None:
                    neutralize_class_ro(ro_file, "class")

            isa = struct.unpack_from("<Q", data, cls_file)[0]
            it, _, _, ibind = decode_ptr64(isa)
            if ibind:
                continue
            meta_vm = la + it
            meta_file = vm_to_file(meta_vm, segments)
            if meta_file is None:
                continue
            meta_bits_off = meta_file + 32
            if meta_bits_off + 8 > len(data):
                continue
            meta_bits = struct.unpack_from("<Q", data, meta_bits_off)[0]
            mbt, _, _, mbind = decode_ptr64(meta_bits)
            if mbind:
                continue
            meta_ro_vm = la + (mbt & ~0x7)
            meta_ro_file = vm_to_file(meta_ro_vm, segments)
            if meta_ro_file is None:
                continue
            neutralize_class_ro(meta_ro_file, "metaclass")

    for catlist_segname in ["__DATA_CONST", "__DATA"]:
        for catlist_section in ["__objc_catlist", "__objc_catlist2", "__objc_nlcatlist"]:
            key = (catlist_segname, catlist_section)
            if key not in sections:
                continue
            _addr, size, fileoff = sections[key]
            if size == 0:
                continue
            n = size // 8
            print(f"  {catlist_section}: {n} categories")
            for i in range(n):
                cat_file = follow_chain_ptr(fileoff + i * 8)
                if cat_file is None:
                    continue
                if catlist_section == "__objc_nlcatlist":
                    stats["nlcatlist_categories"] += 1
                else:
                    # both __objc_catlist and __objc_catlist2 (newer linker
                    # variant) bucket under the same counter
                    stats["catlist_categories"] += 1
                # category_t fields (skip name at 0x00 and cls at 0x08; neutralize the lists)
                for fld_off, stat_key in [
                    (0x10, "cat_instanceMethods_zeroed"),
                    (0x18, "cat_classMethods_zeroed"),
                    (0x20, "cat_protocols_zeroed"),
                    (0x28, "cat_instanceProperties_zeroed"),
                    (0x30, "cat_classProperties_zeroed"),
                ]:
                    field_off = cat_file + fld_off
                    if field_off + 8 > len(data):
                        continue
                    v = struct.unpack_from("<Q", data, field_off)[0]
                    if is_in_crypt_after_fixup(v):
                        if not dry_run:
                            if neutralize_pointer(field_off, data, segments, chain_starts):
                                stats[stat_key] += 1
                        else:
                            stats[stat_key] += 1

    print("  --- Stats ---")
    for k, v in stats.items():
        if v > 0:
            print(f"    {k}: {v}")

    if dry_run:
        print("  (dry-run; no changes written)")
        return stats

    with Path(path).open("wb") as f:
        f.write(data)
    print("  Written.")
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Zero ObjC class_ro_t pointers that point into a Mach-O's "
        "FairPlay-encrypted region, so libobjc's prepareMethodLists "
        "doesn't dereference encrypted bytes."
    )
    parser.add_argument("binary", help="Path to Mach-O binary")
    parser.add_argument(
        "--cryptoff",
        type=lambda x: int(x, 0),
        required=True,
        help="ORIGINAL cryptoff (before patch-macho-surgical zeroed it)",
    )
    parser.add_argument(
        "--cryptsize", type=lambda x: int(x, 0), required=True, help="ORIGINAL cryptsize"
    )
    parser.add_argument("--dry-run", action="store_true", help="count only, do not write")
    args = parser.parse_args()

    if not Path(args.binary).is_file():
        print(f"Not a file: {args.binary}", file=sys.stderr)
        sys.exit(1)

    patch_binary(args.binary, args.cryptoff, args.cryptsize, args.dry_run)


if __name__ == "__main__":
    main()
