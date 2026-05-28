#!/usr/bin/env python3
"""
Surgical Mach-O ObjC metadata neutralizer.

When a binary has FairPlay-encrypted __cstring/__objc_methname/__objc_classname
but unencrypted __DATA/__DATA_CONST containing __objc_classlist, dyld's ObjC
init phase (libobjc's `_read_images` -> `realizeClassWithoutSwift` ->
`prepareMethodLists` -> `fixupMethodList`) walks every class's method_list
and dereferences each method's name pointer. If the method_list_t struct
itself or its inner name pointers reach into the encrypted region, _objc_fatal
aborts the process before any user code (including LC_MAIN entry, dylib
constructors, +load methods) runs.

This script zeroes the on-disk class_ro_t fields that point into the
FairPlay region, neutralizing prepareMethodLists for those classes:

  - baseMethods: the method_list_t pointer
  - baseProtocols: the protocol_list_t pointer (optional but defensive)
  - ivars: the ivar_list_t pointer (defensive)
  - baseProperties: the property_list_t pointer (defensive)

We do NOT zero `name` — libobjc tolerates reading a placeholder name
better than it tolerates reading bad bytes, and many code paths expect
a non-null name. (If a class with a name pointing into encrypted bytes
DOES crash later, that's a separate Round 3 fix.)

Coverage:
  - Every class in __objc_classlist
  - Every metaclass referenced via class.isa
  - Every class in __objc_nlclslist (non-lazy classes — `+load`)
  - Every category in __objc_catlist (instanceMethods, classMethods,
    properties point into method/property lists)
  - Every category in __objc_nlcatlist

The binary uses LC_DYLD_CHAINED_FIXUPS — pointers on disk are 64-bit
chained-fixup encoded. For DYLD_CHAINED_PTR_64 (format 6) rebases:

    bits  0..35 : target (vmaddr offset from preferred load address)
    bits 36..43 : high8
    bits 44..50 : reserved
    bits 51..62 : next (4-byte stride; 0 = end of chain)
    bit  63     : bind (0 = rebase, 1 = bind via imports)

Setting a chain entry to all-zeroes makes it a "rebase to 0" which
resolves to the preferred load address (0x100000000 in our case) +
0 = 0x100000000. That's not NULL — it's __PAGEZERO, which would map
to libobjc dereferencing __PAGEZERO and SEGV.

The correct way to "zero" a chained pointer field is:
  - Replace the 8-byte chain entry with the value
    `0x0000000000000000` ONLY IF it's the last entry in the chain
    (i.e. its `next` field is 0). Otherwise we break the chain.
  - To preserve the chain stride and produce a NULL, write a 64-bit
    value where target=0, but importantly preserve the `next` field
    of the original entry so dyld walks past it correctly. Since
    target=0 with high8=0 and bind=0, the dyld-resolved value will be
    0x100000000 (preferred load addr). That's still wrong.

Better strategy: dyld's chained fixup handler skips entries where the
"raw" value before fixup has bind=0 AND target=0 — actually no, it
unconditionally writes (load_addr + target) for rebases. So we need a
different approach.

Approach used here:
  Use the chained pointer encoding but set high8=0, target=0, and PRESERVE
  the original `next` field. dyld will resolve the field to 0x100000000.
  In objc-runtime-new.mm, `prepareMethodLists` checks `if (mlists[i] == nil)
  continue;` — but it checks for nil after dereferencing data->ro->baseMethods.
  Actually it checks `data->ro->baseMethods()` where `baseMethods()` returns
  the raw pointer. If that pointer is 0x100000000 (PAGEZERO), libobjc will
  dereference it and SEGV trying to read the count field.

  The clean solution: use the imports-table bind format trick — make the
  entry a BIND with ordinal pointing to a known-safe symbol... too complex.

Cleanest solution actually used:
  Since we own the binary's chained fixup metadata too, we can patch the
  CHAIN ITSELF. For each pointer we want to neutralize:
    1. Find the page containing the pointer (in __DATA_CONST or __DATA).
    2. In dyld_chained_starts_in_segment, find the page_start[] entry.
    3. Walk the chain from that page_start, find the chain entry that
       lands on our target offset.
    4. Splice it out: rewrite the previous entry's `next` to skip over
       this entry, then zero the bytes of our entry.

  This produces a real 0x0000000000000000 in memory after fixup, which
  is what we want.

Even simpler: the bytes at the target offset in the on-disk file ALSO
control what dyld writes. After fixup, the value at that address is
(load_addr + target) for rebases. If we want the post-fixup bytes to be
0x0, we need the chain to NOT write to that location.

Splicing chains is fiddly. Pragmatic fallback for Round 2:
  Patch the `target` field of the chain entry to point to a known-safe
  location that contains 0x0 in the file (e.g., file offset 0 inside
  __PAGEZERO, but PAGEZERO is unmapped, can't read 0 from it). Better:
  add a small read-only "zero word" to a non-encrypted section and point
  pointers there.

Better-still pragmatic: since libobjc reads `baseMethods` and treats it
as a pointer to method_list_t, if we can make `baseMethods` resolve to
a valid empty method_list_t (entsize_flags=0, count=0), that's
mlist[0..count-1] iteration done on count=0, no abort. We need to
write a single 8-byte "empty method_list_t" somewhere unencrypted and
point baseMethods at it.

Alternative even simpler: the `LC_DYLD_CHAINED_FIXUPS` chain handler
treats `0x0000000000000000` as "end-of-chain" iff `next=0`. But that
reads ambiguously: the rebase value 0x0 DOES get written (target=0,
high8=0, resolves to LOAD_ADDR + 0 = 0x100000000).

OK — the real solution: walk the chain, splice the entry out so dyld
never writes to that location. Then the on-disk bytes at that location
remain whatever we put there. We can write 0x0 directly and dyld won't
overwrite it.

This is what this script does for each target field.
"""

import argparse
import os
import struct
import sys


# Mach-O constants
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
    for segname, va, vs, fo, fs in segments:
        if vs > 0 and va <= vmaddr < va + vs and segname != "__PAGEZERO":
            return fo + (vmaddr - va)
    return None


def file_to_vm(fileoff, segments):
    for segname, va, vs, fo, fs in segments:
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
        size = struct.unpack_from("<I", data, seg_struct)[0]
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
    """Find the chain entry that controls the value at `target_file_offset`.

    Returns (chain_seg_idx, page_idx, prev_chain_file_offset, chain_file_offset, chain_value)
    where prev_chain_file_offset is None if this is the page-start entry.

    Returns None if target_file_offset is not in any chained segment.
    """
    target_vmaddr = file_to_vm(target_file_offset, segments)
    if target_vmaddr is None:
        return None

    # Find which segment contains target
    for seg_idx, info in chain_starts.items():
        segname, va, vs, fo, fs = segments[seg_idx]
        if not (va <= target_vmaddr < va + vs):
            continue
        page_size = info["page_size"]
        seg_offset_in_target = target_vmaddr - va  # offset within segment
        page_idx = seg_offset_in_target // page_size
        if page_idx >= len(info["page_starts"]):
            return None
        page_start = info["page_starts"][page_idx]
        if page_start == 0xFFFF:  # DYLD_CHAINED_PTR_START_NONE
            return None
        page_file_off = fo + page_idx * page_size
        # Walk chain from page_start
        chain_off = page_file_off + page_start
        prev = None
        while True:
            v = struct.unpack_from("<Q", data, chain_off)[0]
            target, _, nxt, _ = decode_ptr64(v)
            if chain_off == target_file_offset:
                return (seg_idx, page_idx, prev, chain_off, v)
            if nxt == 0:
                return None  # end of chain, didn't find
            prev = chain_off
            chain_off += nxt * 4
    return None


def neutralize_pointer(target_file_offset, data, segments, chain_starts):
    """Splice the chain so the field at target_file_offset stays 0 at runtime.

    Strategy:
      1. Find the chain entry at target_file_offset.
      2. If it's a page-start entry (no prev): rewrite the page_start[]
         to skip to the next entry in the chain.
      3. If it has a prev: rewrite prev's `next` field to bypass us.
      4. Zero out the 8 bytes at target_file_offset.

    After this:
      - dyld walks the chain past our entry, never writing to target_file_offset.
      - target_file_offset retains the 0x0 we wrote, post-fixup memory shows 0.
      - libobjc's `prepareMethodLists` sees baseMethods==0 and skips.

    Returns True if patched, False if not in any chain (already 0 / external bind).
    """
    result = find_chain_entry(target_file_offset, data, segments, chain_starts)
    if result is None:
        # Either the field is already 0, or it's a bind (which would be external),
        # or the chain genuinely doesn't reach this offset (because an upstream
        # splice routed past it). In the last case, dyld won't write here at
        # runtime, so we can safely write 0 to neutralize.
        v = struct.unpack_from("<Q", data, target_file_offset)[0]
        if v == 0:
            return False  # already zero
        # If it's a bind, leave it alone (binds reference imports, not crypt)
        _, _, _, bind = decode_ptr64(v)
        if bind:
            return False
        # Chain doesn't reach us; dyld won't fix this up. Writing 0 sticks.
        struct.pack_into("<Q", data, target_file_offset, 0)
        return True

    seg_idx, page_idx, prev_off, my_off, my_val = result
    target, high8, nxt, bind = decode_ptr64(my_val)
    info = chain_starts[seg_idx]
    page_size = info["page_size"]
    segname, va, vs, fo, fs = segments[seg_idx]
    page_file_off = fo + page_idx * page_size

    # Compute what the next entry's location is (within the page)
    if nxt == 0:
        # We're the last entry in this page's chain.
        if prev_off is None:
            # We were the only entry. Mark page as having no fixups (page_start = 0xFFFF).
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
            # We're the page-start. Update page_start[] to point to the next chain entry's
            # offset within the page.
            new_page_start = next_chain_off - page_file_off
            ps_off = info["page_starts_offset"] + page_idx * 2
            struct.pack_into("<H", data, ps_off, new_page_start)
            # Keep cached page_starts list coherent — without this, later
            # find_chain_entry calls walk from a stale (now-zeroed) offset
            # and incorrectly conclude the target is unreachable, leaving
            # in-crypt method-list pointers untouched. (Coupang Round 7 bug.)
            info["page_starts"][page_idx] = new_page_start
        else:
            # Update prev's next field to skip us. New next stride = old prev.next + my.nxt
            prev_val = struct.unpack_from("<Q", data, prev_off)[0]
            prev_next = (prev_val >> 51) & 0xFFF
            new_next_stride = (next_chain_off - prev_off) // 4
            if new_next_stride > 0xFFF:
                # Stride overflow — chain entries are too far apart.
                # We can't bypass cleanly; leave it.
                return False
            new_val = (prev_val & ~(0xFFF << 51)) | (new_next_stride << 51)
            struct.pack_into("<Q", data, prev_off, new_val)

    # Zero out our entry
    struct.pack_into("<Q", data, my_off, 0)
    return True


def patch_binary(path, original_cryptoff, original_cryptsize, dry_run=False):
    """Patch ObjC metadata pointers that reach into the original crypt region."""
    print(f"\n=== {path} ===")
    print(
        f"  Original crypt region: 0x{original_cryptoff:x} .. 0x{original_cryptoff + original_cryptsize:x}"
    )

    with open(path, "rb") as f:
        data = bytearray(f.read())

    segments, sections, chained_fixups = parse_segments_and_sections(data)
    if chained_fixups is None:
        print(f"  WARN: no LC_DYLD_CHAINED_FIXUPS — skipping (TODO: classic relocations)")
        return

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
        """Zero baseMethods, baseProtocols, ivars, baseProperties if they're in crypt.
        class_ro_t layout:
          0x00 flags (uint32)
          0x04 instanceStart
          0x08 instanceSize
          0x0c reserved
          0x10 ivarLayout (ptr)
          0x18 name (ptr)
          0x20 baseMethods (ptr)         <-- prepareMethodLists reads this
          0x28 baseProtocols (ptr)
          0x30 ivars (ptr)
          0x38 weakIvarLayout (ptr)
          0x40 baseProperties (ptr)

        For metaclass entries, baseMethods is the class-methods list
        (`_OBJC_$_CLASS_METHODS_*` symbols). libobjc's prepareMethodLists
        walks the metaclass's baseMethods exactly the same way as the
        instance class's, so any class-methods list pointing into crypt
        will trigger _objc_fatal during dyld init unless neutralized.
        Tracked separately under `metaclass_baseMethods_zeroed`. (Coupang
        Round 7: AppStartTimeLoader had only class methods in crypt.)
        """
        for fld_off, fld_name, stat_key in [
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

    # ── Process __objc_classlist ──
    if ("__DATA_CONST", "__objc_classlist") in sections:
        addr, size, fileoff = sections[("__DATA_CONST", "__objc_classlist")]
    elif ("__DATA", "__objc_classlist") in sections:
        addr, size, fileoff = sections[("__DATA", "__objc_classlist")]
    else:
        addr = size = fileoff = 0

    if size > 0:
        n = size // 8
        print(f"  __objc_classlist: {n} classes")
        for i in range(n):
            cls_file = follow_chain_ptr(fileoff + i * 8)
            if cls_file is None:
                continue
            stats["classlist_classes"] += 1

            # Mask bits.target's low 3 bits
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

    # ── Process __objc_nlclslist ──
    if ("__DATA_CONST", "__objc_nlclslist") in sections:
        addr, size, fileoff = sections[("__DATA_CONST", "__objc_nlclslist")]
    elif ("__DATA", "__objc_nlclslist") in sections:
        addr, size, fileoff = sections[("__DATA", "__objc_nlclslist")]
    else:
        size = 0
    if size > 0:
        n = size // 8
        print(f"  __objc_nlclslist: {n} non-lazy classes")
        # nlclslist entries are usually a subset of classlist (already
        # neutralized), but we re-walk and re-neutralize defensively in
        # case the linker emitted an nlcls that's not also in classlist.
        # Re-neutralization on an already-zeroed pointer is a no-op
        # (is_in_crypt_after_fixup returns False on 0).
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

    # ── Process __objc_catlist, __objc_catlist2, __objc_nlcatlist ──
    # category_t layout (from objc_runtime-new.mm):
    #   0x00 name (const char *)            <-- string ptr (may be in crypt)
    #   0x08 cls (Class *)                  <-- target class
    #   0x10 instanceMethods (method_list_t *)
    #   0x18 classMethods (method_list_t *)
    #   0x20 protocols (protocol_list_t *)
    #   0x28 instanceProperties (property_list_t *)
    #   0x30 _classProperties (property_list_t *) [optional, recent runtimes]

    for catlist_segname in ["__DATA_CONST", "__DATA"]:
        for catlist_section in ["__objc_catlist", "__objc_catlist2", "__objc_nlcatlist"]:
            key = (catlist_segname, catlist_section)
            if key not in sections:
                continue
            addr, size, fileoff = sections[key]
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

    print(f"  --- Stats ---")
    for k, v in stats.items():
        if v > 0:
            print(f"    {k}: {v}")

    if dry_run:
        print("  (dry-run; no changes written)")
        return stats

    with open(path, "wb") as f:
        f.write(data)
    print(f"  Written.")
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

    if not os.path.isfile(args.binary):
        print(f"Not a file: {args.binary}", file=sys.stderr)
        sys.exit(1)

    patch_binary(args.binary, args.cryptoff, args.cryptsize, args.dry_run)


if __name__ == "__main__":
    main()
