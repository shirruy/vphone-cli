"""57ZZ shared BootKC chained-fixup index (single decoder source of truth).

Exposes build_fixup_index() implementing the canonical decoder semantics:
LC_DYLD_CHAINED_FIXUPS metadata walk, DYLD_CHAINED_PTR_64_KERNEL_CACHE
(format 8) only (other formats fail closed), START_NONE/START_MULTI page
handling, cacheLevel-0 resolution against the KC header base, stride 4.
All 57ZZ generators must consume this module instead of re-implementing
their own walkers.
"""

import struct

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
KC_BASE = 0xFFFFFFF007004000
DC_VM = 0xFFFFFFF007C18000

START_NONE = 0xFFFF
START_MULTI = 0x8000
START_LAST = 0x8000


def _outer_segments(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = []
    fixoff = fixsize = None
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8 : off + 24].split(b"\x00")[0].decode()
            vm, sz, fo, fsz = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append({"name": name, "vm": vm, "size": sz, "fileoff": fo, "filesize": fsz})
        elif cmd == 0x80000034:
            fixoff, fixsize = struct.unpack_from("<II", data, off + 8)
        off += csz
    return segs, fixoff, fixsize


def build_fixup_index(path=None, segment_name="__DATA_CONST"):
    """Return {fixup_location_vm: resolved_target_vm} for one chained segment.

    Fails closed on: missing LC_DYLD_CHAINED_FIXUPS, unknown segment,
    pointer formats other than 8, and nonzero cacheLevels.
    """
    data = open(path or BOOTKC, "rb").read()
    segs, fixoff, fixsize = _outer_segments(data)
    if fixoff is None:
        raise SystemExit("no LC_DYLD_CHAINED_FIXUPS")
    chain = data[fixoff : fixoff + fixsize]

    starts_offset = struct.unpack_from("<I", chain, 4)[0]
    seg_count = struct.unpack_from("<I", chain, starts_offset)[0]
    offs = struct.unpack_from("<%dI" % seg_count, chain, starts_offset + 4)

    # starts-table order follows LC_SEGMENT_64 order
    target_idx = next((i for i, s in enumerate(segs) if s["name"] == segment_name), None)
    if target_idx is None or target_idx >= seg_count or offs[target_idx] == 0:
        raise SystemExit("segment %s has no chain metadata" % segment_name)

    base = starts_offset + offs[target_idx]
    size, page_size, pointer_format = struct.unpack_from("<IHH", chain, base)
    if pointer_format != 8:
        raise SystemExit(
            "segment %s uses pointer_format %d (only 8 = 64_KERNEL_CACHE supported)"
            % (segment_name, pointer_format)
        )
    segment_offset, max_valid = struct.unpack_from("<QI", chain, base + 8)
    page_count = struct.unpack_from("<H", chain, base + 20)[0]
    page_starts = struct.unpack_from("<%dH" % page_count, chain, base + 22)

    owner = next(
        (s for s in segs if s["fileoff"] <= segment_offset < s["fileoff"] + s["filesize"]),
        None,
    )
    if owner is None:
        raise SystemExit("segment_offset unmatched")
    seg_vm = owner["vm"] + (segment_offset - owner["fileoff"])
    seg_fo = segment_offset
    pool_base = base + 22 + 2 * page_count

    index = {}
    nonzero_levels = 0

    def walk(start_off, page_idx):
        nonlocal nonzero_levels
        page_fo = seg_fo + page_idx * page_size
        cur = start_off
        seen = set()
        while True:
            if cur in seen:
                break
            seen.add(cur)
            raw = struct.unpack_from("<Q", data, page_fo + cur)[0]
            cache_level = (raw >> 30) & 0x3
            if cache_level != 0:
                nonzero_levels += 1
            index[seg_vm + page_idx * page_size + cur] = KC_BASE + (raw & 0x3FFFFFFF)
            nxt = (raw >> 51) & 0xFFF
            if nxt == 0:
                break
            cur += nxt * 4

    for page_idx, psv in enumerate(page_starts):
        if psv == START_NONE:
            continue
        if psv & START_MULTI:
            idx = psv & 0x7FFF
            while True:
                entry = struct.unpack_from("<H", chain, pool_base + 2 * idx)[0]
                walk(entry & 0x7FFF, page_idx)
                if entry & START_LAST:
                    break
                idx += 1
        else:
            walk(psv, page_idx)

    if nonzero_levels:
        raise SystemExit("nonzero cacheLevels present; basePointers unknown for them")
    return index


if __name__ == "__main__":
    idx = build_fixup_index()
    print("entries:", len(idx))
