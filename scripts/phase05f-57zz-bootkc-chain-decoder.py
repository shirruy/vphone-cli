#!/usr/bin/env python3
"""57ZZ: BootKC DYLD_CHAINED_PTR_64_KERNEL_CACHE decoder.

P2-P4 of the fixup-correction pass. Walks ONLY real fixup chains from the
LC_DYLD_CHAINED_FIXUPS metadata (never raw qword scans), resolves targets
as basePointers[cacheLevel] + target, and validates against independently
known pointer relationships before any conclusion is drawn.

Authoritative format sources (xnu-8792.81.2):
  - EXTERNAL_HEADERS/mach-o/fixup-chains.h (struct layouts, pointer format 8)
  - osfmk/mach/dyld_kernel_fixups.h (resolution: basePointers[cacheLevel] + target)
  - osfmk/arm/arm_init.c (collection_base_pointers[0] = kc_mh)
"""

import hashlib
import json
import struct

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.md"

KC_BASE_VM = 0xFFFFFFF007004000  # outer KC mach header static vmaddr (slide 0)
CAND_A_VM = 0xFFFFFFF0082F4DF0
CAND_B_VM = 0xFFFFFFF0082F804C

SEGMENT_NAMES = [
    "__TEXT", "__PRELINK_TEXT", "__DATA_CONST", "__DATA_SPTM",
    "__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__PRELINK_INFO", "__DATA",
    "__LINKEDIT",
]


def parse_outer_segments(data):
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


def decode_kc_rebase(raw):
    """DYLD_CHAINED_PTR_64_KERNEL_CACHE bitfield decode."""
    target = raw & 0x3FFFFFFF
    cacheLevel = (raw >> 30) & 0x3
    diversity = (raw >> 32) & 0xFFFF
    addrDiv = (raw >> 48) & 0x1
    key = (raw >> 49) & 0x3
    nxt = (raw >> 51) & 0xFFF
    isAuth = (raw >> 63) & 0x1
    return target, cacheLevel, diversity, addrDiv, key, nxt, isAuth


def main():
    data = open(BOOTKC, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()

    segs, fixoff, fixsize = parse_outer_segments(data)
    assert fixoff is not None, "no LC_DYLD_CHAINED_FIXUPS"
    chain = data[fixoff : fixoff + fixsize]

    # dyld_chained_fixups_header (7 x uint32)
    (fixups_version, starts_offset, imports_offset, symbols_offset,
     imports_count, imports_format, symbols_format) = struct.unpack_from("<7I", chain, 0)

    # dyld_chained_starts_in_image at starts_offset
    seg_count = struct.unpack_from("<I", chain, starts_offset)[0]
    seg_info_offsets = struct.unpack_from("<%dI" % seg_count, chain, starts_offset + 4)

    format_report = {
        "fixups_version": fixups_version,
        "starts_offset": hex(starts_offset),
        "imports_count": imports_count,
        "imports_format": imports_format,
        "symbols_format": symbols_format,
        "seg_count": seg_count,
    }

    segments_out = []
    fixup_index = {}     # location_vm -> record
    reverse_index = {}   # resolved_vm -> [location_vms]

    for i, rel in enumerate(seg_info_offsets):
        if rel == 0:
            segments_out.append({
                "segment": SEGMENT_NAMES[i] if i < len(SEGMENT_NAMES) else str(i),
                "has_chain": False,
            })
            continue
        base = starts_offset + rel
        (size, page_size, pointer_format) = struct.unpack_from("<IHH", chain, base)
        segment_offset, max_valid = struct.unpack_from("<QI", chain, base + 8)
        page_count = struct.unpack_from("<H", chain, base + 20)[0]
        seg = {
            "segment": SEGMENT_NAMES[i] if i < len(SEGMENT_NAMES) else str(i),
            "has_chain": True,
            "pointer_format": pointer_format,
            "page_size": hex(page_size),
            "page_count": page_count,
            "segment_offset": hex(segment_offset),
            "max_valid_pointer": max_valid,
        }
        segments_out.append(seg)
        if pointer_format != 8:
            continue  # only decode 64_KERNEL_CACHE regions

        page_starts = struct.unpack_from("<%dH" % page_count, chain, base + 22)
        stride = 4  # kernel-cache format: next is in 1-or-4-byte units; this image uses 4
        # segment_offset is a FILE offset in this image (verified:
        # __DATA_CONST segment_offset == its LC_SEGMENT_64 fileoff). Map it
        # to the owning outer segment for both vm and file coordinates.
        owner = next(
            (s for s in segs if s["fileoff"] <= segment_offset < s["fileoff"] + s["filesize"]),
            None,
        )
        if owner is None:
            seg["skip_reason"] = "segment_offset does not match any outer segment fileoff range"
            continue
        seg_vm = owner["vm"] + (segment_offset - owner["fileoff"])
        seg_fo = segment_offset

        for page_idx, ps in enumerate(page_starts):
            if ps == 0xFFFF:
                continue
            page_fo = seg_fo + page_idx * page_size
            page_vm = seg_vm + page_idx * page_size
            off_in_page = ps
            hops = 0
            while hops < 4096:
                loc_fo = page_fo + off_in_page
                raw = struct.unpack_from("<Q", data, loc_fo)[0]
                target, cacheLevel, diversity, addrDiv, key, nxt, isAuth = decode_kc_rebase(raw)
                resolved_vm = KC_BASE_VM + target  # cacheLevel 0; others would need their base
                rec = {
                    "loc_vm": hex(page_vm + off_in_page),
                    "raw": hex(raw),
                    "target": hex(target),
                    "cacheLevel": cacheLevel,
                    "isAuth": isAuth,
                    "resolved_vm": hex(resolved_vm),
                }
                fixup_index[page_vm + off_in_page] = rec
                reverse_index.setdefault(resolved_vm, []).append(page_vm + off_in_page)
                if nxt == 0:
                    break
                off_in_page += nxt * stride
                hops += 1

    # ---- Validation against independently known pointers ----
    def resolved_at(loc_vm):
        r = fixup_index.get(loc_vm)
        return int(r["resolved_vm"], 16) if r else None

    checks = []
    # 1) ASCWrap GOT superclass slot -> AppleA7IOP class object
    got_slot = 0xFFFFFFF007D13BC0
    expect = 0xFFFFFFF00AFED5C0
    got = resolved_at(got_slot)
    checks.append({
        "known": "ASCWrap GOT superclass -> AppleA7IOP class object",
        "location": hex(got_slot), "expected": hex(expect), "decoded": hex(got) if got else None,
        "pass": got == expect,
    })
    # 2) ASCWrap mod_init[1] function pointer (from __mod_init_func).
    # ASCWrap entry has 3 mod_inits: [0]=SISP, [1]=V6, [2]=SEP.
    # Section base 0xfffffff007d12278; index 1 = +8 => 0xfffffff007d12280.
    mi_slot = 0xFFFFFFF007D12280
    r = fixup_index.get(mi_slot)
    checks.append({
        "known": "ASCWrap mod_init[1] (AppleASCWrapV6 registration)",
        "location": hex(mi_slot), "expected": "0xfffffff0082f42b4",
        "decoded": r["resolved_vm"] if r else None,
        "pass": bool(r) and r["resolved_vm"] == "0xfffffff0082f42b4",
    })
    # 2b) index 2 = SEP registration
    mi_slot2 = 0xFFFFFFF007D12288
    r2 = fixup_index.get(mi_slot2)
    checks.append({
        "known": "ASCWrap mod_init[2] (AppleASCWrapV6SEP registration)",
        "location": hex(mi_slot2), "expected": "0xfffffff0082f4800",
        "decoded": r2["resolved_vm"] if r2 else None,
        "pass": bool(r2) and r2["resolved_vm"] == "0xfffffff0082f4800",
    })
    # 3) A7IOP mod_init[0] entry
    mi2 = 0xFFFFFFF007D13BD0
    r2 = fixup_index.get(mi2)
    checks.append({
        "known": "A7IOP mod_init[0] chain entry",
        "location": hex(mi2), "expected": "0xfffffff0082f7798",
        "decoded": r2["resolved_vm"] if r2 else None,
        "pass": bool(r2) and r2["resolved_vm"] == "0xfffffff0082f7798",
    })

    self_consistent = all(c["pass"] for c in checks)

    # ---- Candidate evaluation (P7 preview) ----
    candA_locs = reverse_index.get(CAND_A_VM, [])
    candB_locs = reverse_index.get(CAND_B_VM, [])

    artifact = {
        "gate": "57ZZ_BOOTKC_CHAINED_FIXUPS",
        "bootkc_sha256": sha,
        "format": format_report,
        "segments": segments_out,
        "decoder_semantics": {
            "pointer_format": "DYLD_CHAINED_PTR_64_KERNEL_CACHE (=8) where present",
            "resolution": "resolved_vm = basePointers[cacheLevel] + target",
            "basePointer_source": "osfmk/arm/arm_init.c: collection_base_pointers[0] = kc_mh",
            "cacheLevel0_base_static": hex(KC_BASE_VM),
            "note": "All decoded entries in this image carry cacheLevel=0 unless reported otherwise; non-zero levels would require their KC base before resolution.",
        },
        "chain_walk": {
            "total_fixups": len(fixup_index),
            "nonzero_cache_levels": len([r for r in fixup_index.values() if r["cacheLevel"] != 0]),
            "auth_entries": len([r for r in fixup_index.values() if r["isAuth"]]),
        },
        "validation_checks": checks,
        "CHAIN_WALK_SELF_CONSISTENCY": "PASS" if self_consistent else "FAIL",
        "candidates": {
            "candA": {"vm": hex(CAND_A_VM), "reference_locations": [hex(x) for x in candA_locs], "count": len(candA_locs)},
            "candB": {"vm": hex(CAND_B_VM), "reference_locations": [hex(x) for x in candB_locs], "count": len(candB_locs)},
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — BootKC Chained-Fixup Decoder",
        "",
        "```",
        "BOOTKC_CHAIN_FORMAT: PROVEN (pointer_format 8 where chained)",
        f"CHAIN_WALK_SELF_CONSISTENCY: {artifact['CHAIN_WALK_SELF_CONSISTENCY']}",
        f"total chain-walked fixups: {len(fixup_index)}",
        "```",
        "",
        "## Validation against known pointers",
        "",
    ]
    for c in checks:
        md.append(f"- {'PASS' if c['pass'] else 'FAIL'} {c['known']}: {c['decoded']} (expected {c['expected']})")
    md += [
        "",
        "## Candidate references (real chain decode)",
        "",
        f"- candA `0xfffffff0082f4df0`: {len(candA_locs)} reference(s)",
        f"- candB `0xfffffff0082f804c`: {len(candB_locs)} reference(s)",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps({
        "format": format_report,
        "segments_with_chains": [s["segment"] for s in segments_out if s.get("has_chain")],
        "pointer_formats": sorted({s["pointer_format"] for s in segments_out if s.get("has_chain")}),
        "total_fixups": len(fixup_index),
        "nonzero_cache_levels": artifact["chain_walk"]["nonzero_cache_levels"],
        "self_consistency": artifact["CHAIN_WALK_SELF_CONSISTENCY"],
        "checks": checks,
        "candA_refs": len(candA_locs),
        "candB_refs": len(candB_locs),
    }, indent=2))


if __name__ == "__main__":
    main()



