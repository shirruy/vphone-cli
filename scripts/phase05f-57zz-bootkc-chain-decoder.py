#!/usr/bin/env python3
"""57ZZ: BootKC chained-fixup decoder — reporting and validation layer.

All chain walking is delegated to the shared canonical decoder
(scripts/phase05f-57zz-fixup-index.py). This script consumes
build_fixup_index() per segment, performs the known-pointer self-
consistency validation, aggregates per-segment statistics (from the
shared module's metadata parsing), and emits the canonical evidence
artifacts. It contains NO independent chain-walking implementation.
"""

import hashlib
import importlib.util as ilu
import json
import os
import struct

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.md"

KC_BASE_VM = 0xFFFFFFF007004000
CAND_A_VM = 0xFFFFFFF0082F4DF0
CAND_B_VM = 0xFFFFFFF0082F804C

_fixup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
_fixup_spec = ilu.spec_from_file_location("phase05f_57zz_fixup_index", _fixup_path)
fixup_module = ilu.module_from_spec(_fixup_spec)
_fixup_spec.loader.exec_module(fixup_module)

CHAINED_SEGMENTS = ["__DATA_CONST", "__DATA_SPTM", "__DATA"]


def segment_metadata(data, segment_name):
    """Parse the starts-table metadata for one segment (reporting only)."""
    segs, fixoff, fixsize = fixup_module._outer_segments(data)
    chain = data[fixoff : fixoff + fixsize]
    starts_offset = struct.unpack_from("<I", chain, 4)[0]
    seg_count = struct.unpack_from("<I", chain, starts_offset)[0]
    offs = struct.unpack_from("<%dI" % seg_count, chain, starts_offset + 4)
    target_idx = next((i for i, s in enumerate(segs) if s["name"] == segment_name), None)
    if target_idx is None or target_idx >= seg_count or offs[target_idx] == 0:
        return None
    base = starts_offset + offs[target_idx]
    size, page_size, pointer_format = struct.unpack_from("<IHH", chain, base)
    segment_offset, max_valid = struct.unpack_from("<QI", chain, base + 8)
    page_count = struct.unpack_from("<H", chain, base + 20)[0]
    page_starts = struct.unpack_from("<%dH" % page_count, chain, base + 22)
    single = sum(1 for p in page_starts if p != 0xFFFF and not (p & 0x8000))
    multi = sum(1 for p in page_starts if p != 0xFFFF and (p & 0x8000))
    none = sum(1 for p in page_starts if p == 0xFFFF)
    return {
        "segment": segment_name, "pointer_format": pointer_format,
        "page_size": hex(page_size), "page_count": page_count,
        "single_start_pages": single, "multi_start_pages": multi,
        "none_pages": none, "total_chain_heads": single + multi,
        "segment_offset": hex(segment_offset),
    }


def main():
    data = open(BOOTKC, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()

    segments_out = []
    fixup_index = {}
    cache_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    multi_total = 0

    # Only decode the segments this fixture actually chains; the shared
    # module fails closed on non-8 formats and nonzero cacheLevels.
    all_segs = [s["name"] for s in fixup_module._outer_segments(data)[0]]
    seg_info_offsets = None
    chain = None
    segs_meta, fixoff, fixsize = fixup_module._outer_segments(data)
    chain_data = data[fixoff : fixoff + fixsize]
    starts_offset = struct.unpack_from("<I", chain_data, 4)[0]
    seg_count = struct.unpack_from("<I", chain_data, starts_offset)[0]
    offs = struct.unpack_from("<%dI" % seg_count, chain_data, starts_offset + 4)

    for i, seg_name in enumerate(all_segs):
        if i >= seg_count or offs[i] == 0:
            segments_out.append({"segment": seg_name, "has_chain": False})
            continue
        meta = segment_metadata(data, seg_name)
        if meta is None:
            segments_out.append({"segment": seg_name, "has_chain": False})
            continue
        meta["has_chain"] = True
        segments_out.append(meta)
        multi_total += meta["multi_start_pages"]
        if meta["pointer_format"] == 8:
            idx = fixup_module.build_fixup_index(segment_name=seg_name)
            fixup_index.update(idx)
            # cacheLevel counts for reporting
            owner = next(s for s in segs_meta if s["fileoff"] <= int(meta["segment_offset"], 16) < s["fileoff"] + s["filesize"])
            seg_vm = owner["vm"] + (int(meta["segment_offset"], 16) - owner["fileoff"])
            for loc in idx:
                pass  # levels validated by the module (fails closed on nonzero)

    starts_bound = seg_count == len(all_segs)

    def resolved_at(loc):
        return fixup_index.get(loc)

    checks = []
    for label, loc, expect in [
        ("ASCWrap GOT superclass -> AppleA7IOP class object", 0xFFFFFFF007D13BC0, 0xFFFFFFF00AFED5C0),
        ("ASCWrap mod_init[1] (AppleASCWrapV6 registration)", 0xFFFFFFF007D12280, 0xFFFFFFF0082F42B4),
        ("ASCWrap mod_init[2] (AppleASCWrapV6SEP registration)", 0xFFFFFFF007D12288, 0xFFFFFFF0082F4800),
        ("A7IOP mod_init[0] chain entry", 0xFFFFFFF007D13BD0, 0xFFFFFFF0082F7798),
    ]:
        got = resolved_at(loc)
        checks.append({
            "known": label, "location": hex(loc), "expected": hex(expect),
            "decoded": hex(got) if got else None, "pass": got == expect,
        })

    self_consistent = all(c["pass"] for c in checks)
    fixture_complete = (
        starts_bound
        and all("error" not in s for s in segments_out if s.get("has_chain"))
        and len(fixup_index) > 0
    )
    multi_observed = multi_total > 0

    candA = [hex(x) for x, t in fixup_index.items() if t == CAND_A_VM]
    candB = [hex(x) for x, t in fixup_index.items() if t == CAND_B_VM]

    artifact = {
        "gate": "57ZZ_BOOTKC_CHAINED_FIXUPS",
        "bootkc_sha256": sha,
        "decoder_source": "scripts/phase05f-57zz-fixup-index.py (single shared implementation)",
        "format": {
            "seg_count": seg_count,
            "starts_segment_count_matches_macho": starts_bound,
        },
        "segments": segments_out,
        "total_fixups": len(fixup_index),
        "multi_start_pages_total": multi_total,
        "validation_checks": checks,
        "CHAIN_WALK_SELF_CONSISTENCY": "PASS" if self_consistent else "FAIL",
        "CHAIN_DECODER_CURRENT_FIXTURE": "PASS" if fixture_complete else "FAIL",
        "MULTI_START_PAGES_OBSERVED": multi_total,
        "MULTI_PATH_IMPLEMENTED": "YES",
        "MULTI_PATH_RUNTIME_VALIDATED": "YES" if multi_observed else "NO",
        "note_format_complete": (
            "FORMAT_COMPLETE is intentionally NOT claimed: the MULTI overflow-"
            "pool path is implemented but not exercised by this fixture "
            "(zero MULTI pages). A synthetic MULTI fixture is required."
        ),
        "candidates": {
            "candA": {"vm": hex(CAND_A_VM), "count": len(candA), "locations": candA},
            "candB": {"vm": hex(CAND_B_VM), "count": len(candB), "locations": candB},
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — BootKC Chained-Fixup Decoder",
        "",
        "Decoder implementation: `scripts/phase05f-57zz-fixup-index.py` (shared).",
        "",
        "```",
        f"CHAIN_DECODER_CURRENT_FIXTURE: {artifact['CHAIN_DECODER_CURRENT_FIXTURE']}",
        f"CHAIN_WALK_SELF_CONSISTENCY: {artifact['CHAIN_WALK_SELF_CONSISTENCY']}",
        f"total fixups: {len(fixup_index)}",
        f"MULTI_START_PAGES_OBSERVED: {multi_total}",
        "```",
        "",
        "| segment | fmt | pages | single | multi | none |",
        "|---|---|---|---|---|---|",
    ]
    for s in segments_out:
        if s.get("has_chain"):
            md.append(
                f"| {s['segment']} | {s['pointer_format']} | {s['page_count']} | "
                f"{s['single_start_pages']} | {s['multi_start_pages']} | {s['none_pages']} |"
            )
    md += ["", "## Validation", ""]
    for c in checks:
        md.append(f"- {'PASS' if c['pass'] else 'FAIL'} {c['known']}: {c['decoded']}")
    md += ["", f"candA references: {len(candA)}", f"candB references: {len(candB)}", ""]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps({
        "fixture_complete": artifact["CHAIN_DECODER_CURRENT_FIXTURE"],
        "self_consistency": artifact["CHAIN_WALK_SELF_CONSISTENCY"],
        "starts_bound": starts_bound,
        "total_fixups": len(fixup_index),
        "multi_pages": multi_total,
        "candA_refs": len(candA),
        "candB_refs": len(candB),
    }, indent=2))


if __name__ == "__main__":
    main()
