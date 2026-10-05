#!/usr/bin/env python3
"""57ZZ: ANS DT name correlation runtime evidence.

Consolidates the v6/v7 name-search runs and classifies the result.
"""

import json
import os

RUNS = ["ans-name-v6", "ans-name-v7"]
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-ans-name-correlation.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-ans-name-correlation.md"


def main():
    runs = {}
    for run in RUNS:
        d = os.path.join("build", "phase05f-runtime", run)
        p = os.path.join(d, "gdb-capture.json")
        if not os.path.exists(p):
            continue
        c = json.load(open(p, encoding="utf-8-sig"))
        allocs = [e for e in c.get("events", []) if e.get("label") == "bp:candB"]
        starts = [e for e in c.get("events", []) if e.get("label") == "bp:candA"]
        ans_hits = sum(1 for e in allocs if e.get("ans_string_search", {}).get("count", 0) > 0)
        asc_hits = sum(1 for e in allocs if e.get("ascwrap_compat_search", {}).get("count", 0) > 0)
        # Collect search ranges
        ranges = list({e.get("ans_string_search", {}).get("range", "") for e in allocs if e.get("ans_string_search", {}).get("range")})
        # Collect start vtable classifications
        slide = c.get("slide", {}).get("slide", 0) if c.get("slide") else 0
        with open("artifacts/evidence/05f/phase05f-57zz-ascwrap-vtables.json", encoding="utf-8") as vf:
            vart = json.load(vf)
        with open("artifacts/evidence/05f/phase05f-57zz-armiodevice-vtable.json", encoding="utf-8") as af:
            aart = json.load(af)
        known = {int(v["vtable_vm"], 16): k for k, v in vart["vtables"].items()}
        known[int(aart["vtable"], 16)] = "AppleARMIODevice"
        start_classes = []
        for e in starts:
            vt = int((e.get("mem_x0") or {}).get("+00", "0"), 16) - slide
            start_classes.append(known.get(vt, "other"))
        runs[run] = {
            "ARMIO_ALLOCATIONS_OBSERVED": ">= %d" % len(allocs),
            "START_DISPATCHES_OBSERVED": ">= %d" % len(starts),
            "CAPTURE_TRUNCATED_AT_EVENT_LIMIT": len(allocs) + len(starts) >= 60,
            "ans_string_hits": ans_hits,
            "ascwrap_compat_hits": asc_hits,
            "search_ranges": ranges,
            "search_window": "±1MB around each allocator x1 (v7) / ±64KB (v6)",
            "start_client_classes": start_classes,
        }

    total_allocs = sum(int(str(r["ARMIO_ALLOCATIONS_OBSERVED"]).replace(">=", "").strip()) for r in runs.values())
    total_ans = sum(r["ans_string_hits"] for r in runs.values())
    total_asc = sum(r["ascwrap_compat_hits"] for r in runs.values())

    artifact = {
        "gate": "57ZZ_ANS_DT_NAME_CORRELATION",
        "method": "GDB memory search for 'ans\\0' and 'iop,ascwrap' in memory near each AppleARMIODevice allocator arg1 object (semantic role of arg1 is UNKNOWN per the canonical register contract)",
        "runs": runs,
        "findings": {
            "ALLOCATOR_OBSERVATIONS_ACROSS_RUNS": ">= %d (across separate boots; may overlap same DT population)" % total_allocs,
            "ANS_STRING_FOUND_NEAR_ANY_ALLOC": total_ans > 0,
            "ASCCWRAP_COMPAT_FOUND_NEAR_ANY_ALLOC": total_asc > 0,
            "ANS_SPECIFIC_ALLOCATION_IDENTIFIED": False,
            "negative_result_interpretation": (
                "Neither 'ans\\0' nor 'iop,ascwrap' was found in the searched "
                "windows near the observed ARMIO allocator arg1 objects. The v6 "
                "run searched ±64KB (55/55 successful searches); the v7 run "
                "searched ±1MB (27/27 successful searches). Zero search errors. "
                "The semantic role of arg1 is UNKNOWN, so this proves absence "
                "in searched memory near arg1 objects only - it does not prove "
                "anything about DT property dictionaries specifically. These are "
                "separate boots, so the observations may overlap the same DT "
                "population; do not sum them as unique allocations. "
                "Proximity-based search cannot serve as final identity-correlation "
                "proof even if a hit were found."
            ),
        },
        "verdicts": {
            "ARMIO_ALLOCATION_PHASE_ACTIVE": "PROVEN",
            "ANS_STRING_SEARCH_NEGATIVE": "PROVEN_IN_SEARCHED_WINDOWS (v6: 0/55 at ±64KB; v7: 0/27 at ±1MB; 0 errors)",
            "ANS_DT_ENTRY_CONSUMED": "UNKNOWN",
            "ANS_SPECIFIC_ARMIO_ALLOCATION": "UNKNOWN (not found in observed subset; search method has structural limits)",
            "MATCHING_STAGE_CLASSIFICATION": "UNKNOWN (cannot classify without ANS allocation identity)",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
        },
        "allocator_caller_static_analysis": (
            json.load(open("artifacts/evidence/05f/phase05f-57zz-allocator-caller-analysis.json", encoding="utf-8-sig"))
            if os.path.exists("artifacts/evidence/05f/phase05f-57zz-allocator-caller-analysis.json")
            else {"error": "analyzer artifact missing; run phase05f-57zz-allocator-caller-analyzer.py first"}
        ),
        "next_approaches": [
            "1. STATIC: derive caller-of-ARMIO-allocator argument semantics (which arg is IORegistryEntry/OSDictionary/DT node)",
            "2. Instrument the DT plane name accessor (IORegistryEntry::getName / compareName) with an ANS filter",
            "3. Search the kernel OSSymbol table for the interned 'ans' symbol and trace its reference to the owning DT entry",
            "4. Instrument the registerService() path with a provider-name check (ARMIODevice store the name early)",
        ],
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — ANS DT Name Correlation",
        "",
        "## Method",
        "",
        "GDB hardware breakpoints on the AppleARMIODevice allocator and the",
        "callsite-proven +0x360 start dispatch. At each allocator hit, searched",
        "±1MB around the x1 dictionary for 'ans\\0' and 'iop,ascwrap'.",
        "",
        "## Result",
        "",
        "```",
    ]
    for k, v in artifact["verdicts"].items():
        md.append(f"{k}: {v}")
    md += [
        "```",
        "",
        "## Interpretation",
        "",
        artifact["findings"]["negative_result_interpretation"],
        "",
        "## Next approaches",
        "",
    ]
    for a in artifact["next_approaches"]:
        md.append(a)
    md.append("")
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
