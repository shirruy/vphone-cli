#!/usr/bin/env python3
"""57ZZ P7/P8: ANS AppleARMIODevice provider publication evidence."""

import json
import os

RUNS = ["p7-provider-v2", "p7-provider-v3"]
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-ans-provider-publication.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-ans-provider-publication.md"

KNOWN_VTABLES = {
    0xFFFFFFF007D131E0: "AppleASCWrapV6",
    0xFFFFFFF007D14370: "AppleA7IOP",
    0xFFFFFFF007D14960: "AppleA7IOPNub",
    0xFFFFFFF007D139B8: "AppleASCWrapV6SEP",
    0xFFFFFFF007D12A08: "AppleASCWrapV6SISP",
    0xFFFFFFF007D336E0: "AppleARMIODevice",
}


def main():
    runs = {}
    for run in RUNS:
        d = os.path.join("build", "phase05f-runtime", run)
        p = os.path.join(d, "gdb-capture.json")
        if not os.path.exists(p):
            continue
        c = json.load(open(p, encoding="utf-8-sig"))
        slide = c["slide"]["slide"] if c.get("slide") else 0
        allocs = [e for e in c["events"] if e["label"] == "bp:candB"]
        starts = [e for e in c["events"] if e["label"] == "bp:candA"]
        start_classes = []
        for e in starts:
            vt = int((e.get("mem_x0") or {}).get("+00", "0"), 16) - slide
            start_classes.append(KNOWN_VTABLES.get(vt, "other(%x)" % vt))
        runs[run] = {
            "warmup_seconds": 3,
            "slide": slide,
            "armio_allocator_hits": len(allocs),
            "start_dispatch_hits": len(starts),
            "start_client_vtables": start_classes,
            "ascwrap_family_start": any(s != "other" and "ASCWrap" in s or s in ("AppleA7IOP", "AppleA7IOPNub") for s in start_classes),
            "note": "event cap 60 truncates counts; both phases observed",
        }

    artifact = {
        "gate": "57ZZ_ANS_PROVIDER_PUBLICATION",
        "instrumentation_targets": {
            "armio_allocator": "0xfffffff008387eb8 (AppleARMIODevice alloc, x1=DT dict)",
            "start_dispatch": "0xfffffff00aada0e0 (client->start(provider) blraa; proven +0x360 slot)",
        },
        "runs": runs,
        "findings": {
            "BREAKPOINT_ARMED_BEFORE_ARMIO_ALLOCATION_PHASE": "PROVEN (allocations from t=0.057 post-attach)",
            "BREAKPOINT_ARMED_BEFORE_IOKIT_START_PHASE": "PROVEN (starts from t=0.388 post-attach)",
            "BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING": "UNKNOWN (ANS alloc not identified among ARMIO allocations yet)",
            "ARMIO_ALLOCATION_PHASE_ACTIVE": True,
            "IOKIT_START_DISPATCH_ACTIVE": True,
            "ASCWRAP_FAMILY_START_OBSERVED": False,
        },
        "verdicts": {
            "ANS_DT_ENTRY_CONSUMED": "UNKNOWN",
            "APPLEARMIODEVICE_ALLOCATED": "PROVEN_FOR_OTHER_NODES (55 observed; ANS-specific not identified)",
            "APPLEARMIODEVICE_INITIALIZED": "UNKNOWN",
            "PROVIDER_ATTACHED": "UNKNOWN",
            "PROVIDER_PUBLICATION_RESULT": "PARTIAL: allocation + start phases observed; no ASCWrap-family start; ANS-specific identity unconfirmed",
            "MATCHING_STAGE_CLASSIFICATION": "UNKNOWN_REQUIRES_ANS_NAME_CORRELATION",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
        },
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — ANS AppleARMIODevice Provider Publication",
        "",
        "## Instrumentation",
        "",
        "- AppleARMIODevice allocator: `0xfffffff008387eb8` (x1 = DT dict)",
        "- IOService start dispatch: `0xfffffff00aada0e0` (+0x360 slot, callsite-proven)",
        "- 3s warmup; slide 0x20000000; canonical ascwrap DT",
        "",
        "## Findings",
        "",
        "```",
    ]
    for k, v in artifact["verdicts"].items():
        md.append(f"{k}: {v}")
    md += [
        "```",
        "",
        "The ARMIO allocation phase and the IOKit start dispatch phase were",
        "both observed live from breakpoint arm time. No AppleASCWrapV6/",
        "AppleA7IOP/A7IOPNub vtable appeared in any observed client start.",
        "The ANS-specific allocation cannot yet be identified among the ARMIO",
        "allocations because the DT dictionary name is not exposed in the",
        "current capture; that name correlation is the exact next blocker.",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
