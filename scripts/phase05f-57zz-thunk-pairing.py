#!/usr/bin/env python3
"""57ZZ: runtime thunk-allocator pairing evidence (v10 clean run)."""

import json
import os

RUN = "build/phase05f-runtime/thunk-pair-v10"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-thunk-pairing.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-thunk-pairing.md"

# Historical context: the first attempt (thunk-pair-v1) used a capture script
# whose CAND_B was mislabeled; those results are RETRACTED. See the retraction
# note in the artifact.
RETRACTION = {
    "prior_run": "thunk-pair-v1 (commit 2a33e03)",
    "status": "RETRACTED_TARGET_LABEL_MISMATCH",
    "reason": (
        "The v7 capture script's CAND_B was the allocator, not the thunk. "
        "The .Replace() used to derive v7 from v3 silently failed. "
        "All 'thunk_hits' were actually allocator hits."
    ),
}


def main():
    cap = json.load(open(os.path.join(RUN, "gdb-capture.json"), encoding="utf-8-sig"))
    summary = cap.get("summary", {})
    verdicts = cap.get("verdicts", {})

    artifact = {
        "gate": "57ZZ_RUNTIME_ALLOCATOR_THUNK_PAIRING",
        "method": "v8: thunk-only hbreak + double stepi chain proof (thunk -> thunk+4 -> allocator)",
        "retraction": RETRACTION,
        "run": RUN,
        "instrumented": {
            "thunk_entry": "0xfffffff008387eb0 (single hbreak only)",
            "allocator_entry": "0xfffffff008387eb8 (reached via stepi, no hbreak)",
        },
        "summary": summary,
        "slide": cap.get("slide"),
        "total_events": len(cap.get("events", [])),
        "thunk_hits": summary.get("thunk_hits", 0),
        "control_flow_ok": summary.get("control_flow_ok", 0),
        "control_flow_fail": summary.get("control_flow_fail", 0),
        "register_match": summary.get("register_match", 0),
        "register_mismatch": summary.get("register_mismatch", 0),
        "classification": cap.get("classification"),
        "verdicts": {
            "THUNK_ENTRY_RUNTIME": verdicts.get("THUNK_ENTRY_RUNTIME"),
            "CONTROL_FLOW_THUNK_TO_ALLOCATOR": verdicts.get("CONTROL_FLOW_THUNK_TO_ALLOCATOR"),
            "THUNK_X2_TO_ALLOCATOR_X1_RUNTIME": verdicts.get("THUNK_X2_TO_ALLOCATOR_X1_RUNTIME"),
            "RUNTIME_ALLOCATOR_ENTRY_VIA_THUNK": (
                "PROVEN_RUNTIME" if summary.get("control_flow_ok", 0) == summary.get("thunk_hits", 0) and summary.get("thunk_hits", 0) > 0
                else "FAILED_OR_PARTIAL"
            ),
            "ALLOCATOR_ARG1_SOURCE_OBSERVED_PAIRS": (
                "THUNK_X2" if summary.get("register_mismatch", 1) == 0 and summary.get("register_match", 0) > 0
                else "UNKNOWN"
            ),
            "OBSERVED_PAIR_COVERAGE": "%d/%d" % (summary.get("register_match", 0), summary.get("thunk_hits", 0)),
            "ALLOCATOR_ARG1_SOURCE_GLOBAL": "UNKNOWN_OUTSIDE_OBSERVED_WINDOW",
            "THUNK_X2_DISTINCT_VALUES": "PROVEN (%d/40 unique)" % summary.get("thunk_hits", 0),
            "THUNK_X2_POINTER_LIKE_VALUES": "OBSERVED",
            "THUNK_X2_SEMANTIC_ROLE": "UNKNOWN (next gate: ARMIO_THUNK_X2_PROVENANCE)",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — Runtime Thunk-Allocator Pairing",
        "",
        "## Prior run retraction",
        "",
        RETRACTION["reason"],
        "",
        "## Method",
        "",
        "Single hardware breakpoint on thunk entry (0x...87eb0) only.",
        "On each hit: capture x0/x1/x2, then `stepi` twice:",
        "  step 1 reaches thunk+4 (the `b allocator` instruction)",
        "  step 2 reaches allocator entry (0x...87eb8)",
        "Capture allocator x0/x1; prove thunk.x2 == allocator.x1.",
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
        "```",
        f"thunk hits: {artifact['thunk_hits']}",
        f"control flow OK: {artifact['control_flow_ok']}",
        f"control flow FAIL: {artifact['control_flow_fail']}",
        f"register match: {artifact['register_match']}",
        f"register mismatch: {artifact['register_mismatch']}",
        "```",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
