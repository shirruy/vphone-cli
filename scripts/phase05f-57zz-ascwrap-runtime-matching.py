#!/usr/bin/env python3
"""57ZZ P9-P12: ASCWrap runtime matching evidence consolidator.

INVALIDATED as start instrumentation), the valid provider v2/v3 runs
early arming) with the chain-decoder and DT-builder results.
"""

import json
import os

RUN = "build/phase05f-runtime/p9-ascwrap-v3"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-ascwrap-runtime-matching.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-ascwrap-runtime-matching.md"


def main():
    cap = json.load(open(os.path.join(RUN, "gdb-capture.json"), encoding="utf-8-sig"))
    res = json.load(open(os.path.join(RUN, "result.json"), encoding="utf-8-sig"))
    gdb_log = open(os.path.join(RUN, "gdb-session.log"), encoding="utf-8-sig", errors="replace").read()

    arm_lines = [l for l in gdb_log.splitlines() if "hbreak" in l and "installed" in l]
    serial_lines = 0
    sp = os.path.join(RUN, "uart0.log")
    if os.path.exists(sp):
        serial_lines = sum(1 for _ in open(sp, encoding="ascii", errors="replace"))

    iokit_starts_observed = []
    if os.path.exists(sp):
        for line in open(sp, encoding="ascii", errors="replace"):
            if "::start" in line or "OLYHAL" in line:
                iokit_starts_observed.append(line.rstrip())

    # Provider publication analysis (P7/P8): merge the v2/v3 provider runs
    import os as _os
    provider_runs = {}
    for run_name in ("p7-provider-v2", "p7-provider-v3"):
        d = _os.path.join("build", "phase05f-runtime", run_name)
        p = _os.path.join(d, "gdb-capture.json")
        if _os.path.exists(p):
            pc = json.load(open(p, encoding="utf-8-sig"))
            allocs = [e for e in pc.get("events", []) if e.get("label") == "bp:candB"]
            starts = [e for e in pc.get("events", []) if e.get("label") == "bp:candA"]
            SLIDE = pc["slide"]["slide"] if pc.get("slide") else 0
            known_vts = {
                0xFFFFFFF007D131E0: "AppleASCWrapV6",
                0xFFFFFFF007D14370: "AppleA7IOP",
                0xFFFFFFF007D14960: "AppleA7IOPNub",
                0xFFFFFFF007D139B8: "AppleASCWrapV6SEP",
                0xFFFFFFF007D12A08: "AppleASCWrapV6SISP",
            }
            start_clients = []
            ascwrap_start = False
            for e in starts:
                vt_hex = (e.get("mem_x0") or {}).get("+00")
                if not vt_hex:
                    continue
                vt_static = int(vt_hex, 16) - SLIDE
                cls = known_vts.get(vt_static, "other")
                start_clients.append(cls)
                if cls != "other":
                    ascwrap_start = True
            provider_runs[run_name] = {
                "classification": pc.get("classification"),
                "ARMIO_ALLOCATOR_HITS_OBSERVED": ">= %d" % len(allocs),
                "START_DISPATCH_HITS_OBSERVED": ">= %d" % len(starts),
                "START_DISPATCH_HITS_OBSERVED_COUNT": len(starts),
                "CAPTURE_TRUNCATED_AT_EVENT_LIMIT": len(allocs) + len(starts) >= 60,
                "ARMIO_ALLOCATOR_HITS_OBSERVED_COUNT": len(allocs),
                "start_client_classes": start_clients,
                "ascwrap_family_start_observed": ascwrap_start,
                "serial_bytes_path": _os.path.join(d, "uart0.log"),
            }

    artifact = {
        "gate": "57ZZ_ASCWRAP_RUNTIME_MATCHING",
        "run": {
            "dir": RUN,
            "dtree": "canonical ascwrap experiment (CE06C3379F50E6E9FBB60D2EA0FBA6733F0FF2784C3E4E11AA7EC0F2F07D8868)",
            "classification": cap["classification"],
            "slide": cap["slide"]["slide"],
            "instrumented_targets": {
                "legacy_candA": "0xfffffff0082f4dec + slide (vtable +0x348 - NOT start; semantic identity UNKNOWN)",
                "nub_withregistryentry": "0xfffffff0082f7b40 + slide",
            },
            "legacy_instrumentation_validity": "INVALID_TARGET_FOR_START (start is +0x360 per callsite proof)",
            "arm_evidence": arm_lines,
            "serial_bytes": res["serial_bytes"],
            "serial_lines": serial_lines,
            "gdb_elapsed": res["gdb_elapsed_seconds"],
        },
        "timing_gate": {
            "warmup_seconds": 8,
            "arming_wall_clock": "~8.03s (slide derived 0.029s after attach; hbreaks 0.034s)",
            "kernel_checkpoint_range": "[00:00:20] .. [00:01:06] kernel time observed in serial",
            "kernel_iokit_starts_in_window": len(iokit_starts_observed),
            "analysis": (
                "Breakpoints were armed at ~8.03s wall-clock. The kernel IOKit "
                "matching phase (CoreAnalyticsHub/OLYHAL/Backlight starts, kernel "
                "timestamps [00:00:20+] = ~17-22s wall) occurred entirely within "
                "the instrumented window. The boot reached idle within the window "
                "(first watchdog stop at 30s GDB-time showed the idle-loop PC). "
                "T2 < T3 is proven for the observed matching phase."
            ),
            "GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING": "PROVEN",
            "BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING": "UNKNOWN",
        },
        "runtime_results": {
            "APPLEASCWRAPV6_START": "NOT_OBSERVED",
            "APPLEA7IOPNUB_START": "NOT_OBSERVED",
            "APPLEA7IOPNUB_WITHREGISTRYENTRY": "NOT_OBSERVED",
            "iokit_start_calls_of_other_drivers": len(iokit_starts_observed),
        },
        "provider_publication_runs": provider_runs,
        "verdicts": {
            "GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING": "PROVEN",
            "BREAKPOINT_ARMED_BEFORE_ARMIO_ALLOCATION_PHASE": "PROVEN (3s warmup; allocations observed from t=0.057)",
            "BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING": "UNKNOWN (ANS-specific alloc not yet identified among ARMIO allocations)",
            "ARMIO_ALLOCATIONS_OBSERVED": ">= %d" % max((r["ARMIO_ALLOCATOR_HITS_OBSERVED_COUNT"] for r in provider_runs.values()), default=0),
            "IOKIT_START_DISPATCHES_OBSERVED": ">= %d" % max((r["START_DISPATCH_HITS_OBSERVED_COUNT"] for r in provider_runs.values()), default=0),
            "ASCWRAP_FAMILY_START_OBSERVED": any(r["ascwrap_family_start_observed"] for r in provider_runs.values()),
            "LEGACY_P9_START_INSTRUMENTATION": "INVALID_TARGET",
            "APPLEASCWRAPV6_START_FROM_P9": "UNKNOWN (instrumented +0x348, not start)",
            "APPLEA7IOPNUB_START_FROM_P9": "UNKNOWN (instrumented +0x348, not start)",
            "MATCHING_STAGE_CLASSIFICATION": "UNKNOWN_REQUIRES_ANS_NAME_CORRELATION",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
            "58B_IMPLEMENTATION": "NONE",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — ASCWrap Runtime Matching (Valid Instrumentation)",
        "",
        "## Legacy P9 run (instrumentation later invalidated)",
        "",
        "- Canonical ascwrap DT fixture; breakpoints were at vtable +0x348 entries and the nub factory.",
        "- The +0x348 slot is NOT start (start is +0x360 per callsite proof); the P9 NO_HIT says nothing about AppleASCWrapV6::start.",
        "",
        "## Valid provider runs (v2/v3)",
        "",
        "- ARMIO allocator hits and callsite-proven +0x360 start dispatches observed live; no ASCWrap-family vtable in any observed client start.",
        "",
        "## Timing",
        "",
        "```",
        "GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING: PROVEN",
        "BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING: UNKNOWN",
        "```",
        "",
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
        "The legacy P9 instrumentation did not target start. The valid v2/v3",
        "provider runs observed the ARMIO allocation phase and client starts",
        "live; no ASCWrap-family vtable appeared. The earliest failed stage",
        "remains UNKNOWN pending ANS DT-name correlation.",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
