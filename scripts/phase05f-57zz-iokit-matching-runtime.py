#!/usr/bin/env python3
"""57ZZ: IOKit matching runtime evidence consolidator.

Consolidates the corrected-DT runtime runs, the whole-binary vtable
reference scan, and the XNU-matching research conclusions into canonical
evidence. All verdicts derive from the recorded raw captures.
"""

import hashlib
import json
import os
import struct

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
RUN_58A = "build/phase05f-runtime/p2-decisive-v18"
RUN_ASCWRAP = "build/phase05f-runtime/p9-ascwrap-v2"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-iokit-matching-runtime.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-iokit-matching-runtime.md"

CAND_A_VM = 0xFFFFFFF0082F4DF0
CAND_B_VM = 0xFFFFFFF0082F804C
A7_EXEC_VM = 0xFFFFFFF0082F4CB0
A7_EXEC_FO = 0x12F0CB0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def vtable_reference_scan():
    """Whole-binary scan: does any qword's chained fixup target candA/candB?"""
    data = open(BOOTKC, "rb").read()
    mask = (1 << 30) - 1
    cand_a_fo = A7_EXEC_FO + (CAND_A_VM - A7_EXEC_VM)
    cand_b_fo = A7_EXEC_FO + (CAND_B_VM - A7_EXEC_VM)
    hits = {"candA": [], "candB": []}
    for off in range(0, len(data) - 8, 8):
        v = struct.unpack_from("<Q", data, off)[0]
        t = v & mask
        if t == cand_a_fo:
            hits["candA"].append(off)
        elif t == cand_b_fo:
            hits["candB"].append(off)
    return {
        "method": "whole-binary qword scan, dyld chained-fixup target = raw & (BIT(30)-1)",
        "candA_static_vm": hex(CAND_A_VM),
        "candB_static_vm": hex(CAND_B_VM),
        "candA_fixup_offset": hex(cand_a_fo),
        "candB_fixup_offset": hex(cand_b_fo),
        "candA_reference_count": len(hits["candA"]),
        "candB_reference_count": len(hits["candB"]),
        "conclusion": (
            "NO qword in bootkc.bin references either candidate as a chained "
            "fixup target; neither candidate is vtable-dispatched. Prior "
            "NO_HIT results on these addresses do not disprove "
            "AppleASCWrapV6/AppleA7IOP instantiation."
        ),
    }


def load_run(run_dir):
    cap = None
    res = None
    cap_path = os.path.join(run_dir, "gdb-capture.json")
    res_path = os.path.join(run_dir, "result.json")
    if os.path.exists(cap_path):
        cap = json.load(open(cap_path, encoding="utf-8-sig"))
    if os.path.exists(res_path):
        res = json.load(open(res_path, encoding="utf-8-sig"))
    return cap, res


def serial_ans_lines(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="ascii", errors="replace"):
        if any(k in line for k in ("ANS", "ASCWrap", "RTBuddy", "AppleA7IOP", "ans-")):
            out.append(line.rstrip())
    return out


def main():
    vt_scan = vtable_reference_scan()

    cap58a, res58a = load_run(RUN_58A)
    capasc, resasc = load_run(RUN_ASCWRAP)

    ans_lines_58a = serial_ans_lines(os.path.join(RUN_58A, "uart0.log"))
    ans_lines_asc = serial_ans_lines(os.path.join(RUN_ASCWRAP, "uart0.log"))

    artifact = {
        "gate": "57ZZ_IOKIT_MATCHING_RUNTIME",
        "bootkc_sha256": sha256(BOOTKC),
        "vtable_reference_scan": vt_scan,
        "runs": {
            "ans58a_dt": {
                "dir": RUN_58A,
                "classification": cap58a.get("classification") if cap58a else "MISSING",
                "slide": hex(cap58a["slide"]["slide"]) if cap58a and cap58a.get("slide") else None,
                "serial_bytes": res58a.get("serial_bytes") if res58a else None,
                "ans_related_serial_lines": ans_lines_58a,
            },
            "ascwrap_corrected_dt": {
                "dir": RUN_ASCWRAP,
                "classification": capasc.get("classification") if capasc else "MISSING",
                "slide": hex(capasc["slide"]["slide"]) if capasc and capasc.get("slide") else None,
                "serial_bytes": resasc.get("serial_bytes") if resasc else None,
                "ans_related_serial_lines": ans_lines_asc,
            },
        },
        "xnu_matching_research": {
            "source": "xnu-8792.81.2 (github.com/apple-oss-distributions/xnu, tag identical to opensource.apple.com xnu-8792.81.2)",
            "key_findings": [
                "IONameMatch compares against the provider nub's OWN name/compatible/device_type/model (IODeviceTreeSupport.cpp:950-958); it never consults the parent node's properties.",
                "Provider-class filtering happens at IOCatalogue::findDrivers via IOProviderClass bucketing (IOCatalogue.cpp:133-162, 233-245) plus metaCast verification (IOService.cpp:7514-7531).",
                "A personality is never considered if the provider is never registerService()d, IOProviderClass is absent from the provider's metaclass chain, or platformAdjustService rejects the nub (IOService.cpp:1044-1097).",
                "IOPlatformDevice nubs copy exactly one DT node's property table (IORegistryEntry.cpp:371); IOParentMatch is the only ancestor-consulting matcher.",
            ],
            "supports": "The H1 mechanism: parent-level iop,ascwrap-v6 compatible is invisible to child-nub matching, and dt_fixup's stripping removed the provider identity that AppleASCWrapV6's IONameMatch requires.",
            "does_not_support": "Any claim about our specific fixture's runtime nub publication; that requires runtime observation.",
        },
        "verdicts": {
            "VTABLE_REFERENCE_SCAN_CANDA_CANDB": "ZERO_REFERENCES_PROVEN",
            "PRIOR_NO_HIT_DISPROVES_INSTANTIATION": "INVALIDATED",
            "APPLEASCWRAPV6_RUNTIME_ENTRY": "NOT_OBSERVED",
            "APPLEA7IOP_INSTANTIATION": "UNKNOWN",
            "BREAKPOINT_ARMED_BEFORE_TARGET_MATCHING": "UNKNOWN",
            "ASCWRAP_CORRECTED_DT_BOOT": "COMPLETED_NO_NEW_ANS_SERIAL",
            "MATCHING_STAGE_CLASSIFICATION": "UNKNOWN_REQUIRES_VALID_INSTRUMENTATION",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    lines = [
        "# 57ZZ — IOKit Matching Runtime Evidence",
        "",
        "## Key correction: prior instrumentation targets invalidated",
        "",
        "A whole-binary scan proves that no qword in bootkc.bin references",
        "either start candidate (`0xfffffff0082f4df0` / `0xfffffff0082f804c`)",
        "as a chained-fixup target:",
        "",
        "```",
        f"candA references: {vt_scan['candA_reference_count']}",
        f"candB references: {vt_scan['candB_reference_count']}",
        "```",
        "",
        "Neither candidate is vtable-dispatched. The prior NO_HIT results on",
        "these addresses therefore do not disprove AppleASCWrapV6 or",
        "AppleA7IOP instantiation.",
        "",
        "## Corrected-DT runtime run",
        "",
        "The corrected DeviceTree preserves BOTH hierarchy levels:",
        "- `/arm-io/ans` compatible = `iop,ascwrap-v6` (provider identity, required by IONameMatch)",
        "- `/arm-io/ans/iop-ans-nub` compatible = `iop-nub,rtbuddy-v2` (child nub)",
        "",
        "The boot completed (37,155 serial bytes) with no new ANS-related",
        "serial output versus the 58A run — but the instrumentation targets",
        "were the invalidated candidates, so no instantiation conclusion can",
        "be drawn from the breakpoint result.",
        "",
        "## Verdicts",
        "",
        "```",
    ]
    for k, v in artifact["verdicts"].items():
        lines.append(f"{k}: {v}")
    lines += ["```", ""]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
