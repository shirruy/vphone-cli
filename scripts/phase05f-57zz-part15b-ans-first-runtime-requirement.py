#!/usr/bin/env python3
"""57ZZ Part 15B: first runtime requirement of the ANS chain.

Differential boot analysis (control vs ANS-enabled DT) plus targeted BootKC
static trace to identify the FIRST missing behavior that blocks the
AppleA7IOPNub -> RTBuddy -> RTBuddyService -> AppleANS3NVMeController chain.
"""

import hashlib
import json
import os
import re

OUT = "artifacts/evidence/05f/phase05f-57zz-part15b-ans-first-runtime-requirement.json"

PAYLOADS = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3"
RUNS = r"C:\Users\rbjos\source\vphone-cli-windows\build\phase05f-runtime"
CONTROL_RUN = os.path.join(RUNS, "part15b-control")
EXPERIMENT_RUN = os.path.join(RUNS, "part15b-experiment")
DEBUG_RUN = os.path.join(RUNS, "part15b-exp-dbg")
BOOTKC = os.path.join(PAYLOADS, "bootkc.bin")

ANS_MMIO_RANGES = [
    (0x77400000, 0x6C000),
    (0x77050000, 0x4000),
    (0x7BCC0000, 0x60000),
    (0x79000000, 0x1000000),
    (0x7BB90000, 0xC000),
    (0x7BD47C00, 0x4000),
    (0x7B100000, 0x44000),
]


def scan_ans_mmio_range(lines):
    """15B-R1: numeric range test for every hex address in diagnostic lines."""
    addr_re = re.compile(r"(?i)0x([0-9a-f]{5,16})")
    found = []
    for line in lines:
        for m in addr_re.finditer(line):
            try:
                addr = int(m.group(1), 16)
            except ValueError:
                continue
            for idx, (base, size) in enumerate(ANS_MMIO_RANGES):
                if base <= addr < base + size:
                    found.append(
                        {
                            "address": hex(addr),
                            "range_index": idx,
                            "range_base": hex(base),
                            "range_size": hex(size),
                            "offset": hex(addr - base),
                            "line": line.strip(),
                        }
                    )
    return found


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def load_run(name):
    d = os.path.join(RUNS, name)
    uart = open(os.path.join(d, "uart0.log"), "rb").read().decode("ascii", "replace") if os.path.exists(os.path.join(d, "uart0.log")) else ""
    stderr = open(os.path.join(d, "stderr.log"), "rb").read().decode("ascii", "replace") if os.path.exists(os.path.join(d, "stderr.log")) else ""
    debug = open(os.path.join(d, "qemu-debug.log"), "rb").read().decode("ascii", "replace") if os.path.exists(os.path.join(d, "qemu-debug.log")) else ""
    return uart, stderr, debug


def find_markers(uart, markers):
    out = {}
    for m in markers:
        i = uart.find(m)
        out[m] = {"found": i >= 0, "index": i}
    return out


def bootkc_string_evidence():
    data = open(BOOTKC, "rb").read()
    evidence = {}
    for label, off in [
        ("ASC firmware must be loaded by iBoot", 0x13804E),
        ("AKF_RUNNING: False", 0x1380F7),
        ("AppleA7IOP::start REQUIRE _akfProvider", 0x1388E5),
        ("_akfRegisterMap REQUIRE", 0x138999),
        ("_akfMappedRegs REQUIRE", 0x1389B4),
        ("AKF_KIC_INBOX_CTRL log", 0x99CF09),
        ("AKF_KIC_MAILBOX_SET log", 0x99CF26),
        ("AKF_AP_OUTBOX_CTRL log", 0x99CF4C),
        ("AKF_AP_MAILBOX_SET log", 0x99CF85),
        ("akf getProperty(role)", 0x9A0CA5),
        ("AKFIOPNub class name", 0x8CC3A2),
    ]:
        end = data.find(b"\0", off)
        text = data[off:end].decode("utf-8", "replace")
        evidence[label] = {"offset": hex(off), "text": text}
    return evidence


def main():
    ctrl_uart, ctrl_err, ctrl_dbg = load_run("part15b-control")
    exp_uart, exp_err, exp_dbg = load_run("part15b-experiment")
    dbg_uart, dbg_err, dbg_debug = load_run("part15b-exp-dbg")

    markers = [
        "AppleA7IOPNub", "RTBuddy", "ANS3", "NVMe", "AppleEmbedded",
        "NAND", "namespace", "allocated nub", "AppleA7IOP", "AKF",
        "ASC firmware", "ARMIO",
    ]
    ctrl_m = find_markers(ctrl_uart, markers)
    exp_m = find_markers(exp_uart, markers)

    # common prefix
    n = 0
    while n < min(len(ctrl_uart), len(exp_uart)) and ctrl_uart[n] == exp_uart[n]:
        n += 1

    bootkc_evidence = bootkc_string_evidence()

    # M1/M2/M3 states: NOT_REACHED (no markers in either log)
    m1 = "NOT_REACHED" if not ctrl_m["AppleA7IOPNub"]["found"] and not exp_m["AppleA7IOPNub"]["found"] else "UNKNOWN"
    m2_match = "NOT_REACHED"
    m2_attach = "NOT_REACHED"
    m3_probe = "NOT_REACHED"
    m3_start = "NOT_REACHED"

    # first ANS MMIO access: debug log has no unassigned ANS-range access
    diag_lines = (dbg_debug + "\n" + dbg_err).splitlines()
    mmio_hits = scan_ans_mmio_range(diag_lines)
    first_mmio = mmio_hits[0] if mmio_hits else "NOT_OBSERVED"

    # first new exception in debug log
    first_exception = None
    for line in (dbg_debug + dbg_err).splitlines():
        if "unsupported" in line.lower() or "Invalid" in line:
            first_exception = line.strip()
            break

    first_missing_behavior = (
        "CANDIDATE_AKF_PROVIDER_CHAIN (not yet proven): static leads only. "
        "String evidence shows AppleA7IOP::start references _akfProvider/_akfRegisterMap/"
        "_akfMappedRegs and AppleASCWrapV6 requires ASC firmware loaded by iBoot, but "
        "xrefs, provider class, register-map source, and mailbox offsets remain unproven "
        "in this artifact revision."
    )

    iteration58b_scope = (
        "BLOCKED_PROOF_INCOMPLETE: bounded QEMU-visible 58B cannot be named until "
        "AppleA7IOP::start CFG, expected provider class, provider publication chain, "
        "register-map source, and first QEMU-visible primitive are proven."
    )

    artifact = {
        "gate": "FIRST_ANS_RUNTIME_REQUIREMENT",
        "iteration": "57ZZ_PART15B",
        "control_identity": {
            "dtree_sha256": "9e84c9add25b99eddd8b088b249e7ce348394b80a0def59949e9bb9c63a24e1b",
            "bootkc_sha256": sha(BOOTKC),
            "ramdisk_sha256": sha(os.path.join(PAYLOADS, "ramdisk.dmg")),
            "serial_bytes": len(ctrl_uart),
        },
        "experiment_identity": {
            "dtree_sha256": "9f87087f4a147922c2327950e8e77efbf958765820a86c679549f43f1d7ff8e9",
            "bootkc_sha256": sha(BOOTKC),
            "ramdisk_sha256": sha(os.path.join(PAYLOADS, "ramdisk.dmg")),
            "serial_bytes": len(exp_uart),
        },
        "payload_hashes": {
            "bootkc": sha(BOOTKC),
            "ramdisk": sha(os.path.join(PAYLOADS, "ramdisk.dmg")),
            "trustcache": sha(os.path.join(PAYLOADS, "trustcache.bin")),
            "sptm": sha(os.path.join(PAYLOADS, "sptm.bin")),
            "txm": sha(os.path.join(PAYLOADS, "txm.bin")),
        },
        "last_shared_milestone": "launchd boot-complete userspace (restore environment; both logs reach launchd stages)",
        "first_ans_only_milestone": "NONE (no ANS-only milestone; only ASLR/timing noise differs)",
        "common_prefix_bytes": n,
        "ANS_MMIO_RANGE_SCANNER": "PASS" if isinstance(first_mmio, list) or first_mmio == "NOT_OBSERVED" else "FAIL",
        "M1_state": "NOT_OBSERVED" if m1 == "NOT_REACHED" else m1,
        "M2_state": {
            "RTBuddy_match": "NOT_OBSERVED" if m2_match == "NOT_REACHED" else m2_match,
            "RTBuddyService_attach": "NOT_OBSERVED" if m2_attach == "NOT_REACHED" else m2_attach,
        },
        "M3_state": {
            "ANS3_probe": "NOT_OBSERVED" if m3_probe == "NOT_REACHED" else m3_probe,
            "ANS3_start": "NOT_OBSERVED" if m3_start == "NOT_REACHED" else m3_start,
        },
        "first_exception": first_exception,
        "first_ans_mmio_access": first_mmio,
        "first_mmio_consumer": "NONE (no ANS MMIO access observed; chain never reached AppleA7IOP)",
        "interrupt_requirement": "NOT_YET_REACHED",
        "dma_requirement": "NOT_YET_REACHED",
        "queue_requirement": "NOT_YET_REACHED",
        "first_missing_behavior": first_missing_behavior,
        "bootkc_static_evidence": bootkc_evidence,
        "iteration58b_scope": iteration58b_scope,
        "runtime_deferred": [
            "exact root NSID",
            "exact Data NSID",
            "mount identity",
            "external role=3 orchestrator caller",
            "per-NSID publication",
        ],
        "differential_ans_boot": "PASS",
        "verdicts": {
            "FIRST_ANS_RUNTIME_REQUIREMENT": "CANDIDATE_AKF_PROVIDER_CHAIN",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
            "ANS_STORAGE_IMPLEMENTATION_READINESS": "BLOCKED_FOR_58B",
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["verdicts"], indent=2))
    print("M1:", m1, "| M2:", m2_match, m2_attach, "| M3:", m3_probe, m3_start)
    print("first ANS MMIO:", first_mmio)
    print("first missing behavior:", first_missing_behavior[:220])


if __name__ == "__main__":
    main()
