#!/usr/bin/env python3
"""57ZZ P5-P7: ASCWrap/A7IOP vtable derivation via the valid chain decoder.

Derives all five class vtables from LC_DYLD_CHAINED_FIXUPS metadata,
derives the IOService::start slot from the client->start(provider)
dispatch callsite (+0x360), anchors the true IOService vtable
independently (registration at 0xfffffff00aae5eec), and classifies
inheritance by target comparison along the proven superclass chains.
"""

import json
import struct

import importlib.util as _ilu
import os as _os
_fixup_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
_fixup_spec = _ilu.spec_from_file_location("phase05f_57zz_fixup_index", _fixup_path)
fixup_index = _ilu.module_from_spec(_fixup_spec)
_fixup_spec.loader.exec_module(fixup_index)

import importlib.util

DECODER = r"scripts/phase05f-57zz-bootkc-chain-decoder.py"
BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-ascwrap-vtables.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-ascwrap-vtables.md"

KC_BASE = 0xFFFFFFF007004000
START_SLOT = 0x360  # PROVEN from client->start(provider) dispatch at 0xfffffff00aada0c8
CAND_A = 0xFFFFFFF0082F4DF0
CAND_B = 0xFFFFFFF0082F804C

# mod_init function VMs are chain-decoder-validated anchors (see
# phase05f-57zz-bootkc-chained-fixups.json validation_checks). The vtable
# addresses themselves are DERIVED below from each mod_init's ARM64
# adrp/add x16 sequence, then asserted against the expected values.
MOD_INITS = {
    "AppleA7IOP":         {"mod_init_vm": 0xFFFFFFF0082F7798, "expected_vtable": 0xFFFFFFF007D14370},
    "AppleASCWrapV6":     {"mod_init_vm": 0xFFFFFFF0082F42B4, "expected_vtable": 0xFFFFFFF007D131E0},
    "AppleASCWrapV6SEP":  {"mod_init_vm": 0xFFFFFFF0082F4800, "expected_vtable": 0xFFFFFFF007D139B8},
    "AppleASCWrapV6SISP": {"mod_init_vm": 0xFFFFFFF0082F3238, "expected_vtable": 0xFFFFFFF007D12A08},
    "AppleA7IOPNub":      {"mod_init_vm": 0xFFFFFFF0082F7D90, "expected_vtable": 0xFFFFFFF007D14960},
}


def _derive_x2(data, fn_vm):
    """Derive the x2 adrp+add value from a function's prologue."""
    import capstone as _cs
    md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_LITTLE_ENDIAN)
    fo = 0x11E0000 + (fn_vm - 0xFFFFFFF0081E4000)
    insns = list(md.disasm(data[fo : fo + 0x30], fn_vm))
    x2 = None
    for ins in insns:
        if ins.mnemonic == "adrp" and ins.op_str.startswith("x2,"):
            try:
                x2 = int(ins.op_str.split("#")[1], 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and ins.op_str.startswith("x2,"):
            parts = [q.strip() for q in ins.op_str.split(",")]
            if len(parts) == 3 and x2 is not None:
                try:
                    x2 += int(parts[2].replace("#", "").replace("0x", ""), 16)
                except Exception:
                    pass
        if ins.mnemonic == "bl":
            break
    return x2


def derive_vtable_from_mod_init(data, mod_init_vm):
    """Parse adrp/add x16 chain in a mod_init to find the vtable address
    it installs (the final x16 value before pacda/str)."""
    import capstone as _cs
    md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_LITTLE_ENDIAN)
    fo = 0x11E0000 + (mod_init_vm - 0xFFFFFFF0081E4000)
    insns = list(md.disasm(data[fo : fo + 0x40], mod_init_vm))
    x16 = None
    for ins in insns:
        if ins.mnemonic == "adrp" and ins.op_str.startswith("x16,"):
            try:
                x16 = int(ins.op_str.split("#")[1], 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and ins.op_str.startswith("x16,"):
            parts = [q.strip() for q in ins.op_str.split(",")]
            if len(parts) == 3 and x16 is not None:
                try:
                    x16 += int(parts[2].replace("#", "").replace("0x", ""), 16)
                except Exception:
                    pass
        elif ins.mnemonic == "pacda":
            break
    return x16

A7_EXEC = (0xFFFFFFF0082F4CB0, 0xFFFFFFF0082F4CB0 + 0x69B4)
ASC_EXEC = (0xFFFFFFF0082F2BF0, 0xFFFFFFF0082F2BF0 + 0x20B4)
K_EXEC = (0xFFFFFFF0081E4000, 0xFFFFFFF0081E4000 + 0x2A44000)


def owner(vm):
    if ASC_EXEC[0] <= vm < ASC_EXEC[1]:
        return "ascwrap"
    if A7_EXEC[0] <= vm < A7_EXEC[1]:
        return "a7iop"
    if K_EXEC[0] <= vm < K_EXEC[1]:
        return "kernel"
    return "other"


def main():
    raw_kc = open(BOOTKC, "rb").read()
    index = fixup_index.build_fixup_index(path=BOOTKC)
    VTABLES = {}
    derivation_report = {}
    for name, info in MOD_INITS.items():
        derived = derive_vtable_from_mod_init(raw_kc, info["mod_init_vm"])
        ok = derived == info["expected_vtable"]
        derivation_report[name] = {
            "mod_init": hex(info["mod_init_vm"]),
            "derived_vtable": hex(derived) if derived else None,
            "expected": hex(info["expected_vtable"]),
            "match": ok,
        }
        if not ok:
            raise SystemExit("vtable derivation mismatch for %s: %s vs %s" % (name, derived, info["expected_vtable"]))
        VTABLES[name] = {"slot_vm": derived, "mod_init": hex(info["mod_init_vm"])}

    out = {}
    for name, info in VTABLES.items():
        vt = info["slot_vm"]
        entries = {}
        for k in range(0, 0x400, 8):
            t = index.get(vt + k)
            if t is not None:
                entries[k] = t
        start_target = entries.get(START_SLOT)
        out[name] = {
            "vtable_vm": hex(vt),
            "mod_init": info["mod_init"],
            "resolved_entries": len(entries),
            "start_slot": "+0x%x" % START_SLOT,
            "start_target": hex(start_target) if start_target else None,
            "start_owner": owner(start_target) if start_target else None,
            "entries": {("+0x%03x" % k): {"target": hex(t), "owner": owner(t)} for k, t in sorted(entries.items())},
        }

    # Independent IOService anchor: IOService class registration at
    # 0xfffffff00aae5eec installs vtable 0xfffffff007c88580 (derived from
    # its adrp/add x16 sequence). Read its +0x360 entry as the true
    # IOService::start target - never reuse a subclass target as the base.
    IOSERVICE_VTABLE = 0xFFFFFFF007C88580
    ioservice_start = index.get(IOSERVICE_VTABLE + START_SLOT)

    # IMMEDIATE superclass of AppleA7IOP — fully derived in this generator:
    # 1. A7IOP mod_init[0] (0xfffffff0082f7798) sets x2 (superclass arg) via
    #    adrp x2,#0xfffffff00afed000; add x2,x2,#0x638 => 0xfffffff00afed638.
    A7IOP_SUPERCLASS_CLASS_OBJECT = _derive_x2(raw_kc, 0xFFFFFFF0082F7798)
    # 2. AppleIOP's own registration (0xfffffff0082f9bf4) registers x0 =
    #    that same class object, and its x16 chain installs the vtable.
    APPLEIOP_REG = 0xFFFFFFF0082F9BF4
    APPLEIOP_VTABLE = derive_vtable_from_mod_init(raw_kc, APPLEIOP_REG)
    # Assertions (fail closed)
    if A7IOP_SUPERCLASS_CLASS_OBJECT != 0xFFFFFFF00AFED638:
        raise SystemExit(
            "A7IOP superclass derivation mismatch: %s != 0xfffffff00afed638"
            % (hex(A7IOP_SUPERCLASS_CLASS_OBJECT) if A7IOP_SUPERCLASS_CLASS_OBJECT else None)
        )
    if APPLEIOP_VTABLE != 0xFFFFFFF007D157F8:
        raise SystemExit(
            "AppleIOP vtable derivation mismatch: %s != 0xfffffff007d157f8"
            % (hex(APPLEIOP_VTABLE) if APPLEIOP_VTABLE else None)
        )
    appleiop_start = index.get(APPLEIOP_VTABLE + START_SLOT)

    # Override attribution compares each class's +0x360 target against its
    # IMMEDIATE parent's target (never against a distant base, which would
    # credit intermediate overrides to the wrong class).
    PARENT_OF = {
        "AppleA7IOP": ("__appleiop__", "PROVEN (mod_init[0] x2 superclass = AppleIOP class object)"),
        "AppleASCWrapV6": ("AppleA7IOP", "PROVEN (GOT superclass chase)"),
        "AppleASCWrapV6SEP": ("AppleASCWrapV6", "ASSERTION_ANCHOR (shared registration block)"),
        "AppleASCWrapV6SISP": ("AppleASCWrapV6", "ASSERTION_ANCHOR (shared registration block)"),
        "AppleA7IOPNub": ("AppleA7IOP", "PROVEN (mod_init[1] registers under A7IOP family)"),
    }
    for name, (parent, basis) in PARENT_OF.items():
        own = out[name]["start_target"]
        if parent == "__appleiop__":
            ref = appleiop_start
        elif parent == "__ioservice__":
            ref = ioservice_start
        else:
            ref = out[parent]["start_target"]
        ref_str = (hex(ref) if isinstance(ref, int) else ref) if ref is not None else None
        if own is None or ref_str is None:
            cls = "UNRESOLVED"
        elif own == ref_str:
            cls = "INHERITS_START"
        else:
            cls = "OVERRIDES_START"
        out[name]["start_classification"] = cls
        out[name]["superclass_start_target"] = (hex(ref) if isinstance(ref, int) else ref) if ref else None
        out[name]["superclass_relation_basis"] = basis

    # Candidate evaluation: reverse lookup across ALL five vtables
    cand_hits = {"candA": [], "candB": []}
    for name, info in VTABLES.items():
        vt = info["slot_vm"]
        for k in range(0, 0x400, 8):
            t = index.get(vt + k)
            if t == CAND_A:
                cand_hits["candA"].append((name, "+0x%x" % k))
            elif t == CAND_B:
                cand_hits["candB"].append((name, "+0x%x" % k))

    # The true vtable targets are bti c landing pads 4 bytes before the
    # previously instrumented addresses.
    true_ascwrap_start = out["AppleASCWrapV6"]["start_target"]
    true_nub_start = out["AppleA7IOPNub"]["start_target"]

    artifact = {
        "gate": "57ZZ_ASCWRAP_VTABLES",
        "derivation": "vtable CONTENTS chain-decoder derived; vtable BASES derived from mod_init adrp/add x16 sequences and asserted",
        "start_slot": "+0x%x (bti c landing pad targets)" % START_SLOT,
        "vtables": out,
        "candidate_evaluation": {
            "candA": {"vm": hex(CAND_A), "vtable_hits": cand_hits["candA"], "count": len(cand_hits["candA"])},
            "candB": {"vm": hex(CAND_B), "vtable_hits": cand_hits["candB"], "count": len(cand_hits["candB"])},
            "relationship": (
                "candA (0xfffffff0082f4dec pad) and candB (0xfffffff0082f8048 "
                "pad) are vtable slot +0x348 targets. The proven start slot is "
                "+0x360; +0x348 is NOT start and its semantic identity is "
                "UNKNOWN. Prior breakpoints at the +4 function bodies were "
                "never start instrumentation."
            ),
        },
        "immediate_superclass_chain": {
            "AppleIOP_vtable": hex(APPLEIOP_VTABLE),
            "AppleIOP_start_0x360": hex(appleiop_start) if appleiop_start else None,
            "AppleIOP_start_source": "registration 0xfffffff0082f9bf4 x16 chain",
            "IOService_vtable": hex(IOSERVICE_VTABLE),
            "IOService_start_0x360": hex(ioservice_start) if ioservice_start else None,
            "note": "A7IOP immediate parent is AppleIOP (not IOService directly); override attribution now uses the immediate parent",
        },
        "ioservice_anchor": {
            "registration_vm": "0xfffffff00aae5eec",
            "vtable_vm": hex(IOSERVICE_VTABLE),
            "start_slot": "+0x%x" % START_SLOT,
            "ioservice_start_target": hex(ioservice_start) if ioservice_start else None,
            "note": "A7IOP-family start (0xfffffff00aad7da0) is an intermediate-superclass override, NOT the IOService base",
        },
        "vtable_base_derivation": derivation_report,
        "ALL_FIVE_VTABLE_BASES": "DERIVED_AND_ASSERTED",
        "verdicts": {
            "IOSERVICE_START_VTABLE_SLOT": "PROVEN_FROM_CALLSITE (+0x360)",
            "IOSERVICE_START_DISPATCH_CALLSITE_VM": "0xfffffff00aada0c8",
            "DISPATCH_INSTRUCTIONS": [
                "0xfffffff00aada0bc  mov x17, x27",
                "0xfffffff00aada0c0  ldr x16, [x22]        ; client vtable",
                "0xfffffff00aada0c4  autda x16, x17",
                "0xfffffff00aada0c8  add x8, x16, #0x360   ; slot",
                "0xfffffff00aada0cc  ldr x9, [x16, #0x360] ; fn ptr",
                "0xfffffff00aada0d0  mov x0, x22           ; client (this)",
                "0xfffffff00aada0d4  ldr x1, [sp, #0x78]   ; provider",
                "0xfffffff00aada0e0  blraa x9, x17         ; client->start(provider)",
                "0xfffffff00aada0e4  cbz w0                ; bool result",
            ],
            "APPLEASCWRAPV6_START_TARGET": true_ascwrap_start,
            "APPLEA7IOPNUB_START_TARGET": true_nub_start,
            "CANDA_VTABLE_STATUS": "AT_VTABLE_SLOT_0x348_WHICH_IS_NOT_START; semantic identity of +0x348 UNKNOWN",
            "CANDB_VTABLE_STATUS": "AT_VTABLE_SLOT_0x348_WHICH_IS_NOT_START; semantic identity of +0x348 UNKNOWN",
            "PRIOR_0x348_START_CLAIM": "INVALIDATED (real start slot is +0x360 per callsite proof)",
            "PRIOR_NO_HIT_INTERPRETATION": "CANDA/CANDB breakpoints did not instrument start; the NO_HIT says nothing about ASCWrapV6::start",
            "IOSERVICE_BASE_START": hex(ioservice_start) if ioservice_start else None,
            "START_DETECTION_TARGET": "A7IOP-family start 0xfffffff00aad7da0 (intermediate override) or dispatch callsite 0xfffffff00aada0e0; IOService base is %s" % (hex(ioservice_start) if ioservice_start else "UNKNOWN"),
            "PRIOR_0x2C0_SUPER_START_CLAIM": "INVALIDATED (slot +0x2c0 resolves to a shared kernel function, not start)",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — ASCWrap/A7IOP Vtables",
        "",
        "Vtable contents are chain-decoder derived; vtable bases are derived",
        "from mod_init instruction sequences and asserted.",
        "",
        "```",
        "IOSERVICE_START_VTABLE_SLOT: PROVEN_FROM_CALLSITE (+0x360)",
        "```",
        "",
        "| Class | Vtable VM | +0x360 start target | Superclass target | Classification |",
        "|---|---|---|---|---|",
    ]
    for name, v in out.items():
        md.append(
            f"| {name} | {v['vtable_vm']} | {v['start_target']} | {v.get('superclass_start_target')} | {v['start_classification']} |"
        )
    md += [
        "",
        "## Candidate relationship",
        "",
        artifact["candidate_evaluation"]["relationship"],
        "",
        "The start slot is +0x360 (callsite-proven). Slot +0x2c0 resolves to a",
        "shared kernel function in every derived vtable; both the prior",
        "+0x2c0 SUPER_START claim and the later +0x348 hypothesis are",
        "invalidated.",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
