#!/usr/bin/env python3
"""57ZZ: executable allocator caller static analyzer.

Uses the canonical shared fixup decoder to derive:
  - direct BL/B callers of the allocator and its thunk
  - fixup references to the allocator and thunk
  - xrefs to the ARMIO class object
  - thunk register transformation (x2 -> x1)
All results are generated, not hardcoded.
"""

import importlib.util as ilu
import json
import os
import struct

import capstone

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
EXPECTED_BOOTKC_SHA256 = (
    "C01B133237EB9C5AA6C7ED38F54ED5DB"
    "924B4BA2E6465CD51F0245B4C823E800"
)
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-allocator-caller-analysis.json"

_fixup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
_spec = ilu.spec_from_file_location("fixup_index", _fixup_path)
fixup_index = ilu.module_from_spec(_spec)
_spec.loader.exec_module(fixup_index)

ALLOCATOR_VM = 0xFFFFFFF008387EB8
THUNK_VM = 0xFFFFFFF008387EB0
ARMIO_CLASS_OBJECT = 0xFFFFFFF00AFEF458

# Exec segments to scan for BL/B instructions
# Derived from the outer BootKC Mach-O LC_SEGMENT_64 commands; the single
# __TEXT_EXEC segment covers all kernel-cache executable code (fileset
# entries are mapped within it), so scanning it once is exhaustive and
# non-overlapping.
EXEC_SEGMENTS = [
    {"name": "BootKC __TEXT_EXEC", "vm": 0xFFFFFFF0081E4000, "fo": 0x11E0000, "size": 0x2A44000},
]

# Chained segments to search for fixup references
CHAINED_SEGMENTS = ["__DATA_CONST", "__DATA_SPTM", "__DATA"]


def find_bl_b_callers(data, target_vm):
    """Scan exec segments for BL/B instructions targeting target_vm."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    callers = []
    for seg in EXEC_SEGMENTS:
        code = data[seg["fo"] : seg["fo"] + seg["size"]]
        # skip all-zero 4KB pages for speed
        CHUNK = 0x1000
        for b in range(0, len(code), CHUNK):
            chunk = code[b : b + CHUNK]
            if chunk.count(0) == len(chunk):
                continue
            try:
                insns = list(md.disasm(chunk, seg["vm"] + b))
            except Exception:
                continue
            for ins in insns:
                if ins.mnemonic in ("bl", "b"):
                    try:
                        t = int(ins.op_str.replace("#", ""), 16)
                    except Exception:
                        continue
                    if t == target_vm:
                        # Exclude the thunk body itself (self-referential branch)
                        if target_vm == ALLOCATOR_VM and ins.address == THUNK_VM + 4:
                            continue
                        callers.append({"mnemonic": ins.mnemonic, "site": hex(ins.address), "segment": seg["name"]})
    return callers


def find_fixup_refs(index, target_vm):
    """Search the fixup index for entries resolving to target_vm."""
    return [hex(loc) for loc, t in index.items() if t == target_vm]


def find_class_xrefs(data, class_vm):
    """Scan __TEXT_EXEC (chunked) for adrp+add pairs targeting the class object.

    Chunked disassembly (4KB pages, skip all-zero) avoids the single-stream
    disasm failure mode across the ~42MB segment.
    """
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    seg = EXEC_SEGMENTS[0]
    hits = []
    CHUNK = 0x1000
    for b in range(0, seg["size"], CHUNK):
        chunk = data[seg["fo"] + b : seg["fo"] + b + CHUNK]
        if chunk.count(0) == len(chunk):
            continue
        try:
            insns = list(md.disasm(chunk, seg["vm"] + b))
        except Exception:
            continue
        pages = {}
        for ins in insns:
            if ins.mnemonic == "adrp":
                parts = [q.strip() for q in ins.op_str.split(",")]
                try:
                    pages[parts[0]] = int(parts[1].replace("#", ""), 16)
                except Exception:
                    pass
            elif ins.mnemonic == "add":
                parts = [q.strip() for q in ins.op_str.split(",")]
                if len(parts) == 3 and parts[0] == parts[1] and parts[0] in pages:
                    try:
                        if pages[parts[0]] + int(parts[2].replace("#", "").replace("0x", ""), 16) == class_vm:
                            hits.append(hex(ins.address))
                    except Exception:
                        pass
            if ins.mnemonic in ("bl", "blr", "br", "ret", "b"):
                pages = {}
    return hits


def analyze_thunk(data):
    """Disassemble the thunk and derive the register transformation."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    seg = EXEC_SEGMENTS[0]  # single __TEXT_EXEC covers all exec code
    fo = seg["fo"] + (THUNK_VM - seg["vm"])
    insns = list(md.disasm(data[fo : fo + 0x10], THUNK_VM))
    result = []
    for ins in insns:
        result.append({"addr": hex(ins.address), "mnemonic": ins.mnemonic, "operands": ins.op_str})
    return result


def main():
    data = open(BOOTKC, "rb").read()
    import hashlib as _hl
    _sha = _hl.sha256(data).hexdigest().upper()
    if _sha != EXPECTED_BOOTKC_SHA256:
        raise SystemExit(
            "BOOTKC_SHA_MISMATCH: got %s expected %s" % (_sha, EXPECTED_BOOTKC_SHA256)
        )

    # Build fixup indices for all chained segments
    all_fixups = {}
    for seg_name in CHAINED_SEGMENTS:
        idx = fixup_index.build_fixup_index(path=BOOTKC, segment_name=seg_name)
        all_fixups.update(idx)

    alloc_bl = find_bl_b_callers(data, ALLOCATOR_VM)
    thunk_bl = find_bl_b_callers(data, THUNK_VM)
    alloc_fixup = find_fixup_refs(all_fixups, ALLOCATOR_VM)
    thunk_fixup = find_fixup_refs(all_fixups, THUNK_VM)
    class_xrefs = find_class_xrefs(data, ARMIO_CLASS_OBJECT)

    # Fail-closed anchor assertion: the seven previously established xrefs
    # must still be present. If any disappears, the scanner regressed.
    EXPECTED_XREFS = {
        "0xfffffff008387ef0", "0xfffffff008388ce8", "0xfffffff008388d68",
        "0xfffffff008388dd8", "0xfffffff008388e34", "0xfffffff00838a1b4",
        "0xfffffff00838a208",
    }
    missing = EXPECTED_XREFS - set(class_xrefs)
    if missing:
        raise SystemExit(
            "CLASS_XREF_ANCHOR_REGRESSION: %d expected xrefs missing: %s"
            % (len(missing), sorted(missing))
        )
    thunk_insns = analyze_thunk(data)

    # Fail-closed thunk register-flow assertion
    _thunk_flow_ok = (
        len(thunk_insns) >= 2
        and thunk_insns[0]["mnemonic"] == "mov"
        and thunk_insns[0]["operands"].replace(" ", "") == "x1,x2"
        and thunk_insns[1]["mnemonic"] == "b"
        and int(thunk_insns[1]["operands"].lstrip("#").replace(" ", ""), 16) == ALLOCATOR_VM
    )
    if not _thunk_flow_ok:
        raise SystemExit("THUNK_REGISTER_FLOW_MISMATCH: expected mov x1,x2; b allocator, got %s" % thunk_insns)

    artifact = {
        "gate": "57ZZ_ALLOCATOR_CALLER_ANALYSIS",
        "bootkc_sha256": EXPECTED_BOOTKC_SHA256,
        "method": "executable: canonical fixup decoder + Capstone BL/B scan + adrp/add xref scan",
        "fixup_decoder": "scripts/phase05f-57zz-fixup-index.py (shared canonical)",
        "chained_segments_searched": CHAINED_SEGMENTS,
        "total_fixup_index_size": len(all_fixups),
        "allocator": {
            "vm": hex(ALLOCATOR_VM),
            "direct_bl_b_callers": alloc_bl,
            "fixup_references": alloc_fixup,
        },
        "thunk": {
            "vm": hex(THUNK_VM),
            "instructions": thunk_insns,
            "register_transformation": "thunk x2 -> allocator x1 (derived from 'mov x1, x2')",
            "direct_bl_b_callers": thunk_bl,
            "fixup_references": thunk_fixup,
        },
        "armio_class_object": {
            "vm": hex(ARMIO_CLASS_OBJECT),
            "xrefs_in_BootKC_TEXT_EXEC": class_xrefs,
        },
        "verdicts": {
            "DIRECT_CALLER_TO_ALLOCATOR": "NOT_OBSERVED" if not alloc_bl else "OBSERVED",
            "DIRECT_CALLER_TO_THUNK": "NOT_OBSERVED" if not thunk_bl else "OBSERVED",
            "FIXUP_REFERENCE_TO_ALLOCATOR": "NOT_OBSERVED" if not alloc_fixup else "OBSERVED",
            "FIXUP_REFERENCE_TO_THUNK": "NOT_OBSERVED" if not thunk_fixup else "OBSERVED",
            "INDIRECT_CALL_MECHANISM": "UNKNOWN",
            "OSMETACLASS_DISPATCH": "SUPPORTED_HYPOTHESIS_ONLY (not proven)",
            "THUNK_X2_TO_ALLOCATOR_X1": "PROVEN_STATIC (fail-closed assertion passed)",
            "RUNTIME_ALLOCATOR_ENTRY_VIA_THUNK": "UNKNOWN (not yet proven; indirect entry bypassing thunk is possible)",
            "ALLOCATOR_ARG1_SOURCE_GLOBAL": "UNKNOWN (depends on runtime entry path)",
            "THUNK_X2_SEMANTIC_ROLE": "UNKNOWN (next gate target)",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
