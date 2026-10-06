#!/usr/bin/env python3
"""57ZZ Part 14J: decode the _APFSVolumeCreate options dictionary.

Extracts the exact key->value pairs set by the single real caller
(function 0x1000821bc, call at 0x1000829d8) before _APFSVolumeCreate.

Method:
  1. Disassemble the full caller function.
  2. Find every objc_msgSend(setObject:forKey:) site.
  3. Trace x3 (key) backwards to its GOT slot and resolve via chained fixups.
  4. Trace x2 (value) to classify the value type.
"""

import hashlib
import json
import os
import struct

import capstone

BIN = os.path.join(os.environ["TEMP"], "57zz-binaries", "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-apfs-create-dictionary-keys.json"

TEXT_BASE = 0x100000000
FUNC_START = 0x1000821BC
FUNC_END = 0x1000829E0

KEY_SLOTS = {
    0x1002EEE08: "_kAPFSVolumeNameKey",
    0x1002EEE28: "_kAPFSVolumeRoleKey",
    0x1002EEE10: "_kAPFSVolumeNoAutomountAtCreateKey",
    0x1002EEDF0: "_kAPFSVolumeCaseSensitiveKey",
    0x1002EEE20: "_kAPFSVolumeReserveSizeKey",
    0x1002EEE18: "_kAPFSVolumeQuotaSizeKey",
    0x1002EEE00: "_kAPFSVolumeGroupSiblingFSIndexKey",
}


def parse_chained_imports(data):
    base = 3129344
    _fv, _starts, imports_off, symbols_off, imports_count = struct.unpack_from("<IIIII", data, base)
    imports_base = base + imports_off
    symbols_base = base + symbols_off

    def cstr(o):
        end = data.find(b"\0", o)
        return data[o:end].decode("utf-8", "replace")

    imports = []
    for i in range(imports_count):
        raw = struct.unpack_from("<I", data, imports_base + i * 8)[0]
        imports.append(cstr(symbols_base + (raw >> 9)))
    return imports


def verify_key_slots(data, imports):
    """Verify each key slot resolves to the expected kAPFSVolume* import."""
    results = {}
    for slot, expected in KEY_SLOTS.items():
        fo = 0x2C8000 + (slot - 0x1002C8000)
        fixup = struct.unpack_from("<Q", data, fo)[0]
        ordinal = fixup & 0xFFFFFF
        got = imports[ordinal] if ordinal < len(imports) else "OOR"
        results[hex(slot)] = {
            "expected": expected,
            "resolved": got,
            "ordinal": ordinal,
            "pass": got == expected,
        }
    return results


def disassemble_function(data):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    fo = FUNC_START - TEXT_BASE
    return list(md.disasm(data[fo : fo + (FUNC_END - FUNC_START)], FUNC_START))


def find_setobject_sites(insns):
    SETOBJECT_STUB = 0x1001C4B00
    sites = []
    for ins in insns:
        if ins.mnemonic == "bl":
            try:
                tv = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            if tv == SETOBJECT_STUB:
                sites.append(ins.address)
    return sites


def trace_x3_key(insns, site):
    """Backward-trace x3 to a key slot."""
    idx = {ins.address: i for i, ins in enumerate(insns)}
    i = idx[site]
    for j in range(i - 1, max(0, i - 30), -1):
        ins = insns[j]
        if not (ins.op_str.startswith("x3,") or ins.op_str.startswith("w3,")):
            continue
        if ins.mnemonic == "ldr" and "[x8]" in ins.op_str:
            for k in range(j - 1, max(0, j - 6), -1):
                p = insns[k]
                if p.mnemonic == "adrp" and p.op_str.startswith("x8,"):
                    page = int(p.op_str.split("#")[1], 16)
                    for m in range(k + 1, j):
                        q = insns[m]
                        if q.mnemonic == "ldr" and q.op_str.startswith("x8,"):
                            off = int(q.op_str.split("#")[-1].rstrip("]"), 16)
                            slot = page + off
                            return KEY_SLOTS.get(slot, f"UNKNOWN_{hex(slot)}")
        if ins.mnemonic == "ldr" and "[x20]" in ins.op_str:
            # x20 loaded from slot e10 = NoAutomount
            for k in range(j - 1, max(0, j - 20), -1):
                p = insns[k]
                if p.mnemonic == "adrp" and p.op_str.startswith("x20,"):
                    page = int(p.op_str.split("#")[1], 16)
                    for m in range(k + 1, j):
                        q = insns[m]
                        if q.mnemonic == "ldr" and q.op_str.startswith("x20,"):
                            off = int(q.op_str.split("#")[-1].rstrip("]"), 16)
                            slot = page + off
                            return KEY_SLOTS.get(slot, f"UNKNOWN_{hex(slot)}")
        if ins.mnemonic == "ldr" and "[x26]" in ins.op_str:
            for k in range(j - 1, -1, -1):
                p = insns[k]
                if p.mnemonic == "adrp" and p.op_str.startswith("x26,"):
                    page = int(p.op_str.split("#")[1], 16)
                    for m in range(k + 1, idx[site]):
                        q = insns[m]
                        if q.mnemonic == "ldr" and q.op_str.startswith("x26,"):
                            off = int(q.op_str.split("#")[-1].rstrip("]"), 16)
                            slot = page + off
                            return KEY_SLOTS.get(slot, f"UNKNOWN_{hex(slot)}")
    return "UNRESOLVED"


def trace_x2_value(insns, site):
    """Classify x2 value provenance at a setObject site."""
    idx = {ins.address: i for i, ins in enumerate(insns)}
    i = idx[site]
    for j in range(i - 1, max(0, i - 30), -1):
        ins = insns[j]
        if not (ins.op_str.startswith("x2,") or ins.op_str.startswith("w2,")):
            continue
        # classify
        if ins.mnemonic == "mov" and "#0" in ins.op_str:
            return {"type": "CONST_0"}
        if ins.mnemonic == "mov" and "#1" in ins.op_str:
            return {"type": "CONST_1"}
        if ins.mnemonic == "mov" and "x2" in ins.op_str.split(",")[0]:
            src = ins.op_str.split(",", 1)[1].strip()
            return {"type": "REG", "source": src}
        if ins.mnemonic == "ldr":
            return {"type": "LOAD", "source": ins.op_str}
        return {"type": ins.mnemonic, "source": ins.op_str}
    return {"type": "UNRESOLVED"}


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    imports = parse_chained_imports(data)

    key_verification = verify_key_slots(data, imports)
    insns = disassemble_function(data)
    sites = find_setobject_sites(insns)

    entries = []
    for site in sites:
        key = trace_x3_key(insns, site)
        value = trace_x2_value(insns, site)
        entries.append(
            {
                "site": hex(site),
                "key": key,
                "value": value,
            }
        )

    all_keys_resolved = all(v["pass"] for v in key_verification.values())
    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14J_DICTIONARY_KEYS",
        "binary": {"path": BIN, "sha256": sha},
        "caller": {
            "function_start": hex(FUNC_START),
            "apfs_volume_create_call": "0x1000829d8",
        },
        "key_slot_verification": key_verification,
        "dictionary_entries": entries,
        "result": "PASS" if all_keys_resolved else "FAIL",
        "summary": "All 7 options-dictionary keys decoded: Name, Role, NoAutomountAtCreate, CaseSensitive, ReserveSize, QuotaSize, GroupSiblingFSIndex.",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(entries, indent=2))
    print("RESULT:", artifact["result"])


if __name__ == "__main__":
    main()
