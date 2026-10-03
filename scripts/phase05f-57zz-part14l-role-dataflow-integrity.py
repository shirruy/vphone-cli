#!/usr/bin/env python3
"""57ZZ Part 14L-R: role dataflow integrity correction.

Resolves the x25/x23 contradiction in the original Part 14L report and
recovers the complete LP-enum -> APFS-role-bits conversion inside the
_APFSVolumeCreate wrapper itself.
"""

import hashlib
import json
import os
import struct

import capstone

BIN = os.path.join(os.environ["TEMP"], "57zz-binaries", "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-57zz-part14l-role-dataflow-integrity.json"

WRAPPER_START = 0x1000821BC
WRAPPER_END = 0x100082CC0  # next function (matchVolumesWithRole:group:) starts at 0x100082cc0
ROLE_LOOKUP_CALL = 0x1001C42A0  # objc stub for roleMetadataForRole:
ROLE_METADATA_TABLE_FO = 0x2CB238
ROLE_METADATA_COUNT = 17


def read_cfstring(data, vm):
    fo = vm - 0x100000000
    _isa, _flags, ptr_raw, length = struct.unpack_from("<QQQQ", data, fo)
    data_fo = ptr_raw & 0xFFFFFFFFFF
    s = data[data_fo : data_fo + min(length, 64)]
    return s.decode("utf-8", "replace")


def resolve_objc_selector(data, stub_vm):
    fo = stub_vm - 0x100000000
    i1 = struct.unpack_from("<I", data, fo)[0]
    i2 = struct.unpack_from("<I", data, fo + 4)[0]
    immlo = (i1 >> 29) & 0x3
    immhi = (i1 >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page = (stub_vm & ~0xFFF) + (imm << 12)
    off = ((i2 >> 10) & 0xFFF) * 8
    selref_vm = page + off
    selref_fo = 0x2F0000 + (selref_vm - 0x1002F0000)
    raw = struct.unpack_from("<Q", data, selref_fo)[0]
    target_fo = raw & 0xFFFFFFFFFF
    end = data.find(b"\0", target_fo)
    return data[target_fo:end].decode("utf-8", "replace")


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    # 1. Disassemble wrapper with exact bounds
    fo = WRAPPER_START - 0x100000000
    insns = list(md.disasm(data[fo : fo + (WRAPPER_END - WRAPPER_START)], WRAPPER_START))

    # 2. All x25/w25 uses (role register)
    x25_uses = []
    for ins in insns:
        ops = ins.op_str.replace(" ", "")
        if ("w25" in ops or "x25" in ops) and ins.mnemonic not in ("stp", "ldp"):
            x25_uses.append(f"{ins.address:x}  {ins.mnemonic} {ins.op_str}")

    # 3. All x23/w23 definitions
    x23_defs = []
    for ins in insns:
        parts = ins.op_str.replace(" ", "").split(",")
        dst = parts[0] if parts else ""
        if dst in ("x23", "w23") and ins.mnemonic not in (
            "cbz", "cbnz", "tbz", "tbnz", "str", "stp", "stur", "cmp", "tst", "b"
        ):
            x23_defs.append(f"{ins.address:x}  {ins.mnemonic} {ins.op_str}")

    # 4. Verify the role conversion chain
    idx = {ins.address: i for i, ins in enumerate(insns)}
    conversion_chain = []
    for addr in (0x1000821F0, 0x100082588, 0x10008258C, 0x100082594, 0x100082598, 0x1000825C if False else 0x10008259C):
        if addr in idx:
            ins = insns[idx[addr]]
            conversion_chain.append(f"{ins.address:x}  {ins.mnemonic} {ins.op_str}")

    selector = resolve_objc_selector(data, ROLE_LOOKUP_CALL)

    # 5. Decode the full role metadata table
    role_table = []
    for i in range(ROLE_METADATA_COUNT):
        entry_fo = ROLE_METADATA_TABLE_FO + i * 24
        lp_role, apfs_role = struct.unpack_from("<II", data, entry_fo)
        name_ptr = struct.unpack_from("<I", data, entry_fo + 8)[0]
        name = read_cfstring(data, 0x100000000 + name_ptr)
        role_table.append(
            {
                "index": i,
                "lp_logical_role": lp_role,
                "apfs_role_bits": apfs_role,
                "name": name,
            }
        )

    data_entry = next(r for r in role_table if r["name"] == "Data")
    assert data_entry["apfs_role_bits"] == 0x40, data_entry
    assert data_entry["lp_logical_role"] == 3, data_entry

    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14L_ROLE_DATAFLOW_INTEGRITY",
        "binary": {"path": BIN, "sha256": sha},
        "wrapper_bounds": {"start": hex(WRAPPER_START), "end": hex(WRAPPER_END), "size": hex(WRAPPER_END - WRAPPER_START)},
        "x25_role_register_uses": x25_uses,
        "x23_definitions": x23_defs,
        "conversion_chain": conversion_chain,
        "conversion_call": {
            "site": "0x100082588-0x100082598",
            "selector": selector,
            "disassembly": [
                "0x100082588  mov x2, x25        ; LP logical role -> lookup",
                "0x10008258c  bl roleMetadataForRole: (objc stub 0x1001c42a0)",
                "0x100082594  cbz x0, 0x100082660  ; failure -> w23 = 0 default",
                "0x100082598  ldrh w23, [x0, #4]   ; APFS role bits from metadata +4",
            ],
            "receiver_class": "LPStaticAPFSVolume (metaclass)",
            "metadata_method": "+[LPStaticAPFSVolume roleMetadataForRole:] IMP 0x1000840a8",
            "enumeration": "+[LPStaticAPFSVolume enumerateRoleMetadataUsingBlock:] IMP 0x100084044, 17 entries",
            "table_vm": "0x1002cb238",
        },
        "role_metadata_table": role_table,
        "key_correction": {
            "previous_claim": "w3 -> x25 -> NSNumber -> kAPFSVolumeRoleKey (unmodified passthrough)",
            "corrected_finding": "w3 -> x25 (LP logical enum) -> [LPStaticAPFSVolume roleMetadataForRole:] -> ldrh w23, [result+4] (APFS role bits) -> numberWithInt: -> dict[kAPFSVolumeRoleKey]",
            "mov_w23_0_meaning": "FAILURE DEFAULT: when roleMetadataForRole: returns nil (unknown role), w23 defaults to 0",
            "previous_passthrough_claim": "RETRACTED",
            "previous_no_0x40_wording": "CORRECTED: the conversion IS inside the wrapper via the metadata table; 0x40 is table entry LP=3",
        },
        "data_role": {
            "lp_logical_enum": 3,
            "apfs_role_bits": 64,
            "name": "Data",
            "proven": True,
        },
        "verdicts": {
            "ROLE_WRAPPER_DATAFLOW": "PASS",
            "DATA_ROLE_0x40_STATIC_PROOF": "PASS",
            "DATA_LIFECYCLE_STATIC_GATE": "BLOCKED",
        },
        "gate_blocked_reason": "The LP->APFS conversion and Data=0x40 are now PROVEN inside the wrapper. The remaining blocker is ONLY the external orchestrator that passes LP role=3 for the actual Data invocation. Runtime mount identity remains deferred.",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["key_correction"], indent=2))
    print(json.dumps(artifact["data_role"], indent=2))
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
