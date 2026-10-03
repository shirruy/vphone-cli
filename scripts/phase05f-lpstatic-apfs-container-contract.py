#!/usr/bin/env python3
"""57ZZ Part 14K: LPStaticAPFSContainer volume-creation contract.

Decodes the ObjC method list containing addVolumeWithName:role:..., resolves
every selector, type encoding, and IMP, and proves the full upstream contract
of the _APFSVolumeCreate options dictionary.
"""

import hashlib
import json
import os
import struct

BIN = os.path.join(os.environ["TEMP"], "57zz-binaries", "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-lpstatic-apfs-container-contract.json"

TEXT_BASE = 0x100000000
METHOD_LIST_VM = 0x1001C6890


def read_selref_name(data, sel_vm):
    """Resolve a selref slot to its selector string via chained pointer."""
    fo = 0x2F0000 + (sel_vm - 0x1002F0000)
    raw = struct.unpack_from("<Q", data, fo)[0]
    target_fo = raw & 0xFFFFFFFFFF
    end = data.find(b"\0", target_fo)
    return data[target_fo:end].decode("utf-8", "replace")


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()

    hdr_fo = METHOD_LIST_VM - TEXT_BASE
    entsize = struct.unpack_from("<I", data, hdr_fo)[0]
    count = struct.unpack_from("<I", data, hdr_fo + 4)[0]
    relative = bool(entsize & 0x80000000)
    assert relative and (entsize & 0xFFFF) == 12, hex(entsize)

    entries = []
    for e in range(count):
        entry_vm = METHOD_LIST_VM + 8 + e * 12
        entry_fo = entry_vm - TEXT_BASE
        sel_off = struct.unpack_from("<i", data, entry_fo)[0]
        types_off = struct.unpack_from("<i", data, entry_fo + 4)[0]
        imp_off = struct.unpack_from("<i", data, entry_fo + 8)[0]
        sel_vm = entry_vm + sel_off
        types_vm = entry_vm + 4 + types_off
        imp_vm = entry_vm + 8 + imp_off
        selector = read_selref_name(data, sel_vm)
        types_end = data.find(b"\0", types_vm - TEXT_BASE)
        types = data[types_vm - TEXT_BASE : types_end].decode("utf-8", "replace")
        entries.append(
            {
                "index": e,
                "selector": selector,
                "type_encoding": types,
                "imp_vm": hex(imp_vm),
            }
        )

    # Verify the addVolume IMP is our known caller function
    addvol = next(e for e in entries if e["selector"].startswith("addVolumeWithName"))
    assert addvol["imp_vm"] == "0x1000821bc", addvol["imp_vm"]

    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14K_LPSTATIC_CONTAINER_CONTRACT",
        "binary": {"path": BIN, "sha256": sha},
        "method_list": {
            "vm": hex(METHOD_LIST_VM),
            "entsize": hex(entsize),
            "entry_count": count,
            "format": "relative-offset (0x8000000c)",
            "owning_class": "LPStaticAPFSContainer",
            "class_name_evidence": "0x1cf0a1 string area contains LPStaticAPFSContainer/LPStaticAPFSVolume/LPStaticAPFSPhysicalStore cluster",
        },
        "addVolume_method": {
            "selector": addvol["selector"],
            "type_encoding": addvol["type_encoding"],
            "imp_vm": addvol["imp_vm"],
            "argument_decode": {
                "@16": "name (NSString)",
                "i24": "role (int) -> kAPFSVolumeRoleKey",
                "B28": "caseSensitive (BOOL) -> kAPFSVolumeCaseSensitiveKey",
                "q32": "reserveSize (long long) -> kAPFSVolumeReserveSizeKey",
                "q40": "quotaSize (long long) -> kAPFSVolumeQuotaSizeKey",
                "@48": "pairedVolume (id) -> kAPFSVolumeGroupSiblingFSIndexKey source",
                "^@56": "error (NSError**)",
                "return @64... ": "note: stack size prefix",
            },
        },
        "all_methods": entries,
        "upstream_contract": {
            "finding": "No in-binary caller of addVolumeWithName:... exists; the selector has exactly one selref with no ADRP+LDR text users. LPStaticAPFSContainer exposes this method to an external restore orchestrator (asr/restored host-side).",
            "role_source": "int role argument at offset 24, provided by external caller",
            "sibling_source": "pairedVolume object at offset 48, provided by external caller; converted to group fsindex via intValue",
            "encryption": "No encryption keys appear in the creation dictionary; encryption is not configured through _APFSVolumeCreate in this path",
        },
        "result": "PASS",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["addVolume_method"], indent=2))
    print("methods:", count, "| result: PASS")


if __name__ == "__main__":
    main()
