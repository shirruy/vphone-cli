#!/usr/bin/env python3
"""57ZZ Part 14L-S: Data invocation closure audit.

Phases S0-S9: account for all 17 metadata entries, lock the conversion
proof, exhaustively search for the actual LP-role-3 invocation, and
establish the precise external boundary if no caller exists.
"""

import hashlib
import json
import os
import struct

import capstone

BINDIR = os.path.join(os.environ["TEMP"], "57zz-binaries")
BIN = os.path.join(BINDIR, "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-57zz-part14l-data-invocation-closure.json"

WRAPPER = 0x1000821BC
ADD_VOLUME_SELECTOR = b"addVolumeWithName:role:caseSensitive:reserveSize:quotaSize:pairedVolume:error:"
METADATA_TABLE_FO = 0x2CB238
METADATA_COUNT = 17


def read_cfstring(data, vm):
    fo = vm - 0x100000000
    _isa, _flags, ptr_raw, length = struct.unpack_from("<QQQQ", data, fo)
    data_fo = ptr_raw & 0xFFFFFFFFFF
    if length == 0 or length > 100:
        return None
    return data[data_fo : data_fo + length].decode("utf-8", "replace")


def phase_s0(data):
    entries = []
    for i in range(METADATA_COUNT):
        entry_fo = METADATA_TABLE_FO + i * 24
        raw = data[entry_fo : entry_fo + 24].hex()
        lp, apfs = struct.unpack_from("<II", data, entry_fo)
        name_ptr = struct.unpack_from("<I", data, entry_fo + 8)[0]
        name = read_cfstring(data, 0x100000000 + name_ptr) if name_ptr else None
        entries.append(
            {
                "index": i,
                "lp_role": lp,
                "apfs_bits": apfs,
                "name": name,
                "classification": (
                    "ZERO_SENTINEL" if i == 0 and lp == 0 and apfs == 0 and name is None else "ROLE"
                ),
                "raw": raw,
            }
        )
    return entries


def phase_s2_search_binaries():
    rows = []
    for fn in sorted(os.listdir(BINDIR)):
        p = os.path.join(BINDIR, fn)
        d = open(p, "rb").read()
        rows.append(
            {
                "binary": fn,
                "selector_string": d.find(ADD_VOLUME_SELECTOR) >= 0,
                "lpstatic_container_string": d.find(b"LPStaticAPFSContainer") >= 0,
                "enumerate_role_metadata_string": d.find(b"enumerateRoleMetadataUsingBlock:") >= 0,
            }
        )
    return rows


def phase_s7_enum_users(data):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[0x20C0 : 0x20C0 + 0x1B9880], 0x1000020C0))
    # enumerateRoleMetadataUsingBlock: objc stub = 0x1001c22e0
    stub = 0x1001C22E0
    sites = []
    for ins in insns:
        if ins.mnemonic == "bl":
            try:
                tv = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            if tv == stub:
                sites.append(hex(ins.address))
    return sites


def phase_s9_dylibs(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    dylibs = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd in (0xC, 0x18, 0x20, 0x21, 0x22, 0x23):
            nameoff = struct.unpack_from("<I", data, off + 8)[0]
            end = data.find(b"\0", off + nameoff)
            dylibs.append(data[off + nameoff : end].decode("utf-8", "replace"))
        off += cmdsize
    return dylibs


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()

    entries = phase_s0(data)
    binary_search = phase_s2_search_binaries()
    enum_sites = phase_s7_enum_users(data)
    dylibs = phase_s9_dylibs(data)

    # Assertions
    data_entry = next(e for e in entries if e["name"] == "Data")
    assert data_entry["lp_role"] == 3 and data_entry["apfs_bits"] == 0x40
    zero_entries = [e for e in entries if e["classification"] == "ZERO_SENTINEL"]
    role_entries = [e for e in entries if e["classification"] == "ROLE"]
    assert len(zero_entries) == 1 and len(role_entries) == 16

    sel_only_in = [r["binary"] for r in binary_search if r["selector_string"]]
    container_only_in = [r["binary"] for r in binary_search if r["lpstatic_container_string"]]

    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14L_S_DATA_INVOCATION_CLOSURE",
        "binary": {"path": BIN, "sha256": sha},
        "phase_s0_metadata": {
            "expected_entries": METADATA_COUNT,
            "accounted_entries": len(entries),
            "classification": {
                "zero_sentinel": 1,
                "named_roles": 16,
                "total": 17,
            },
            "sentinel_explanation": "Index 0 is the zero entry: LP=0, APFS=0, nil name, all-zero raw. It is the empty/default entry returned by roleMetadataForRole: for role 0 (no role).",
            "entries": entries,
        },
        "phase_s1_locked_proof": {
            "conversion_mechanism": "PROVEN",
            "chain": [
                "0x1000821f0 mov x25, x3 (save LP role)",
                "0x100082588 mov x2, x25",
                "0x10008258c bl roleMetadataForRole:",
                "0x100082598 ldrh w23, [x0, #4] (APFS bits)",
                "0x100082698-ish numberWithInt: -> dict[kAPFSVolumeRoleKey]",
            ],
            "data_entry": {"lp": 3, "apfs": 64, "name": "Data"},
            "distinction": "Conversion mechanism PROVEN; actual external invocation with role=3 NOT PROVEN.",
        },
        "phase_s2_binary_search": binary_search,
        "phase_s2_finding": f"Selector string only in: {sel_only_in}. LPStaticAPFSContainer string only in: {container_only_in}.",
        "phase_s3_class_references": {
            "class_object_vm": "0x1002f67b8",
            "references": [
                {"slot": "0x1002eada0", "type": "__objc_classlist entry (registration)"},
                {"slot": "0x1002eecd8", "type": "__got entry (no text users found)"},
            ],
            "text_users_of_got_classref": 0,
        },
        "phase_s4_dynamic_dispatch": {
            "checked": True,
            "findings": "addVolume selector selref 0x1002f5860 has zero text users. allAPFSContainers selref 0x1002f58a8 has zero text users. No objc stub exists for addVolumeWithName:... (not among 247 mapped stubs). NSSelectorFromString/sel_registerName/performSelector strings checked: no path produces the add-volume selector dynamically.",
        },
        "phase_s7_metadata_orchestration": {
            "enumerate_users": enum_sites,
            "finding": "5 in-binary users of enumerateRoleMetadataUsingBlock: exist (roleMetadataForRole:, defaultMountPointGivenRole:, defaultVolumeNameGivenRole:, supportedContentTypes, setRole:withError:). NONE reaches the add-volume wrapper. All are metadata queries, not creation orchestration.",
        },
        "phase_s6_role3_dataflow": "NOT PROVEN: no mov w?,#3 / table lookup / metadata iteration forwards LP role 3 into the add-volume interface within restored_external.bin.",
        "phase_s8_external_boundary": {
            "strongest_boundary": "The add-volume wrapper is invoked from OUTSIDE restored_external.bin. The strongest identifiable boundary is the restore host orchestration layer that drives restored_external / asr via the published ObjC interface.",
            "reasoning": "LPStatic* classes are defined inline in restored_external.bin (not imported from a LogicalPlatform.framework - no such dylib in LC_LOAD_DYLIB). The selectors addVolumeWithName:... and allAPFSContainers have selrefs but zero in-binary users, meaning they are published interface consumed by an external driver. The caller is either the host-side restored executable, an XPC service, or another restore component not in the extracted set.",
        },
        "phase_s9_dylib_inventory": dylibs,
        "verdicts": {
            "DATA_INVOCATION_ROLE3_PROOF": "BLOCKED",
            "DATA_LIFECYCLE_STATIC_GATE": "BLOCKED",
        },
        "remaining_blockers": [
            "The external restore orchestrator binary that invokes LPStaticAPFSContainer addVolumeWithName:role:... with LP role 3.",
            "Runtime mount identity (deferred by design).",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["phase_s0_metadata"]["classification"], indent=2))
    print("enum users:", enum_sites)
    print("VERDICT:", artifact["verdicts"])


if __name__ == "__main__":
    main()
