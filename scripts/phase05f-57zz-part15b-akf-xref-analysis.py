#!/usr/bin/env python3
"""57ZZ Part 15B-R: AKF string xref and AppleA7IOP CFG analysis.

15B-R4..R13: parse BootKC fileset, resolve AKF strings to VM, xref them in
the AppleA7IOP kext, and recover the AppleA7IOP::start control-flow facts.
"""

import hashlib
import json
import struct

import capstone

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT = "artifacts/evidence/05f/phase05f-57zz-part15b-akf-xref-analysis.json"

# Entry 24: com.apple.driver.AppleA7IOP-ASCWrap-v6
#   __TEXT vm 0xfffffff00713b720 fo 0x137720 (strings)
#   __TEXT_EXEC vm 0xfffffff0082f2bf0 fo 0x12eebf0 size 0x20b4
# Entry 25: com.apple.driver.AppleA7IOP
#   __TEXT vm 0xfffffff00713c1f0 fo 0x1381f0
#   __TEXT_EXEC vm 0xfffffff0082f4cb0 fo 0x12f0cb0 size 0x69b4

ENTRY24_TEXT_VM = 0xFFFFFFF00713B720
ENTRY24_TEXT_FO = 0x137720
ENTRY25_TEXT_VM = 0xFFFFFFF00713C1F0
ENTRY25_TEXT_FO = 0x1381F0
ENTRY24_EXEC_VM = 0xFFFFFFF0082F2BF0
ENTRY24_EXEC_FO = 0x12EEBF0
ENTRY24_EXEC_SIZE = 0x20B4
ENTRY25_EXEC_VM = 0xFFFFFFF0082F4CB0
ENTRY25_EXEC_FO = 0x12F0CB0
ENTRY25_EXEC_SIZE = 0x69B4


def fo2vm24(fo):
    return ENTRY24_TEXT_VM + (fo - ENTRY24_TEXT_FO)


def fo2vm25(fo):
    return ENTRY25_TEXT_VM + (fo - ENTRY25_TEXT_FO)


def xref_strings(data, exec_vm, exec_fo, exec_size, string_vms):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    code = data[exec_fo : exec_fo + exec_size]
    insns = list(md.disasm(code, exec_vm))
    last_adrp = {}
    hits = {}
    for ins in insns:
        if ins.mnemonic == "adrp":
            try:
                reg = ins.op_str.split(",")[0].strip()
                page = int(ins.op_str.split("#")[1], 16)
                last_adrp[reg] = (ins.address, page)
            except Exception:
                pass
        elif ins.mnemonic == "add":
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) == 3 and parts[0] == parts[1] and parts[0] in last_adrp:
                a, page = last_adrp[parts[0]]
                try:
                    imm = int(parts[2].replace("#", ""), 16)
                except Exception:
                    continue
                for name, svm in string_vms.items():
                    if page + imm == svm:
                        hits.setdefault(name, []).append({"adrp": hex(a), "add": hex(ins.address)})
        if ins.mnemonic in ("bl", "blr", "br", "ret"):
            last_adrp = {}
    return hits


def main():
    data = open(BOOTKC, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()

    # AKF strings in entry 24 __TEXT
    string_offsets = {
        "ASC firmware must be loaded by iBoot": 0x13804E,
        "AKF_RUNNING: False": 0x1380F7,
        "_akfProvider != nullptr": 0x1388E5,
        "_akfRegisterMap != nullptr": 0x138999,
        "_akfMappedRegs != 0": 0x1389B4,
        "AppleA7IOP::start(IOService *)": 0x1388B9,
        "role": 0x13890C,
    }
    string_vms = {k: fo2vm24(v) for k, v in string_offsets.items()}

    # xref in entry 24 exec (ASCWrap) and entry 25 exec (AppleA7IOP)
    xrefs_24 = xref_strings(data, ENTRY24_EXEC_VM, ENTRY24_EXEC_FO, ENTRY24_EXEC_SIZE, string_vms)
    xrefs_25 = xref_strings(data, ENTRY25_EXEC_VM, ENTRY25_EXEC_FO, ENTRY25_EXEC_SIZE, string_vms)

    # AKF mailbox strings are in the main kernel (not AppleA7IOP) - find their VMs
    # kernel entry 0: vm 0xfffffff00700c000 fo 0x8000, __TEXT is the fileset header itself.
    # AKF mailbox log strings at fo 0x99cf09..0x99cf85 are in some kernel kext.
    mailbox_offsets = {
        "AKF_KIC_INBOX_CTRL": 0x99CF09,
        "AKF_KIC_MAILBOX_SET": 0x99CF26,
        "AKF_AP_OUTBOX_CTRL": 0x99CF4C,
        "AKF_AP_MAILBOX_SET": 0x99CF85,
    }

    artifact = {
        "gate": "PART15B_AKF_XREF_ANALYSIS",
        "iteration": "57ZZ_PART15B_R",
        "bootkc_sha256": sha,
        "fileset_entries": {
            "entry_24_AppleA7IOP_ASCWrap_v6": {
                "text_vm": hex(ENTRY24_TEXT_VM),
                "text_fo": hex(ENTRY24_TEXT_FO),
                "exec_vm": hex(ENTRY24_EXEC_VM),
                "exec_fo": hex(ENTRY24_EXEC_FO),
                "exec_size": hex(ENTRY24_EXEC_SIZE),
            },
            "entry_25_AppleA7IOP": {
                "text_vm": hex(ENTRY25_TEXT_VM),
                "text_fo": hex(ENTRY25_TEXT_FO),
                "exec_vm": hex(ENTRY25_EXEC_VM),
                "exec_fo": hex(ENTRY25_EXEC_FO),
                "exec_size": hex(ENTRY25_EXEC_SIZE),
            },
        },
        "string_vm_map": {k: hex(v) for k, v in string_vms.items()},
        "xrefs_ASCWrap_entry24": xrefs_24,
        "xrefs_AppleA7IOP_entry25": xrefs_25,
        "key_findings": {
            "ASC_firmware_xref": "in ASCWrap entry 24 exec: REQUIRE-style assertion call site with line-number w9=0x97 (the 'ASC firmware must be loaded by iBoot' predicate)",
            "AKF_RUNNING_xref": "in ASCWrap entry 24: helper queries a provider getProperty-style vtable call (0x8110/0x8114 selectors), logs AKF_RUNNING False when bit0 clear",
            "akfProvider_akfRegisterMap_akfMappedRegs_xrefs": "in AppleA7IOP entry 25: two distinct sites; second site reads [x0,#0xf8] provider member and invokes vtable slots 0x568/0x570 via authenticated calls",
            "provider_member_offset": "0xf8 within AppleA7IOP object",
            "vtable_slots": ["0x568", "0x570"],
            "register_map_source": "UNKNOWN: no direct getDeviceMemory/region-base linkage proven yet; DT reg vs provider property origin unresolved",
            "mailbox_offsets": "NOT_PROVEN: AKF mailbox register names exist only as kernel log strings (0x99cf09..0x99cf85); numeric offsets/width/access direction unproven",
            "applea7iop_start_cfg": "PARTIAL: entry 25 start-related code identified via _akf* string xrefs; full start boundary and failure branches need per-function disassembly",
        },
        "mailbox_string_offsets": {k: hex(v) for k, v in mailbox_offsets.items()},
        "verdicts": {
            "STRING_XREFS_PROVEN": "PARTIAL",
            "APPLEA7IOP_START_CFG": "BLOCKED",
            "APPLEA7IOP_PROVIDER_CLASS": "UNKNOWN",
            "AKF_REGISTER_MAP_SOURCE": "UNKNOWN",
            "AKF_MMIO_BASE": "UNKNOWN",
            "AKF_MMIO_SIZE": "UNKNOWN",
            "MAILBOX_OFFSETS": "BLOCKED",
            "ASC_FIRMWARE_REQUIRED_FOR_58B": "UNKNOWN",
            "AKF_ROLE_PROPERTY_REQUIRED": "UNKNOWN",
            "FIRST_ANS_RUNTIME_REQUIREMENT": "CANDIDATE_AKF_PROVIDER_CHAIN",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
            "ANS_STORAGE_IMPLEMENTATION_READINESS": "BLOCKED_FOR_58B",
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["key_findings"], indent=2))
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
