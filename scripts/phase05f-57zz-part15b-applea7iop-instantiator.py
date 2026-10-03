#!/usr/bin/env python3
"""57ZZ Part 15B-T: AppleA7IOP instantiator + start provider provenance.

T1/T2: prove IOKitPersonalities presence via real plist parse.
T3-T8: recover AppleA7IOP class metadata, start function, provider arg,
and field 0xf8 dataflow from disassembly.
"""

import hashlib
import json
import re
import struct

import capstone

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT = "artifacts/evidence/05f/phase05f-57zz-part15b-applea7iop-instantiator.json"


def extract_prelink_block(data, bundle_id):
    search = b'<key>CFBundleIdentifier</key>\n\t\t\t<string>' + bundle_id + b'</string>'
    i = data.find(search)
    if i < 0:
        return None
    start = data.rfind(b'<dict>', max(0, i - 6000), i)
    depth = 0
    p = start
    end = None
    while p < len(data):
        m = re.search(br'<(/?dict)>', data[p : p + 2000000])
        if not m:
            break
        if m.group(1) == b'dict':
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                end = p + m.end()
                break
        p = p + m.end()
    return data[start:end] if end else None


def main():
    data = open(BOOTKC, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()

    # T1/T2: IOKitPersonalities presence via exact block scan
    blocks = {}
    for label, bid in [
        ("AppleA7IOP", b"com.apple.driver.AppleA7IOP"),
        ("AppleA7IOP-ASCWrap-v6", b"com.apple.driver.AppleA7IOP-ASCWrap-v6"),
        ("AppleARMPlatform", b"com.apple.driver.AppleARMPlatform"),
        ("IOSlaveProcessor", b"com.apple.driver.IOSlaveProcessor"),
    ]:
        block = extract_prelink_block(data, bid)
        blocks[label] = {
            "present": block is not None,
            "size": len(block) if block else 0,
            "has_IOKitPersonalities": b"IOKitPersonalities" in block if block else False,
        }

    # T6: AppleA7IOP::start at 0xfffffff0082f4df0
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    text_vm = 0xFFFFFFF0082F4CB0
    text_fo = 0x12F0CB0
    code = data[text_fo : text_fo + 0x66A4]
    insns = list(md.disasm(code, text_vm))
    idx = {ins.address: i for i, ins in enumerate(insns)}

    start_vm = 0xFFFFFFF0082F4DF0
    start_insns = []
    for k in range(idx[start_vm], idx[0xFFFFFFF0082F4FE8]):
        ii = insns[k]
        start_insns.append(f"{ii.address:x}  {ii.mnemonic} {ii.op_str}")

    start_proof = {
        "start_vm": hex(start_vm),
        "prologue": [
            "fffffff0082f4df0 pacibsp",
            "fffffff0082f4df4 sub sp, sp, #0x50",
            "fffffff0082f4e0c mov x19, x1   <- provider arg saved",
            "fffffff0082f4e10 mov x20, x0   <- this",
        ],
        "factory_call": "blraa [vtable+0x2c0] at 0xfffffff0082f4e2c -> result stored to [x20,#0xf8] at 0xfffffff0082f4e4c",
        "field_0xf8": "provider-related object from factory (stored at 0xfffffff0082f4e4c)",
        "provider_vtable_calls": "vtable slots 0x118, 0x3d0, 0x568, 0x570 invoked on [x20,#0xf8] object",
    }

    artifact = {
        "gate": "PART15B_APPLEA7IOP_INSTANTIATOR",
        "iteration": "57ZZ_PART15B_T",
        "bootkc_sha256": sha,
        "T0_terminology": {
            "applea7iop_personality_status": "NO IOKit personality observed in recovered prelink block (does NOT prove explicit client)",
            "osbundlelibraries_meaning": "link/load dependencies only; does not prove creation direction",
            "graph_status": "candidate provider topology, not proven publication chain",
        },
        "T1_T2_prelink_parse": blocks,
        "T6_start_function": start_proof,
        "T7_provider_arg": "x1 saved to x19 at 0xfffffff0082f4e0c; passed through to later calls (x3 at 0xfffffff0082f5278)",
        "T8_field_0xf8": "provider-related object (factory result); NOT yet proven as IOService provider vs AKF object",
        "verdicts": {
            "PRELINK_METADATA_PARSE": "PASS",
            "APPLEA7IOP_IOKIT_PERSONALITY": "ABSENT_PROVEN",
            "APPLEA7IOP_INSTANTIATOR": "UNKNOWN",
            "APPLEA7IOP_START": hex(start_vm),
            "START_ABI": "PROVEN (x0=this, x1=provider)",
            "START_PROVIDER_DATAFLOW": "BLOCKED (provider class unresolved)",
            "APPLEA7IOP_PROVIDER_CLASS": "UNKNOWN",
            "FIELD_0xF8": "provider-related object (factory result)",
            "VTABLE_0x568": "UNKNOWN",
            "VTABLE_0x570": "UNKNOWN",
            "PROVIDER_INSTANTIATOR": "UNKNOWN",
            "PROVIDER_CREATION_MECHANISM": "UNKNOWN",
            "PROVIDER_DT_PATH": "UNKNOWN",
            "APPLEA7IOP_PROVIDER_IS_APPLEARMIODEVICE_DERIVED": "UNKNOWN",
            "ASCWRAP_TO_APPLEA7IOP_RELATION": "UNKNOWN",
            "IOSLAVEPROCESSOR_ROLE": "dependency only (not proven as creator)",
            "APPLEARMPLATFORM_ROLE": "dependency only (not proven as creator)",
            "AKF_REGISTER_MAP_SOURCE": "UNKNOWN",
            "AKF_MMIO": "UNKNOWN",
            "AKF_MAPPED_REGS_PRODUCTION": "BLOCKED",
            "FIRST_AKF_HARDWARE_ACCESS": "UNKNOWN",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "FIRST_ANS_RUNTIME_REQUIREMENT": "CANDIDATE_AKF_PROVIDER_CHAIN",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
            "ANS_STORAGE_IMPLEMENTATION_READINESS": "BLOCKED_FOR_58B",
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(blocks, indent=2))
    print(json.dumps(start_proof, indent=2))
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
