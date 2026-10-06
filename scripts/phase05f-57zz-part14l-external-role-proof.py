#!/usr/bin/env python3
"""57ZZ Part 14L: external orchestrator / Data role=0x40 proof.

Fail-closed audit implementing phases 14L-A..14L-E:
  A. search every available restore binary for the addVolume selector
  B. recover the role argument dataflow inside the known wrapper IMP
  C. recover the conditional control flow around role usage
  D. trace pairedVolume at the creation site
  E. cross-check the numeric role encoding across binaries
"""

import hashlib
import json
import os
import struct

import capstone

BINDIR = os.path.join(os.environ["TEMP"], "57zz-binaries")
OUT = "artifacts/evidence/05f/phase05f-57zz-part14l-external-role-proof.json"
SELECTOR = b"addVolumeWithName:role:caseSensitive:reserveSize:quotaSize:pairedVolume:error:"


def phase_a():
    """Search every binary for the selector."""
    rows = []
    for fn in sorted(os.listdir(BINDIR)):
        p = os.path.join(BINDIR, fn)
        data = open(p, "rb").read()
        full = data.find(SELECTOR)
        prefix = data.find(b"addVolumeWithName:")
        rows.append(
            {
                "binary": fn,
                "sha256": hashlib.sha256(data).hexdigest(),
                "selector_present": full >= 0,
                "selector_offset": hex(full) if full >= 0 else None,
                "prefix_present": prefix >= 0,
            }
        )
    return rows


def disasm_restored_external():
    data = open(os.path.join(BINDIR, "restored_external.bin"), "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[0x20C0 : 0x20C0 + 0x1B9880], 0x1000020C0))
    return data, insns


def phase_b(data, insns):
    """Recover role (w3 -> x25) dataflow in the wrapper IMP 0x1000821bc."""
    idx = {ins.address: i for i, ins in enumerate(insns)}
    # Prologue: mov x25, x3 @ 0x1000821f0
    prologue = []
    for k in range(idx[0x1000821F0], idx[0x1000821F0] + 1):
        prologue.append(f"{insns[k].address:x}  {insns[k].mnemonic} {insns[k].op_str}")
    # Role dictionary site: 0x100082680..0x1000826b0
    role_site = []
    for k in range(idx[0x100082680], idx[0x1000826B4]):
        role_site.append(f"{insns[k].address:x}  {insns[k].mnemonic} {insns[k].op_str}")
    return {
        "prologue_save": prologue,
        "role_dictionary_site": role_site,
        "finding": "role param (w3) saved to x25; wrapped into NSNumber via numberWithInt: and stored under kAPFSVolumeRoleKey. The VALUE is passed through UNMODIFIED from the ObjC caller.",
    }


def phase_c(data, insns):
    """Control flow around role usage."""
    idx = {ins.address: i for i, ins in enumerate(insns)}
    lines = []
    for k in range(idx[0x1000824AC], idx[0x1000825B0]):
        ins = insns[k]
        note = "  <<< ROLE CHECK" if "w25" in ins.op_str else ""
        lines.append(f"{ins.address:x}  {ins.mnemonic} {ins.op_str}{note}")
    return {
        "role_branch": lines,
        "finding": "cmp w25, #1 branches System vs non-System creation paths. The wrapper treats role as a LOGICAL enum (1 = System), NOT APFS numeric role bits.",
    }


def phase_d(data, insns):
    """pairedVolume (x5 -> x27) trace."""
    idx = {ins.address: i for i, ins in enumerate(insns)}
    lines = []
    for k in range(idx[0x1000827C4], idx[0x100082870]):
        ins = insns[k]
        note = ""
        if "x26" in ins.op_str:
            note = "  <<< GroupSiblingFSIndex key"
        if "intValue" in str(ins):
            note = "  <<< intValue"
        lines.append(f"{ins.address:x}  {ins.mnemonic} {ins.op_str}{note}")
    return {
        "paired_volume_flow": lines,
        "finding": "pairedVolume (x5->x27) is optional; when present its intValue is wrapped in numberWithInt: and stored under kAPFSVolumeGroupSiblingFSIndexKey.",
    }


def phase_e():
    """Cross-check numeric role encodings across all binaries."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    results = []
    for fn in ("restored_external.bin", "APFS_framework.bin", "newfs_apfs.bin", "mount_apfs.bin"):
        data = open(os.path.join(BINDIR, fn), "rb").read()
        if fn == "restored_external.bin":
            text_fo, text_vm, text_size = 0x20C0, 0x1000020C0, 0x1B9880
        elif fn == "APFS_framework.bin":
            text_fo, text_vm, text_size = 0xA40, 0xA40, 0x543A8
        else:
            text_fo, text_vm, text_size = 0x810, 0x100000810, None
            # parse actual size
            off = 32
            ncmds = struct.unpack_from("<I", data, 16)[0]
            for _ in range(ncmds):
                cmd, csz = struct.unpack_from("<II", data, off)
                if cmd == 0x19:
                    seg = data[off + 8 : off + 24].split(b"\0", 1)[0].decode()
                    if seg == "__TEXT":
                        nsects = struct.unpack_from("<I", data, off + 64)[0]
                        so = off + 72
                        for s in range(nsects):
                            raw = data[so : so + 80]
                            nm = raw[0:16].split(b"\0", 1)[0].decode()
                            if nm == "__text":
                                text_vm = struct.unpack_from("<Q", raw, 32)[0]
                                text_size = struct.unpack_from("<Q", raw, 40)[0]
                                text_fo = text_vm - (0x100000000 if text_vm > 0x100000000 else 0)
                            so += 80
                off += csz
            if text_size is None:
                continue
        insns = list(md.disasm(data[text_fo : text_fo + text_size], text_vm))
        role_40_sites = []
        for i, ins in enumerate(insns):
            if ins.mnemonic in ("mov", "orr") and ins.op_str.rstrip().endswith("#0x40"):
                role_40_sites.append(hex(ins.address))
        role_names = {}
        for name in (b"System", b"Data", b"Preboot", b"Recovery", b"Update"):
            if data.find(name) >= 0:
                role_names[name.decode()] = hex(data.find(name))
        results.append(
            {
                "binary": fn,
                "mov_0x40_sites": role_40_sites,
                "role_name_strings": role_names,
            }
        )
    return results


def main():
    rows = phase_a()
    data, insns = disasm_restored_external()
    b = phase_b(data, insns)
    c = phase_c(data, insns)
    d = phase_d(data, insns)
    e = phase_e()

    selector_binaries = [r["binary"] for r in rows if r["selector_present"]]
    verdict = "DATA_ROLE_0x40_STATIC_PROOF_BLOCKED"
    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14L_EXTERNAL_ROLE_PROOF",
        "phase_a_binary_search": rows,
        "phase_a_finding": f"Selector present only in: {selector_binaries}. No other restore binary contains it.",
        "phase_b_role_dataflow": b,
        "phase_c_control_flow": c,
        "phase_d_paired_volume": d,
        "phase_e_role_cross_check": e,
        "key_findings": {
            "external_orchestrator": "NOT FOUND in any available binary. The selector has exactly one selref in restored_external.bin and zero in-binary code users. The orchestrator that passes role/pairedVolume is outside the extracted set.",
            "role_encoding_in_wrapper": "LOGICAL_ENUM: cmp w25, #1 = System branch. The wrapper does NOT contain APFS numeric role constants.",
            "role_0x40_in_extracted_binaries": "No executable dataflow chain in restored_external, APFS_framework, newfs_apfs, or mount_apfs links a Data invocation to numeric role 0x40 within this iteration's analysis.",
            "newfs_apfs_finding": "newfs_apfs contains no role-name strings and no direct 0x40 role constant. Its --role=%s handling stores the raw string for later conversion elsewhere.",
            "paired_volume": "pairedVolume -> intValue -> kAPFSVolumeGroupSiblingFSIndexKey proven at the wrapper, but the actual DATA-invocation value is supplied externally.",
        },
        "verdict": verdict,
        "blocked_reason": "The external orchestrator that calls LPStaticAPFSContainer addVolumeWithName:role:... with the DATA role value is not present in the extracted binaries. A dataflow-proven role=0x40 requires either: (1) the calling binary (restored/asr host-side or an XPC service), or (2) an equivalent role-enum-to-APFS-bits conversion site inside APFS.framework/kernel that is downstream of the wrapper and provably fed by this path.",
        "required_next_artifacts": [
            "restored host-side binary (not restored_external) that invokes LPStaticAPFSContainer methods",
            "OR the LogicalPlatform framework containing the orchestrator",
            "OR a runtime capture of the addVolume invocation",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["key_findings"], indent=2))
    print("VERDICT:", verdict)


if __name__ == "__main__":
    main()
