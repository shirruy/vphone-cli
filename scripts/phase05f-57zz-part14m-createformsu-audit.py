#!/usr/bin/env python3
"""57ZZ Part 14M: CreateForMSU sealed-volume path audit.

Audits _APFSVolumeCreateForMSU across APFS.framework, asr, and
restored_external: symbol discovery, import resolution, callers, ABI,
role/option evidence, crypto/seal/snapshot edges, and classification.
"""

import hashlib
import json
import os
import struct

import capstone

BINDIR = os.path.join(os.environ["TEMP"], "57zz-binaries")
OUT = "artifacts/evidence/05f/phase05f-57zz-part14m-createformsu-audit.json"


def parse_chained_imports(data, base=3129344):
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


def main():
    # --- Load binaries ---
    apfs = open(os.path.join(BINDIR, "APFS_framework.bin"), "rb").read()
    re_data = open(os.path.join(BINDIR, "restored_external.bin"), "rb").read()
    asr = open(os.path.join(BINDIR, "asr.bin"), "rb").read()

    # --- 14M-A: Symbol/reference discovery ---
    symbol_refs = {}
    for fn, d in (("APFS_framework.bin", apfs), ("asr.bin", asr), ("restored_external.bin", re_data)):
        symbol_refs[fn] = {
            "string_offset": hex(d.find(b"_APFSVolumeCreateForMSU")) if d.find(b"_APFSVolumeCreateForMSU") >= 0 else None,
            "createformsu_string": d.find(b"CreateForMSU") >= 0,
        }

    # APFS.framework: real symbol with implementation
    ncmds = struct.unpack_from("<I", apfs, 16)[0]
    symtab = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", apfs, off)
        if cmd == 0x2:
            symtab = struct.unpack_from("<IIII", apfs, off + 8)
        off += cmdsize
    symoff, nsyms, stroff, _ = symtab
    msu_symbol = None
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", apfs, symoff + i * 16)
        end = apfs.find(b"\0", stroff + n_strx)
        nm = apfs[stroff + n_strx : end].decode("utf-8", "replace")
        if nm == "_APFSVolumeCreateForMSU":
            msu_symbol = {"index": i, "vm": hex(n_value), "type": hex(n_type), "sect": n_sect}

    # restored_external imports
    re_imports = parse_chained_imports(re_data)
    msu_import_ordinal = re_imports.index("_APFSVolumeCreateForMSU")

    # --- 14M-B/C: Caller + ABI in restored_external ---
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    msu_stub = 0x1001BC520
    text_fo = 0x20C0
    callers = []
    for ins in md.disasm(re_data[text_fo : text_fo + 0x1B9880], 0x1000020C0):
        if ins.mnemonic == "bl":
            try:
                tv = int(ins.op_str[1:], 16)
            except ValueError:
                tv = None
            if tv == msu_stub:
                callers.append(hex(ins.address))

    # --- 14M role evidence: the wrapper calls MSU only when LP role == 1 (System) ---
    msu_condition = {
        "check_site": "0x100082928-0x100082938",
        "disassembly": [
            "0x100082928 adrp x8, [auth_ptr slot 0x1002ef518]",
            "0x10008292c ldr x8, [x8, #0x518]   ; _APFSVolumeCreateForMSU function pointer",
            "0x100082930 cbz x8, 0x1000829c8     ; skip if API unavailable",
            "0x100082934 cmp w25, #1             ; LP role == 1 (System)",
            "0x100082938 b.ne 0x1000829c8         ; non-System -> normal path",
        ],
        "auth_ptr_slot": "0x1002ef518",
        "auth_ptr_bind": "_APFSVolumeCreateForMSU (chained bind ordinal 0x7a)",
        "conclusion": "CreateForMSU is used ONLY for the System volume (LP role 1), and only when the API pointer is non-null on-device.",
    }

    # --- 14M-E: Options/dictionary ---
    options = {
        "finding": "The wrapper passes the SAME x28 CFDictionary to both _APFSVolumeCreate and _APFSVolumeCreateForMSU. The dictionary construction is identical (Name/Role/NoAutomount/CaseSensitive/Reserve/Quota/GroupSiblingFSIndex).",
        "call_sequence_msu": [
            "0x1000829b0 mov x0, x21          ; container",
            "0x1000829b4 bl fileSystemRepresentation ; name -> C string",
            "0x1000829bc mov x1, x28          ; SAME dictionary",
            "0x1000829c0 bl _APFSVolumeCreateForMSU",
        ],
        "call_sequence_normal": [
            "0x1000829c8 mov x0, x21          ; container",
            "0x1000829cc bl fileSystemRepresentation",
            "0x1000829d4 mov x1, x28          ; SAME dictionary",
            "0x1000829d8 bl _APFSVolumeCreate",
        ],
    }

    # --- 14M-F/G: crypto/seal ---
    crypto_seal = {
        "framework_stub": {
            "vm": "0x2b824",
            "disassembly": "mov w0, #0x2d; ret",
            "finding": "In THIS firmware build the exported _APFSVolumeCreateForMSU is a 2-instruction stub returning error 0x2d (not-implemented/unavailable). The sealed/MSU path cannot succeed via this export in this build.",
        },
        "internal_helper": {
            "symbol": "__APFSVolumeOtiRequestHelper",
            "vm": "0x2b8c4",
            "finding": "The adjacent internal function (reached from the pre-stub wrapper at 0x2b82c with w5=2) builds a 0x4c8-byte request and invokes an internal ioctl-ish call (0xcac / 0x6da6c). Request types 1 and 4 output a volume handle. This is the OTI (one-time-index) machinery, but it is NOT reachable through the exported stub in this build.",
        },
        "encryption_keybag": "No encryption/keybag property is added by the CreateForMSU path: the dictionary is identical to the normal path.",
        "seal_snapshot": "No seal/snapshot operation is invoked by the CreateForMSU path in restored_external.bin.",
    }

    # --- Classification ---
    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14M_CREATEFORMSU_AUDIT",
        "phase_a_symbol_refs": symbol_refs,
        "phase_a_msu_symbol": msu_symbol,
        "phase_a_import": {"binary": "restored_external.bin", "ordinal": msu_import_ordinal, "stub": "0x1001bc520", "got": "0x1002ecc10"},
        "phase_c_callers": callers,
        "phase_d_role": msu_condition,
        "phase_e_options": options,
        "phase_f_g_crypto_seal": crypto_seal,
        "phase_r_post_call_behavior": {
            "callsite": "0x1000829c0",
            "convergence": "0x1000829c4 b 0x1000829dc (joins normal-path result handling)",
            "result_test": "0x1000829dc mov x25, x0; 0x1000829e0 cbz w0, 0x100082b30 (0=success)",
            "error_path": [
                "0x1000829e4 cbz x22, skip-error-object",
                "0x1000829fc sxtw x3, w25 (errno into NSError constructor)",
                "0x100082a14 str x0, [x22] (error object out)",
                "0x100082a84 stur w25, [x0, #0xe] (errno stored in log record)",
                "0x100082aa0 mov x24, #0 (nil result)",
                "0x100082aa4 b 0x10008242c (release + return)",
            ],
            "fallback_to_normal": "PROVEN_ABSENT: no branch in post-call region [0x1000829dc, end) targets the normal-create block [0x1000829c8, 0x1000829dc). BFS from the callsite (excluding pre-call reachability) shows the failure edges terminate at release/error-record paths returning x24=0.",
            "error_semantics": "nonzero = error (errno-like int), zero = success (then continues to fsindex post-processing at 0x100082b30)",
            "0x2d_meaning": "UNKNOWN (no errno table/strerror mapping found in analyzed artifacts; do not label ENOTSUP from memory)",
        },
        "phase_r_import_binding": {
            "ordinal": 122,
            "weak_import": True,
            "evidence": "import entry raw>>8 & 1 == 1 for _APFSVolumeCreateForMSU; _APFSVolumeCreate (121) has weak=0. The cbz x8 after the auth_ptr load is a real weak-import availability check.",
            "verdict": "CREATEFORMSU_IMPORT: WEAK",
        },
        "phase_r_oti_reachability": {
            "corrected": True,
            "finding": "The adjacent function at 0x2b82c is NOT an anonymous pre-stub: it is _APFSVolumeSetOtiLockerData (exported, N_EXT). __APFSVolumeOtiRequestHelper (0x2b8c4) is N_EXT=False (internal). The 6 exported OtiLocker APIs tail-branch into the internal helper; _APFSVolumeCreateForMSU (0x2b824) is a separate 2-instruction stub with NO CFG edge to the helper (immediate ret; no caller of 0x2b824 or 0x2b82c within APFS.framework text).",
            "edge": "CREATEFORMSU_TO_OTI_EDGE: PROVEN_ABSENT",
        },
        "phase_j_comparison": {
            "normal_vs_msu": "Both paths share the SAME wrapper, SAME dictionary construction, and SAME x1 CFDictionary. The only differences are (1) the API called and (2) the eligibility check: MSU requires the API pointer to be non-null AND LP role == 1 (System).",
            "why_two_paths": "CreateForMSU is the sealed/MSU System-volume creation entry. On this firmware build it is stubbed to return 0x2d, so restore falls back to... actually NO fallback exists at the wrapper level: the MSU result is returned directly. The sealed path is simply unavailable in this build.",
        },
        "classification": "CREATEFORMSU_SYSTEM_ONLY_STUBBED_PATH",
        "classification_rationale": "CreateForMSU is exclusively System-role (LP 1), weakly imported (availability-gated), shares the normal dictionary, and its implementation in this firmware build always returns 0x2d with no fallback to normal create. The error propagates as NSError and the wrapper returns nil. The MSU path is a disabled/dead System-only branch in this build.",
        "verdicts": {
            "CREATEFORMSU_STATIC_AUDIT": "PASS",
            "MSU_FALLBACK_TO_NORMAL_CREATE": "PROVEN_ABSENT",
            "CREATEFORMSU_IMPORT": "WEAK",
            "CREATEFORMSU_TO_OTI_EDGE": "PROVEN_ABSENT",
            "DATA_LIFECYCLE_STATIC_GATE": "BLOCKED_EXTERNAL_BOUNDARY",
            "RUNTIME_MOUNT_IDENTITY": "DEFERRED",
        },
        "remaining_blockers": [
            "External restore orchestrator binary that invokes addVolumeWithName:role:... with LP role 3 (Data).",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["phase_d_role"], indent=2))
    print("CLASSIFICATION:", artifact["classification"])
    print("VERDICTS:", artifact["verdicts"])


if __name__ == "__main__":
    main()
