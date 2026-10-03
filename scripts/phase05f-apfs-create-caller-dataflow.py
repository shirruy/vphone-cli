#!/usr/bin/env python3
"""57ZZ Part 14I: true _APFSVolumeCreate caller dataflow via chained fixups.

CORRECTION: Part 14H used an indirect-symbol-table resolver that misindexed
__auth_got slots (missing the reserved1 base). It identified stub 0x1001bc990
as _APFSVolumeCreate; that stub is actually _CFArrayGetTypeID.

This script resolves stubs through chained fixups (validated: _APFSVolumeCreate
is import ordinal 121, not present in the classic symtab), scans the full
__text section, and decodes the single real caller at 0x1000829d8 including
ObjC selector stubs and the dictionary construction chain.
"""

import hashlib
import json
import os
import struct

import capstone

BIN = os.path.join(os.environ["TEMP"], "57zz-binaries", "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-apfs-create-caller-dataflow.json"
OUT_TXT = "artifacts/evidence/05f/phase05f-apfs-create-caller-dataflow.txt"

TEXT_BASE = 0x100000000
TEXT_START = 0x1000020C0
TEXT_SIZE = 0x1B9880


def parse_macho(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    chained = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            dataoff, datasize = struct.unpack_from("<II", data, off + 8)
            chained = {"off": dataoff, "size": datasize}
        off += cmdsize
    return chained


def parse_chained_imports(data, chained):
    base = chained["off"]
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


SEGMENTS = [
    ("__TEXT", 0x100000000, 0x2C8000, 0x0),
    ("__DATA_CONST", 0x1002C8000, 0x28000, 0x2C8000),
    ("__DATA", 0x1002F0000, 0x10000, 0x2F0000),
]


def resolve_auth_stub(data, imports, stub_vm):
    """16-byte __auth_stubs: adrp/add/ldr/braa -> GOT -> chained bind ordinal."""
    fo = stub_vm - TEXT_BASE
    i1 = struct.unpack_from("<I", data, fo)[0]
    i2 = struct.unpack_from("<I", data, fo + 4)[0]
    if (i1 & 0x9F000000) != 0x90000000 or (i2 & 0xFF800000) != 0x91000000:
        return None
    immlo = (i1 >> 29) & 0x3
    immhi = (i1 >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page = (stub_vm & ~0xFFF) + (imm << 12)
    add_imm = (i2 >> 10) & 0xFFF
    got = page + add_imm
    for _name, vm, sz, fo in SEGMENTS:
        if vm <= got < vm + sz:
            gfo = fo + (got - vm)
            fixup = struct.unpack_from("<Q", data, gfo)[0]
            ordinal = fixup & 0xFFFFFF
            return {"got": hex(got), "ordinal": ordinal, "symbol": imports[ordinal] if ordinal < len(imports) else "OOR"}
    return None


def resolve_objc_stub(data, stub_vm):
    """12-byte __objc_stubs: adrp/ldr/br -> selref -> selector string."""
    fo = stub_vm - TEXT_BASE
    i1 = struct.unpack_from("<I", data, fo)[0]
    i2 = struct.unpack_from("<I", data, fo + 4)[0]
    if (i1 & 0x9F000000) != 0x90000000:
        return None
    if (i2 & 0xFFC00000) != 0xF9400000:  # ldr x16,[x16,#imm]
        return None
    immlo = (i1 >> 29) & 0x3
    immhi = (i1 >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page = (stub_vm & ~0xFFF) + (imm << 12)
    off = ((i2 >> 10) & 0xFFF) * 8
    selref_vm = page + off
    # __objc_selrefs lives in __DATA
    selref_fo = 0x2F0000 + (selref_vm - 0x1002F0000)
    raw = struct.unpack_from("<Q", data, selref_fo)[0]
    # chained pointer: target file offset in low 40 bits
    target_fo = raw & 0xFFFFFFFFFF
    end = data.find(b"\0", target_fo)
    selector = data[target_fo:end].decode("utf-8", "replace")
    return {"selref_vm": hex(selref_vm), "selector": selector}


def symbolize_bl(data, imports, target_vm):
    # auth stubs: 0x1001bb940..0x1001c00b0 (16B each)
    if 0x1001BB940 <= target_vm < 0x1001BB940 + 0x4770:
        r = resolve_auth_stub(data, imports, target_vm)
        return f"import:{r['symbol']}" if r else "auth_stub_unresolved"
    # objc stubs: 0x1001c00c0..0x1001c5d60 (12B each)
    if 0x1001C00C0 <= target_vm < 0x1001C00C0 + 0x5CA0:
        r = resolve_objc_stub(data, target_vm)
        return f"objc:{r['selector']}" if r else "objc_stub_unresolved"
    return None


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    chained = parse_macho(data)
    imports = parse_chained_imports(data, chained)

    # Validate: import 121 must be _APFSVolumeCreate
    assert imports[121] == "_APFSVolumeCreate", imports[121]
    # Find the real stub for _APFSVolumeCreate
    real_stub = None
    for i in range(0x4770 // 16):
        sv = 0x1001BB940 + i * 16
        r = resolve_auth_stub(data, imports, sv)
        if r and r["symbol"] == "_APFSVolumeCreate":
            real_stub = sv
            break
    assert real_stub is not None, "stub not found"

    # Full __text scan
    text_fo = TEXT_START - TEXT_BASE
    callsites = []
    for ins in md.disasm(data[text_fo : text_fo + TEXT_SIZE], TEXT_START):
        if ins.mnemonic != "bl":
            continue
        try:
            tv = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if tv == real_stub:
            callsites.append(ins.address)

    # Disassemble around the real caller(s) with full symbolization
    dump_lines = []
    for cs in callsites:
        start = cs - 0x300
        fo = start - TEXT_BASE
        for ins in md.disasm(data[fo : fo + 0x308], start):
            note = ""
            if ins.mnemonic == "bl":
                try:
                    tv = int(ins.op_str[1:], 16)
                except ValueError:
                    tv = None
                if tv:
                    sym = symbolize_bl(data, imports, tv)
                    if sym:
                        note = f"  ; {sym}"
            marker = " <<<< _APFSVolumeCreate" if ins.address == cs else ""
            dump_lines.append(f"{ins.address:x}  {ins.mnemonic:<8} {ins.op_str}{note}{marker}")

    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14I_CORRECTION",
        "binary": {"path": BIN, "sha256": sha},
        "correction": {
            "part14h_claim": "6 callers via stub 0x1001bc990",
            "part14h_bug": "indirect-symbol resolver missing reserved1 base index",
            "actual_stub_0x1001bc990": "_CFArrayGetTypeID",
            "real_APFSVolumeCreate_stub": hex(real_stub),
            "real_stub_resolution": resolve_auth_stub(data, imports, real_stub),
        },
        "full_text_scan": {
            "target": "_APFSVolumeCreate",
            "stub": hex(real_stub),
            "callsite_count": len(callsites),
            "callsites": [hex(c) for c in callsites],
        },
        "caller_dataflow_summary": {
            "callsite": "0x1000829d8",
            "x1_setup": "mov x1, x28 @ 0x1000829d4",
            "x28_dictionary_origin": [
                "0x10008282c bl objc:intValue -> x28 = x0 (role/int value)",
                "0x100082840 mov x2, x28 (value arg)",
                "0x100082848 bl objc:setObject:forKey: (dictionary insert)",
                "0x100082844 mov x28, x21 (x21 = the CFDictionary)",
            ],
            "dictionary_construction_calls": [
                "objc:intValue",
                "objc:numberWithInt:",
                "objc:setObject:forKey:",
                "objc:numberWithBool:",
                "objc:numberWithLongLong:",
                "objc:objectAtIndex:",
                "objc:count",
            ],
        },
        "verdict": "PART14H_RETRACTED_SINGLE_TRUE_CALLER",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(dump_lines))
    print(json.dumps(artifact["correction"], indent=2))
    print("callsites:", [hex(c) for c in callsites])
    print("wrote", OUT, "and", OUT_TXT)


if __name__ == "__main__":
    main()
