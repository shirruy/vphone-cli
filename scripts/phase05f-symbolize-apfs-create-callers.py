#!/usr/bin/env python3
"""57ZZ Part 14H: symbolized caller analysis for _APFSVolumeCreate.

Uses the indirect symbol table (validated against __auth_got) to symbolize
every BL in the caller functions, then classifies the x0/x1 provenance
at each _APFSVolumeCreate callsite.

CRITICAL FINDING from this iteration: the previously-reported 7th caller
(0x1001a2320 -> stub 0x1001be950) is actually _dispatch_queue_set_specific,
NOT _APFSVolumeCreate. The true direct caller count is 6.
"""

import json
import os
import struct
import hashlib

import capstone

BIN = os.path.join(os.environ["TEMP"], "57zz-binaries", "restored_external.bin")
OUT = "artifacts/evidence/05f/phase05f-apfs-create-callers-symbolized.json"
OUT_TXT = "artifacts/evidence/05f/phase05f-apfs-create-callers-symbolized.txt"

TEXT_BASE = 0x100000000
TEXT_START = 0x1000020C0
TEXT_SIZE = 0x1B9880
APFS_CREATE_STUB = 0x1001BC990


def parse_macho(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    symtab = None
    dysymtab = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x2:  # LC_SYMTAB
            symtab = struct.unpack_from("<IIII", data, off + 8)
        elif cmd == 0xB:  # LC_DYSYMTAB
            dysymtab = struct.unpack_from("<14I", data, off + 8)
        off += cmdsize
    return symtab, dysymtab


def build_stub_map(data, symtab, dysymtab):
    symoff, nsyms, stroff, _strsize = symtab
    indirectsymoff = dysymtab[12]

    def sym_name(idx):
        if idx >= nsyms:
            return f"<invalid:{idx}>"
        n_strx = struct.unpack_from("<I", data, symoff + idx * 16)[0]
        end = data.find(b"\0", stroff + n_strx)
        return data[stroff + n_strx : end].decode("utf-8", "replace")

    # __auth_stubs: vm 0x1001bb940, size 0x4770, 16 bytes each
    # __auth_got:   vm 0x1002ec8e0, size 0x23d0, 8 bytes each
    auth_stubs_vm, auth_stubs_size = 0x1001BB940, 0x4770
    got_base_vm, got_size = 0x1002EC8E0, 0x23D0
    n_got = got_size // 8

    stub_map = {}
    for i in range(auth_stubs_size // 16):
        sv = auth_stubs_vm + i * 16
        fo = sv - TEXT_BASE
        i1 = struct.unpack_from("<I", data, fo)[0]
        i2 = struct.unpack_from("<I", data, fo + 4)[0]
        if (i1 & 0x9F000000) != 0x90000000:  # adrp
            continue
        if (i2 & 0xFF800000) != 0x91000000:  # add
            continue
        immlo = (i1 >> 29) & 0x3
        immhi = (i1 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (sv & ~0xFFF) + (imm << 12)
        add_imm = (i2 >> 10) & 0xFFF
        got = page + add_imm
        gi = (got - got_base_vm) // 8
        if 0 <= gi < n_got:
            isym = struct.unpack_from("<I", data, indirectsymoff + gi * 4)[0] & 0xFFFFFF
            stub_map[sv] = sym_name(isym)
    return stub_map


CALLERS = [
    {"callsite": 0x100024428, "window_start": 0x1000243B8, "window_size": 0x13C},
    {"callsite": 0x10003F970, "window_start": 0x10003F880, "window_size": 0x284},
    {"callsite": 0x100053458, "window_start": 0x100053278, "window_size": 0x2FC},
    {"callsite": 0x10007C1AC, "window_start": 0x10007C138, "window_size": 0x408},
    {"callsite": 0x10007C1C4, "window_start": 0x10007C138, "window_size": 0x408},
    {"callsite": 0x10007E874, "window_start": 0x10007E4DC, "window_size": 0x7B4},
    # 0x1001a2320 EXCLUDED: stub 0x1001be950 -> _dispatch_queue_set_specific (verified)
]


def classify_x1(window_insns, callsite):
    """Find last x1 write before callsite and whether an intervening BL exists."""
    last_x1_write = None
    intervening_bl = False
    for ins in window_insns:
        if ins.address >= callsite:
            break
        writes_x1 = ins.mnemonic in ("mov", "add", "ldr", "orr") and ins.op_str.startswith(("x1,", "w1,"))
        if writes_x1:
            last_x1_write = {"vm": hex(ins.address), "insn": f"{ins.mnemonic} {ins.op_str}"}
            intervening_bl = False
        elif ins.mnemonic == "bl" and last_x1_write is not None:
            intervening_bl = True
    return {
        "last_x1_write": last_x1_write,
        "intervening_bl_after_write": intervening_bl,
        "classification": (
            "ABI_CLOBBERED" if intervening_bl else ("LOCAL_DEF" if last_x1_write else "NONE_FOUND")
        ),
    }


def main():
    data = open(BIN, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    symtab, dysymtab = parse_macho(data)
    stub_map = build_stub_map(data, symtab, dysymtab)

    # sanity: the known stub must resolve
    assert stub_map.get(APFS_CREATE_STUB) == "_APFSVolumeCreate", stub_map.get(APFS_CREATE_STUB)

    # Full-text scan for every BL targeting the _APFSVolumeCreate stub
    text_fo = TEXT_START - TEXT_BASE
    all_callsites = []
    for ins in md.disasm(data[text_fo : text_fo + TEXT_SIZE], TEXT_START):
        if ins.mnemonic != "bl":
            continue
        try:
            tv = int(ins.op_str[1:], 16)
        except ValueError:
            continue
        if tv == APFS_CREATE_STUB:
            all_callsites.append(ins.address)
    assert all_callsites == [c["callsite"] for c in CALLERS], (
        f"callsite drift: scan={list(map(hex, all_callsites))}"
    )

    results = []
    txt_lines = []
    for c in CALLERS:
        fo = c["window_start"] - TEXT_BASE
        code = data[fo : fo + c["window_size"]]
        insns = list(md.disasm(code, c["window_start"]))

        lines = []
        bl_symbols = []
        for ins in insns:
            note = ""
            if ins.mnemonic == "bl":
                tv = int(ins.op_str[1:], 16)
                if tv in stub_map:
                    note = f"  ; {stub_map[tv]}"
                    bl_symbols.append({"vm": hex(ins.address), "target": stub_map[tv]})
                elif 0x1001C00C0 <= tv < 0x1001C00C0 + 0x5CA0:
                    note = "  ; __objc_stubs"
                    bl_symbols.append({"vm": hex(ins.address), "target": "__objc_stubs"})
                else:
                    note = "  ; local"
                    bl_symbols.append({"vm": hex(ins.address), "target": "local"})
            marker = " <<<< _APFSVolumeCreate" if ins.address == c["callsite"] else ""
            lines.append(f"{ins.address:x}  {ins.mnemonic:<8} {ins.op_str}{note}{marker}")

        x1 = classify_x1(insns, c["callsite"])
        results.append(
            {
                "callsite_vm": hex(c["callsite"]),
                "window": [hex(c["window_start"]), hex(c["window_start"] + c["window_size"])],
                "x1_provenance": x1,
                "bl_sequence": bl_symbols,
            }
        )
        txt_lines.append(f"=== CALLER {hex(c['callsite'])} ===")
        txt_lines.extend(lines)
        txt_lines.append("")

    artifact = {
        "gate": "IOS_DATA_VOLUME_LIFECYCLE_AUDIT",
        "iteration": "57ZZ_PART14H_SYMBOLIZED_CALLERS",
        "binary": {"path": BIN, "sha256": sha},
        "full_text_bl_scan": {
            "target_stub": hex(APFS_CREATE_STUB),
            "resolved_symbol": stub_map.get(APFS_CREATE_STUB),
            "callsite_count": len(all_callsites),
            "callsites": [hex(a) for a in all_callsites],
            "excluded_false_caller": {
                "vm": "0x1001a2320",
                "stub": "0x1001be950",
                "actual_symbol": "_dispatch_queue_set_specific",
            },
        },
        "stub_map_validation": {
            "0x1001bc990": stub_map.get(0x1001BC990),
            "resolver": "indirect_symbol_table_via_auth_got",
        },
        "callers": results,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))
    print(f"wrote {OUT} and {OUT_TXT}")
    for r in results:
        print(r["callsite_vm"], r["x1_provenance"]["classification"], r["x1_provenance"]["last_x1_write"])


if __name__ == "__main__":
    main()
