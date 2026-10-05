#!/usr/bin/env python3
"""57ZZ: canonical AppleARMIODevice vtable derivation.

Derives the AppleARMIODevice class object, vtable, and allocator from the
AppleARMPlatform fileset entry using mod_init registration analysis and the
chained-fixup decoder. Consumed by the provider-publication evidence so the
ARMIO addresses have a single source of truth.
"""

import importlib.util as _ilu
import json
import os as _os

import capstone

_fixup_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
_fixup_spec = _ilu.spec_from_file_location("phase05f_57zz_fixup_index", _fixup_path)
fixup_index = _ilu.module_from_spec(_fixup_spec)
_fixup_spec.loader.exec_module(fixup_index)

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-armiodevice-vtable.json"

KC = 0xFFFFFFF007004000

# AppleARMPlatform fileset entry segments (established in the provider pass)
EVM, EFO, ESZ = 0xFFFFFFF00837BEE0, 0x1377EE0, 0x60000

# Established anchors (validated by instruction evidence below):
REG_FN = 0xFFFFFFF008388BB0        # class registration (x1 = "AppleARMIODevice")
ALLOC_FN = 0xFFFFFFF008387EB8      # allocator (both args forwarded to init)


def vm2fo(vm):
    return EFO + (vm - EVM)


def derive():
    data = open(BOOTKC, "rb").read()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    # --- registration analysis: vtable from registration fn x16 chain ---
    reg_fo = vm2fo(REG_FN)
    reg_insns = list(md.disasm(data[reg_fo : reg_fo + 0x50], REG_FN))
    class_obj = None
    vtable = None
    pages = {}
    for ins in reg_insns:
        if ins.mnemonic == "adrp":
            parts = [p.strip() for p in ins.op_str.split(",")]
            try:
                pages[parts[0]] = int(parts[1].replace("#", ""), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add":
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) == 3 and parts[0] == parts[1] and parts[0] in pages:
                try:
                    imm = int(parts[2].replace("#", "").replace("0x", ""), 16)
                    pages[parts[0]] = pages[parts[0]] + imm
                except Exception:
                    pass
        elif ins.mnemonic == "pacda":
            vtable = pages.get("x16")
            break

    # --- class object from the allocator's x22 setup (0x...87eec/ef0):
    #     adrp x22, #0xfffffff00afef000; add x22, x22, #0x458 ---
    alloc_fo = vm2fo(ALLOC_FN)
    alloc_insns = list(md.disasm(data[alloc_fo : alloc_fo + 0x50], ALLOC_FN))
    apages = {}
    for ins in alloc_insns:
        if ins.mnemonic == "adrp":
            parts = [p.strip() for p in ins.op_str.split(",")]
            try:
                apages[parts[0]] = int(parts[1].replace("#", ""), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add":
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) == 3 and parts[0] == parts[1] == "x22" and "x22" in apages:
                try:
                    class_obj = apages["x22"] + int(parts[2].replace("#", "").replace("0x", ""), 16)
                except Exception:
                    pass
        if ins.mnemonic == "bl" and ins.address > ALLOC_FN + 0x40:
            break

    # --- vtable +0x360 resolution via the shared canonical decoder ---
    index = fixup_index.build_fixup_index(path=BOOTKC)

    start_target = index.get(vtable + 0x360) if vtable else None

    artifact = {
        "gate": "57ZZ_APPLEARMIODEVICE_VTABLE",
        "class_object": hex(class_obj) if class_obj else None,
        "registration_function": hex(REG_FN),
        "vtable": hex(vtable) if vtable else None,
        "start_slot_0x360": hex(start_target) if start_target else None,
        "allocator_function": hex(ALLOC_FN),
        "allocator_register_contract": {
            "note": "both args forwarded unchanged to the init virtual (see provider-publication evidence)",
        },
        "expected_assertions": {
            "class_object": "0xfffffff00afef458",
            "vtable": "0xfffffff007d336e0",
        },
    }
    ok = (
        class_obj == 0xFFFFFFF00AFEF458
        and vtable == 0xFFFFFFF007D336E0
        and start_target is not None
    )
    artifact["verdict"] = "PASS" if ok else "FAIL"
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(derive())
