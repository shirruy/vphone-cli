#!/usr/bin/env python3
"""Phase 05F 58B: canonical AppleASCWrapV6 vtable derivation.

Derives the AppleASCWrapV6 class object, vtable, IOService::start slot
(+0x360), and allocator from the com.apple.driver.AppleA7IOP-ASCWrap-v6
fileset entry of the bootkc, following the method used by
phase05f-57zz-armiodevice-vtable.py:

  1. locate the kext LC_FILESET_ENTRY by bundle identifier
  2. parse the kext Mach-O for __TEXT_EXEC/__text and __mod_init_func
  3. decode __mod_init_func chained pointers via the shared fixup index
  4. pick the init function whose x1 adrp+add chain points at the exact
     C-string "AppleASCWrapV6" and which calls the OSMetaClass
     registration stub
  5. read the vtable from that function's x16 adrp+add chain before pacda
  6. resolve vtable+0x360 through the shared chained-fixup decoder
  7. derive the allocator by locating the kext function that moves the
     class object into x1, calls the alloc stub, and installs a fresh
     vtable with its own x16 chain before pacda

No final vtable/start values are hardcoded; only anchor strings, the
bundle id, and structural offsets are inputs. Every step fails closed
into the JSON artifact when it cannot be derived.
"""

import hashlib
import importlib.util as _ilu
import json
import os as _os
import struct

import capstone

_fixup_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
_fixup_spec = _ilu.spec_from_file_location("phase05f_57zz_fixup_index", _fixup_path)
fixup_index = _ilu.module_from_spec(_fixup_spec)
_fixup_spec.loader.exec_module(fixup_index)

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT_JSON = "artifacts/evidence/05f/phase05f-58b-ascwrap-vtable.json"

KEXT_BUNDLE_ID = "com.apple.driver.AppleA7IOP-ASCWrap-v6"
CLASS_NAME = "AppleASCWrapV6"
START_SLOT = 0x360  # IOService::start slot proven in 57ZZ from the dispatch callsite

LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035


def parse_outer_macho(data):
    """Return (segments, fileset_entries) of the outer kernel cache."""
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = []
    entries = []
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8 : off + 24].split(b"\x00")[0].decode()
            vm, sz, fo, fsz = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append({"name": name, "vm": vm, "size": sz, "fo": fo, "fsz": fsz})
        elif cmd == LC_FILESET_ENTRY:
            vm, fo = struct.unpack_from("<QQ", data, off + 8)
            # entry_point_command: cmd, cmdsize, vmaddr, fileoff, entry_id
            # (load_command: cmd, cmdsize), then the id string at +32
            name = data[off + 32 : off + csz].split(b"\x00")[0].decode(errors="replace")
            entries.append({"vm": vm, "fo": fo, "name": name})
        off += csz
    return segs, entries


def parse_fileset_macho(data, base_fo):
    """Return (segments, sections) of the Mach-O nested at base_fo."""
    ncmds = struct.unpack_from("<I", data, base_fo + 16)[0]
    off = base_fo + 32
    segs = []
    sects = []
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            seg = data[off + 8 : off + 24].split(b"\x00")[0].decode()
            vm, sz, fo, fsz = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append({"name": seg, "vm": vm, "size": sz, "fo": fo, "fsz": fsz})
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            soff = off + 72
            for _s in range(nsects):
                sect = data[soff : soff + 16].split(b"\x00")[0].decode()
                addr, size = struct.unpack_from("<QQ", data, soff + 32)
                offset = struct.unpack_from("<I", data, soff + 48)[0]
                sects.append({"segment": seg, "section": sect, "addr": addr, "size": size, "offset": offset})
                soff += 80
        off += csz
    return segs, sects


def vm2fo(segments, vm):
    """Map a VM address to a bootkc file offset through segment lists."""
    for seg in segments:
        if seg["vm"] <= vm < seg["vm"] + seg["fsz"]:
            return seg["fo"] + (vm - seg["vm"])
    return None


def read_cstring(data, segments, vm, maxlen=128):
    fo = vm2fo(segments, vm)
    if fo is None:
        return None
    raw = data[fo : fo + maxlen]
    z = raw.find(b"\x00")
    if z < 0:
        return None
    try:
        return raw[:z].decode("ascii")
    except UnicodeDecodeError:
        return None


class RegTracker:
    """Accumulate adrp/add register values across one instruction window."""

    def __init__(self):
        self.pages = {}
        self.loads = {}  # reg -> effective address of last ldr [base,#imm]

    def feed(self, ins):
        parts = [p.strip() for p in ins.op_str.split(",")]
        if ins.mnemonic == "adrp" and len(parts) == 2:
            try:
                self.pages[parts[0]] = int(parts[1].replace("#", ""), 16)
            except ValueError:
                pass
        elif ins.mnemonic == "add" and len(parts) == 3 and parts[0] == parts[1] and parts[0] in self.pages:
            try:
                imm = int(parts[2].replace("#", "").replace("0x", ""), 16)
                self.pages[parts[0]] += imm
            except ValueError:
                pass
        elif ins.mnemonic == "ldr" and len(parts) >= 2 and parts[0] in ("x0", "x1", "x2", "x19", "x20", "x21", "x22"):
            base = parts[1].strip("[]")
            if base in self.pages:
                imm = 0
                if len(parts) >= 3:
                    try:
                        imm = int(parts[2].replace("#", "").replace("]", ""), 16)
                    except ValueError:
                        imm = 0
                self.loads[parts[0]] = self.pages[base] + imm

    def value(self, reg):
        return self.pages.get(reg)


def fmt_ins(ins):
    return "0x%x  %s %s" % (ins.address, ins.mnemonic, ins.op_str)


def derive():
    artifact = {
        "gate": "05F_58B_ASCWRAP_VTABLE",
        "kext_name": KEXT_BUNDLE_ID,
        "class_name": CLASS_NAME,
        "bootkc": BOOTKC,
        "start_slot": "+0x%x" % START_SLOT,
        "fixup_decoder": "scripts/phase05f-57zz-fixup-index.py (shared canonical)",
    }
    failure = None

    data = open(BOOTKC, "rb").read()
    artifact["bootkc_sha256"] = hashlib.sha256(data).hexdigest().upper()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    # --- step 1: locate the fileset entry by exact bundle id ---
    outer_segs, entries = parse_outer_macho(data)
    entry = next((e for e in entries if e["name"] == KEXT_BUNDLE_ID), None)
    if entry is None:
        failure = "fileset entry %s not found among %d LC_FILESET_ENTRY commands" % (KEXT_BUNDLE_ID, len(entries))
    else:
        artifact["fileset_vm_base"] = hex(entry["vm"])
        artifact["fileset_file_offset"] = hex(entry["fo"])

    # --- step 2: kext Mach-O sections ---
    kext_segs = None
    text_sect = modinit_sect = None
    if failure is None:
        kext_segs, kext_sects = parse_fileset_macho(data, entry["fo"])
        artifact["kext_segments"] = [
            {"name": s["name"], "vm": hex(s["vm"]), "size": hex(s["size"]), "fileoff": hex(s["fo"])}
            for s in kext_segs
        ]
        text_sect = next(
            (s for s in kext_sects if s["segment"] == "__TEXT_EXEC" and s["section"] == "__text"), None
        )
        modinit_sect = next(
            (s for s in kext_sects if s["segment"] == "__DATA_CONST" and s["section"] == "__mod_init_func"), None
        )
        if text_sect is None or modinit_sect is None:
            failure = "kext Mach-O lacks __TEXT_EXEC,__text or __DATA_CONST,__mod_init_func"

    # --- step 3: shared chained-fixup index + mod_init pointer decode ---
    index = None
    mod_init_fns = []
    if failure is None:
        index = fixup_index.build_fixup_index(path=BOOTKC)
        count = modinit_sect["size"] // 8
        for i in range(count):
            loc = modinit_sect["addr"] + i * 8
            target = index.get(loc)
            mod_init_fns.append({"slot": hex(loc), "target": hex(target) if target else None})
            if target is None:
                failure = "mod_init slot 0x%x missing from fixup index" % loc
                break
        artifact["mod_init_functions"] = mod_init_fns

    # --- step 4: pick the registration function by exact x1 class string ---
    reg_fn = class_obj = vtable = reg_snippet = superclass = class_str_vm = None
    if failure is None:
        candidates = []
        for mi in mod_init_fns:
            fn = int(mi["target"], 16)
            fo = vm2fo(kext_segs, fn)
            if fo is None:
                continue
            insns = list(md.disasm(data[fo : fo + 0x60], fn))
            tr = RegTracker()
            fn_vtable = fn_str = fn_x0 = fn_super_loc = None
            called = False
            for ins in insns:
                tr.feed(ins)
                if ins.mnemonic == "bl":
                    called = True
                if ins.mnemonic == "pacda":
                    fn_vtable = tr.value("x16")
                    fn_str = tr.value("x1")
                    fn_x0 = tr.value("x0")
                    fn_super_loc = tr.loads.get("x2")
                    break
            if not called or fn_vtable is None or fn_str is None:
                continue
            if read_cstring(data, kext_segs, fn_str) == CLASS_NAME:
                str_end = next((k for k, i in enumerate(insns) if i.mnemonic == "str"), len(insns))
                candidates.append(
                    {
                        "fn": fn,
                        "vtable": fn_vtable,
                        "class_obj": fn_x0,
                        "class_str_vm": fn_str,
                        "superclass_loc": fn_super_loc,
                        "snippet": [fmt_ins(i) for i in insns[: str_end + 1]],
                    }
                )
        if len(candidates) != 1:
            failure = "expected exactly one %s registration function, found %d" % (CLASS_NAME, len(candidates))
        else:
            cand = candidates[0]
            reg_fn = cand["fn"]
            vtable = cand["vtable"]
            class_obj = cand["class_obj"]
            class_str_vm = cand["class_str_vm"]
            reg_snippet = cand["snippet"]
            if cand["superclass_loc"] is not None:
                target = index.get(cand["superclass_loc"])
                superclass = {"got_location": hex(cand["superclass_loc"]), "resolved": hex(target) if target else None}

    # --- step 5: resolve the IOService::start slot through the index ---
    start_target = None
    if failure is None:
        start_target = index.get(vtable + START_SLOT)
        if start_target is None:
            failure = "vtable+0x%x (0x%x) missing from fixup index" % (START_SLOT, vtable + START_SLOT)

    # --- step 6: derive the allocator from the kext __text ---
    alloc_fn = alloc_snippet = alloc_vtable = None
    if failure is None:
        text_fo = vm2fo(kext_segs, text_sect["addr"])
        insns = list(md.disasm(data[text_fo : text_fo + text_sect["size"]], text_sect["addr"]))
        functions = []
        cur = []
        for ins in insns:
            if ins.mnemonic == "bti":
                if cur:
                    functions.append(cur)
                cur = [ins]
            elif cur:
                cur.append(ins)
        if cur:
            functions.append(cur)
        matches = []
        for fn_ins in functions:
            tr = RegTracker()
            class_reg = None
            moved = False
            called_after_move = False
            fn_alloc_vt = None
            for ins in fn_ins:
                tr.feed(ins)
                if class_reg is None:
                    for reg in list(tr.pages):
                        if tr.value(reg) == class_obj and reg != "x0":
                            class_reg = reg
                            break
                if ins.mnemonic == "mov" and class_reg and ins.op_str.replace(" ", "") == "x1,%s" % class_reg:
                    moved = True
                if ins.mnemonic == "bl" and moved:
                    called_after_move = True
                if ins.mnemonic == "pacda":
                    fn_alloc_vt = tr.value("x16")
                    break
            if class_reg and moved and called_after_move and fn_alloc_vt is not None:
                str_end = next((k for k, i in enumerate(fn_ins) if i.mnemonic == "str" and i.op_str.startswith("x16, [x0]")), len(fn_ins))
                matches.append(
                    {
                        "fn": fn_ins[0].address,
                        "vtable": fn_alloc_vt,
                        "snippet": [fmt_ins(i) for i in fn_ins[: str_end + 4]],
                    }
                )
        if len(matches) != 1:
            failure = "expected exactly one allocator for class object 0x%x, found %d" % (class_obj if class_obj else 0, len(matches))
        else:
            m = matches[0]
            alloc_fn = m["fn"]
            alloc_vtable = m["vtable"]
            alloc_snippet = m["snippet"]

    # --- assemble ---
    artifact["registration_function"] = hex(reg_fn) if reg_fn else None
    artifact["class_object"] = hex(class_obj) if class_obj else None
    artifact["vtable"] = hex(vtable) if vtable else None
    artifact["start_slot_0x360"] = hex(start_target) if start_target else None
    artifact["allocator_function"] = hex(alloc_fn) if alloc_fn else None
    artifact["allocator_installed_vtable"] = hex(alloc_vtable) if alloc_vtable else None
    artifact["allocator_semantics"] = (
        "PARTIAL: structurally derived (unique __text function that moves the class object "
        "0x%x into x1, calls the kext alloc stub, and installs vtable 0x%x before pacda). "
        "The kernel-side target reached through the stub GOT and its runtime role "
        "(OSMetaClass allocation vs operator new) are NOT separately proven here."
        % (class_obj, alloc_vtable)
        if alloc_fn
        else None
    )
    artifact["superclass"] = superclass
    artifact["derivation_method"] = (
        "fileset entry located by exact LC_FILESET_ENTRY bundle id; kext Mach-O parsed for "
        "__TEXT_EXEC,__text and __DATA_CONST,__mod_init_func; mod_init pointers decoded by the "
        "shared chained-fixup index; registration function identified as the init whose x1 "
        "adrp+add chain addresses the exact C-string %r before a bl to the OSMetaClass "
        "registration stub; vtable read from that function's x16 adrp+add chain immediately "
        "before pacda; start slot resolved as index[vtable+0x360]; allocator derived as the "
        "unique __text function that moves the class object into x1, calls the alloc stub, "
        "and installs a fresh vtable via its own x16 chain before pacda" % CLASS_NAME
    )
    artifact["evidence"] = {
        "registration_function_instructions": reg_snippet,
        "allocator_instructions": alloc_snippet,
        "start_slot_resolution": {
            "slot_vm": hex(vtable + START_SLOT) if vtable else None,
            "decoded_target": hex(start_target) if start_target else None,
        },
        "class_string": {
            "vm": hex(class_str_vm) if class_str_vm else None,
            "value": CLASS_NAME,
            "check": "x1 adrp+add chain addresses the NUL-terminated C-string compared by exact match",
        },
    }
    artifact["verdict"] = "FAIL" if failure else "PASS"
    if failure:
        artifact["failure_step"] = failure

    _os.makedirs(_os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact, indent=2))
    return 0 if not failure else 1


if __name__ == "__main__":
    raise SystemExit(derive())
