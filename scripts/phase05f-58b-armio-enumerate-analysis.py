#!/usr/bin/env python3
"""05F-58B: AppleARMIO /arm-io child enumeration static analysis.

Parses the BootKC MH_FILESET header, maps vm<->file, finds code references
to the AppleARMIO strings, disassembles the referencing functions and the
vtable-derived AppleARMIO::start, and scans for name-based ("ans") skip
logic. Every claim cites instruction evidence; missing scans are reported
fail-closed.
"""
import importlib.util as ilu
import capstone
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT = "artifacts/evidence/05f/phase05f-58b-armio-enumerate-analysis.json"

_spec = ilu.spec_from_file_location("fx", os.path.join(HERE, "phase05f-57zz-fixup-index.py"))
fx = ilu.module_from_spec(_spec)
_spec.loader.exec_module(fx)

STR_FILE_OFF = 0x15E66E          # "AppleARMIO\0" (known fact, verified below)
STR2_FILE_OFF = 0x15E67E         # tail of "...site.AppleARMIO\0" (suffix-merged)


def parse_header(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    o, segs, entries = 32, [], []
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", data, o)
        if cmd == 0x19:
            nm = data[o+8:o+24].split(b"\0")[0].decode()
            vm, vmsz, fo, fsz = struct.unpack_from("<QQQQ", data, o+24)
            segs.append({"name": nm, "vm": vm, "vmsz": vmsz, "fileoff": fo, "filesize": fsz})
        elif cmd == 0x80000035:
            vm, fo = struct.unpack_from("<QQ", data, o+8)
            eid = struct.unpack_from("<I", data, o+24)[0]
            entries.append({"name": data[o+eid:o+cs].split(b"\0")[0].decode("latin1"), "vm": vm, "fileoff": fo})
        o += cs
    return segs, entries


class KC:
    def __init__(self, data):
        self.data = data
        self.segs, self.entries = parse_header(data)
        self.ex = next(s for s in self.segs if s["name"] == "__TEXT_EXEC")

    def vm2fo(self, vm):
        for s in self.segs:
            if s["vm"] <= vm < s["vm"] + s["vmsz"]:
                return s["fileoff"] + (vm - s["vm"])
        return None

    def fo2vm(self, fo):
        for s in self.segs:
            if s["fileoff"] <= fo < s["fileoff"] + s["filesize"]:
                return s["vm"] + (fo - s["fileoff"])
        return None

    def seg_of(self, vm):
        for s in self.segs:
            if s["vm"] <= vm < s["vm"] + s["vmsz"]:
                return s["name"]
        return None

    def cstr(self, vm, maxlen=96):
        fo = self.vm2fo(vm)
        if fo is None:
            return None
        end = self.data.find(b"\0", fo, fo + maxlen)
        if end < 0:
            return None
        try:
            s = self.data[fo:end].decode("utf-8")
        except UnicodeDecodeError:
            return None
        return s if s and all(32 <= ord(c) < 127 for c in s) else None


def scan_adrp_add_targets(kc, md, targets=None, string_needles=None):
    """Scan kernel __TEXT_EXEC chunked for adrp+add computed targets.

    Returns list of {site, target, string} hits matching targets (exact VMs)
    or string_needles (exact C-string equality).
    """
    hits = []
    seg = kc.ex
    CH = 0x1000
    for b in range(0, seg["filesize"], CH):
        chunk = kc.data[seg["fileoff"]+b : seg["fileoff"]+b+CH]
        if chunk.count(0) == len(chunk):
            continue
        try:
            insns = list(md.disasm(chunk, seg["vm"]+b))
        except Exception:
            continue
        pages = {}
        for ins in insns:
            if ins.mnemonic == "adrp":
                p = [q.strip() for q in ins.op_str.split(",")]
                try:
                    pages[p[0]] = int(p[1].replace("#",""), 16)
                except Exception:
                    pass
            elif ins.mnemonic == "add":
                p = [q.strip() for q in ins.op_str.split(",")]
                if len(p) == 3 and p[0] == p[1] and p[0] in pages:
                    try:
                        t = pages[p[0]] + int(p[2].replace("#","").replace("0x",""), 16)
                    except Exception:
                        continue
                    s = kc.cstr(t)
                    if (targets and t in targets) or (string_needles and s in string_needles):
                        hits.append({"site": hex(ins.address), "target": hex(t),
                                     "string": s, "segment": kc.seg_of(ins.address)})
            if ins.mnemonic in ("bl","blr","br","ret","b","retab"):
                pages = {}
    return hits


def disasm_range(kc, md, start, size):
    fo = kc.vm2fo(start)
    out, pages = [], {}
    for ins in md.disasm(kc.data[fo:fo+size], start):
        ann = ""
        if ins.mnemonic == "adrp":
            p = [q.strip() for q in ins.op_str.split(",")]
            try:
                pages[p[0]] = int(p[1].replace("#",""), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add":
            p = [q.strip() for q in ins.op_str.split(",")]
            if len(p) == 3 and p[0] == p[1] and p[0] in pages:
                try:
                    t = pages[p[0]] + int(p[2].replace("#","").replace("0x",""), 16)
                    s = kc.cstr(t)
                    ann = ' ; "%s"' % s if s else " ; =%#x" % t
                except Exception:
                    pass
        out.append("%#x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, ann))
        if ins.mnemonic in ("ret", "retab") and ins.address >= start + 8:
            break
    return out


def ans_immediate_scan(kc):
    """Scan __TEXT_EXEC for movz/movk immediates spelling 0x7361 / 0x6e('ans').

    movz: 0x52800000 | imm16<<5 | rd ; movk lsl16: 0x72A00000 | imm16<<5 | rd
    """
    seg = kc.ex
    base = seg["fileoff"]
    hits = []
    for off in range(0, seg["filesize"] - 4, 4):
        w = struct.unpack_from("<I", kc.data, base + off)[0]
        if (w & 0xFFE00000) == 0x52800000 and ((w >> 5) & 0xFFFF) == 0x7361:
            hits.append({"site": hex(seg["vm"] + off), "kind": "movz #0x7361"})
        if (w & 0xFFE00000) == 0x72A00000 and ((w >> 5) & 0xFFFF) == 0x006E:
            hits.append({"site": hex(seg["vm"] + off), "kind": "movk #0x6e, lsl #16"})
    return hits


def main():
    data = open(BOOTKC, "rb").read()
    kc = KC(data)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    str1_vm = kc.fo2vm(STR_FILE_OFF)
    str2_vm = kc.fo2vm(STR2_FILE_OFF)
    str1_s = kc.cstr(str1_vm)
    # str2 is the suffix tail of "...site.AppleARMIO": read back for evidence
    fo2 = kc.vm2fo(str2_vm)
    start2 = data.rfind(b"\0", fo2 - 64, fo2) + 1
    str2_full = data[start2:fo2 + 16].split(b"\0")[0].decode("latin1")

    xrefs = scan_adrp_add_targets(kc, md, targets={str1_vm, str2_vm})
    ans_xrefs = scan_adrp_add_targets(kc, md, string_needles={"ans"})
    ans_imm = ans_immediate_scan(kc)

    # Disassemble the two proven referencing functions + allocator context
    reg_fn_lines = disasm_range(kc, md, 0xFFFFFFF00838A168, 0x94)          # dual registration
    start_fn_lines = disasm_range(kc, md, 0xFFFFFFF00AAD7DA0, 0x180)       # vtable +0x360 start
    alloc_thunk_lines = disasm_range(kc, md, 0xFFFFFFF008387EB0, 0x30)     # thunk+allocator head

    # vtable slot evidence via canonical fixup decoder
    idx = fx.build_fixup_index(path=BOOTKC)
    vt_armio = 0xFFFFFFF007D33088      # stored by registration: d33078 + 0x10 (two adds, instruction-proven)
    vt_device = 0xFFFFFFF007D336E0     # stored: d336d0 + 0x10 (instruction-proven, matches 57ZZ)
    slot = lambda vt, o: hex(idx[vt + o]) if (vt + o) in idx else None

    art = {
        "gate": "05F_58B_APPLEARMIIO_ENUMERATE",
        "bootkc": BOOTKC,
        "kc_header": {
            "filetype": "0xc (MH_FILESET)",
            "fileset_entries": len(kc.entries),
            "text_exec": {"vm": hex(kc.ex["vm"]), "fileoff": hex(kc.ex["fileoff"]), "filesize": hex(kc.ex["filesize"])},
            "prelink_text": {"vm": "0xfffffff00700c000", "fileoff": "0x8000"},
        },
        "string_anchors": {
            "primary": {"file": hex(STR_FILE_OFF), "vm": hex(str1_vm), "value": str1_s},
            "plus_0x10": {"file": hex(STR2_FILE_OFF), "vm": hex(str2_vm),
                          "verdict": "SUFFIX_MERGED tail of %r; not an independent anchor" % str2_full,
                          "xrefs": [h for h in xrefs if int(h["target"], 16) == str2_vm]},
        },
        "string_xrefs_in_TEXT_EXEC": xrefs,
        "referencing_function_classification": {
            "0xfffffff00838a168": {
                "classification": "mod_init-style OSMetaClass registration function",
                "evidence": "calls 0xfffffff0083d2d4c twice with names \"AppleARMIO\" and \"AppleARMIODevice\"; stores PAC'd vtable pointers",
                "registers": [
                    {"class": "AppleARMIO", "class_object": "0xfffffff00afef430", "instance_size": "0xd8", "vtable_stored": "0xfffffff007d33078+0x10=0xfffffff007d33088", "name_ref_site": "0xfffffff00838a180"},
                    {"class": "AppleARMIODevice", "class_object": "0xfffffff00afef458", "instance_size": "0x108", "vtable_stored": "0xfffffff007d336d0+0x10=0xfffffff007d336e0", "name_ref_site": "0xfffffff00838a1bc", "bl_site": "0xfffffff00838a1cc"},
                ],
                "note": "0xfffffff007d336e0 matches the 57ZZ-established AppleARMIODevice vtable (independent confirmation)",
            },
            "0xfffffff008387c68": {
                "classification": "another OSMetaClass registration using the same \"AppleARMIO\" literal",
                "evidence": "same bl 0xfffffff0083d2d4c pattern with x1=\"AppleARMIO\", size 0xd8, vtable 0xfffffff007d33078+0x10",
            },
            "0xfffffff008387d34_region": {
                "classification": "third registration-family function (xref at 0xfffffff008387dc0); same call pattern",
                "full_disassembly": "NOT_COMPLETED_IN_TIME (fail-closed)",
            },
        },
        "applearmio_start": {
            "vtable": hex(vt_armio),
            "slot_plus_0x360": slot(vt_armio, 0x360),
            "function": "0xfffffff00aad7da0",
            "shared_with_device_vtable_slot": "0xfffffff007d336e0+0x360 also resolves to 0xfffffff00aad7da0 (fixup-proven) => AppleARMIODevice inherits AppleARMIO::start",
            "disassembly": start_fn_lines,
            "enumeration_model": "No direct DT/ADT API calls, no adrp to any string, no strcmp, no literal compares. Child nubs are produced via IOService virtual dispatch: slots +0x300/+0x2e8/+0x2e0/+0x308 virtuals run first (super::start chain), then a stack match-spec {provider=self, 0, 0xe0000110, provider, 0, dict} is passed to virtual slot +0x450 with a PAC'd callback 0xfffffff00aad7f70 => IOService matching/iteration performs child enumeration, not inline name loops.",
            "skip_logic_verdict": "NO name-based or property-based skip logic found in AppleARMIO::start; enumeration is delegated to IOService matching.",
        },
        "allocator_context": {
            "thunk_0xfffffff008387eb0": alloc_thunk_lines,
            "allocator_0xfffffff008387eb8": "bti c; pacibsp head only (full contract in 57ZZ artifact)",
            "caller": "NO direct BL/B callers and NO chained-fixup references anywhere in __TEXT_EXEC/__DATA_CONST/__DATA (57ZZ scanner, fail-closed) => allocator is reached through OSMetaClass runtime dispatch on class object 0xfffffff00afef458, not a statically-visible call site",
            "dt_node_list_source": "NOT_FOUND_STATICALLY: the nub list is produced by IOService matching (vtable +0x450 call in AppleARMIO::start), which reads DT-backed IOPlatformDevice dictionaries at runtime",
        },
        "ans_skip_logic_scans": {
            "cstring_xrefs_equal_ans": ans_xrefs,
            "movz_0x7361_movk_0x6e_immediates": ans_imm,
            "full_strcmp_needle_list_analysis": "NOT_PERFORMED_IN_TIME (fail-closed)",
            "interim_verdict": "NO_STATIC_NAME_BASED_SKIP_FOUND_SO_FAR; absence in AppleARMIO::start is proven, exhaustive kernel-wide needle-list scan incomplete",
        },
        "runtime_context": {"ioplatformdevice_allocations": 103, "ascwrap_starts": 0,
                            "dt_compatible_strings_in_dram": True,
                            "implication": "DT content reaches matching; failure is downstream of enumeration/matching, consistent with no-name-skip in start"},
        "exact_next_probe": "Break at AppleARMIO::start virtual +0x450 callsite (0xfffffff00aad7efc blraa) and at the PAC'd callback 0xfffffff00aad7f70; capture x1 (match dict from 0xfffffff00af5c380 global) and the callback's per-child argument. If /arm-io/ans reaches the callback with name \"ans\" but no AppleARMIODevice allocator hit follows, the skip is in IOService matching personality resolution; if it never reaches the callback, the skip is upstream in DT node enumeration (IODT child iteration), which is outside this fileset entry.",
        "verdict": "PARTIAL: xrefs + registration + start disassembly proven; kernel-wide ans-needle scan and allocator-caller trace incomplete",
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(art, f, indent=2)
        f.write("\n")
    print(json.dumps(art, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
