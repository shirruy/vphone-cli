#!/usr/bin/env python3
"""57ZZ v9: thunk x2 object identification.

At each thunk hit, read the x2 object's:
  - vtable pointer (x2+0x00) -> identify class from canonical vtable map
  - first 0x30 bytes -> structure analysis
  - chase pointer at x2+0x10 -> potential name/registry data
  - search 256 bytes around x2 for printable strings (targeted, not ±1MB)

Also capture the x0 object (which stays constant across hits - likely the
platform expert) for comparison.
"""

import gdb
import json
import os
import struct
import time

THUNK_STATIC = 0xFFFFFFF008387EB0
ALLOCATOR_STATIC = 0xFFFFFFF008387EB8

BOOTKC_PATH = os.environ.get(
    "PHASE05F_BOOTKC",
    r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin",
)
BOOTKC_EXEC_VM = 0xFFFFFFF0081E4000
BOOTKC_EXEC_FO = 0x11E0000
BOOTKC_EXEC_SZ = 0x2A44000
PC_MATCH_LEN = 48
SLIDE_ALIGN = 0x200000

MAX_HITS = 40
BUDGET_SECONDS = 120.0

# Known vtables (static, pre-slide)
KNOWN_VTABLES = {
    0xFFFFFFF007D14370: "AppleA7IOP",
    0xFFFFFFF007D131E0: "AppleASCWrapV6",
    0xFFFFFFF007D139B8: "AppleASCWrapV6SEP",
    0xFFFFFFF007D12A08: "AppleASCWrapV6SISP",
    0xFFFFFFF007D14960: "AppleA7IOPNub",
    0xFFFFFFF007D336E0: "AppleARMIODevice",
    0xFFFFFFF007D157F8: "AppleIOP",
    0xFFFFFFF007C88580: "IOService",
}

events = []
notes = []
T0 = time.time()
_bootkc_cache = None
pair_count = 0
termination_reason = None


def note(msg):
    line = "[%08.3f] %s" % (time.time() - T0, msg)
    notes.append(line)
    gdb.write("CAPTURE %s\n" % line)


def bootkc_exec():
    global _bootkc_cache
    if _bootkc_cache is None:
        with open(BOOTKC_PATH, "rb") as fh:
            fh.seek(BOOTKC_EXEC_FO)
            _bootkc_cache = fh.read(BOOTKC_EXEC_SZ)
    return _bootkc_cache


def read_mem(addr, length):
    inferior = gdb.selected_inferior()
    return bytes(inferior.read_memory(addr, length))


def try_read(addr, length):
    try:
        return read_mem(addr, length)
    except Exception:
        return None


def read_u64(addr):
    return struct.unpack("<Q", read_mem(addr, 8))[0]


def try_u64(addr):
    try:
        return read_u64(addr)
    except Exception:
        return None


def fmt(x):
    return "0x%016x" % x


def get_reg(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def extract_strings(raw):
    strings = []
    cur = []
    for b in raw:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                strings.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        strings.append("".join(cur))
    return strings


def derive_slide():
    pc = get_reg("pc")
    if pc is None or pc < 0xFFFFFFF000000000:
        return None, "pc_not_kernel_high_half"
    chunk = try_read(pc, PC_MATCH_LEN)
    if chunk is None:
        return None, "pc_read_failed"
    hay = bootkc_exec()
    idx = hay.find(chunk)
    if idx < 0:
        return None, "pc_bytes_not_in_bootkc"
    if hay.find(chunk, idx + 1) >= 0:
        return None, "pc_bytes_not_unique"
    static_vm = BOOTKC_EXEC_VM + idx
    slide = pc - static_vm
    if slide & (SLIDE_ALIGN - 1):
        return None, "slide_not_2mb_aligned"
    sig = try_read(THUNK_STATIC + slide, 8)
    if sig != bytes.fromhex("e10302aa01000014"):
        return None, "thunk_sig_mismatch"
    return slide, None


def identify_object(obj_ptr, slide):
    """Identify an object by reading its vtable and structure."""
    if obj_ptr is None or obj_ptr < 0x1000:
        return {"error": "invalid_pointer"}

    result = {"address": fmt(obj_ptr)}

    # Read vtable pointer at obj+0
    vt = try_u64(obj_ptr)
    if vt is not None:
        result["vtable_runtime"] = fmt(vt)
        vt_static = vt - slide
        result["vtable_static"] = fmt(vt_static)
        # Look up in known map
        cls = KNOWN_VTABLES.get(vt_static)
        if cls:
            result["identified_class"] = cls
        else:
            result["identified_class"] = "unknown_vtable"
    else:
        result["vtable_read_failed"] = True

    # Read first 0x30 bytes
    raw = try_read(obj_ptr, 0x30)
    if raw:
        result["raw_hex"] = raw.hex()
        # Extract inline strings
        strs = extract_strings(raw)
        if strs:
            result["inline_strings"] = strs

    # Chase pointer at +0x10 (common layout: vtable, refcount, data_ptr)
    ptr10 = try_u64(obj_ptr + 0x10)
    if ptr10 and ptr10 >= 0xFFFFFF0000000000:
        result["ptr_at_10"] = fmt(ptr10)
        raw10 = try_read(ptr10, 0x40)
        if raw10:
            strs10 = extract_strings(raw10)
            if strs10:
                result["strings_at_10"] = strs10
            # Also read the vtable of the pointed object
            vt10 = try_u64(ptr10)
            if vt10:
                result["ptr10_vtable_static"] = fmt(vt10 - slide)
                cls10 = KNOWN_VTABLES.get(vt10 - slide)
                if cls10:
                    result["ptr10_class"] = cls10

    # Chase pointer at +0x18
    ptr18 = try_u64(obj_ptr + 0x18)
    if ptr18 and ptr18 >= 0xFFFFFF0000000000:
        result["ptr_at_18"] = fmt(ptr18)
        raw18 = try_read(ptr18, 0x40)
        if raw18:
            strs18 = extract_strings(raw18)
            if strs18:
                result["strings_at_18"] = strs18

    # Chase pointer at +0x20
    ptr20 = try_u64(obj_ptr + 0x20)
    if ptr20 and ptr20 >= 0xFFFFFF0000000000:
        result["ptr_at_20"] = fmt(ptr20)
        raw20 = try_read(ptr20, 0x40)
        if raw20:
            strs20 = extract_strings(raw20)
            if strs20:
                result["strings_at_20"] = strs20

    return result


def write_output(classification, slide_info, extra=None):
    out = {
        "gate": "ARMIO_THUNK_X2_PROVENANCE",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "capture_pair_limit": MAX_HITS,
        "captured_pairs": pair_count,
        "captured_breakpoint_events": pair_count,
        "total_events": len(events),
        "capture_termination_reason": (
            "PAIR_LIMIT" if pair_count >= MAX_HITS
            else (termination_reason if termination_reason
                  else ("BUDGET_EXPIRED" if (time.time() - T0) >= BUDGET_SECONDS else "COMPLETED"))
        ),
        "slide": slide_info,
        "events": events,
        "notes": notes,
        "classification": classification,
    }
    if extra:
        out.update(extra)
    outpath = os.path.join(os.environ.get("P2_OUT_DIR", "."), "gdb-capture.json")
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    note("wrote %s" % outpath)
    return outpath


note("v9 x2 identification attached")
pc0 = get_reg("pc")
note("initial pc=%s" % (fmt(pc0) if pc0 else "none"))

# Derive slide
slide = None
for attempt in range(21):
    slide, err = derive_slide()
    if slide is not None:
        break
    if err not in ("pc_not_kernel_high_half", "pc_read_failed", "pc_bytes_not_in_bootkc", "pc_bytes_not_unique"):
        break
    try:
        gdb.execute("stepi", to_string=True)
    except Exception:
        break

if slide is None:
    note("SLIDE_DERIVATION_FAILED: %s" % err)
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", None, {"slide_error": err})
    raise gdb.GdbError("slide derivation failed")

thunk_runtime = THUNK_STATIC + slide
note("slide=%s thunk=%s" % (fmt(slide), fmt(thunk_runtime)))

# Install breakpoint on thunk
try:
    gdb.execute("hbreak *%#x" % thunk_runtime, to_string=True)
    note("hbreak THUNK @ %s installed" % fmt(thunk_runtime))
except Exception as e:
    note("hbreak THUNK failed: %s" % e)
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", {"slide": fmt(slide)}, {"hbreak_error": str(e)})
    raise gdb.GdbError("hbreak failed")

# Main loop
while pair_count < MAX_HITS and (time.time() - T0) < BUDGET_SECONDS:
    try:
        gdb.execute("signal 0", to_string=True)
    except Exception as e:
        termination_reason = "CONTINUE_ERROR"
        note("continue failed: %s" % e)
        break

    pc = get_reg("pc")
    if pc is None:
        termination_reason = "PC_READ_FAILED"
        note("pc read failed")
        break

    if pc != thunk_runtime:
        note("non-thunk stop: %s" % fmt(pc))
        continue

    # THUNK HIT - identify x0 and x2
    x0 = get_reg("x0")
    x2 = get_reg("x2")

    rec = {
        "label": "thunk_hit",
        "t": round(time.time() - T0, 3),
        "x0": fmt(x0),
        "x2": fmt(x2),
        "x0_identity": identify_object(x0, slide),
        "x2_identity": identify_object(x2, slide),
    }
    events.append(rec)
    pair_count += 1

    x2_cls = rec["x2_identity"].get("identified_class", "?")
    x2_strs = rec["x2_identity"].get("inline_strings", []) + rec["x2_identity"].get("strings_at_10", [])
    note("hit #%d: x0_cls=%s x2_cls=%s x2_strs=%s" % (pair_count, rec["x0_identity"].get("identified_class", "?"), x2_cls, x2_strs[:3]))

# Summary
x2_classes = {}
x2_all_strings = set()
for e in events:
    cls = e.get("x2_identity", {}).get("identified_class", "unknown")
    x2_classes[cls] = x2_classes.get(cls, 0) + 1
    for k in ("inline_strings", "strings_at_10", "strings_at_18", "strings_at_20"):
        for s in e.get("x2_identity", {}).get(k, []):
            x2_all_strings.add(s)

# Check for ANS
ans_strings = [s for s in x2_all_strings if "ans" in s.lower()]

summary = {
    "total_hits": pair_count,
    "x2_class_distribution": x2_classes,
    "all_x2_strings": sorted(x2_all_strings),
    "ans_related_strings": ans_strings,
    "x0_class": events[0]["x0_identity"].get("identified_class") if events else None,
}

classification = "IDENTIFIED" if x2_classes else "NO_HITS"
if ans_strings:
    classification = "ANS_FOUND"

write_output(classification, {"slide": fmt(slide)}, {"summary": summary})
note("done: %s" % classification)
gdb.execute("quit")
