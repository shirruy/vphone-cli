#!/usr/bin/env python3
"""57ZZ v11: compareName virtual breakpoint for DT entry name extraction.

Breakpoint on the x2 vtable's +0x90 slot function (0xfffffff00aac9778).
At each hit, x0 = the DT entry object, x1 = the name being compared.
Read the name from x1 (OSSymbol or OSString) via multiple strategies.
"""

import gdb
import json
import os
import struct
import time

THUNK_STATIC2 = 0xFFFFFFF008387EB0
THUNK_STATIC = 0xFFFFFFF008387EB0

BOOTKC_PATH = os.environ.get(
    "PHASE05F_BOOTKC",
    r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin",
)
BOOTKC_EXEC_VM = 0xFFFFFFF0081E4000
BOOTKC_EXEC_FO = 0x11E0000
BOOTKC_EXEC_SZ = 0x2A44000
PC_MATCH_LEN = 48
SLIDE_ALIGN = 0x200000

MAX_HITS = 10
BUDGET_SECONDS = 120.0

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


def try_u64(addr):
    try:
        return struct.unpack("<Q", read_mem(addr, 8))[0]
    except Exception:
        return None


def fmt(x):
    return "0x%016x" % x


def get_reg(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def read_cstring(addr, max_len=128):
    raw = try_read(addr, max_len)
    if raw is None:
        return None
    end = raw.find(0)
    if end < 0:
        end = len(raw)
    s = raw[:end]
    if all(0x20 <= b < 0x7F for b in s[:min(len(s), 8)]):
        return s.decode("ascii", errors="replace")
    return None


def try_read_name(ptr):
    """Try multiple strategies to read a name from an object pointer."""
    if not ptr or ptr < 0x1000:
        return None
    
    # Strategy 1: direct C string at ptr (some names are inline)
    s = read_cstring(ptr)
    if s and len(s) >= 2:
        return ("direct", s)
    
    # Strategy 2: OSSymbol/OSString with char* at +0x10
    charp = try_u64(ptr + 0x10)
    if charp and charp > 0x1000:
        s = read_cstring(charp)
        if s and len(s) >= 2:
            return ("ptr_10", s)
    
    # Strategy 3: char* at +0x18
    charp = try_u64(ptr + 0x18)
    if charp and charp > 0x1000:
        s = read_cstring(charp)
        if s and len(s) >= 2:
            return ("ptr_18", s)
    
    # Strategy 4: char* at +0x08
    charp = try_u64(ptr + 0x08)
    if charp and charp > 0x1000:
        s = read_cstring(charp)
        if s and len(s) >= 2:
            return ("ptr_08", s)
    
    # Strategy 5: read the object at ptr, check if data is inline after header
    for off in (0x08, 0x10, 0x14, 0x18, 0x20):
        s = read_cstring(ptr + off)
        if s and len(s) >= 2:
            return ("inline+%02x" % off, s)
    
    return None


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


def write_output(classification, slide_info, extra=None):
    out = {
        "gate": "DT_ENTRY_NAME_EXTRACTION",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "capture_event_limit": MAX_HITS,
        "captured_breakpoint_events": pair_count,
        "total_events": len(events),
        "capture_termination_reason": (
            "BREAKPOINT_EVENT_LIMIT" if pair_count >= MAX_HITS
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


note("v11 compareName capture attached")

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

thunk_rt = THUNK_STATIC2 + slide
note("slide=%s thunk=%s" % (fmt(slide), fmt(thunk_rt)))

try:
    gdb.execute("hbreak *%#x" % thunk_rt, to_string=True)
    note("hbreak THUNK @ %s installed" % fmt(thunk_rt))
except Exception as e:
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", {"slide": fmt(slide)}, {"hbreak_error": str(e)})
    raise gdb.GdbError("hbreak failed")

# Main loop
while pair_count < MAX_HITS and (time.time() - T0) < BUDGET_SECONDS:
    try:
        gdb.execute("signal 0", to_string=True)
    except Exception as e:
        termination_reason = "CONTINUE_ERROR"
        break

    pc = get_reg("pc")
    if pc is None:
        termination_reason = "PC_READ_FAILED"
        break

    if pc != thunk_rt:
        continue

    # Capture x0 (this) and x1 (name parameter)
    x2 = get_reg("x2")

    rec = {
        "label": "thunk_hit",
        "t": round(time.time() - T0, 3),
        "x2": fmt(x2),
        "properties": [],
    }

    # Walk x2's property dictionary at x2+0x10
    dict_ptr = try_u64(x2 + 0x10) if x2 else None
    if dict_ptr and dict_ptr > 0xFFFFFF0000000000:
        # Try OSDictionary layouts: (count_offset, data_offset)
        for count_off, data_off in [(0x08, 0x10), (0x10, 0x18)]:
            count = try_u64(dict_ptr + count_off)
            if count is None or count == 0 or count > 200:
                continue
            data_ptr = try_u64(dict_ptr + data_off)
            if data_ptr is None or data_ptr < 0xFFFFFF0000000000:
                continue
            for i in range(min(count, 15)):
                key_ptr = try_u64(data_ptr + i * 16)
                val_ptr = try_u64(data_ptr + i * 16 + 8)
                if key_ptr is None or key_ptr < 0xFFFFFF0000000000:
                    continue
                key_str = None
                for ko in (0x10, 0x18, 0x08, 0x14):
                    cp = try_u64(key_ptr + ko)
                    if cp and cp > 0x1000:
                        key_str = read_cstring(cp)
                        if key_str:
                            break
                if not key_str:
                    key_str = read_cstring(key_ptr + 0x10)
                if key_str:
                    prop = {"key": key_str}
                    if val_ptr and val_ptr > 0xFFFFFF0000000000:
                        for vo in (0x10, 0x18, 0x08):
                            vp = try_u64(val_ptr + vo)
                            if vp and vp > 0x1000:
                                vs = read_cstring(vp)
                                if vs:
                                    prop["val"] = vs
                                    break
                    rec["properties"].append(prop)
            if rec["properties"]:
                break

    events.append(rec)
    pair_count += 1

    props = rec.get("properties", [])
    note("hit #%d: %d props: %s" % (pair_count, len(props), [p["key"] for p in props[:5]]))

# Summary
all_names = set()
for e in events:
    for p in e.get("properties", []):
        all_names.add(p["key"])
        if "val" in p:
            all_names.add(p["val"])

ans_names = [n for n in all_names if "ans" in n.lower()]

summary = {
    "total_hits": pair_count,
    "unique_names": sorted(all_names),
    "total_unique_names": len(all_names),
    "ans_names": ans_names,
}

classification = "NAMES_EXTRACTED" if all_names else "NO_NAMES"
if ans_names:
    classification = "ANS_NAME_FOUND"

write_output(classification, {"slide": fmt(slide)}, {"summary": summary})
note("done: %s (%d strings, ANS: %s)" % (classification, len(all_names), ans_names[:3]))
gdb.execute("quit")

