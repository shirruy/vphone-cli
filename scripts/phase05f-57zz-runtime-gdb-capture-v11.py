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

COMPARE_NAME_STATIC = 0xFFFFFFF00AAC9778
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

MAX_HITS = 100
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

compare_name_runtime = COMPARE_NAME_STATIC + slide
note("slide=%s compareName=%s" % (fmt(slide), fmt(compare_name_runtime)))

try:
    gdb.execute("hbreak *%#x" % compare_name_runtime, to_string=True)
    note("hbreak compareName @ %s installed" % fmt(compare_name_runtime))
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

    if pc != compare_name_runtime:
        continue

    # Capture x0 (this) and x1 (name parameter)
    x0 = get_reg("x0")
    x1 = get_reg("x1")
    x2 = get_reg("x2")

    rec = {
        "label": "compareName_hit",
        "t": round(time.time() - T0, 3),
        "x0_this": fmt(x0),
        "x1_name_param": fmt(x1),
        "x2": fmt(x2),
    }

    # Try to read name from x1
    if x1 and x1 > 0x1000:
        name_result = try_read_name(x1)
        if name_result:
            rec["x1_name"] = name_result[1]
            rec["x1_name_source"] = name_result[0]
        else:
            rec["x1_name"] = None

    # Try to read name from x0 (the this object might have inline name)
    if x0 and x0 > 0x1000:
        name_result = try_read_name(x0)
        if name_result:
            rec["x0_name"] = name_result[1]
            rec["x0_name_source"] = name_result[0]

    events.append(rec)
    pair_count += 1

    x1_name = rec.get("x1_name")
    x0_name = rec.get("x0_name")
    note("hit #%d: x1_name=%r x0_name=%r" % (pair_count, x1_name, x0_name))

# Summary
all_names = set()
for e in events:
    if e.get("x1_name"):
        all_names.add(e["x1_name"])
    if e.get("x0_name"):
        all_names.add(e["x0_name"])

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
note("done: %s (%d names, ANS: %s)" % (classification, len(all_names), ans_names[:3]))
gdb.execute("quit")
