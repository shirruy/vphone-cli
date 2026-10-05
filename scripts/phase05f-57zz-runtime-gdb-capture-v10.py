#!/usr/bin/env python3
"""57ZZ v10: x2 property table chase for ANS identification.

At each thunk hit, deeply explore the x2 object's property table to find
the DT entry's "name" property. Uses a multi-offset OSDictionary walk.
"""

import gdb
import json
import os
import struct
import time

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

MAX_HITS = 40
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


def read_cstring(addr, max_len=64):
    """Read a NUL-terminated string from memory."""
    raw = try_read(addr, max_len)
    if raw is None:
        return None
    end = raw.find(0)
    if end < 0:
        end = len(raw)
    s = raw[:end].decode("ascii", errors="replace")
    return s if len(s) >= 1 else None


def try_read_osstring(ptr):
    """Try to read an OSString object's char* data."""
    if not ptr or ptr < 0xFFFFFF0000000000:
        return None
    # OSString: +0x10 = char* string pointer (in some layouts)
    # or the string is inline starting at some offset
    # Try: read char* at +0x10
    charp = try_u64(ptr + 0x10)
    if charp and charp >= 0xFFFFFF0000000000:
        s = read_cstring(charp)
        if s and len(s) >= 1:
            return s
    # Try: string inline at +0x10 (some OSString store data directly)
    s = read_cstring(ptr + 0x10)
    if s and len(s) >= 1:
        return s
    # Try: char* at +0x08
    charp8 = try_u64(ptr + 0x08)
    if charp8 and charp8 >= 0xFFFFFF0000000000:
        s = read_cstring(charp8)
        if s and len(s) >= 1:
            return s
    # Try: string inline at +0x08
    s = read_cstring(ptr + 0x08)
    if s and len(s) >= 1:
        return s
    return None


def chase_object_graph(root_ptr, depth=2, max_width=8):
    """BFS through object graph to find any readable strings."""
    strings = []
    visited = set()
    queue = [(root_ptr, 0)]
    while queue and len(strings) < 30:
        ptr, d = queue.pop(0)
        if ptr in visited or d > depth:
            continue
        visited.add(ptr)
        if ptr < 0xFFFFFF0000000000:
            continue
        # Read object header
        for off in range(0x00, 0x40, 8):
            val = try_u64(ptr + off)
            if val is None:
                continue
            if val >= 0xFFFFFF0000000000:
                # pointer: try reading as OSString first
                s = try_read_osstring(val)
                if s:
                    strings.append(("obj+%02x->%s" % (off, fmt(val)), s))
                else:
                    # queue for BFS
                    if len(queue) < 50:
                        queue.append((val, d + 1))
            # Try inline string at each offset
            raw = try_read(ptr + off, 32)
            if raw:
                # check if starts with printable ASCII
                for skip in range(0, 8):
                    chunk = raw[skip:skip+32]
                    if len(chunk) >= 4 and all(0x20 <= b < 0x7F for b in chunk[:4]):
                        end = 0
                        while end < len(chunk) and 0x20 <= chunk[end] < 0x7F:
                            end += 1
                        if end >= 4:
                            strings.append(("inline+%02x+%d" % (off, skip), chunk[:end].decode('ascii', 'replace')))
                        break
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


def write_output(classification, slide_info, extra=None):
    out = {
        "gate": "ARMIO_THUNK_X2_NAME_EXTRACTION",
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


note("v10 x2 name extraction attached")

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

try:
    gdb.execute("hbreak *%#x" % thunk_runtime, to_string=True)
    note("hbreak THUNK @ %s installed" % fmt(thunk_runtime))
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

    if pc != thunk_runtime:
        continue

    x2 = get_reg("x2")

    # Deep object graph chase
    graph_strings = chase_object_graph(x2, depth=2, max_width=8)

    # Wide-area search for "ans\0" near x2
    # Search the full kernel-visible heap for "iop,ascwrap" (first hit only)
    if pair_count == 0:
        rec_ans_wide = {"heap_search": []}
        # Search common heap regions based on observed x2 address ranges
        # x2 values are around 0xffffffdf09c... and 0xffffffdd36...
        # These suggest the heap spans roughly 0xffffffd000000000 to 0xffffffe400000000
        for region_name, region_lo, region_hi in [
            ("heap_dfx", 0xFFFFFFDF00000000 + slide, 0xFFFFFFE000000000 + slide),
            ("heap_ddx", 0xFFFFFFDD00000000 + slide, 0xFFFFFFDE00000000 + slide),
            ("dt_plane", 0xFFFFFFDF00000000 + slide, 0xFFFFFFDF10000000 + slide),
        ]:
            try:
                result = gdb.execute(
                    "find /b 0x%x, 0x%x, 0x69, 0x6f, 0x70, 0x2c, 0x61, 0x73, 0x63" % (region_lo, region_hi),
                    to_string=True,
                )
                hits = []
                for line2 in result.splitlines():
                    line2 = line2.strip()
                    if line2.startswith("0x"):
                        hits.append(line2.split()[0])
                rec_ans_wide["heap_search"].append({
                    "region": region_name, "lo": hex(region_lo), "hi": hex(region_hi),
                    "hits": hits[:10], "count": len(hits)
                })
                if hits:
                    note("FOUND iop,ascwrap in %s at %s" % (region_name, hits[:5]))
            except Exception as e:
                rec_ans_wide["heap_search"].append({"region": region_name, "error": str(e)})
    else:
        rec_ans_wide = {"skipped": True}
    rec = {
        "label": "thunk_hit",
        "t": round(time.time() - T0, 3),
        "x2": fmt(x2),
        "graph_strings": graph_strings,
        "wide_ans_search": rec_ans_wide,
    }
    events.append(rec)
    pair_count += 1

    # Check for 'ans'
    found_ans = any("ans" in s.lower() for _, s in graph_strings)
    if found_ans:
        note("hit #%d: *** ANS FOUND *** strings=%s" % (pair_count, [s for _, s in graph_strings if "ans" in s.lower()]))
    else:
        # log unique strings only
        new_strs = [s for _, s in graph_strings if s not in {x for _, x in (rec.get("graph_strings") or [])}]
        note("hit #%d: %d strings, first: %s" % (pair_count, len(graph_strings), [s for _, s in graph_strings[:3]]))

# Summary
all_strings = set()
for e in events:
    for _, s in e.get("graph_strings", []):
        all_strings.add(s)

ans_hits = []
for e in events:
    for src, s in e.get("graph_strings", []):
        if "ans" in s.lower():
            ans_hits.append({"t": e["t"], "x2": e["x2"], "source": src, "string": s})

summary = {
    "total_hits": pair_count,
    "all_unique_strings": sorted(all_strings),
    "total_unique_strings": len(all_strings),
    "ans_hits": ans_hits,
    "ans_found": len(ans_hits) > 0,
}

classification = "ANS_FOUND" if ans_hits else "NO_ANS_IN_GRAPH"

write_output(classification, {"slide": fmt(slide)}, {"summary": summary})
note("done: %s (%d ans hits)" % (classification, len(ans_hits)))
gdb.execute("quit")


