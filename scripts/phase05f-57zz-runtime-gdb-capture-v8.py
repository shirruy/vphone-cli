#!/usr/bin/env python3
"""57ZZ: thunk-only breakpoint + single-step chain to allocator.

Protocol:
  1. Attach to running QEMU gdbstub.
  2. Derive KASLR slide via PC-anchored bootkc byte match.
  3. Install ONE hardware breakpoint on the THUNK entry only
     (0xfffffff008387eb0 + slide).
  4. On each hit: capture x0/x1/x2/lr/sp, then single-step twice:
       step 1: expected PC = thunk+4 (the branch instruction)
       step 2: expected PC = allocator entry (0xfffffff008387eb8 + slide)
  5. Capture allocator x0/x1 after the second step.
  6. Prove: thunk.x2 == allocator.x1 for every pair.

No string-replacement inheritance. All constants are explicit.
"""

import gdb
import json
import os
import struct
import time

# EXPLICIT constants - no inherited variables
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

MAX_PAIRS = 40
BUDGET_SECONDS = 120.0

events = []
notes = []
T0 = time.time()
_bootkc_cache = None


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


def fmt(x):
    return "0x%016x" % x


def get_reg(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
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
    # verify thunk signature at slide
    sig = try_read(THUNK_STATIC + slide, 8)
    # thunk: mov x1,x2; b allocator => e103 02aa 0100 0014
    if sig != bytes.fromhex("e10302aa01000014"):  # mov x1,x2; b allocator
        return None, "thunk_sig_mismatch"
    return slide, None


def capture(label, pc):
    regs = {r: get_reg(r) for r in ("pc", "lr", "sp", "x0", "x1", "x2")}
    rec = {
        "label": label,
        "t": round(time.time() - T0, 3),
        "regs": {k: (fmt(v) if v is not None else None) for k, v in regs.items()},
    }
    events.append(rec)
    return rec


def write_output(classification, slide_info, extra=None):
    out = {
        "gate": "RUNTIME_ALLOCATOR_THUNK_PAIRING_V8",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "capture_pair_limit": MAX_PAIRS,
        "captured_pairs": pair_count,
        "captured_breakpoint_events": pair_count,
        "allocator_step_captures": control_flow_ok,
        "total_events": len(events),
        "capture_termination_reason": (
            "PAIR_LIMIT" if pair_count >= MAX_PAIRS
            else ("BUDGET_EXPIRED" if (time.time() - T0) >= BUDGET_SECONDS else "COMPLETED")
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


note("v8 thunk-only capture attached")
pc0 = get_reg("pc")
note("initial pc=%s" % (fmt(pc0) if pc0 else "none"))

# Derive slide
slide_info = None
for attempt in range(21):
    slide_info, err = derive_slide()
    if slide_info is not None:
        break
    if err not in ("pc_not_kernel_high_half", "pc_read_failed", "pc_bytes_not_in_bootkc", "pc_bytes_not_unique"):
        break
    try:
        gdb.execute("stepi", to_string=True)
    except Exception:
        break

if slide_info is None:
    note("SLIDE_DERIVATION_FAILED: %s" % err)
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", None, {"slide_error": err})
    raise gdb.GdbError("slide derivation failed")

slide = slide_info if isinstance(slide_info, int) else slide_info.get("slide", 0)
thunk_runtime = THUNK_STATIC + slide
allocator_runtime = ALLOCATOR_STATIC + slide
note("slide=%s thunk=%s allocator=%s" % (fmt(slide), fmt(thunk_runtime), fmt(allocator_runtime)))

# Install ONE breakpoint on the thunk
try:
    gdb.execute("hbreak *%#x" % thunk_runtime, to_string=True)
    note("hbreak THUNK @ %s installed" % fmt(thunk_runtime))
except Exception as e:
    note("hbreak THUNK failed: %s" % e)
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", {"slide": fmt(slide)}, {"hbreak_error": str(e)})
    raise gdb.GdbError("hbreak failed")

# Main loop: hit thunk, capture, stepi twice, capture allocator
pair_count = 0
control_flow_ok = 0
control_flow_fail = 0
register_match = 0
register_mismatch = 0

while pair_count < MAX_PAIRS and (time.time() - T0) < BUDGET_SECONDS:
    try:
        gdb.execute("signal 0", to_string=True)
    except Exception as e:
        note("continue failed: %s" % e)
        break

    pc = get_reg("pc")
    if pc is None:
        note("pc read failed")
        break

    if pc != thunk_runtime:
        note("stopped at non-thunk PC: %s" % fmt(pc))
        continue

    # THUNK HIT
    thunk_rec = capture("thunk_hit", pc)
    note("thunk hit #%d: x0=%s x1=%s x2=%s" % (pair_count + 1, thunk_rec["regs"]["x0"], thunk_rec["regs"]["x1"], thunk_rec["regs"]["x2"]))

    # Step 1: expect PC = thunk + 4 (the branch instruction)
    try:
        gdb.execute("stepi", to_string=True)
    except Exception:
        note("stepi 1 failed")
        control_flow_fail += 1
        pair_count += 1
        continue
    pc1 = get_reg("pc")
    step1_ok = (pc1 == thunk_runtime + 4)

    # Step 2: expect PC = allocator entry
    try:
        gdb.execute("stepi", to_string=True)
    except Exception:
        note("stepi 2 failed")
        control_flow_fail += 1
        pair_count += 1
        continue
    pc2 = get_reg("pc")
    step2_ok = (pc2 == allocator_runtime)

    if step1_ok and step2_ok:
        control_flow_ok += 1
        # Capture allocator entry
        alloc_rec = capture("allocator_after_thunk", pc2)
        # Check thunk.x2 == allocator.x1
        thunk_x2 = int(thunk_rec["regs"]["x2"], 16)
        alloc_x1 = int(alloc_rec["regs"]["x1"], 16)
        if thunk_x2 == alloc_x1:
            register_match += 1
            note("PAIR OK: thunk.x2 == alloc.x1 == %s" % fmt(thunk_x2))
        else:
            register_mismatch += 1
            note("REGISTER MISMATCH: thunk.x2=%s alloc.x1=%s" % (fmt(thunk_x2), fmt(alloc_x1)))
    else:
        control_flow_fail += 1
        note("CONTROL FLOW MISMATCH: step1_ok=%s step2_ok=%s pc1=%s pc2=%s" % (step1_ok, step2_ok, fmt(pc1) if pc1 else "?", fmt(pc2) if pc2 else "?"))

    pair_count += 1

# Summary
if pair_count == 0:
    classification = "NO_THUNK_HITS"
elif control_flow_fail == pair_count:
    classification = "ALL_CONTROL_FLOW_FAILED"
elif register_mismatch > 0:
    classification = "REGISTER_MISMATCHES_PRESENT"
elif control_flow_ok == pair_count and register_match == pair_count:
    classification = "ALL_PAIRS_PROVEN"
else:
    classification = "PARTIAL"

write_output(classification, {"slide": fmt(slide)}, {
    "summary": {
        "thunk_hits": pair_count,
        "control_flow_ok": control_flow_ok,
        "control_flow_fail": control_flow_fail,
        "register_match": register_match,
        "register_mismatch": register_mismatch,
    },
    "verdicts": {
        "THUNK_ENTRY_RUNTIME": "PROVEN" if pair_count > 0 else "NOT_OBSERVED",
        "CONTROL_FLOW_THUNK_TO_ALLOCATOR": "PROVEN_RUNTIME" if control_flow_ok == pair_count and control_flow_ok > 0 else "FAILED_OR_PARTIAL",
        "THUNK_X2_TO_ALLOCATOR_X1_RUNTIME": "PROVEN_RUNTIME" if register_match == pair_count and register_match > 0 else "FAILED_OR_PARTIAL",
    },
})
note("done: %s (%d pairs, %d cf_ok, %d reg_match)" % (classification, pair_count, control_flow_ok, register_match))
gdb.execute("quit")
