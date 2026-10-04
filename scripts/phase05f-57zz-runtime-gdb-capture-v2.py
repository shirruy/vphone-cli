#!/usr/bin/env python3
"""57ZZ runtime boundary: GDB breakpoint capture for AppleA7IOP start candidates.

DIAGNOSTIC ONLY. Executed by gdb-multiarch (not standalone).

Protocol:
  1. Attach to a QEMU gdbstub that is already executing the kernel.
  2. Derive the BootKC KASLR slide by anchoring on the current PC: read the
     instruction bytes at the PC, find them uniquely in bootkc __TEXT_EXEC,
     and compute slide = runtime_pc - static_vm. Verify by matching the
     AppleA7IOPNub::withRegistryEntry prologue at the slid address.
  3. Install breakpoints on candidate A, candidate B, and
     AppleA7IOPNub::withRegistryEntry.
  4. Continue execution and capture raw register/memory evidence per hit.

No guest binary is modified. No production QEMU behavior changes.
"""
import gdb
import json
import os
import struct
import time

# TRUE vtable +0x348 targets (chain-decoder derived; bti c landing pads)
CAND_A_STATIC = 0xFFFFFFF0082F4DEC  # AppleASCWrapV6/A7IOP-family start entry
CAND_B_STATIC = 0xFFFFFFF0082F8048  # AppleA7IOPNub-family start entry
NUB_WRE_STATIC = 0xFFFFFFF0082F7B40
SIG_NUB_WRE = bytes.fromhex("7f2303d5ff4301d1f65702a9f44f03a9fd7b04a9fd030191f40301aaf50300aa")
SIG_A = bytes.fromhex("5f2403d57f2303d5ff4301d1f85f01a9")  # bti c; pacibsp; sub sp prologue

BOOTKC_PATH = os.environ.get(
    "PHASE05F_BOOTKC",
    r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin",
)
BOOTKC_EXEC_VM = 0xFFFFFFF0081E4000
BOOTKC_EXEC_FO = 0x11E0000
BOOTKC_EXEC_SZ = 0x2A44000
PC_MATCH_LEN = 16
SLIDE_ALIGN = 0x200000

MAX_HITS = 60
BUDGET_SECONDS = 150.0

events = []
notes = []
read_errors = {}
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

def read_u64(addr):
    return struct.unpack("<Q", read_mem(addr, 8))[0]

def try_read(addr, length):
    try:
        return read_mem(addr, length)
    except Exception as e:
        if len(read_errors) < 16:
            read_errors["0x%x" % addr] = str(e)
        return None

def fmt(x):
    return "0x%016x" % x

def get_reg(name):
    try:
        return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None

def derive_slide_from_pc():
    """Adaptive-window PC anchor: try 16/32/64/128-byte windows until a
    unique match in bootkc __TEXT_EXEC is found."""
    pc = get_reg("pc")
    if pc is None or pc < 0xFFFFFFF000000000:
        return None, "pc_not_kernel_high_half"
    hay = bootkc_exec()
    tried_windows = []
    for wlen in (16, 32, 64, 128):
        chunk = try_read(pc, wlen)
        if chunk is None or len(chunk) != wlen:
            tried_windows.append({"window": wlen, "result": "read_failed"})
            continue
        idx = hay.find(chunk)
        if idx < 0:
            tried_windows.append({"window": wlen, "result": "not_found"})
            continue
        if hay.find(chunk, idx + 1) >= 0:
            tried_windows.append({"window": wlen, "result": "not_unique"})
            continue
        static_vm = BOOTKC_EXEC_VM + idx
        if static_vm & 3:
            tried_windows.append({"window": wlen, "result": "misaligned"})
            continue
        slide = pc - static_vm
        if slide & (SLIDE_ALIGN - 1):
            tried_windows.append({"window": wlen, "result": "slide_not_aligned", "slide": fmt(slide)})
            continue
        nub = try_read(NUB_WRE_STATIC + slide, len(SIG_NUB_WRE))
        if nub != SIG_NUB_WRE:
            tried_windows.append({"window": wlen, "result": "nub_sig_mismatch", "slide": fmt(slide)})
            continue
        return {
            "slide": slide,
            "runtime_pc": pc,
            "static_vm": static_vm,
            "match_window": wlen,
            "nub_runtime": NUB_WRE_STATIC + slide,
            "nub_bytes": nub.hex(),
            "pc_anchor_hex_first16": chunk[:16].hex(),
            "tried_windows": tried_windows,
        }, None
    return None, "no_unique_match:%s" % json.dumps(tried_windows)

def capture_state(label, pc):
    regs = {r: get_reg(r) for r in ("pc", "lr", "sp", "x0", "x1", "x2", "x3", "x19", "x20")}
    rec = {
        "label": label,
        "t": round(time.time() - T0, 3),
        "regs": {k: (fmt(v) if v is not None else None) for k, v in regs.items()},
    }
    for regname in ("x0", "x1"):
        v = regs[regname]
        if v is None or v < 0x1000:
            continue
        dump = {}
        for off in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0xF8):
            try:
                dump["+%02x" % off] = fmt(read_u64(v + off))
            except Exception:
                dump["+%02x" % off] = None
        rec["mem_%s" % regname] = dump
    events.append(rec)
    note("hit %s pc=%s x0=%s x1=%s" % (label, fmt(pc), fmt(regs["x0"]), fmt(regs["x1"])))
    return rec

def write_output(classification, slide_info, extra=None):
    out = {
        "gate": "PART15B_RUNTIME_BREAKPOINT_CAPTURE",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "candidates_static": {
            "A": fmt(CAND_A_STATIC),
            "B": fmt(CAND_B_STATIC),
            "nubWRE": fmt(NUB_WRE_STATIC),
        },
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

note("attached")
pc0 = get_reg("pc")
note("initial pc=%s" % (fmt(pc0) if pc0 else "none"))

def pc_context_sample(bg_seconds=2.0):
    """Sample a new PC: switch gdb to async mode, resume, interrupt."""
    try:
        gdb.execute("set target-async on", to_string=True)
    except Exception:
        pass
    try:
        gdb.execute("set non-stop on", to_string=True)
    except Exception:
        pass
    try:
        # In batch mode with a remote target, use scheduler-locking instead:
        # single-stepi advances one instruction and always yields a new stop.
        for _ in range(50):
            gdb.execute("stepi", to_string=True)
        return get_reg("pc")
    except Exception as e:
        note("stepi sampling failed: %s" % e)
        return None

GDB_PORT = os.environ.get("P2_GDB_PORT", "1235")

def reattach():
    """Detach and re-attach to sample a fresh PC. Each attach interrupts the
    CPU at a new execution point; roughly half land in kernel context."""
    try:
        gdb.execute("detach", to_string=True)
    except Exception:
        pass
    time.sleep(0.15)
    try:
        gdb.execute("target remote 127.0.0.1:%s" % GDB_PORT, to_string=True)
        return True
    except Exception as e:
        note("re-attach failed: %s" % e)
        return False

slide_info = None
last_error = None
attempts = 0
sample_pcs = []
for attempts in range(1, 21):
    slide_info, err = derive_slide_from_pc()
    if slide_info is not None:
        break
    last_error = err
    pc_now = get_reg("pc")
    sample_pcs.append(fmt(pc_now) if pc_now else None)
    note("attempt %d failed: %s (pc=%s)" % (attempts, err, fmt(pc_now) if pc_now else "none"))
    if not reattach():
        last_error = "reattach_failed"
        break

if slide_info is None:
    note("SLIDE_DERIVATION_FAILED after %d attempts: %s" % (attempts, last_error))
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", None, {
        "slide_error": last_error,
        "attempts": attempts,
        "sampled_pcs": sample_pcs,
        "read_errors": read_errors,
    })
    raise gdb.GdbError("slide derivation failed")

slide = slide_info["slide"]
nub_runtime = slide_info["nub_runtime"]
cand_a = CAND_A_STATIC + slide
cand_b = CAND_B_STATIC + slide
note("slide=%s static_anchor=%s runtime_pc=%s attempts=%d" % (
    fmt(slide), fmt(slide_info["static_vm"]), fmt(slide_info["runtime_pc"]), attempts))
note("candA=%s candB=%s nubWRE=%s" % (fmt(cand_a), fmt(cand_b), fmt(nub_runtime)))

va = try_read(cand_a, len(SIG_A))
vb = try_read(cand_b, len(SIG_A))
if va != SIG_A or vb != SIG_A:
    note("CANDIDATE_BYTE_VERIFY_FAILED")
    write_output("BLOCKED_DIAGNOSTIC_FAILURE", slide_info, {
        "candidate_bytes": {"A": va.hex() if va else None, "B": vb.hex() if vb else None},
    })
    raise gdb.GdbError("candidate byte verify failed")

# QEMU gdbstub on this target cannot write software breakpoints into the
# protected kernel text. Use hardware breakpoints exclusively.
for label, addr in (("candA", cand_a), ("candB", cand_b), ("nubWRE", nub_runtime)):
    try:
        gdb.execute("hbreak *%#x" % addr, to_string=True)
        note("hbreak %s @ %s installed" % (label, fmt(addr)))
    except Exception as e:
        note("hbreak %s failed: %s" % (label, e))
        write_output("BLOCKED_DIAGNOSTIC_FAILURE", slide_info, {"hbreak_error": str(e)})
        raise gdb.GdbError("hbreak failed")

addr_map = {cand_a: "bp:candA", cand_b: "bp:candB", nub_runtime: "bp:nubWRE"}
bp_hits = 0
import threading

def timed_continue(timeout=30.0):
    """Continue with a watchdog: interrupt the target after `timeout` seconds
    if no breakpoint hit occurs, so the loop can re-check the budget."""
    result = {"stopped": False, "error": None}

    def watchdog():
        time.sleep(timeout)
        if not result["stopped"]:
            try:
                gdb.execute("interrupt", to_string=True)
            except Exception:
                pass

    t = threading.Thread(target=watchdog, daemon=True)
    t.start()
    try:
        gdb.execute("signal 0", to_string=True)
        result["stopped"] = True
    except Exception as e:
        result["stopped"] = True
        result["error"] = str(e)
    return result

CONTINUE_TIMEOUT = 30.0
while bp_hits < MAX_HITS and (time.time() - T0) < BUDGET_SECONDS:
    r = timed_continue(CONTINUE_TIMEOUT)
    if r["error"]:
        note("continue failed: %s" % r["error"])
        break
    try:
        pc = int(gdb.parse_and_eval("$pc")) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        note("pc read failed after stop")
        break
    if pc in addr_map:
        capture_state(addr_map[pc], pc)
        bp_hits += 1
    else:
        capture_state("stop_other:%x" % pc, pc)

bp_labels = [e["label"] for e in events if e["label"].startswith("bp:")]
if not bp_labels:
    classification = "NO_HIT"
elif "bp:candA" in bp_labels and "bp:candB" in bp_labels:
    classification = "BOTH_WITH_DISTINCT_RECEIVERS"
elif "bp:candA" in bp_labels:
    classification = "A"
else:
    classification = "B"

write_output(classification, slide_info)
note("done classification=%s bp_hits=%d" % (classification, bp_hits))
gdb.execute("quit")









