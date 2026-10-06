#!/usr/bin/env python3
"""57ZZ v13: locate DT in kernel virtual memory via direct region scan.

From QEMU xnuboot_sptm.c:
  args.virtBase = STRIP_L2_PT_INDEX(bkc_virtlo) = 0xfffffff000000000
  args.physBase = DRAM base (0x100000000 for 8GB)
  args.deviceTreeP = dtree_base_phys - physBase + virtBase

The DT binary (~260KB) is in the blob area within the first ~50MB of DRAM.
In virtual memory, that translates to 0xfffffff000000000 + offset.

This script scans that range for the DT content (specifically "iop,ascwrap-v6"
and "ans\\0") using GDB find.
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

# Virtual base (from QEMU STRIP_L2_PT_INDEX)
KERNEL_VIRT_BASE = 0xFFFFFFF000000000

MAX_HITS = 5  # only need a few hits to establish the DT location
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


def try_read(addr, length):
    try:
        inferior = gdb.selected_inferior()
        return bytes(inferior.read_memory(addr, length))
    except Exception:
        return None


def try_u64(addr):
    try:
        inferior = gdb.selected_inferior()
        return struct.unpack("<Q", bytes(inferior.read_memory(addr, 8)))[0]
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
    sig = try_read(THUNK_STATIC + slide, 8)
    if sig != bytes.fromhex("e10302aa01000014"):
        return None, "thunk_sig_mismatch"
    return slide, None


def gdb_find(start, end, hex_bytes):
    """Use GDB find command to search for a byte pattern."""
    hex_str = ", ".join("0x%02x" % b for b in hex_bytes)
    cmd = "find /b 0x%x, 0x%x, %s" % (start, end, hex_str)
    try:
        result = gdb.execute(cmd, to_string=True)
        hits = []
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("0x"):
                hits.append(line.split()[0])
        return hits
    except Exception:
        return []


def write_output(data):
    outpath = os.path.join(os.environ.get("P2_OUT_DIR", "."), "gdb-capture.json")
    with open(outpath, "w") as f:
        json.dump(data, f, indent=2)
    note("wrote %s" % outpath)


note("v13 DT location scan attached")

# Derive slide (we need it to compute kernel addresses)
GDB_PORT = os.environ.get("P2_GDB_PORT", "1235")

def reattach():
    try:
        gdb.execute("detach", to_string=True)
    except Exception:
        pass
    time.sleep(0.15)
    try:
        gdb.execute("target remote 127.0.0.1:%s" % GDB_PORT, to_string=True)
        return True
    except Exception:
        return False

slide = None
last_err = None
for attempt in range(21):
    slide, err = derive_slide()
    if slide is not None:
        break
    last_err = err
    if err in ("pc_not_kernel_high_half", "pc_read_failed", "pc_bytes_not_in_bootkc", "pc_bytes_not_unique"):
        if not reattach():
            break
    else:
        break

if slide is None:
    note("SLIDE_DERIVATION_FAILED: %s" % last_err)
    write_output({"gate": "DT_LOCATION_SCAN", "classification": "BLOCKED", "slide_error": last_err})
    raise gdb.GdbError("slide derivation failed")

note("slide=%s" % fmt(slide))

# Search for "iop,ascwrap" in the kernel virtual space starting from
# KERNEL_VIRT_BASE (0xfffffff000000000) through the first 64MB
# The DT should be within this range based on the QEMU blob layout
SEARCH_START = KERNEL_VIRT_BASE
SEARCH_END = KERNEL_VIRT_BASE + 0x4000000  # 64MB

note("searching for 'iop,ascwrap' in 0x%x-0x%x ..." % (SEARCH_START, SEARCH_END))
iop_hits = gdb_find(SEARCH_START, SEARCH_END, b"iop,ascwrap")
note("iop,ascwrap hits: %s (%d)" % (iop_hits[:10], len(iop_hits)))

# Also search for "ans\0" as a DT node name
note("searching for 'ans\\0' in same range...")
ans_hits = gdb_find(SEARCH_START, SEARCH_END, b"ans\x00")
note("ans\\0 hits: %s (%d)" % (ans_hits[:10], len(ans_hits)))

# Also search for "/arm-io" 
note("searching for '/arm-io'...")
armio_hits = gdb_find(SEARCH_START, SEARCH_END, b"/arm-io")
note("/arm-io hits: %s (%d)" % (armio_hits[:5], len(armio_hits)))

# If we found iop,ascwrap, read surrounding context to confirm DT
dt_confirmed = False
dt_base = None
if iop_hits:
    addr = int(iop_hits[0], 16)
    # Read context around the hit
    ctx = try_read(addr - 0x100, 0x200)
    if ctx:
        note("context around iop,ascwrap: %s" % ctx[:100].hex())
        # Check for DT node structure nearby
        if b"ans" in ctx or b"compatible" in ctx:
            dt_confirmed = True
            # Try to find DT base by searching backwards for root node structure
            note("DT CONFIRMED: found compatible+ans near %s" % iop_hits[0])

# If DT not found in 64MB, try larger range
if not iop_hits:
    note("not found in 64MB, trying 128MB...")
    iop_hits = gdb_find(KERNEL_VIRT_BASE, KERNEL_VIRT_BASE + 0x8000000, b"iop,ascwrap")
    note("128MB iop,ascwrap hits: %s" % iop_hits[:5])

result = {
    "gate": "DT_LOCATION_SCAN",
    "classification": "DT_FOUND" if iop_hits else "DT_NOT_FOUND",
    "slide": fmt(slide),
    "search_range": "0x%x-0x%x" % (SEARCH_START, SEARCH_END),
    "iop_ascwrap_hits": iop_hits,
    "iop_ascwrap_count": len(iop_hits),
    "ans_null_hits": ans_hits[:20],
    "ans_null_count": len(ans_hits),
    "arm_io_hits": armio_hits[:5],
    "arm_io_count": len(armio_hits),
    "dt_confirmed": dt_confirmed,
    "notes": notes,
}

write_output(result)
note("done: %s (%d iop hits, %d ans hits)" % (result["classification"], len(iop_hits), len(ans_hits)))
gdb.execute("quit")
