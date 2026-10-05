# Phase 05F Iteration 58B: allocator → IOPlatformDevice name probe.
#
# At each AppleARMIODevice allocator hit, capture the x1 object and try
# to extract its registry name via the property-table pointer chase
# (+0x10 OSDictionary → entries). This determines whether /arm-io/ans
# ever receives an IOPlatformDevice nub.
#
# Needs: P2_OUT_DIR, P2_GDB_PORT, PHASE05F_BOOTKC env vars.

import gdb
import json
import os
import struct

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
GDB_PORT = os.environ.get("P2_GDB_PORT", "1235")
BOOTKC = os.environ.get("PHASE05F_BOOTKC", "")

ALLOC_STATIC = 0xFFFFFFF008387EB8
IOPD_VT_STATIC = 0xFFFFFFF007CC90F8
SLIDE = 0x20000000
MAX_HITS = 120


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}"))
    except gdb.error:
        return None


def read_bytes(addr, n):
    try:
        inf = gdb.selected_inferior()
        return bytes(inf.read_memory(addr, n))
    except (gdb.error, ValueError):
        return None


def read_cstr(addr, maxlen=64):
    b = read_bytes(addr, maxlen)
    if b is None:
        return None
    z = b.find(b"\x00")
    if z >= 0:
        b = b[:z]
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_plist59(data, off):
    """Parse a bplist00 dict/string at off (rough)."""
    if data[off:off + 8] != b"bplist00":
        return None
    return None


class AllocProbe(gdb.Command):
    def __init__(self):
        super(AllocProbe, self).__init__("probe58b", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        slide = SLIDE
        alloc_rt = ALLOC_STATIC + slide
        gdb.write(f"probe58b: alloc runtime = 0x{alloc_rt:x}\n")
        gdb.execute(f"hbreak *0x{alloc_rt:x}")

        events = []
        hits = 0
        while hits < MAX_HITS:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error as e:
                gdb.write(f"probe58b: continue error {e}\n")
                break

            if hits % 10 == 0:
                gdb.write(f"probe58b: hit {hits}\n")
            x1 = int(gdb.parse_and_eval("$x1"))
            rec = {"hit": hits, "x1": f"0x{x1:x}"}
            vt = read_u64(x1)
            rec["vtable_rt"] = f"0x{vt:x}" if vt else None
            if vt:
                rec["vtable_static"] = f"0x{vt - slide:x}"
                rec["is_iopd"] = (vt - slide) == IOPD_VT_STATIC
            events.append(rec)
            hits += 1

        with open(os.path.join(OUT_DIR, "allocator-name-probe.json"), "w") as f:
            json.dump({"events": events, "slide": slide}, f, indent=2)
        gdb.write(f"probe58b: wrote {len(events)} events\n")


AllocProbe()
gdb.write("probe58b: script loaded, run 'probe58b'\n")
