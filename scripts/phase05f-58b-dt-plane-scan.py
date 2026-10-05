# Phase 05F 58B: DT plane compatible scan.
#
# After boot, search kernel DRAM for the exact DT property strings
# "iop,ascwrap-v6" and "iop-nub,rtbuddy-v2". If present, the DT plane
# retained the compatible properties; the blocker is matching. If
# absent, the encoder/plane copy dropped them.

import gdb
import json
import os

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")

NEEDLES = [b"iop,ascwrap-v6", b"iop-nub,rtbuddy-v2", b"iop,ascwrap-v7",
           b"ANS2", b"arm-io", b"uart0", b"ans\x00"]

# Focused kernel-heap windows derived from observed IOPlatformDevice
# allocation addresses across runs (0xffffffd.../0xffffffe... ranges).
# Focused windows around observed kernel-heap addresses (from allocator
# captures: 0xffffffdfe..., 0xffffffe0..., 0xffffffe1..., 0xffffffe2...).
# Narrow windows around the exact page regions where allocator captures
# placed IOPlatformDevice objects: 0xffffffdf0...-0xffffffdf1...,
# 0xffffffe00...-0xffffffe2e... The kernel heap is sparse; these are
# the empirically observed live zones.
SCAN_WINDOWS = [
    (0xFFFFFFDF00000000, 0xFFFFFFDF10000000),
    (0xFFFFFFDF10000000, 0xFFFFFFDF20000000),
    (0xFFFFFFE000000000, 0xFFFFFFE10000000),
    (0xFFFFFFE10000000, 0xFFFFFFE20000000),
    (0xFFFFFFE12000000, 0xFFFFFFE13000000),
    (0xFFFFFFE20000000, 0xFFFFFFE21000000),
    (0xFFFFFFE25000000, 0xFFFFFFE26000000),
]
CHUNK = 0x1000000


class DTPlaneScan(gdb.Command):
    def __init__(self):
        super(DTPlaneScan, self).__init__("scan58d", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        inf = gdb.selected_inferior()
        found = {n.decode(): [] for n in NEEDLES}
        scanned = 0
        for (start, end) in SCAN_WINDOWS:
            addr = start
            while addr < end:
                buf = None
                try:
                    buf = bytes(inf.read_memory(addr, 0x1000))
                except (gdb.error, ValueError):
                    pass
                if buf is None:
                    addr += CHUNK
                    continue
                # page readable; read the full chunk
                try:
                    buf = bytes(inf.read_memory(addr, CHUNK))
                except (gdb.error, ValueError):
                    addr += CHUNK
                    continue
                scanned += 1
                for n in NEEDLES:
                    idx = 0
                    while True:
                        i = buf.find(n, idx)
                        if i < 0:
                            break
                        found[n.decode()].append(addr + i)
                        idx = i + 1
                addr += CHUNK

        result = {
            "gate": "58B_DT_PLANE_COMPATIBLE_SCAN",
            "scan_windows": [[hex(a), hex(b)] for a, b in SCAN_WINDOWS],
            "chunks_scanned": scanned,
            "hits": {k: [hex(a) for a in v[:20]] for k, v in found.items()},
            "hit_counts": {k: len(v) for k, v in found.items()},
        }
        with open(os.path.join(OUT_DIR, "dt-plane-scan.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"scan58d: scanned {scanned} chunks\n")
        for k, v in result["hit_counts"].items():
            gdb.write(f"  {k}: {v}\n")


DTPlaneScan()
gdb.write("scan58d: loaded; run scan58d\n")
