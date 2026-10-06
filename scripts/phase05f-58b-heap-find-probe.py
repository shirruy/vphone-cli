# Phase 05F 58B: GDB find for ascwrap strings near live nub heap.

import gdb
import json
import os

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")


class HeapFindProbe(gdb.Command):
    def __init__(self):
        super(HeapFindProbe, self).__init__("probe58l", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        results = {}
        # Nub heap observed at 0xffffffec1c00xxxx / 0xffffffe167d6xxxx etc.
        # Scan focused 64MB windows around observed heap zones.
        windows = [
            ("heap-ec1c00", 0xFFFFFFEC1C000000, 0xFFFFFFEC1D000000),
            ("heap-e167d6", 0xFFFFFFE167D00000, 0xFFFFFFE167E00000),
        ]
        for name, lo, hi in windows:
            gdb.write(f"probe58l: scanning {name} 0x{lo:x}-0x{hi:x}\n")
            for needle in (b"iop,ascwrap-v6", b"ans", b"ANS2"):
                try:
                    out = gdb.execute(
                        f"find /b 0x{lo:x}, 0x{hi:x}, "
                        + ", ".join(str(b) for b in needle[:8]),
                        to_string=True,
                    )
                    lines = [l for l in out.splitlines() if l.startswith("0x")]
                    results[f"{name}:{needle.decode()}"] = lines[:12]
                    gdb.write(f"  {needle.decode()}: {len(lines)} hits\n")
                except gdb.error as e:
                    results[f"{name}:{needle.decode()}"] = [f"error: {e}"]
        # Dump context around the ans hit
        ans_addr = 0xFFFFFFEC1C004686
        try:
            out = gdb.execute(
                f"x/64bx 0x{ans_addr - 0x40:x}", to_string=True)
            results["ans_context_hex"] = out
            gdb.write("context dumped\n")
        except gdb.error as e:
            results["ans_context_hex"] = f"error: {e}"
        # find the containing object: scan backward for a vtable-like pointer
        # (value starting 0xfffffff0) on 8-byte alignment
        for back in range(0x40, 0x400, 8):
            try:
                v = int(gdb.parse_and_eval(
                    f"*(unsigned long long*)0x{ans_addr - back:x}"))
                if (v & 0xFFFFFFF000000000) == 0xFFFFFFF000000000:
                    results["candidate_obj"] = {
                        "obj": f"0x{ans_addr - back:x}",
                        "vt": f"0x{v:x}",
                        "back": hex(back),
                    }
                    gdb.write(f"candidate obj at 0x{ans_addr-back:x} vt=0x{v:x}\n")
                    break
            except gdb.error:
                continue
        with open(os.path.join(OUT_DIR, "heap-find.json"), "w") as f:
            json.dump(results, f, indent=2)
        gdb.write("probe58l: done\n")


HeapFindProbe()
gdb.write("probe58l loaded\n")
