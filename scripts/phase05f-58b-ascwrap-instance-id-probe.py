# Phase 05F 58B: ASCWrap allocator instance identity probe.
#
# Two-stage hbreak: (1) at the allocator entry 0x...82f34a8, then
# (2) at its retab 0x...82f3514. At the return, x0 = the instance.
# Read the instance vtable pointer to definitively identify which
# class was instantiated (V6 vs SEP vs SISP vs other).

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
ALLOC_RET_SITE = 0xFFFFFFF0082F32E0  # instr AFTER the V6 vtable store
SLIDE = 0x20000000

KNOWN_VTABLES = {
    0xFFFFFFF007D131F0: "AppleASCWrapV6 (stored ptr)",
    0xFFFFFFF007D139C8: "AppleASCWrapV6SEP (stored ptr)",
    0xFFFFFFF007D12A18: "AppleASCWrapV6SISP (stored ptr)",
    0xFFFFFFF007D12AA0: "allocator-installed ptr (observed in disasm)",
    0xFFFFFFF007D14970: "AppleA7IOPNub (stored ptr)",
}

_done = threading.Event()


def _killer():
    if not _done.wait(50):
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


class InstanceIdProbe(gdb.Command):
    def __init__(self):
        super(InstanceIdProbe, self).__init__("probe58n", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.execute(f"hbreak *0x{ALLOC_RET_SITE + SLIDE:x}")
        threading.Thread(target=_killer, daemon=True).start()

        events = []
        t0 = time.time()
        rounds = 0
        while rounds < 5 and (time.time() - t0) < 40:
            gdb.execute("continue", to_string=False)
            try:
                x0 = int(gdb.parse_and_eval("$x0")) & 0xFFFFFFFFFFFFFFFF
            except (gdb.error, TypeError):
                x0 = 0
            rec = {"round": rounds, "instance": f"0x{x0:x}"}
            if x0:
                vt = read_u64(x0)
                if vt:
                    rec["vtable_runtime"] = f"0x{vt:x}"
                    rec["vtable_static"] = f"0x{vt - SLIDE:x}"
                    rec["identity"] = KNOWN_VTABLES.get(
                        vt - SLIDE, "UNKNOWN_VTABLE")
            events.append(rec)
            gdb.write(f"probe58n: round={rounds} obj=0x{x0:x} "
                      f"identity={rec.get('identity')}\n")
            rounds += 1

        result = {"gate": "58B_ASCWRAP_INSTANCE_IDENTITY",
                  "site": f"0x{ALLOC_RET_SITE:x}",
                  "events": events}
        with open(os.path.join(OUT_DIR, "instance-id.json"), "w") as f:
            json.dump(result, f, indent=2)
        _done.set()
        gdb.execute("detach", to_string=False)


InstanceIdProbe()
gdb.write("probe58n loaded\n")
