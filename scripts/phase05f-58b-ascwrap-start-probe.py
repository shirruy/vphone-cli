# Phase 05F 58B: AppleASCWrapV6::start runtime probe.
#
# Breakpoint at the ASCWrap-family start function (inherited A7IOP
# start, slot +0x360 of vtable 0xfffffff007d131e0). Any hit proves
# the personality attached to a provider nub. Zero hits across a
# full boot window means matching never fired.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")

ASCWRAP_START_STATIC = 0xFFFFFFF00AAD7DA0
SLIDE = 0x20000000
MAX_HITS = 40
RUN_SECONDS = 30

_done = threading.Event()


def _timeout_killer():
    if not _done.wait(RUN_SECONDS + 15):
        gdb.write("probe58c: HARD TIMEOUT; posting interrupt\n")
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


class ASCWrapStartProbe(gdb.Command):
    def __init__(self):
        super(ASCWrapStartProbe, self).__init__("probe58c", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        slide = SLIDE
        start_rt = ASCWRAP_START_STATIC + slide
        gdb.write(f"probe58c: ASCWrap start runtime = 0x{start_rt:x}\n")
        gdb.execute(f"hbreak *0x{start_rt:x}")

        killer = threading.Thread(target=_timeout_killer, daemon=True)
        killer.start()

        events = []
        hits = 0
        t0 = time.time()
        while hits < MAX_HITS and (time.time() - t0) < RUN_SECONDS:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error as e:
                gdb.write(f"probe58c: continue error {e}\n")
                break
            x0 = int(gdb.parse_and_eval("$x0")) & 0xFFFFFFFFFFFFFFFF
            x1 = int(gdb.parse_and_eval("$x1")) & 0xFFFFFFFFFFFFFFFF
            rec = {"hit": hits, "t": round(time.time() - t0, 3),
                   "x0_this": f"0x{x0:x}", "x1_provider": f"0x{x1:x}"}
            vt = read_u64(x0)
            if vt:
                rec["x0_vtable_static"] = f"0x{vt - slide:x}"
                rec["is_ascwrap_v6"] = (vt - slide) == 0xFFFFFFF007D131E0
            events.append(rec)
            gdb.write(f"probe58c: hit {hits} x0=0x{x0:x}\n")
            hits += 1

        result = {
            "gate": "58B_ASCWRAP_START_RUNTIME",
            "start_static": f"0x{ASCWRAP_START_STATIC:x}",
            "slide": slide,
            "events": events,
            "hit_count": len(events),
            "ascwrap_v6_hits": sum(1 for e in events if e.get("is_ascwrap_v6")),
        }
        with open(os.path.join(OUT_DIR, "ascwrap-start-probe.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58c: {len(events)} hits "
                  f"({result['ascwrap_v6_hits']} ASCWrapV6)\n")
        _done.set()
        gdb.execute("detach", to_string=False)


ASCWrapStartProbe()
gdb.write("probe58c: loaded; run probe58c\n")
