# Phase 05F 58B: registerService return probe.
#
# hbreak at 0x...83881f0 (right after nub vtable+0x2a0 registerService).
# x0/w0 = result; x21 = nub. If registration fails, matching never runs.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
POST_REG_STATIC = 0xFFFFFFF0083881F0
SLIDE = 0x20000000
MAX_HITS = 130

_done = threading.Event()


def _killer():
    if not _done.wait(40):
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


class RegisterReturnProbe(gdb.Command):
    def __init__(self):
        super(RegisterReturnProbe, self).__init__("probe58j", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = POST_REG_STATIC + SLIDE
        gdb.write(f"probe58j: post-register runtime = 0x{rt:x}\n")
        gdb.execute(f"hbreak *0x{rt:x}")
        threading.Thread(target=_killer, daemon=True).start()

        events = []
        n = 0
        t0 = time.time()
        while n < MAX_HITS and (time.time() - t0) < 30:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error:
                break
            try:
                x0 = int(gdb.parse_and_eval("$x0")) & 0xFFFFFFFFFFFFFFFF
            except (gdb.error, TypeError):
                x0 = 0xDEAD
            try:
                x21 = int(gdb.parse_and_eval("$x21")) & 0xFFFFFFFFFFFFFFFF
            except (gdb.error, TypeError):
                x21 = 0
            ok = (x0 & 0xFFFFFFFF) == 0  # IOReturn success = 0
            rec = {"n": n, "reg_raw": f"0x{x0 & 0xFFFFFFFF:x}", "reg_ok": ok,
                   "nub": f"0x{x21:x}"}
            events.append(rec)
            if n % 20 == 0:
                gdb.write(f"probe58j: n={n} ok={ok} raw=0x{x0 & 0xFFFFFFFF:x}\n")
            n += 1

        okc = sum(1 for e in events if e.get("reg_ok"))
        result = {"gate": "58B_REGISTER_SERVICE_RETURN",
                  "site": f"0x{POST_REG_STATIC:x}",
                  "events": events, "total": len(events),
                  "reg_ok_count": okc}
        with open(os.path.join(OUT_DIR, "register-return.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58j: {len(events)} events, {okc} ok\n")
        _done.set()
        gdb.execute("detach", to_string=False)


RegisterReturnProbe()
gdb.write("probe58j loaded\n")
