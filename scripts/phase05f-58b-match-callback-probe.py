# Phase 05F 58B: ARMIO match-callback probe.
#
# Breakpoint at the PAC callback 0xfffffff00aad7f70 (the per-child
# invocation from AppleARMIO::start's virtual +0x450 matching call).
# Captures x0 (the candidate child) and its vtable to determine
# whether /arm-io/ans reaches the matching stage.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")

CALLBACK_STATIC = 0xFFFFFFF00AAD7C6C  # ASCWrapV6 real start (stored-ptr +0x360)
CALLSITE_STATIC = 0xFFFFFFF00AAD7EFC
SLIDE = 0x20000000
MAX_HITS = 200
RUN_SECONDS = 25

_done = threading.Event()


def _timeout_killer():
    if not _done.wait(RUN_SECONDS + 12):
        gdb.write("probe58e: HARD TIMEOUT\n")
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


def read_cstr(addr, maxlen=48):
    try:
        inf = gdb.selected_inferior()
        b = bytes(inf.read_memory(addr, maxlen))
        z = b.find(b"\x00")
        if z >= 0:
            b = b[:z]
        return b.decode("ascii", errors="replace")
    except (gdb.error, ValueError):
        return None


def try_name(obj):
    """Best-effort name via fPropertyTable (+0x20) walk."""
    pt = read_u64(obj + 0x20)
    if not pt:
        return None
    cnt = read_u64(pt + 0x18) & 0xFFFFFFFF
    if not cnt or cnt > 0x400:
        return None
    ent = read_u64(pt + 0x20)
    if not ent:
        return None
    for i in range(min(cnt, 128)):
        k = read_u64(ent + i * 16)
        v = read_u64(ent + i * 16 + 8)
        if not k or not v:
            continue
        ks = read_u64(k + 0x18)
        if not ks:
            continue
        if read_cstr(ks, 16) == "name":
            vs = read_u64(v + 0x18)
            if vs:
                return read_cstr(vs)
    return None


class MatchCallbackProbe(gdb.Command):
    def __init__(self):
        super(MatchCallbackProbe, self).__init__("probe58e", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cb_rt = CALLBACK_STATIC + SLIDE
        gdb.write(f"probe58e: callback runtime = 0x{cb_rt:x}\n")
        gdb.execute(f"hbreak *0x{cb_rt:x}")

        killer = threading.Thread(target=_timeout_killer, daemon=True)
        killer.start()

        events = []
        t0 = time.time()
        n = 0
        while n < MAX_HITS and (time.time() - t0) < RUN_SECONDS:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error as e:
                gdb.write(f"probe58e: continue error: {e}\n")
                break
            x0 = int(gdb.parse_and_eval("$x0")) & 0xFFFFFFFFFFFFFFFF
            rec = {"n": n, "t": round(time.time() - t0, 3), "x0": f"0x{x0:x}"}
            vt = read_u64(x0)
            if vt:
                rec["vt_static"] = f"0x{vt - SLIDE:x}"
            nm = try_name(x0)
            if nm:
                rec["name"] = nm
            events.append(rec)
            if n % 20 == 0:
                gdb.write(f"probe58e: {n} hits\n")
            n += 1

        named = [e for e in events if e.get("name")]
        result = {
            "gate": "58B_ARMIO_MATCH_CALLBACK",
            "callback_static": f"0x{CALLBACK_STATIC:x}",
            "slide": SLIDE,
            "events": events,
            "hit_count": len(events),
            "named_count": len(named),
            "ans_hits": [e for e in named if "ans" in e["name"].lower()],
        }
        with open(os.path.join(OUT_DIR, "match-callback-probe.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58e: {len(events)} hits, {len(named)} named\n")
        _done.set()
        gdb.execute("detach", to_string=False)


MatchCallbackProbe()
gdb.write("probe58e: loaded\n")
