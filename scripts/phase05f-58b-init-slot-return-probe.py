# Phase 05F 58B: capture the init (+0x540) return value inside the allocator.
#
# hbreak at 0x...8387f64 (right after the init virtual call) to read w0
# per child. Also capture x19 (fresh object) and x21 (provider), x20 (DT).

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
AFTER_INIT_STATIC = 0xFFFFFFF008387F64
SLIDE = 0x20000000
MAX_HITS = 120

_done = threading.Event()


def _killer():
    if not _done.wait(40):
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


def read_cstr(addr, maxlen=48):
    try:
        b = bytes(gdb.selected_inferior().read_memory(addr, maxlen))
        z = b.find(b"\x00")
        if z >= 0:
            b = b[:z]
        return b.decode("ascii", errors="replace")
    except (gdb.error, ValueError):
        return None


def dt_entry_name(entry):
    """The x20 DT entry is an IORegistryEntry from the DT plane."""
    pt = read_u64(entry + 0x20)
    if not pt:
        return None
    cnt = read_u64(pt + 0x18) & 0xFFFFFFFF
    ent = read_u64(pt + 0x20)
    if not ent or not cnt or cnt > 0x400:
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


class InitSlotReturnProbe(gdb.Command):
    def __init__(self):
        super(InitSlotReturnProbe, self).__init__("probe58h", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = AFTER_INIT_STATIC + SLIDE
        gdb.write(f"probe58h: after-init runtime = 0x{rt:x}\n")
        gdb.execute(f"hbreak *0x{rt:x}")
        threading.Thread(target=_killer, daemon=True).start()

        events = []
        n = 0
        t0 = time.time()
        while n < MAX_HITS and (time.time() - t0) < 25:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error:
                break
            w0 = int(gdb.parse_and_eval("$x0")) & 0xFFFFFFFFFFFFFFFF
            x19 = int(gdb.parse_and_eval("$x19")) & 0xFFFFFFFFFFFFFFFF
            x20 = int(gdb.parse_and_eval("$x20")) & 0xFFFFFFFFFFFFFFFF
            rec = {"n": n, "init_ok": bool(w0 & 1), "w0": f"0x{w0:x}",
                   "obj": f"0x{x19:x}", "dt_entry": f"0x{x20:x}"}
            nm = dt_entry_name(x20)
            if nm:
                rec["dt_name"] = nm
            events.append(rec)
            if rec["init_ok"]:
                gdb.write(f"probe58h: n={n} OK name={nm}\n")
            n += 1

        ok = sum(1 for e in events if e.get("init_ok"))
        named = [e for e in events if e.get("dt_name")]
        result = {"gate": "58B_INIT_SLOT_RETURN",
                  "after_init_site": f"0x{AFTER_INIT_STATIC:x}",
                  "events": events,
                  "total": len(events),
                  "init_ok_count": ok,
                  "named": named,
                  "ans": [e for e in named if "ans" in e["dt_name"].lower()]}
        with open(os.path.join(OUT_DIR, "init-slot-return.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58h: {len(events)} events, {ok} init-ok\n")
        _done.set()
        gdb.execute("detach", to_string=False)


InitSlotReturnProbe()
gdb.write("probe58h loaded\n")
