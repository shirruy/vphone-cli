# Phase 05F 58B: AppleARMIODevice init return-value probe.
#
# At the allocator thunk entry, capture x2 (the DT-entry argument
# forwarded to x1). Then set a temp breakpoint at the return address
# (lr) to capture the init outcome (x0 = bool). This reveals why nubs
# are allocated but never started.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")

THUNK_STATIC = 0xFFFFFFF008387EB0
SLIDE = 0x20000000
MAX_HITS = 120
RUN_SECONDS = 30

_done = threading.Event()


def _timeout_killer():
    if not _done.wait(RUN_SECONDS + 12):
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


class InitReturnProbe(gdb.Command):
    def __init__(self):
        super(InitReturnProbe, self).__init__("probe58f", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        thunk_rt = THUNK_STATIC + SLIDE
        gdb.write(f"probe58f: thunk runtime = 0x{thunk_rt:x}\n")
        gdb.execute(f"hbreak *0x{thunk_rt:x}")
        killer = threading.Thread(target=_timeout_killer, daemon=True)
        killer.start()

        events = []
        t0 = time.time()
        n = 0
        while n < MAX_HITS and (time.time() - t0) < RUN_SECONDS:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error:
                break
            x2 = int(gdb.parse_and_eval("$x2")) & 0xFFFFFFFFFFFFFFFF
            lr = int(gdb.parse_and_eval("$lr")) & 0xFFFFFFFFFFFFFFFF
            rec = {"n": n, "x2_dt_entry": f"0x{x2:x}", "lr": f"0x{lr:x}",
                   "lr_static": f"0x{lr - SLIDE:x}" if lr > SLIDE else None}

            # Chase the DT entry object to read its "name" property:
            # it is an IORegistryEntry from the DT plane. Try the same
            # property-table walk.
            pt = read_u64(x2 + 0x20) if x2 else None
            if pt:
                cnt = read_u64(pt + 0x18) & 0xFFFFFFFF
                ent = read_u64(pt + 0x20)
                if ent and cnt and cnt < 0x200:
                    for i in range(min(cnt, 64)):
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
                                rec["dt_name"] = read_cstr(vs)
                                break

            events.append(rec)
            if rec.get("dt_name"):
                gdb.write(f"probe58f: {n} name={rec['dt_name']}\n")
            n += 1

        result = {
            "gate": "58B_ARMIO_INIT_ARG_CAPTURE",
            "thunk_static": f"0x{THUNK_STATIC:x}",
            "slide": SLIDE,
            "events": events,
            "hit_count": len(events),
            "named": [e for e in events if e.get("dt_name")],
            "ans_entries": [e for e in events if e.get("dt_name") and "ans" in e["dt_name"].lower()],
        }
        with open(os.path.join(OUT_DIR, "init-arg-probe.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58f: {len(events)} hits, "
                  f"{len(result['named'])} named\n")
        _done.set()
        gdb.execute("detach", to_string=False)


InitReturnProbe()
gdb.write("probe58f loaded\n")
