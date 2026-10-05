# Phase 05F 58B: provider vtable capture at the nub factory call.
#
# hbreak at the blraa site (0x...8388140 + slide). On hit, read x19
# (provider) and its vtable pointer, then resolve the +0x598 override
# target to identify which class actually runs the factory.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
CALLSITE_STATIC = 0xFFFFFFF008388140
SLIDE = 0x20000000
MAX_HITS = 20

_done = threading.Event()


def _killer():
    if not _done.wait(45):
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


class ProviderVtProbe(gdb.Command):
    def __init__(self):
        super(ProviderVtProbe, self).__init__("probe58g", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = CALLSITE_STATIC + SLIDE
        gdb.write(f"probe58g: callsite runtime = 0x{rt:x}\n")
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
            x19 = int(gdb.parse_and_eval("$x19")) & 0xFFFFFFFFFFFFFFFF
            rec = {"n": n, "x19": f"0x{x19:x}"}
            vt_raw = read_u64(x19)
            if vt_raw:
                # strip PAC bits to get the plain vtable pointer
                vt = vt_raw & 0x0000000FFFFFFFFF if vt_raw > 0xFFFFFFF000000000 else vt_raw
                # vtable pointer points to vtable+0x10 (Itanium); the object's
                # stored pointer is vtable_addr+0x10. Slot addr = ptr + 0x598.
                rec["vt_ptr_raw"] = f"0x{vt_raw:x}"
                slot_target = read_u64((vt_raw & 0x000000FFFFFFFFFF) + 0x598) if vt_raw else None
                # Simpler: read target from ptr+0x598 directly
                slot2 = read_u64(vt_raw + 0x598) if vt_raw else None
                rec["slot_598_direct"] = f"0x{slot2:x}" if slot2 else None
                if slot2:
                    rec["slot_598_static"] = f"0x{slot2 - SLIDE:x}"
            events.append(rec)
            gdb.write(f"probe58g: n={n} x19=0x{x19:x} vt=0x{vt_raw:x}\n")
            n += 1

        result = {"gate": "58B_PROVIDER_VTABLE_AT_FACTORY",
                  "callsite": f"0x{CALLSITE_STATIC:x}",
                  "events": events}
        with open(os.path.join(OUT_DIR, "provider-vtable.json"), "w") as f:
            json.dump(result, f, indent=2)
        _done.set()
        gdb.execute("detach", to_string=False)


ProviderVtProbe()
gdb.write("probe58g loaded\n")
