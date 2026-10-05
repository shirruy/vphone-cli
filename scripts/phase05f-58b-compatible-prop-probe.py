# Phase 05F 58B: find the nub whose compatible == iop,ascwrap-v6.
#
# At each post-start hit, walk the property table and dump the
# "compatible" OSData value. This identifies which nub is ANS and
# proves whether the compatible property survived into the registry.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
POST_START_STATIC = 0xFFFFFFF008388174
SLIDE = 0x20000000
MAX_HITS = 110

_done = threading.Event()


def _killer():
    if not _done.wait(45):
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}")) & 0xFFFFFFFFFFFFFFFF
    except gdb.error:
        return None


def read_bytes(addr, n):
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, n))
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


def prop_table(obj):
    """Return (count, entries) for the first valid OSDictionary at +0x20/0x18."""
    for off in (0x20, 0x18):
        pt = read_u64(obj + off)
        if not pt:
            continue
        cnt = read_u64(pt + 0x18) & 0xFFFFFFFF
        ent = read_u64(pt + 0x20)
        if ent and cnt and cnt < 0x400:
            return cnt, ent
    return 0, None


def get_str_prop(obj, key):
    """Get a string property: value may be OSString or OSData."""
    cnt, ent = prop_table(obj)
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
        if read_cstr(ks, 24) != key:
            continue
        # OSString: char* at +0x18. OSData: data ptr at +0x20, len at +0x10.
        cs = read_u64(v + 0x18)
        if cs:
            s = read_cstr(cs, 64)
            if s:
                return s
        ln = read_u64(v + 0x10)
        dp = read_u64(v + 0x20)
        if dp and ln and ln < 0x100:
            b = read_bytes(dp, ln)
            if b:
                z = b.find(b"\x00")
                if z >= 0:
                    b = b[:z]
                try:
                    return b.decode("ascii")
                except UnicodeDecodeError:
                    return None
    return None


class CompatibleProbe(gdb.Command):
    def __init__(self):
        super(CompatibleProbe, self).__init__("probe58k", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = POST_START_STATIC + SLIDE
        gdb.write(f"probe58k: runtime site = 0x{rt:x}\n")
        gdb.execute(f"hbreak *0x{rt:x}")
        threading.Thread(target=_killer, daemon=True).start()

        events = []
        n = 0
        t0 = time.time()
        while n < MAX_HITS and (time.time() - t0) < 35:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error:
                break
            try:
                x21 = int(gdb.parse_and_eval("$x21") or 0) & 0xFFFFFFFFFFFFFFFF
            except (gdb.error, TypeError):
                break
            if not x21:
                n += 1
                continue
            rec = {"n": n, "nub": f"0x{x21:x}"}
            nm = get_str_prop(x21, "name")
            if nm:
                rec["name"] = nm
            compat = get_str_prop(x21, "compatible")
            if compat:
                rec["compatible"] = compat
                gdb.write(f"probe58k: n={n} name={nm} compat={compat}\n")
            events.append(rec)
            n += 1

        named = [e for e in events if e.get("name")]
        with_compat = [e for e in events if e.get("compatible")]
        result = {
            "gate": "58B_NUB_COMPATIBLE_SCAN",
            "events": events,
            "total": len(events),
            "named": named,
            "with_compatible": with_compat,
            "ans": [e for e in named if e.get("name") and "ans" in e["name"].lower()],
            "ascwrap_compat": [e for e in with_compat if "ascwrap" in e["compatible"]],
        }
        with open(os.path.join(OUT_DIR, "nub-compatible-scan.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58k: {len(events)} nubs, {len(named)} named, "
                  f"{len(with_compat)} with compat, "
                  f"{len(result['ascwrap_compat'])} ascwrap\n")
        _done.set()
        gdb.execute("detach", to_string=False)


CompatibleProbe()
gdb.write("probe58k loaded\n")
