# Phase 05F 58B: per-nub start result + name probe (inside the loop).
#
# hbreak at 0x...8388174 (right after nub vtable+0x360 start call).
# x0 = start bool, x21 = nub, x19 = provider, x20 = iterator.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
POST_START_STATIC = 0xFFFFFFF008388174
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


def read_cstr(addr, maxlen=48):
    try:
        b = bytes(gdb.selected_inferior().read_memory(addr, maxlen))
        z = b.find(b"\x00")
        if z >= 0:
            b = b[:z]
        return b.decode("ascii", errors="replace")
    except (gdb.error, ValueError):
        return None


def obj_name(obj):
    for pt_off in (0x20, 0x18, 0x10):
        pt = read_u64(obj + pt_off)
        if not pt:
            continue
        nm = _walk_dict(pt)
        if nm:
            return nm
    return None


def obj_prop_keys(obj, limit=24):
    """Dump property key names from the first plausible dict."""
    for pt_off in (0x20, 0x18, 0x10):
        pt = read_u64(obj + pt_off)
        if not pt:
            continue
        cnt = read_u64(pt + 0x18) & 0xFFFFFFFF
        ent = read_u64(pt + 0x20)
        if not ent or not cnt or cnt > 0x400:
            continue
        keys = []
        for i in range(min(cnt, limit)):
            k = read_u64(ent + i * 16)
            if not k:
                continue
            ks = read_u64(k + 0x18)
            if not ks:
                continue
            nm = read_cstr(ks, 32)
            if nm:
                keys.append(nm)
        if keys:
            return keys
    return None


def _walk_dict(pt):
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


class PostStartProbe(gdb.Command):
    def __init__(self):
        super(PostStartProbe, self).__init__("probe58i", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = POST_START_STATIC + SLIDE
        gdb.write(f"probe58i: post-start runtime = 0x{rt:x}\n")
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
            w0 = int(gdb.parse_and_eval("$x0") or 0) & 0xFFFFFFFFFFFFFFFF
            x21 = int(gdb.parse_and_eval("$x21") or 0) & 0xFFFFFFFFFFFFFFFF
            rec = {"n": n, "start_ok": bool(w0 & 1), "nub": f"0x{x21:x}"}
            nm = obj_name(x21) if x21 else None
            if nm:
                rec["name"] = nm
            if n < 8:  # dump keys for the first few
                keys = obj_prop_keys(x21) if x21 else None
                if keys:
                    rec["prop_keys"] = keys
                gdb.write(f"probe58i: n={n} ok={rec['start_ok']} name={nm}\n")
            events.append(rec)
            n += 1

        named = [e for e in events if e.get("name")]
        result = {
            "gate": "58B_POST_START_PER_NUB",
            "site": f"0x{POST_START_STATIC:x}",
            "events": events,
            "total": len(events),
            "start_ok_count": sum(1 for e in events if e.get("start_ok")),
            "named": named,
            "ans": [e for e in named if "ans" in e["name"].lower()],
        }
        with open(os.path.join(OUT_DIR, "post-start.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58i: {len(events)} events, "
                  f"ok={result['start_ok_count']}, named={len(named)}\n")
        _done.set()
        gdb.execute("detach", to_string=False)


PostStartProbe()
gdb.write("probe58i loaded\n")
