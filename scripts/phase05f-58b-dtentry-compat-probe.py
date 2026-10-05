# Phase 05F 58B: DT-entry compatible probe at the factory call.
#
# hbreak at 0x...8388140 (factory blraa). x2 = the DT entry
# (IORegistryEntry in the DT plane). Walk its property table and dump
# name + compatible for each entry. This proves whether the ANS DT
# entry retains compatible=iop,ascwrap-v6 inside the DT plane objects.

import gdb
import json
import os
import threading
import time

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
CALLSITE_STATIC = 0xFFFFFFF008388140
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


def dict_of(obj):
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
    cnt, ent = dict_of(obj)
    if not ent:
        return None
    for i in range(min(cnt, 128)):
        k = read_u64(ent + i * 16)
        v = read_u64(ent + i * 16 + 8)
        if not k or not v:
            continue
        ks = read_u64(k + 0x18)
        if not ks:
            ks = read_u64(k + 0x10)  # proven layout: string at +0x10
        if not ks:
            continue
        if read_cstr(ks, 24) != key:
            continue
        cs = read_u64(v + 0x18)
        if not cs:
            cs = read_u64(v + 0x10)
        if cs:
            s = read_cstr(cs, 64)
            if s:
                return s
        ln = read_u64(v + 0x10) & 0xFFFFFFFF
        dp = read_u64(v + 0x20)
        if dp and ln and ln < 0x100:
            b = read_bytes(dp, min(ln, 64))
            if b:
                z = b.find(b"\x00")
                if z >= 0:
                    b = b[:z]
                try:
                    return b.decode("ascii")
                except UnicodeDecodeError:
                    return None
    return None


class DTEntryCompatProbe(gdb.Command):
    def __init__(self):
        super(DTEntryCompatProbe, self).__init__("probe58m", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rt = CALLSITE_STATIC + SLIDE
        gdb.write(f"probe58m: factory callsite runtime = 0x{rt:x}\n")
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
                x2 = int(gdb.parse_and_eval("$x2") or 0) & 0xFFFFFFFFFFFFFFFF
            except (gdb.error, TypeError):
                break
            if not x2:
                n += 1
                continue
            rec = {"n": n, "dt_entry": f"0x{x2:x}"}
            nm = get_str_prop(x2, "name")
            if nm:
                rec["name"] = nm
            compat = get_str_prop(x2, "compatible")
            if compat:
                rec["compatible"] = compat
            if nm or compat:
                gdb.write(f"probe58m: n={n} name={nm} compat={compat}\n")
            if n < 3:  # raw dump for layout debugging
                dump = {}
                for off in range(0, 0x40, 8):
                    v = read_u64(x2 + off)
                    dump[f"+{off:02x}"] = f"0x{v:x}" if v else "0"
                gdb.write(f"probe58m: entry dump {hex(x2)}: {dump}\n")
                # dump the candidate property tables at +0x18/+0x20
                for pt_off in (0x18, 0x20):
                    pt = read_u64(x2 + pt_off)
                    if not pt:
                        continue
                    pd = {}
                    for off in range(0, 0x30, 8):
                        v = read_u64(pt + off)
                        pd[f"+{off:02x}"] = f"0x{v:x}" if v else "0"
                    gdb.write(f"  dict@+{pt_off:x} {hex(pt)}: {pd}\n")
                    # try first 2 entries with both entries-pointer assumptions
                    for ent_off in (0x20, 0x28):
                        ent = read_u64(pt + ent_off)
                        if not ent:
                            continue
                        for ei in range(2):
                            k = read_u64(ent + ei * 16)
                            v = read_u64(ent + ei * 16 + 8)
                            gdb.write(f"    ent{ei}({hex(ent_off)}): k=0x{k:x} v=0x{v:x}\n")
                            if k:
                                for so in (0x18, 0x20, 0x10):
                                    sp = read_u64(k + so)
                                    if sp:
                                        s = read_cstr(sp, 32)
                                        if s:
                                            gdb.write(f"      key[{hex(so)}]={s!r}\n")
            events.append(rec)
            n += 1

        named = [e for e in events if e.get("name")]
        with_compat = [e for e in events if e.get("compatible")]
        result = {
            "gate": "58B_DT_ENTRY_COMPAT_AT_FACTORY",
            "events": events,
            "total": len(events),
            "named": named,
            "with_compatible": with_compat,
            "ans": [e for e in named if e.get("name") and "ans" in e["name"].lower()],
            "ascwrap": [e for e in with_compat if "ascwrap" in (e.get("compatible") or "")],
        }
        with open(os.path.join(OUT_DIR, "dtentry-compat.json"), "w") as f:
            json.dump(result, f, indent=2)
        gdb.write(f"probe58m: {len(events)} entries, {len(named)} named, "
                  f"{len(with_compat)} compat, {len(result['ascwrap'])} ascwrap\n")
        _done.set()
        gdb.execute("detach", to_string=False)


DTEntryCompatProbe()
gdb.write("probe58m loaded\n")
