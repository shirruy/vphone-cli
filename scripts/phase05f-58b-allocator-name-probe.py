# Phase 05F Iteration 58B: allocator → IOPlatformDevice name probe.
#
# At each AppleARMIODevice allocator hit, capture the x1 object and try
# to extract its registry name via the property-table pointer chase
# (+0x10 OSDictionary → entries). This determines whether /arm-io/ans
# ever receives an IOPlatformDevice nub.
#
# Needs: P2_OUT_DIR, P2_GDB_PORT, PHASE05F_BOOTKC env vars.

import gdb
import json
import os
import time
import threading
import struct

OUT_DIR = os.environ.get("P2_OUT_DIR", ".")
GDB_PORT = os.environ.get("P2_GDB_PORT", "1235")
BOOTKC = os.environ.get("PHASE05F_BOOTKC", "")

ALLOC_STATIC = 0xFFFFFFF008387EB8
IOPD_VT_STATIC = 0xFFFFFFF007CC90F8
SLIDE = 0x20000000
MAX_HITS = 120
TIMEOUT_SECONDS = 30

_done = threading.Event()


def _timeout_killer():
    """Force GDB batch to stop if the continue loop hangs."""
    if not _done.wait(TIMEOUT_SECONDS + 15):
        gdb.write("probe58b: HARD TIMEOUT; posting interrupt\n")
        gdb.post_event(lambda: gdb.execute("interrupt", to_string=False))


def read_u64(addr):
    try:
        return int(gdb.parse_and_eval(f"*(unsigned long long*)0x{addr:x}"))
    except gdb.error:
        return None


def read_bytes(addr, n):
    try:
        inf = gdb.selected_inferior()
        return bytes(inf.read_memory(addr, n))
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


def try_extract_name(obj_addr):
    """Extract the registry name from the property table.

    Layout (XNU 8792.81.2, iOS arm64, ALIGN_CONTAINERS=1):
      IORegistryEntry +0x20 -> fPropertyTable (OSDictionary)
      OSDictionary   +0x18 -> count (low 32 bits)
                     +0x20 -> dictEntry* (array of {key, value})
      dictEntry[i]   +0x00 -> key (OSSymbol)
                     +0x08 -> value
      OSSymbol/OSString +0x18 -> char* string
    """
    ptable = read_u64(obj_addr + 0x20)
    if not ptable or ptable == 0xFFFFFFFFFFFFFFFF:
        return None
    count = read_u64(ptable + 0x18) & 0xFFFFFFFF
    if count is None or count == 0 or count > 0x1000:
        return None
    entries = read_u64(ptable + 0x20)
    if not entries:
        return None

    for i in range(min(count, 256)):
        key_ptr = read_u64(entries + i * 16)
        val_ptr = read_u64(entries + i * 16 + 8)
        if not key_ptr or not val_ptr:
            continue
        key_str_ptr = read_u64(key_ptr + 0x18)
        if not key_str_ptr:
            continue
        key = read_cstr(key_str_ptr, 32)
        if key == "name":
            val_str_ptr = read_u64(val_ptr + 0x18)
            if val_str_ptr:
                return read_cstr(val_str_ptr, 48)
    return None


class AllocProbe(gdb.Command):
    def __init__(self):
        super(AllocProbe, self).__init__("probe58b", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        slide = SLIDE
        alloc_rt = ALLOC_STATIC + slide
        gdb.write(f"probe58b: alloc runtime = 0x{alloc_rt:x}\n")
        gdb.execute(f"hbreak *0x{alloc_rt:x}")

        killer = threading.Thread(target=_timeout_killer, daemon=True)
        killer.start()

        events = []
        hits = 0
        captured_addrs = []
        start = time.time()
        while hits < MAX_HITS and (time.time() - start) < TIMEOUT_SECONDS:
            try:
                gdb.execute("continue", to_string=False)
            except gdb.error as e:
                gdb.write(f"probe58b: continue error {e}\n")
                break

            if hits % 10 == 0:
                gdb.write(f"probe58b: hit {hits}\n")
            x1 = int(gdb.parse_and_eval("$x1")) & 0xFFFFFFFFFFFFFFFF
            rec = {"hit": hits, "x1": f"0x{x1:x}"}
            vt = read_u64(x1)
            rec["vtable_rt"] = f"0x{vt:x}" if vt else None
            if vt:
                rec["vtable_static"] = f"0x{vt - slide:x}"
                rec["is_iopd"] = (vt - slide) == IOPD_VT_STATIC
            if rec.get("is_iopd"):
                captured_addrs.append(x1)
            events.append(rec)
            hits += 1

        # Phase 2 is a separate attach (see probe58b_walk); write the
        # captured addresses now. The caller re-attaches after boot and
        # runs probe58b_walk to extract names from the live objects.
        with open(os.path.join(OUT_DIR, "allocator-addresses.json"), "w") as f:
            json.dump({"addresses": [f"0x{a:x}" for a in captured_addrs],
                       "slide": slide}, f, indent=2)

        with open(os.path.join(OUT_DIR, "allocator-name-probe.json"), "w") as f:
            json.dump({"events": events, "slide": slide}, f, indent=2)
        gdb.write(f"probe58b: wrote {len(events)} events\n")
        _done.set()
        # Detach and let the kernel continue booting for the walk pass.
        gdb.execute("detach", to_string=False)


class AllocWalk(gdb.Command):
    """Second-pass: walk captured allocator addresses on a live kernel."""

    def __init__(self):
        super(AllocWalk, self).__init__("probe58b_walk", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        addr_file = os.path.join(OUT_DIR, "allocator-addresses.json")
        with open(addr_file) as f:
            d = json.load(f)
        slide = d["slide"]
        results = []
        for a in d["addresses"]:
            addr = int(a, 16)
            rec = {"address": a}
            vt = read_u64(addr)
            if vt:
                rec["vtable_static"] = f"0x{vt - slide:x}"
                rec["is_iopd"] = (vt - slide) == IOPD_VT_STATIC
            if rec.get("is_iopd"):
                nm = try_extract_name(addr)
                if nm:
                    rec["name"] = nm
            results.append(rec)
        with open(os.path.join(OUT_DIR, "allocator-walk.json"), "w") as f:
            json.dump({"results": results, "slide": slide}, f, indent=2)
        named = sum(1 for r in results if r.get("name"))
        ans = [r for r in results if r.get("name") and "ans" in r["name"].lower()]
        gdb.write(f"probe58b_walk: {len(results)} objs, {named} named, "
                  f"{len(ans)} ANS-related\n")
        # Dump the first valid IOPD for layout debugging.
        for r in results:
            if r.get("is_iopd"):
                a = int(r["address"], 16)
                dump = {}
                for off in range(0, 0x40, 8):
                    v = read_u64(a + off)
                    dump[f"+{off:02x}"] = f"0x{v:x}" if v else "0"
                gdb.write(f"walk dump {r['address']}: {dump}\n")
                # Chase the three pointer candidates
                for cand_off in (0x10, 0x18, 0x20):
                    cand = read_u64(a + cand_off)
                    if not cand:
                        continue
                    vt = read_u64(cand)
                    cnt = read_u64(cand + 0x18) & 0xFFFFFFFF
                    ent = read_u64(cand + 0x20)
                    if ent and cnt and cnt < 0x100:
                        # try first entry key string
                        k = read_u64(ent)
                        if k:
                            ks = read_u64(k + 0x18)
                            if ks:
                                kn = read_cstr(ks, 32)
                                gdb.write(f"    entry0 key: {kn!r}\n")
                    gdb.write(f"  cand +{cand_off:x}: ptr=0x{cand:x} vt=0x{vt:x} "
                              f"count={cnt} entries=0x{ent:x}\n")
                    # Full dict dump to locate the real entries pointer
                    ddump = {}
                    for doff in range(0, 0x40, 8):
                        v = read_u64(cand + doff)
                        ddump[f"+{doff:02x}"] = f"0x{v:x}" if v else "0"
                    gdb.write(f"    dict dump: {ddump}\n")
                break


AllocWalk()


AllocProbe()
gdb.write("probe58b: script loaded, run 'probe58b'\n")
