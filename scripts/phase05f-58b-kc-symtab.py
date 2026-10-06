import hashlib, json, struct, collections, os
BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT = "artifacts/evidence/05f/phase05f-58b-kc-symtab.json"
data = open(BOOTKC,"rb").read()
sha = hashlib.sha256(data).hexdigest().upper()

# --- Mach-O segments ---
ncmds = struct.unpack_from("<I", data, 16)[0]
off, segs = 32, []
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        nm = data[off+8:off+24].split(b"\0")[0].decode()
        vm, vsz, fo, fsz = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((nm, vm, vsz, fo, fsz))
    off += cs
le = next(s for s in segs if s[0]=="__LINKEDIT")
seg = {"vm": le[1], "vm_size": le[2], "fileoff": le[3], "filesize": le[4]}

# --- locate plist trailer (unique constrained candidate) ---
LO, HI = seg["fileoff"], seg["fileoff"]+seg["filesize"]
blob = data[LO:HI]
cands=[]
for pos in range(0, len(blob)-32):
    t = blob[pos:pos+32]
    if any(t[i] for i in range(5)): continue
    offSz, refSz = t[6], t[7]
    if not (1<=offSz<=8 and 1<=refSz<=8): continue
    num, top, oto = struct.unpack(">QQQ", t[8:32])
    if num<2 or num>1000000 or top>=num: continue
    if oto + num*offSz > pos: continue
    cands.append((pos,offSz,refSz,num,top,oto))
assert len(cands)==1, cands[:3]
tpos, offSz, refSz, num, top, oto = cands[0]
plist_len = tpos+32
offs=[int.from_bytes(blob[oto+i*offSz:oto+(i+1)*offSz],"big") for i in range(num)]
census = collections.Counter(blob[o]>>4 for o in offs)
def rd(pos,n): return int.from_bytes(blob[pos:pos+n],"big")
def length(off, info):
    if info != 0xF: return info, off+1
    lm = blob[off+1]; cnt = 1 << (lm & 0xF)
    return rd(off+2, cnt), off+2+cnt
def parse(i):
    o = offs[i]; m = blob[o]; k, info = m>>4, m&0xF
    if k == 0x5:
        ln, p = length(o, info)
        return blob[p:p+ln].decode("latin1")
    if k == 0xA:
        c, p = length(o, info)
        return [rd(p+j*refSz, refSz) for j in range(c)]
    if k == 0xD:
        c, p = length(o, info)
        keys=[rd(p+j*refSz,refSz) for j in range(c)]
        vals=[rd(p+c*refSz+j*refSz,refSz) for j in range(c)]
        return dict(zip(keys,vals))
    return ("UNSUPPORTED", hex(m))
strings = {}
for i in range(num):
    if blob[offs[i]]>>4 == 5:
        try:
            s = parse(i)
            if isinstance(s,str): strings.setdefault(s, i)
        except Exception: pass

targets = [
 "__ZNK15IORegistryEntry12compareNamesEP8OSObjectPP8OSString",
 "__ZNK15IORegistryEntry11compareNameEP8OSStringPS1_",
 "__ZTV15IORegistryEntry", "__ZTV9IOService",
 "__ZTV16IOPlatformDevice",
]
resolved=[]
for t in targets:
    i = strings.get(t)
    resolved.append({"name":t,
        "name_present": i is not None,
        "name_object_index": i,
        "name_file_offset": hex(LO+offs[i]) if i is not None else None,
        "address": None,
        "address_status": "NOT_ENCODED_IN_CONTAINER"})

patterns=[]
for a,b,label in [("IOService","match","IOService+match"),("IOCatalogue","","IOCatalogue"),("IODTCompare","","IODTCompare")]:
    hits=sorted(n for n in strings if a.lower() in n.lower() and b.lower() in n.lower())
    patterns.append({"pattern":label,"count":len(hits),"names":hits[:120],"addresses":[None]*len(hits[:120])})

# calibration falsification: bytes after anchor name are a plist dict, not a ULEB delta
ai = strings.get("__ZTV16IOPlatformDevice")
anchor_bytes = bytes(blob[offs[ai]:offs[ai]+3+len("__ZTV16IOPlatformDevice")+6]) if ai is not None else None
follow = None; follow_decode = None
if ai is not None:
    p = offs[ai]+3+len("__ZTV16IOPlatformDevice")
    follow = bytes(blob[p:p+5])
    # d1 = dict count 1; refs 00 04 / 20 b9 (ref_size 2)
    kref = int.from_bytes(follow[1:3],"big"); vref = int.from_bytes(follow[3:5],"big")
    follow_decode = {"marker":"0xd1 dict count=1",
                     "key_ref":kref,"key_decoded":parse(kref) if isinstance(parse(kref),str) else parse(kref),
                     "value_ref":vref,"value_decoded":parse(vref)}

art = {
 "gate":"05F_58B_KC_SYMTAB",
 "bootkc":BOOTKC, "bootkc_sha256":sha,
 "linkedit_segment":{k:(hex(v) if isinstance(v,int) else v) for k,v in seg.items()},
 "format":{
   "container":"Apple binary plist at __LINKEDIT head (bplist00)",
   "plist_file_start":hex(LO),"plist_file_end":hex(LO+plist_len),"length":plist_len,
   "trailer":{"file_offset":hex(LO+tpos),"offset_int_size":offSz,"object_ref_size":refSz,
              "num_objects":num,"top_object":top,"offset_table_offset":hex(oto)},
   "object_marker_census":{hex(k):v for k,v in sorted(census.items())},
   "census_interpretation":"0x5=ASCII strings, 0xA=arrays, 0xD=dicts. ZERO integer (0x2/0x3) and ZERO UID (0x8) objects exist in the container.",
   "encoding":"Names are plist string objects (5f 10 LL / 5n / 5f-int-ext markers). The observed 'd1 00 04 XX YY' after each name is a dict marker (0xd1 = dict with 1 pair) whose refs decode to {'SymbolName': <next name>}; it is NOT a ULEB address delta.",
   "name_count_distinct":len(strings),
   "delta_hypothesis":"REJECTED by decode: anchor-following bytes d1 00 04 20 b9 decode as dict{4:'__ZTV5IORTC'} (key object 4 = string 'SymbolName').",
   "address_availability":"NOT AVAILABLE: container stores symbol NAMES only (symbol-name sets per kext / weak-ref sets). No address values of any width are encoded.",
 },
 "calibration":{
   "requested_anchor":{"name":"__ZTV16IOPlatformDevice","claimed_address":"0xfffffff007cc90f8",
     "name_present":ai is not None,
     "address_reproducible_from_container":False,
     "anchor_following_bytes":anchor_bytes.hex(" ") if anchor_bytes else None,
     "anchor_following_decode":follow_decode,
     "result":"FAIL_CLOSED: name decoded; address cannot be derived from this container; claimed address has no supporting encoding here."},
   "verdict":"CALIBRATION FAILED — the premise that this region encodes addresses is disproven by the complete object-marker census.",
 },
 "resolved_targets":resolved,
 "pattern_targets":patterns,
 "fail_closed":[
   "compareNames/compareName/__ZTV15IORegistryEntry/__ZTV9IOService: names PRESENT (see resolved_targets); addresses NOT RESOLVABLE from this format.",
   "IOService+match / IOCatalogue / IODTCompare: see pattern_targets for presence lists; addresses NOT RESOLVABLE from this format.",
   "Any prior address claim tied to 'd1 00 04' deltas must be re-derived from the real symbol value source (e.g., fileset-entry symtab/strtab or LC_SYMTAB of embedded MH_FILESET kernels), not this plist.",
 ],
 "SYMTAB_NAME_DECODE":"PASS" if all(r["name_present"] for r in resolved) else "PARTIAL",
 "ADDRESS_RESOLUTION":"NOT_CERTIFIED (addresses not encoded in this container)",
 "notes":["Static decode only; no runtime claim.","All offsets are file offsets into bootkc.bin."],
}
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT,"w",encoding="utf-8").write(json.dumps(art,indent=2)+"\n")
print(json.dumps(art,indent=2))
