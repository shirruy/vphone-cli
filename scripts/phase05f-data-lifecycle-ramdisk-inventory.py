"""57ZY ramdisk FSTREE full file inventory.

Enumerates every DIR_REC record in the ramdisk's active FSTREE using the
authoritative NXSB -> OMAP -> APSB -> FSTREE chain, producing a complete
file/directory listing for producer identification.
"""
import hashlib
import json
import struct
import sys

IMG = 'C:/Users/rbjos/vphone-private/phase05f-known-good/payloads-v3/ramdisk.dmg'
OUT = 'artifacts/evidence/05f/phase05f-data-lifecycle-ramdisk-inventory.json'

BLOCK = 4096
MOD = 0xFFFFFFFF

# reuse the proven transition-probe helpers
sys.path.insert(0, 'scripts')

def fletcher64(blk):
    n = (len(blk) - 8) // 4
    words = struct.unpack('<%dI' % n, blk[8:])
    s1 = s2 = 0
    for w in words:
        s1 = (s1 + w) % MOD
        s2 = (s2 + s1) % MOD
    c1 = MOD - ((s1 + s2) % MOD)
    c2 = MOD - ((s1 + c1) % MOD)
    return c1 | (c2 << 32)

def checksum_ok(blk):
    return struct.unpack('<Q', blk[0:8])[0] == fletcher64(blk)

f = open(IMG, 'rb')
def rd(b):
    f.seek(b * BLOCK)
    return f.read(BLOCK)

# NXSB at block 0 -> omap_oid 1462 (from previous analysis)
nx = rd(0)
assert nx[0x20:0x24] == b'NXSB'
nx_xid = struct.unpack('<Q', nx[0x10:0x18])[0]
nx_omap_oid = struct.unpack('<Q', nx[0xA0:0xA8])[0]
nx_fs_oid = struct.unpack('<Q', nx[0xB8:0xC0])[0]  # first fs
print('NXSB: xid=%d omap_oid=%d fs_oid=%d' % (nx_xid, nx_omap_oid, nx_fs_oid))

# container omap_phys at block 1462
om = rd(nx_omap_oid)
assert checksum_ok(om)
om_tree = struct.unpack('<Q', om[0x30:0x38])[0]
print('omap_phys block=%d om_tree_oid=%d' % (nx_omap_oid, om_tree))

# OMAP tree root is physical block
omap_root = rd(om_tree)
assert checksum_ok(omap_root)
# collect OMAP entries: {oid,xid}->paddr
# root: fixed-KV, level, nkeys
flags = struct.unpack('<H', omap_root[0x20:0x22])[0]
level = struct.unpack('<H', omap_root[0x22:0x24])[0]
nkeys = struct.unpack('<I', omap_root[0x24:0x28])[0]
table_off = struct.unpack('<H', omap_root[0x28:0x2A])[0]
table_len = struct.unpack('<H', omap_root[0x2A:0x2C])[0]
print('omap root: flags=%x level=%d nkeys=%d table=%d+%d' % (flags, level, nkeys, table_off, table_len))

omap_entries = []
def walk_omap(blk_idx, is_root):
    blk = rd(blk_idx)
    assert checksum_ok(blk), 'checksum fail at %d' % blk_idx
    fl = struct.unpack('<H', blk[0x20:0x22])[0]
    lv = struct.unpack('<H', blk[0x22:0x24])[0]
    nk = struct.unpack('<I', blk[0x24:0x28])[0]
    to = struct.unpack('<H', blk[0x28:0x2A])[0]
    tl = struct.unpack('<H', blk[0x2A:0x2C])[0]
    key_base = 0x38 + to + tl
    val_base = (BLOCK - 0x28) if is_root else BLOCK
    for i in range(nk):
        toc = 0x38 + to + i * 4
        ko = struct.unpack('<H', blk[toc:toc+2])[0]
        vo = struct.unpack('<H', blk[toc+2:toc+4])[0]
        kp = key_base + ko
        vp = val_base - vo
        if lv > 0:
            child = struct.unpack('<Q', blk[vp:vp+8])[0]
            walk_omap(child, False)
        else:
            oid = struct.unpack('<Q', blk[kp:kp+8])[0]
            xid = struct.unpack('<Q', blk[kp+8:kp+16])[0]
            paddr = struct.unpack('<Q', blk[vp+8:vp+16])[0]
            omap_entries.append((oid, xid, paddr))

walk_omap(om_tree, True)
print('OMAP entries:', len(omap_entries))

# resolve APSB (fs_oid=1026)
best = None
for oid, xid, paddr in omap_entries:
    if oid == nx_fs_oid and xid <= nx_xid:
        if best is None or xid > best[1]:
            best = (oid, xid, paddr)
print('APSB: oid=%d xid=%d paddr=%d' % best)

apsb = rd(best[2])
assert apsb[0x20:0x24] == b'APSB'
vol_omap_oid = struct.unpack('<Q', apsb[0x80:0x88])[0]
root_tree_oid = struct.unpack('<Q', apsb[0x88:0x90])[0]
vol_xid = struct.unpack('<Q', apsb[0x10:0x18])[0]
print('APSB: vol_omap=%d root_tree_oid=%d vol_xid=%d' % (vol_omap_oid, root_tree_oid, vol_xid))

# volume omap
vol_om = rd(vol_omap_oid)
assert checksum_ok(vol_om)
vol_om_tree = struct.unpack('<Q', vol_om[0x30:0x38])[0]
print('vol omap_phys=%d tree=%d' % (vol_omap_oid, vol_om_tree))

# walk volume omap
vol_entries = []
def walk_vomap(blk_idx, is_root):
    blk = rd(blk_idx)
    assert checksum_ok(blk), 'vol omap checksum fail'
    fl = struct.unpack('<H', blk[0x20:0x22])[0]
    lv = struct.unpack('<H', blk[0x22:0x24])[0]
    nk = struct.unpack('<I', blk[0x24:0x28])[0]
    to = struct.unpack('<H', blk[0x28:0x2A])[0]
    tl = struct.unpack('<H', blk[0x2A:0x2C])[0]
    key_base = 0x38 + to + tl
    val_base = (BLOCK - 0x28) if is_root else BLOCK
    for i in range(nk):
        toc = 0x38 + to + i * 4
        ko = struct.unpack('<H', blk[toc:toc+2])[0]
        vo = struct.unpack('<H', blk[toc+2:toc+4])[0]
        kp = key_base + ko
        vp = val_base - vo
        if lv > 0:
            child = struct.unpack('<Q', blk[vp:vp+8])[0]
            walk_vomap(child, False)
        else:
            oid = struct.unpack('<Q', blk[kp:kp+8])[0]
            xid = struct.unpack('<Q', blk[kp+8:kp+16])[0]
            paddr = struct.unpack('<Q', blk[vp+8:vp+16])[0]
            vol_entries.append((oid, xid, paddr))

walk_vomap(vol_om_tree, True)
print('vol OMAP entries:', len(vol_entries))

def resolve_vol(oid):
    b = None
    for o, x, p in vol_entries:
        if o == oid and x <= vol_xid:
            if b is None or x > b[1]:
                b = (o, x, p)
    return b[2] if b else None

# FSTREE: variable-KV. enumerate all records
root_block = resolve_vol(root_tree_oid)
print('FSTREE root block:', root_block)

records = []
def walk_fstree(blk_idx, is_root):
    blk = rd(blk_idx)
    if not checksum_ok(blk):
        print('FSTREE checksum fail at', blk_idx)
        return
    fl = struct.unpack('<H', blk[0x20:0x22])[0]
    lv = struct.unpack('<H', blk[0x22:0x24])[0]
    nk = struct.unpack('<I', blk[0x24:0x28])[0]
    to = struct.unpack('<H', blk[0x28:0x2A])[0]
    tl = struct.unpack('<H', blk[0x2A:0x2C])[0]
    fixed_kv = (fl & 0x04) != 0
    entry_size = 4 if fixed_kv else 8
    key_base = 0x38 + to + tl
    val_base = (BLOCK - 0x28) if is_root else BLOCK

    for i in range(nk):
        toc = 0x38 + to + i * entry_size
        if fixed_kv:
            ko = struct.unpack('<H', blk[toc:toc+2])[0]
            vo = struct.unpack('<H', blk[toc+2:toc+4])[0]
            kp = key_base + ko
            vp = val_base - vo
        else:
            ko, kl, vo, vl = struct.unpack('<HHHH', blk[toc:toc+8])
            kp = key_base + ko
            vp = val_base - vo

        if lv > 0:
            child = struct.unpack('<Q', blk[vp:vp+8])[0]
            cb = resolve_vol(child)
            if cb:
                walk_fstree(cb, False)
        else:
            oid_type = struct.unpack('<Q', blk[kp:kp+8])[0]
            records.append((oid_type, blk[kp:kp+8+kl] if not fixed_kv else b'', kp, vp, blk))

# We need kl for leaf keys; variable-KV gives us kl in TOC. Walk with it.
records2 = []
def walk_leaf_records(blk_idx, is_root):
    blk = rd(blk_idx)
    if not checksum_ok(blk):
        return
    fl = struct.unpack('<H', blk[0x20:0x22])[0]
    lv = struct.unpack('<H', blk[0x22:0x24])[0]
    nk = struct.unpack('<I', blk[0x24:0x28])[0]
    to = struct.unpack('<H', blk[0x28:0x2A])[0]
    tl = struct.unpack('<H', blk[0x2A:0x2C])[0]
    fixed_kv = (fl & 0x04) != 0
    entry_size = 4 if fixed_kv else 8
    key_base = 0x38 + to + tl
    val_base = (BLOCK - 0x28) if is_root else BLOCK

    for i in range(nk):
        toc = 0x38 + to + i * entry_size
        if fixed_kv:
            ko = struct.unpack('<H', blk[toc:toc+2])[0]
            vo = struct.unpack('<H', blk[toc+2:toc+4])[0]
            kl = 0; vl = 0
        else:
            ko, kl, vo, vl = struct.unpack('<HHHH', blk[toc:toc+8])
        kp = key_base + ko
        vp = val_base - vo

        if lv > 0:
            child = struct.unpack('<Q', blk[vp:vp+8])[0]
            cb = resolve_vol(child)
            if cb:
                walk_leaf_records(cb, False)
        else:
            oid_type = struct.unpack('<Q', blk[kp:kp+8])[0]
            rec_type = oid_type >> 60
            oid = oid_type & 0x0FFFFFFFFFFFFFFF
            if rec_type == 9:  # DIR_REC (hashed names: incompat & 0x8)
                len_hash = struct.unpack('<I', blk[kp+8:kp+12])[0]
                stored_len = len_hash & 0x3FF
                if stored_len < 1 or stored_len > 1023:
                    continue
                raw = blk[kp+12:kp+12+stored_len]
                if raw and raw[-1] == 0:
                    name = raw[:-1].decode('utf-8', errors='replace')
                else:
                    name = raw.decode('utf-8', errors='replace')
                if not name or any(ord(c) < 32 or ord(c) > 126 for c in name):
                    continue
                file_id = struct.unpack('<Q', blk[vp:vp+8])[0]
                records2.append({
                    'parent_cnid': oid,
                    'name': name,
                    'child_cnid': file_id,
                })

walk_leaf_records(root_block, True)
print('DIR_REC records:', len(records2))

# Build CNID -> name map for path resolution
cnid_name = {r['child_cnid']: r['name'] for r in records2}
parent_map = {r['child_cnid']: r['parent_cnid'] for r in records2}

def full_path(cnid):
    parts = []
    cur = cnid
    while cur and cur != 2:
        if cur in cnid_name:
            parts.append(cnid_name[cur])
            cur = parent_map.get(cur, 2)
        else:
            parts.append('?%d' % cur)
            break
    return '/' + '/'.join(reversed(parts))

entries = []
for r in records2:
    entries.append({
        'path': full_path(r['child_cnid']),
        'name': r['name'],
        'cnid': r['child_cnid'],
        'parent_cnid': r['parent_cnid'],
    })

sha = hashlib.sha256(open(IMG,'rb').read()).hexdigest()
out = {
    'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
    'iteration': '57ZY',
    'date': '2026-10-02',
    'ramdisk_sha256': sha,
    'total_dir_records': len(entries),
    'method': 'authoritative NXSB->OMAP->APSB->volume OMAP->FSTREE DIR_REC enumeration',
    'entries': sorted(entries, key=lambda e: e['path']),
}
json.dump(out, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
print('WROTE', OUT)
# print executables and interesting files
for e in out['entries']:
    p = e['path']
    if any(k in p for k in ('apfs','asr','restore','disk','container','mount','fsck','newfs','crypto','keybag','seal')):
        print(' ', p)
