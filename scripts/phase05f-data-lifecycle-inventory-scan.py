"""Quick ramdisk binary/string inventory for 57ZY item 3.

Scans the ramdisk.dmg raw image for executable-relevant strings and
catalogs them for the producer inventory. This is a first-pass
reconnaissance; detailed FSTREE-based enumeration follows.
"""
import hashlib
import json
import re

IMG = 'C:/Users/rbjos/vphone-private/phase05f-known-good/payloads-v3/ramdisk.dmg'
OUT = 'artifacts/evidence/05f/phase05f-data-lifecycle-producer-inventory.json'

data = open(IMG, 'rb').read()
print('image size:', len(data))

# Target strings per reviewer item 3
targets = [
    b'newfs_apfs', b'fsck_apfs', b'diskmanagement', b'DiskManagement',
    b'addVolume', b'createVolume', b'volume role', b'volumeRole',
    b'volume_group', b'volumeGroup', b'volumeGroupUUID',
    b'apfs_add', b'apfsutil', b'APFSVol', b'apfs_role',
    b'restore', b'Restore', b'asr', b'mis', b'personalize',
    b'seal', b'keybag', b'AppleKeyStore', b'crypto',
    b'/System/Volumes/Data', b'/private/var',
    b'fs_role', b'fs_file', b'fs_type', b'fstab',
    b'ramdisk', b'container', b'Container',
    b'eraseVolume', b'createContainer', b'APFSContainer',
    b'IOMedia', b'IOMedia', b'DiskArbitration',
]

results = []
for needle in targets:
    hits = []
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx == -1:
            break
        # extract context
        start = max(0, idx - 40)
        end = min(len(data), idx + len(needle) + 60)
        ctx = data[start:end]
        # printable context
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
        hits.append({'offset': hex(idx), 'context': txt})
        idx += 1
        if len(hits) >= 12:
            break
    if hits:
        results.append({'needle': needle.decode('ascii', errors='replace'),
                        'hit_count': len(hits), 'samples': hits[:5]})
        print('%-25s %d hits' % (needle.decode('ascii', errors='replace'), len(hits)))

sha = hashlib.sha256(data).hexdigest()
out = {
    'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
    'iteration': '57ZY',
    'date': '2026-10-02',
    'ramdisk_sha256': sha,
    'ramdisk_size': len(data),
    'method': 'raw string scan first pass; FSTREE-based file enumeration follows',
    'findings': results,
}
json.dump(out, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
print('WROTE', OUT)
print('FIRST_PASS_TOTAL_DISTINCT_NEEDLES_WITH_HITS:', len(results))
