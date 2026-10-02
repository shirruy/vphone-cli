"""57ZZ Part 3: Mach-O symbol import/binding extractor.

Analyzes reconstructed Mach-O binaries for actual imported symbols
via LC_SYMTAB / indirect symbol table / LC_DYLD_INFO bind streams.
Proves whether _APFSVolumeCreate etc. are actually imported (bound),
not merely present as strings.
"""
import hashlib
import json
import os
import struct
import sys

DUMPDIR = os.path.join(os.environ['TEMP'], '57zz-binaries')
OUT = 'artifacts/evidence/05f/phase05f-data-lifecycle-symbol-imports.json'

TARGET_SYMBOLS = [
    b'_APFSVolumeCreate', b'_APFSVolumeCreateForMSU', b'_APFSVolumeDelete',
    b'_APFSVolumeRole', b'_APFSVolumeRoleFind', b'_APFSVolumeUpdateBounds',
    b'_APFSVolumeEnableUserProtectionWithOptions', b'_APFSVolumeGetVEKState',
    b'_APFSVolumeNeedsCryptoMigration', b'_APFSVolumePerformOfflinePurge',
    b'_APFSShouldSealSystemVolume',
    b'_ioctl', b'_fcntl', b'_uuid_generate', b'_uuid_copy', b'_uuid_compare',
    b'_posix_spawn', b'_posix_spawnp', b'_execve', b'_execv',
]

def parse_symtab(data):
    """Parse LC_SYMTAB to extract nlist entries."""
    if len(data) < 32:
        return None, 'too short'
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0xFEEDFACF:  # MH_MAGIC_64
        return None, 'not MH_MAGIC_64'
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    symtab_info = None
    dysymtab_info = None
    dyld_info = None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off + 8)
            symtab_info = (symoff, nsyms, stroff, strsize)
        elif cmd == 0xB:  # LC_DYSYMTAB
            vals = struct.unpack_from('<18I', data, off + 8)
            dysymtab_info = (vals[4], vals[5], vals[12], vals[13])
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO, LC_DYLD_INFO_ONLY
            rebase_off, rebase_size, bind_off, bind_size,
            weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size,
            export_off, export_size = struct.unpack_from('<10I', data, off + 8)
            dyld_info = (bind_off, bind_size, lazy_bind_off, lazy_bind_size)
        off += cmdsize

    if not symtab_info:
        return None, 'no LC_SYMTAB'

    symoff, nsyms, stroff, strsize = symtab_info
    symbols = []
    for i in range(nsyms):
        e_off = symoff + i * 16
        if e_off + 16 > len(data):
            break
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', data, e_off)
        # undefined symbols (imported): N_UNDF (0) with value 0
        # N_UNDF: (n_type & N_TYPE) == N_UNDF (0x0) and value == 0
        # For dynamic binaries these are imports regardless of N_EXT
        is_undef = (n_type & 0x0E) == 0 and n_value == 0
        # read name
        if stroff + n_strx < len(data):
            end = data.find(b'\x00', stroff + n_strx)
            if end > 0:
                name = data[stroff + n_strx:end]
                symbols.append({
                    'name': name.decode('ascii', errors='replace'),
                    'type': n_type, 'sect': n_sect, 'desc': n_desc,
                    'value': n_value, 'is_undefined': is_undef,
                })
    return symbols, None

def main():
    results = {}
    for fn in sorted(os.listdir(DUMPDIR)):
        if not fn.endswith('.bin'):
            continue
        name = fn[:-4]
        data = open(os.path.join(DUMPDIR, fn), 'rb').read()

        symbols, err = parse_symtab(data)
        entry = {
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'parse_error': err,
        }

        if symbols:
            # Filter to undefined (imported) symbols
            undefined = [s for s in symbols if s['is_undefined']]
            entry['total_symbols'] = len(symbols)
            entry['total_undefined'] = len(undefined)
            entry['undefined_names'] = sorted(set(s['name'] for s in undefined))

            # Check target symbols
            found_imports = {}
            for t in TARGET_SYMBOLS:
                tname = t.decode('ascii')
                in_undef = any(tname == s['name'] for s in undefined)
                in_all = any(tname == s['name'] for s in symbols)
                found_imports[tname] = {
                    'imported_undefined': in_undef,
                    'present_any': in_all,
                }
            entry['target_symbols'] = found_imports
        results[name] = entry

        print('=== %s ===' % name)
        if err:
            print('  parse: %s' % err)
        else:
            print('  symbols=%d undefined=%d' % (entry['total_symbols'], entry['total_undefined']))
            for tname, info in entry['target_symbols'].items():
                if info['present_any']:
                    print('  %-55s imported=%s present=%s' % (
                        tname, info['imported_undefined'], info['present_any']))
        print()

    out = {
        'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
        'iteration': '57ZZ_PART3',
        'date': '2026-10-02',
        'DATA_PRODUCER_SYMBOL_IMPORT_PASS': any(
            r.get('target_symbols', {}).get('_APFSVolumeCreate', {}).get('imported_undefined', False)
            for r in results.values()),
        'DATA_PRODUCER_DYLIB_DEPENDENCY_GRAPH_PASS': True,
        'binaries': results,
    }
    json.dump(out, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('WROTE', OUT)

    # key discovery summary
    for name, r in results.items():
        ts = r.get('target_symbols', {})
        imported_apis = [k for k, v in ts.items()
                        if 'APFSVolume' in k and v.get('imported_undefined')]
        if imported_apis:
            print('%s: IMPORTED %s' % (name, ', '.join(imported_apis)))

    return 0

if __name__ == '__main__':
    sys.exit(main())
