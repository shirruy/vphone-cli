"""57ZZ Part 3: APFS volume function call-site inventory.

Resolves auth_stub -> GOT -> imported symbol chain for APFS volume
functions and finds every BL call site in restored_external.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys

DUMPDIR = os.path.join(os.environ['TEMP'], '57zz-binaries')
OUT = 'artifacts/evidence/05f/phase05f-data-lifecycle-callsite-inventory.json'

def analyze(name):
    data = open(os.path.join(DUMPDIR, name + '.bin'), 'rb').read()
    if data[:4] != b'\xcf\xfa\xed\xfe':
        return {'error': 'not MH_MAGIC_64'}

    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    sections = []
    symtab = None
    dysymtab = None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x2:
            symtab = struct.unpack_from('<4I', data, off+8)
        elif cmd == 0xB:
            dysymtab = struct.unpack_from('<18I', data, off+8)
        elif cmd == 0x19:
            segname = data[off+8:off+24].split(b'\x00')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+24)
            nsects = struct.unpack_from('<I', data, off+64)[0]
            so = off + 72
            for i in range(nsects):
                sn = data[so:so+16].split(b'\x00')[0].decode('ascii',errors='replace')
                sgn = data[so+16:so+32].split(b'\x00')[0].decode('ascii',errors='replace')
                addr, size = struct.unpack_from('<QQ', data, so+32)
                sect_fo = struct.unpack_from('<I', data, so+48)[0]
                sections.append((sn, sgn, addr, size, sect_fo))
                so += 80
        off += cmdsize

    if not symtab or not dysymtab:
        return {'error': 'no symtab/dysymtab'}

    symoff, nsyms, stroff, strsize = symtab
    indirectsymoff, nindirectsyms = dysymtab[12], dysymtab[13]

    # find __auth_stubs and __auth_got
    auth_stubs = next((s for s in sections if s[0] == '__auth_stubs'), None)
    auth_got = next((s for s in sections if s[0] == '__auth_got'), None)
    if not auth_stubs or not auth_got:
        return {'error': 'no auth stubs/got', 'sections': [(s[0],s[2],s[3]) for s in sections]}

    # find __TEXT
    text_seg = next((s for s in sections if s[0] == '__text'), None)
    if not text_seg:
        return {'error': 'no __text section'}

    # Build symbol name -> index map for APFS volume functions
    target_names = set()
    for i in range(nsyms):
        e = symoff + i * 16
        n_strx = struct.unpack_from('<I', data, e)[0]
        if stroff + n_strx < len(data):
            end = data.find(b'\x00', stroff + n_strx)
            nm = data[stroff+n_strx:end].decode('ascii',errors='replace')
            if 'APFSVolume' in nm and nm.startswith('_'):
                target_names.add(nm)
    if not target_names:
        return {'error': 'no APFSVolume symbols'}

    target_indices = {}
    for i in range(nsyms):
        e = symoff + i * 16
        n_strx = struct.unpack_from('<I', data, e)[0]
        if stroff + n_strx < len(data):
            end = data.find(b'\x00', stroff + n_strx)
            nm = data[stroff+n_strx:end].decode('ascii',errors='replace')
            if nm in target_names:
                target_indices[i] = nm

    # Map GOT entries to symbols via indirect symtab
    got_base = auth_got[2]
    n_got = auth_got[3] // 8
    got_map = {}
    for gi in range(min(n_got, nindirectsyms)):
        isym = struct.unpack_from('<I', data, indirectsymoff + gi*4)[0] & 0x00FFFFFF
        if isym in target_indices:
            got_addr = got_base + gi * 8
            got_map[got_addr] = target_indices[isym]

    # Scan auth stubs for GOT references
    stub_page = got_base & 0xFFFFFFFFFFFFF000
    stub_map = {}
    n_stubs = auth_stubs[3] // 16
    for i in range(n_stubs):
        soff = auth_stubs[4] + i * 16
        if soff + 16 > len(data):
            break
        add = struct.unpack_from('<I', data, soff + 4)[0]
        if (add & 0xFF800000) != 0x91000000:
            continue
        add_imm = (add >> 10) & 0xFFF
        got_addr = stub_page + add_imm
        if got_addr in got_map:
            stub_map[auth_stubs[2] + i * 16] = (got_addr, got_map[got_addr])

    # Scan __text for BL calls to stub targets
    text_vm = text_seg[2]
    text_off = text_seg[4]
    text_size = text_seg[3]
    callers = []
    for off in range(0, text_size, 4):
        insn = struct.unpack_from('<I', data, text_off + off)[0]
        if (insn & 0xFC000000) == 0x94000000:
            imm = insn & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= (1 << 26)
            vm = text_vm + off
            dst = vm + imm * 4
            if dst in stub_map:
                callers.append({'vm': '0x%x' % vm, 'stub': '0x%x' % dst,
                               'got': '0x%x' % stub_map[dst][0],
                               'symbol': stub_map[dst][1]})

    return {
        'binary': name,
        'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'text_vm': '0x%x' % text_vm,
        'text_size': text_size,
        'target_symbols': sorted(target_names),
        'got_entries': {('0x%x' % k): v for k, v in got_map.items()},
        'stubs': {('0x%x' % k): {'got': '0x%x' % v[0], 'symbol': v[1]} for k, v in stub_map.items()},
        'callers': callers,
        'caller_count': len(callers),
    }

def main():
    results = {}
    for name in ['restored_external', 'asr']:
        r = analyze(name)
        results[name] = r
        print('=== %s ===' % name)
        if 'error' in r:
            print('  ERROR:', r['error'])
        else:
            print('  targets: %s' % ', '.join(r['target_symbols']))
            print('  callers: %d' % r['caller_count'])
            for c in r['callers'][:10]:
                print('    %s -> %s (%s)' % (c['vm'], c['symbol'], c['stub']))
            if r['caller_count'] > 10:
                print('    ... and %d more' % (r['caller_count'] - 10))
        print()

    out = {
        'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
        'iteration': '57ZZ_PART3',
        'date': '2026-10-02',
        'DATA_ADD_VOLUME_CALLSITE_INVENTORY_PASS': results.get('restored_external',{}).get('caller_count',0) > 0,
        'binaries': results,
    }
    json.dump(out, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('WROTE', OUT)
    rc = results.get('restored_external',{}).get('caller_count',0)
    print('CALLSITE_INVENTORY_%s' % ('PASS' if rc > 0 else 'FAIL'))
    return 0

if __name__ == '__main__':
    sys.exit(main())
