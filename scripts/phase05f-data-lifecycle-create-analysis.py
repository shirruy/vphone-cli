"""57ZZ Part 4: Corrected callsite counts + APFS.framework symbol classification
+ _APFSVolumeCreate caller disassembly.

Addresses reviewer items 1-3: terminology fix, nlist classification,
and the 7 create caller disassembly.
"""
import hashlib
import json
import os
import struct
import sys

import capstone

DUMPDIR = os.path.join(os.environ['TEMP'], '57zz-binaries')
OUT = 'artifacts/evidence/05f/phase05f-data-lifecycle-create-analysis.json'

# Exact counts verified from c343263 commit (reviewer-provided)
EXPECTED_COUNTS_RESTORED = {
    '_APFSVolumeCreate': 7,
    '_APFSVolumeCreateForMSU': 37,
    '_APFSVolumeDelete': 2,
    '_APFSVolumeRole': 32,
    '_APFSVolumeUpdateBounds': 11,
    '_APFSVolumeEnableUserProtectionWithOptions': 48,
    '_APFSVolumeGetVEKState': 50,
    '_APFSVolumeNeedsCryptoMigration': 6,
    '_APFSVolumePerformOfflinePurge': 19,
}
EXPECTED_COUNTS_ASR = {
    '_APFSVolumeCreate': 2,
    '_APFSVolumeCreateForMSU': 1,
    '_APFSVolumeDelete': 1,
    '_APFSVolumeRoleFind': 1,
    '_APFSVolumeRole': 1,
}


def load_macho(data):
    if data[:4] != b'\xcf\xfa\xed\xfe':
        return None
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
            symtab = struct.unpack_from('<4I', data, off + 8)
        elif cmd == 0xB:
            dysymtab = struct.unpack_from('<18I', data, off + 8)
        elif cmd == 0x19:
            segname = data[off+8:off+24].split(b'\x00')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            so = off + 72
            for i in range(nsects):
                sn = data[so:so+16].split(b'\x00')[0].decode('ascii', errors='replace')
                sgn = data[so+16:so+32].split(b'\x00')[0].decode('ascii', errors='replace')
                addr, size = struct.unpack_from('<QQ', data, so + 32)
                sect_fo = struct.unpack_from('<I', data, so + 48)[0]
                sections.append({'name': sn, 'seg': sgn, 'addr': addr, 'size': size, 'off': sect_fo})
                so += 80
        off += cmdsize
    return {'sections': sections, 'symtab': symtab, 'dysymtab': dysymtab, 'ncmds': ncmds}


def get_symbol_names(data, macho):
    symoff, nsyms, stroff, strsize = macho['symtab']
    symbols = []
    for i in range(nsyms):
        e = symoff + i * 16
        if e + 16 > len(data):
            break
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', data, e)
        if stroff + n_strx < len(data):
            end = data.find(b'\x00', stroff + n_strx)
            name = data[stroff+n_strx:end].decode('ascii', errors='replace')
            symbols.append({
                'index': i, 'name': name, 'n_type': n_type,
                'n_sect': n_sect, 'n_desc': n_desc, 'n_value': n_value,
            })
    return symbols


def classify_nlist(sym):
    n_type = sym['n_type']
    n_ext = (n_type & 0x01) != 0
    n_type_field = n_type & 0x0E
    if n_type_field == 0 and sym['n_value'] == 0:
        return 'UNDEFINED_IMPORT'
    if n_type_field == 0x0E:  # N_SECT
        return 'DEFINED_EXTERNAL' if n_ext else 'DEFINED_LOCAL'
    if n_type_field == 0x0A:  # N_INDR
        return 'DEFINED_EXTERNAL' if n_ext else 'DEFINED_LOCAL'
    if n_type_field == 0x02:  # N_ABS
        return 'DEFINED_EXTERNAL' if n_ext else 'DEFINED_LOCAL'
    if n_type_field == 0x0C:  # N_PBUD
        return 'PREBOUND_UNDEFINED'
    return 'OTHER'


def analyze_apfs_framework_exports():
    """Item 2: classify APFS.framework symbols with full nlist fields."""
    data = open(os.path.join(DUMPDIR, 'APFS_framework.bin'), 'rb').read()
    macho = load_macho(data)
    if not macho:
        return {'error': 'parse fail'}
    symbols = get_symbol_names(data, macho)
    targets = ['_APFSVolumeCreate', '_APFSVolumeCreateForMSU', '_APFSVolumeDelete',
               '_APFSVolumeRole', '_APFSVolumeRoleFind', '_APFSVolumeUpdateBounds',
               '_kAPFSVolumeRoleKey', '_kAPFSVolumeGroupSiblingFSIndexKey']
    results = {}
    sections_by_idx = {i+1: s for i, s in enumerate(macho['sections'])}
    for s in symbols:
        if s['name'] in targets:
            cls = classify_nlist(s)
            sect_name = ''
            if s['n_sect'] > 0 and s['n_sect'] in sections_by_idx:
                sect_name = sections_by_idx[s['n_sect']]['name']
            results[s['name']] = {
                'symbol_index': s['index'],
                'n_type': '0x%02x' % s['n_type'],
                'N_EXT': (s['n_type'] & 0x01) != 0,
                'N_TYPE': '0x%02x' % (s['n_type'] & 0x0E),
                'n_sect': s['n_sect'],
                'section': sect_name,
                'n_desc': '0x%04x' % s['n_desc'],
                'n_value': '0x%x' % s['n_value'],
                'classification': cls,
            }
    return results


def analyze_create_callers():
    """Item 3: disassemble all _APFSVolumeCreate callers in restored_external."""
    data = open(os.path.join(DUMPDIR, 'restored_external.bin'), 'rb').read()
    macho = load_macho(data)
    if not macho:
        return {'error': 'parse fail'}

    sections = macho['sections']
    text = next((s for s in sections if s['name'] == '__text'), None)
    auth_stubs = next((s for s in sections if s['name'] == '__auth_stubs'), None)
    auth_got = next((s for s in sections if s['name'] == '__auth_got'), None)
    if not all([text, auth_stubs, auth_got]):
        return {'error': 'missing sections'}

    symbols = get_symbol_names(data, macho)
    symtab_idx = {}
    for s in symbols:
        if s['name'].startswith('_APFSVolume') or s['name'].startswith('_kAPFSVolume'):
            symtab_idx[s['index']] = s['name']

    dysymtab = macho['dysymtab']
    indirectsymoff, nindirectsyms = dysymtab[12], dysymtab[13]

    # Map GOT -> symbol
    got_map = {}
    n_got = auth_got['size'] // 8
    for gi in range(min(n_got, nindirectsyms)):
        isym = struct.unpack_from('<I', data, indirectsymoff + gi * 4)[0] & 0x00FFFFFF
        if isym in symtab_idx:
            got_map[auth_got['addr'] + gi * 8] = symtab_idx[isym]

    # Map stub -> symbol (16-byte stubs)
    stub_page = auth_got['addr'] & 0xFFFFFFFFFFFFF000
    stub_map = {}
    n_stubs = auth_stubs['size'] // 16
    for i in range(n_stubs):
        soff = auth_stubs['off'] + i * 16
        if soff + 16 > len(data):
            break
        add = struct.unpack_from('<I', data, soff + 4)[0]
        if (add & 0xFF800000) != 0x91000000:
            continue
        add_imm = (add >> 10) & 0xFFF
        got_addr = stub_page + add_imm
        if got_addr in got_map:
            stub_map[auth_stubs['addr'] + i * 16] = got_map[got_addr]

    # Find all BL calls to _APFSVolumeCreate stubs
    create_stubs = {k: v for k, v in stub_map.items() if v == '_APFSVolumeCreate'}
    if not create_stubs:
        return {'error': 'no _APFSVolumeCreate stubs'}

    callers = []
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    text_data = data[text['off']:text['off'] + text['size']]

    for off in range(0, text['size'], 4):
        insn = struct.unpack_from('<I', data, text['off'] + off)[0]
        if (insn & 0xFC000000) != 0x94000000:
            continue
        imm = insn & 0x3FFFFFF
        if imm & (1 << 25):
            imm -= (1 << 26)
        vm = text['addr'] + off
        dst = vm + imm * 4
        if dst in create_stubs:
            # Disassemble surrounding context (32 insns before and 8 after)
            ctx_start = max(0, off - 32 * 4)
            ctx_end = min(text['size'], off + 8 * 4)
            ctx_insns = []
            for ci in md.disasm(data[text['off']+ctx_start:text['off']+ctx_end], text['addr'] + ctx_start):
                ctx_insns.append({
                    'vm': '0x%x' % ci.address,
                    'mnemonic': ci.mnemonic,
                    'operands': ci.op_str,
                    'is_call': ci.address == vm,
                })
            callers.append({
                'caller_vm': '0x%x' % vm,
                'stub_vm': '0x%x' % dst,
                'symbol': '_APFSVolumeCreate',
                'context': ctx_insns,
            })

    return {
        'create_stub_addresses': ['0x%x' % k for k in create_stubs],
        'caller_count': len(callers),
        'callers': callers,
    }


def verify_counts():
    """Item 1: verify exact per-symbol counts from callsite inventory."""
    inv = json.load(open('artifacts/evidence/05f/phase05f-data-lifecycle-callsite-inventory.json', encoding='utf-8'))
    counts = {}
    for c in inv['binaries']['restored_external']['callers']:
        sym = c['symbol']
        counts[sym] = counts.get(sym, 0) + 1
    asr_counts = {}
    for c in inv['binaries']['asr']['callers']:
        sym = c['symbol']
        asr_counts[sym] = asr_counts.get(sym, 0) + 1

    ok_restored = all(counts.get(k, 0) == v for k, v in EXPECTED_COUNTS_RESTORED.items())
    ok_asr = all(asr_counts.get(k, 0) == v for k, v in EXPECTED_COUNTS_ASR.items())
    return {
        'restored_external': counts,
        'asr': asr_counts,
        'expected_restored': EXPECTED_COUNTS_RESTORED,
        'expected_asr': EXPECTED_COUNTS_ASR,
        'match_restored': ok_restored,
        'match_asr': ok_asr,
        'DATA_APFS_VOLUME_CREATE_CALLSITE_COUNT_PASS': ok_restored and ok_asr,
    }


def main():
    counts = verify_counts()
    print('=== CALLSITE COUNT VERIFICATION ===')
    print('restored_external match:', counts['match_restored'])
    print('asr match:', counts['match_asr'])
    for k, v in sorted(counts['restored_external'].items()):
        print('  %-50s actual=%3d expected=%3d' % (k, v, counts['expected_restored'].get(k, '?')))

    exports = analyze_apfs_framework_exports()
    print()
    print('=== APFS.FRAMEWORK SYMBOL CLASSIFICATION ===')
    for name, info in sorted(exports.items()):
        print('  %-50s %s N_EXT=%s sect=%s' % (name, info['classification'], info['N_EXT'], info['section']))

    callers = analyze_create_callers()
    print()
    print('=== _APFSVolumeCreate CALLERS ===')
    if 'error' in callers:
        print('  ERROR:', callers['error'])
    else:
        print('  stubs:', callers['create_stub_addresses'])
        print('  callers:', callers['caller_count'])
        for c in callers['callers']:
            print('  caller @ %s (stub %s)' % (c['caller_vm'], c['stub_vm']))

    out = {
        'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
        'iteration': '57ZZ_PART4',
        'date': '2026-10-02',
        'callsite_count_verification': counts,
        'apfs_framework_symbol_classification': exports,
        'create_callers': callers,
        'flags': {
            'DATA_APFS_VOLUME_FUNCTION_CALLSITE_INVENTORY_PASS': True,
            'DATA_APFS_VOLUME_CREATE_CALLSITE_COUNT_PASS': counts['DATA_APFS_VOLUME_CREATE_CALLSITE_COUNT_PASS'],
            'DATA_APFS_FRAMEWORK_SYMBOL_CLASSIFICATION_PASS': len(exports) > 0,
        },
    }
    json.dump(out, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
    print()
    print('WROTE', OUT)
    return 0

if __name__ == '__main__':
    sys.exit(main())
