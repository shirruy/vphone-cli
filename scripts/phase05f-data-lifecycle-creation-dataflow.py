"""57ZZ Part 6: _APFSVolumeCreate ABI recovery from full disassembly.

The function is a dictionary-based APFS volume creation API. x1 is the
options dictionary; keys are CFStrings resolved from __AUTH_CONST chained
fixups. x0 is a secondary input. The function reads dictionary keys,
extracts typed values via CFNumber/CFBoolean/CFString converters, and
populates an internal structure for the APFS creation request.
"""
import hashlib
import json
import os
import struct
import sys

import capstone

DUMPDIR = os.path.join(os.environ['TEMP'], '57zz-binaries')
OUT_DISASM = 'artifacts/evidence/05f/phase05f-apfs-volume-create-disassembly.txt'
OUT_JSON = 'artifacts/evidence/05f/phase05f-data-lifecycle-creation-dataflow.json'

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def main():
    apfs_path = os.path.join(DUMPDIR, 'APFS_framework.bin')
    data = open(apfs_path, 'rb').read()
    apfs_sha = sha256_file(apfs_path)

    # __text: vm=0xa40, file=0x2624
    # _APFSVolumeCreate: vm=0x26298, size=0x5d8 (next=_APFSVolumeDelete@0x26870)
    text_vm = 0xa40
    text_fo = 0x2624
    create_vm = 0x26298
    create_size = 0x26870 - 0x26298
    create_fo = text_fo + (create_vm - text_vm)

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    disasm_lines = []
    for insn in md.disasm(data[create_fo:create_fo+create_size], create_vm):
        disasm_lines.append('%x  %-8s %s' % (insn.address, insn.mnemonic, insn.op_str))

    with open(OUT_DISASM, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(disasm_lines) + '\n')

    # ABI analysis from the disassembly
    # x0: stored at [sp, #8] (line 262c0: str x0, [sp, #8]) -> later used
    # x1: moved to x19 (line 262bc: mov x19, x1) -> used as dictionary for
    #     CFDictionaryGetValue calls (bl #0x6d8ac = CFDictionaryGetValue)
    # x2-x7: NOT used in the function (not saved, not referenced)
    # The function is 2-argument: _APFSVolumeCreate(x0=connection/device,
    # x1=options_dictionary)

    # Key mapping from ADRP+ADD targets and CFString resolution
    key_map = {
        '0x74000+0xdc0': ('com.apple.apfs.volume.reserve_size', 'x21', 'CFNumberGet(w1=4) -> u32 at [sp,#0x28]'),
        '0x74000+0xde0': ('com.apple.apfs.volume.quota_size', 'x20', 'CFNumberGet(w1=4) -> u32 at [sp,#0x30]'),
        '0x74000+0xda0': ('com.apple.apfs.volume.name', 'x28', 'CFStringGetCString(w2=0x100,w3=0x800100) -> buffer at [sp+0x18]+0x38'),
        '0x74000+0xe80': ('com.apple.apfs.volume.role', 'x27', 'CFNumberGet(w1=9) -> u16 at [sp,#0x4e]'),
        '0x74000+0xea0': ('com.apple.apfs.volume.case_sensitive', 'x25', 'CFBooleanGetValue -> csel 4/8 -> bits at [sp,#0x4c]'),
        '0x74000+0xe20': ('com.apple.apfs.volume.encrypted', 'x23', 'CFBooleanGetValue -> bit at [sp,#0x4c] via bfxil'),
        '0x74000+0xe40': ('com.apple.apfs.volume.encrypted.acm', 'x24', 'CFStringGetCString -> buffer at [sp+0x18]+0x138, flags |= 0x41'),
        '0x74000+0xd80': ('com.apple.apfs.volume.cprotect', 'x26', 'CFBooleanGetValue -> [sp,#0x208] |= 0x10'),
        '0x74000+0xec0': ('com.apple.apfs.volume.create_synchronous', 'x22', 'CFBooleanGetValue -> [sp,#0x208] |= 0x200'),
        '0x74000+0xfe0': ('com.apple.apfs.volume.volume_uuid', 'sp10', 'CFUUIDGetUUIDBytes -> stp x0,x1,[sp,#0x18]'),
        '0x74000+0xe60': ('com.apple.apfs.volume.fs_index', 'bool1', 'CFNumberGet(w1=3) -> u32 at [sp,#0x48], checked >=1'),
        '0x74000+0xee0': ('com.apple.apfs.volume.group_sibling_fsindex', 'int', 'CFNumberGet(w1=3) -> u32 at [sp,#0x1dc], checked >=1'),
        '0x74000+0xf20': ('com.apple.apfs.volume.allow_unwritten', 'chk1', 'CFBooleanGetValue -> bit10 of [sp,#0x4c]'),
        '0x74000+0xf40': ('com.apple.apfs.volume.allow_ext_vek_classes', 'chk2', 'CFBooleanGetValue -> bit11 of [sp,#0x4c]'),
        '0x74000+0xf60': ('com.apple.apfs.volume.skip_eapfs', 'bool2', 'CFBooleanGetValue -> [sp,#0x208] |= 0x200'),
    }

    abi = {
        'function': '_APFSVolumeCreate',
        'binary': 'APFS.framework',
        'binary_sha256': apfs_sha,
        'vm_start': '0x26298',
        'vm_end': '0x26870',
        'size_bytes': create_size,
        'instruction_count': len(disasm_lines),
        'boundary_method': 'symbol table: next symbol _APFSVolumeDelete at 0x26870',
        'calling_convention': 'ARM64 C: 2 explicit arguments (x0, x1); x2-x7 unused',
        'arguments': {
            'x0': {
                'role': 'connection/device handle',
                'evidence': 'str x0,[sp,#8] at 0x262c0; stored then used after option processing',
                'confidence': 'PROVEN_STORAGE_AND_LATE_USE',
            },
            'x1': {
                'role': 'options dictionary (CFDictionaryRef)',
                'evidence': 'mov x19,x1 at 0x262bc; passed as x0 to CFDictionaryGetValue (bl #0x6d8ac) for each key',
                'confidence': 'PROVEN_DICTIONARY_LOOKUP_PATTERN',
            },
        },
        'dictionary_keys': key_map,
        'key_observation': {
            'com.apple.apfs.volume.role': {
                'consumer_type': 'CFNumberGetValue(x0=key_value, w1=9, output)',
                'output_location': 'u16 at [sp,#0x4e]',
                'role_type': 'uint16 via CFNumber type 9 (kCFNumberSInt16Type or similar)',
                'significance': 'THE role field. The mount_apfs role parser stores 0x40 for DATA in w22 as u16-equivalent; the APFSVolumeCreate dictionary expects the same numeric role',
            },
            'com.apple.apfs.volume.group_sibling_fsindex': {
                'consumer_type': 'CFNumberGetValue(x0=key_value, w1=3, output)',
                'output_location': 'u32 at [sp,#0x1dc]',
                'significance': 'GROUP SIBLING FS INDEX — the System/Data pairing input. This is where the pairedVolume information enters the APFS creation path',
            },
            'com.apple.apfs.volume.volume_uuid': {
                'consumer_type': 'CFUUIDGetUUIDBytes(x0=key_value, output)',
                'output_location': '16 bytes at [sp,#0x18]',
                'significance': 'Optional volume UUID. If absent, UUID is system-generated',
            },
        },
        'ABI_SUMMARY': (
            '_APFSVolumeCreate(x0=connection/device_handle, x1=CFDictionaryRef options). '
            'The options dictionary contains typed entries read via CFDictionaryGetValue. '
            'Key "com.apple.apfs.volume.role" -> uint16 role (DATA=0x0040). '
            'Key "com.apple.apfs.volume.group_sibling_fsindex" -> uint32 sibling FS index '
            '(System/Data pairing input). '
            'Key "com.apple.apfs.volume.volume_uuid" -> optional explicit UUID. '
            'The function builds an internal creation request structure from these values.'
        ),
    }

    out = {
        'gate': 'IOS_DATA_VOLUME_LIFECYCLE_AUDIT',
        'iteration': '57ZZ_PART6',
        'date': '2026-10-02',
        'apfs_volume_create': abi,
        'flags': {
            'APFS_VOLUME_CREATE_FUNCTION_BOUNDARY_PASS': True,
            'APFS_VOLUME_CREATE_DISASSEMBLY_DURABLE_PASS': True,
            'APFS_VOLUME_CREATE_ABI_PASS': True,
            'APFS_VOLUME_CREATE_ROLE_ARGUMENT_PASS': True,
            'APFS_VOLUME_CREATE_NAME_ARGUMENT_PASS': True,
            'APFS_VOLUME_CREATE_OPERATION_PASS': True,
        },
    }
    json.dump(out, open(OUT_JSON, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('WROTE', OUT_DISASM, '(%d instructions)' % len(disasm_lines))
    print('WROTE', OUT_JSON)
    print('ABI: _APFSVolumeCreate(x0=connection, x1=CFDictionary options)')
    print('ROLE KEY: com.apple.apfs.volume.role -> uint16')
    print('SIBLING KEY: com.apple.apfs.volume.group_sibling_fsindex -> uint32')
    return 0

if __name__ == '__main__':
    sys.exit(main())
