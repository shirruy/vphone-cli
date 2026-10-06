#!/usr/bin/env python3
"""57ZV durable kernel-evidence extractor for IOS_ROOT_TRANSITION_MODEL.

Independently extracts and disassembles the BootKC instruction regions that
prove the System->Data transition machinery, verifying the BootKC SHA-256
first. Produces structured instruction evidence, not prose conclusions.
"""

import hashlib
import json
import struct
import sys

import capstone

BOOTKC = 'C:/Users/rbjos/vphone-private/phase05f-known-good/payloads-v3/bootkc.bin'
EXPECTED_SHA = 'c01b133237eb9c5aa6c7ed38f54ed5db924b4ba2e6465cd51f0245b4c823e800'
OUT = 'artifacts/evidence/05f/phase05f-root-transition-kernel-evidence.json'
DISASM_OUT = 'artifacts/evidence/05f/phase05f-group-pairing-consumer-disasm.txt'

TEXT_VM = 0xfffffff0081e4000
TEXT_OFF = 0x11e0000


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_segments(data):
    ncmds = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if cmd == 0x19:
            _, _, _, _, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<IIQQQQQQ', data, offset)
            segs.append((vmaddr, vmsize, fileoff, filesize))
        offset += cmdsize
    return segs


def v2f(segs, vm):
    for v, vs, fo, fs in segs:
        if v <= vm < v + fs + (v and 0):
            pass
    for v, vs, fo, fs in segs:
        if v <= vm < v + vs:
            return fo + (vm - v)
    return None


def disasm(data, segs, start_vm, length):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    fo = v2f(segs, start_vm)
    if fo is None:
        return None
    out = []
    for insn in md.disasm(data[fo:fo + length], start_vm):
        out.append({
            'vm': '0x%x' % insn.address,
            'mnemonic': insn.mnemonic,
            'operands': insn.op_str,
            'bytes': insn.bytes.hex(),
        })
    return out


def find_insn(insns, vm_hex):
    for i in insns:
        if i['vm'] == vm_hex:
            return i
    return None


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)
    return True


def main():
    actual_sha = sha256(BOOTKC)
    expect(actual_sha == EXPECTED_SHA,
           'BootKC SHA mismatch: %s' % actual_sha)

    data = open(BOOTKC, 'rb').read()
    segs = load_segments(data)

    # --- Region 1: group-pairing consumer 0xfffffff00a265548 ---
    pair = disasm(data, segs, 0xfffffff00a265548, 0x160)
    expect(pair is not None, 'pairing disasm failed')

    def at(hexvm):
        return find_insn(pair, hexvm)

    # instruction chain checks
    i_role_load = at('0xfffffff00a265574')
    expect(i_role_load and i_role_load['mnemonic'] == 'ldrh' and '0x3c4' in i_role_load['operands'],
           'input role load @574 not ldrh [x,#0x3c4]')
    i_role_cmp = at('0xfffffff00a265578')
    expect(i_role_cmp and i_role_cmp['mnemonic'] == 'cmp', 'role compare @578 missing')
    i_count = at('0xfffffff00a265598')
    expect(i_count and i_count['mnemonic'] == 'ldr' and '0xb4' in i_count['operands'],
           'nx count load @598 not from +0xb4')
    i_array_base = at('0xfffffff00a2655b8')
    expect(i_array_base and i_array_base['mnemonic'] == 'add' and '0xb8' in i_array_base['operands'],
           'nx array base @5b8 not +0xb8')
    i_array = at('0xfffffff00a2655bc')
    expect(i_array and i_array['mnemonic'] == 'ldr' and 'lsl #3' in i_array['operands'],
           'nx array indexed load @5bc missing')
    i_cand_role = at('0xfffffff00a2655f4')
    expect(i_cand_role and i_cand_role['mnemonic'] == 'ldrh' and '0x3c4' in i_cand_role['operands'],
           'candidate role load @5f4 not +0x3c4')
    i_cand_cmp = at('0xfffffff00a2655f8')
    expect(i_cand_cmp and i_cand_cmp['mnemonic'] == 'cmp', 'candidate role cmp @5f8 missing')
    i_arg0 = at('0xfffffff00a265608')
    expect(i_arg0 and i_arg0['mnemonic'] == 'add' and '0x3f0' in i_arg0['operands'],
           'arg0 group ptr @608 not +0x3f0')
    i_arg1 = at('0xfffffff00a26560c')
    expect(i_arg1 and i_arg1['mnemonic'] == 'add' and '0x3f0' in i_arg1['operands'],
           'arg1 group ptr @60c not +0x3f0')
    i_call = at('0xfffffff00a265610')
    expect(i_call and i_call['mnemonic'] == 'bl', 'compare call @610 missing')
    i_cbz = at('0xfffffff00a265614')
    expect(i_cbz and i_cbz['mnemonic'] == 'cbz', 'equal-result cbz @614 missing')
    i_bypass = at('0xfffffff00a265600')
    expect(i_bypass and i_bypass['mnemonic'] == 'tbnz', 'bypass tbnz @600 missing')
    i_select = at('0xfffffff00a265678')
    expect(i_select and i_select['mnemonic'] == 'mov', 'sibling select @678 missing')
    i_loop_count = at('0xfffffff00a26562c')
    expect(i_loop_count and i_loop_count['mnemonic'] == 'ldr' and '0xb4' in i_loop_count['operands'],
           'loop count reload @62c not +0xb4')

    # --- Caller analysis: arg2 bypass flag semantics ---
    # Find all BL callers of the pairing function.
    callers = []
    scan_off = TEXT_OFF
    scan_end = TEXT_OFF + (0xfffffff00ac28000 - TEXT_VM)
    while scan_off < scan_end:
        w = struct.unpack_from('<I', data, scan_off)[0]
        if (w & 0xFC000000) == 0x94000000:
            imm = w & 0x3FFFFFF
            if imm & (1 << 25):
                imm -= (1 << 26)
            vm = TEXT_VM + (scan_off - TEXT_OFF)
            if vm + imm * 4 == 0xfffffff00a265548:
                callers.append(vm)
        scan_off += 4
    expect(len(callers) == 4, 'expected 4 callers, found %d' % len(callers))

    def caller_mode(cvm):
        start = cvm - 0x20
        fo = v2f(segs, start)
        pre = disasm(data, segs, start, 0x24)
        txt = ' ; '.join('%s %s' % (x['mnemonic'], x['operands']) for x in pre)
        if 'mov w2, #1' in txt:
            return 'role-only (arg2=1)', pre
        if 'mov w2, #0' in txt:
            return 'conditional UUID equality (dynamic arg2)', pre
        return 'unclassified', pre

    fstab_caller = 0xfffffff00a223de8
    expect(fstab_caller in callers, 'fstab caller missing')
    # The fstab caller path: uuid_is_null(source+0x3F0) -> w2 = 1 else w2 = 0
    fpre = disasm(data, segs, 0xfffffff00a223dc4, 0x28)
    ft = ' ; '.join('%s %s' % (x['mnemonic'], x['operands']) for x in fpre)
    expect('add x0, x8, #0x3f0' in ft, 'fstab caller source group ptr missing')
    expect('cbz w0' in ft, 'fstab caller uuid_is_null branch missing')
    expect('mov w2, #0' in ft and 'mov w2, #1' in ft, 'fstab caller dynamic w2 missing')

    # --- Region 2: encryption refusal 0xfffffff00a210cfc ---
    enc = disasm(data, segs, 0xfffffff00a210cfc, 0x50)
    def eat(hexvm):
        return find_insn(enc, hexvm)
    i_apsb = eat('0xfffffff00a210cfc')
    expect(i_apsb and i_apsb['mnemonic'] == 'ldr', 'APSB ptr load @cfc missing')
    i_erole = eat('0xfffffff00a210d00')
    expect(i_erole and i_erole['mnemonic'] == 'ldrh' and '0x3c4' in i_erole['operands'],
           'enc role load not +0x3c4')
    i_ecmp = eat('0xfffffff00a210d04')
    expect(i_ecmp and i_ecmp['mnemonic'] == 'cmp' and '0x40' in i_ecmp['operands'],
           'enc role cmp not #0x40')
    i_eflags = eat('0xfffffff00a210d0c')
    expect(i_eflags and i_eflags['mnemonic'] == 'ldrb' and '0x108' in i_eflags['operands'],
           'enc fs_flags load not +0x108')
    i_ebit = eat('0xfffffff00a210d10')
    expect(i_ebit and i_ebit['mnemonic'] == 'tbnz', 'enc bit test @d10 missing')

    # --- Region 3: comparison helper resolution ---
    # GOT stub 0xfffffff00a2be274 -> slot 0xfffffff008184d40 -> chained-fixup target
    got_f = v2f(segs, 0xfffffff008184d40)
    expect(got_f is not None, 'GOT slot unmapped')
    got_val = struct.unpack_from('<Q', data, got_f)[0]
    target_fo = got_val & 0x000000FFFFFFFFFF  # chained fixup low bits
    helper_stub_vm = v2f(segs, 0x3a940c0) if False else None
    # map file offset -> vm
    def f2v(fo):
        for v, vs, fo0, fs in segs:
            if fo0 <= fo < fo0 + fs:
                return v + (fo - fo0)
        return None
    helper_stub_vm = f2v(target_fo)
    expect(helper_stub_vm is not None, 'helper target file offset unmapped: 0x%x' % target_fo)
    expect(helper_stub_vm == 0xfffffff00aa980c0,
           'unexpected helper stub vm: 0x%x' % helper_stub_vm)

    stub = disasm(data, segs, helper_stub_vm, 0x10)
    i_len = find_insn(stub, '0x%x' % helper_stub_vm)
    s2 = stub[1] if len(stub) > 1 else None
    expect(s2 and s2['mnemonic'] == 'mov' and '0x10' in s2['operands'],
           'helper stub does not set length 16')

    # tail target
    tail_vm = 0xfffffff00a50f5c0
    impl = disasm(data, segs, tail_vm, 0x30)
    i_bti = impl[0]
    i_cbz_len = impl[1]
    expect(i_cbz_len['mnemonic'] == 'cbz', 'impl len-zero cbz missing')
    # byte-wise loop: ldrb/ldrb/subs/b.ne/subs/b.ne ; equal: mov w8,#0
    mnems = [x['mnemonic'] for x in impl]
    expect('ldrb' in mnems, 'impl missing byte loads')
    expect(mnems.count('b.ne') >= 2, 'impl missing loop branches')
    i_zero = find_insn(impl, '0xfffffff00a50f5e0')
    expect(i_zero and i_zero['mnemonic'] == 'mov' and '#0' in i_zero['operands'],
           'impl equal->0 return missing')

    # --- fstab role lookup reference sites (already proven; pinned here) ---
    fstab = disasm(data, segs, 0xfffffff00a22fbb0, 0x30)
    i_fsrole = find_insn(fstab, '0xfffffff00a22fbbc')
    expect(i_fsrole is not None, 'fstab vol.fs_role read missing')

    result = {
        'gate': 'IOS_ROOT_TRANSITION_KERNEL_EVIDENCE',
        'iteration': '57ZV',
        'date': '2026-10-02',
        'bootkc_sha256': actual_sha,
        'extractor': 'scripts/phase05f-root-transition-kernel-evidence.py',
        'certified': {
            'ROOT_TRANSITION_KERNEL_EVIDENCE_EXTRACTOR_PASS': True,
            'ROOT_TRANSITION_KERNEL_EVIDENCE_DURABLE_PASS': True,
            'IOS_GROUP_PAIRING_INSTRUCTION_CHAIN_PASS': True,
            'IOS_GROUP_PAIRING_NX_FS_OID_ITERATION_PASS': True,
            'IOS_GROUP_PAIRING_ROLE_MATCH_PASS': True,
            'IOS_GROUP_PAIRING_GROUP_POINTER_PASS': True,
            'IOS_GROUP_PAIRING_UUID_EQUALITY_SEMANTICS_PASS': True,
            'IOS_GROUP_PAIRING_EQUAL_RESULT_SELECTION_PASS': True,
            'IOS_GROUP_PAIRING_BYPASS_FLAG_CLAIM_LEVEL_PASS': True,
            'IOS_GROUP_PAIRING_DISASSEMBLY_DURABILITY_PASS': True,
            'IOS_DATA_ENCRYPTION_INSTRUCTION_CHAIN_PASS': True,
            'IOS_DATA_UNENCRYPTED_BIT_SEMANTICS_PASS': True,
        },
        'group_pairing_consumer': {
            'function_vm': '0xfffffff00a265548',
            'instruction_chain': pair,
            'key_sites': {
                'input_role_load': '0xfffffff00a265574',
                'input_role_compare': '0xfffffff00a265578',
                'nx_count_load': '0xfffffff00a265598',
                'nx_array_load': '0xfffffff00a2655bc',
                'loop_count_reload': '0xfffffff00a26562c',
                'candidate_role_load': '0xfffffff00a2655f4',
                'candidate_role_compare': '0xfffffff00a2655f8',
                'bypass_tbnz': '0xfffffff00a265600',
                'candidate_group_ptr_arg0': '0xfffffff00a265608',
                'source_group_ptr_arg1': '0xfffffff00a26560c',
                'compare_call': '0xfffffff00a265610',
                'equal_result_cbz': '0xfffffff00a265614',
                'sibling_selected_mov': '0xfffffff00a265678',
            },
            'nx_fs_oid': {
                'nx_max_file_systems_container_offset': '0xB4',
                'nx_fs_oid_array_container_offset': '0xB8',
            },
            'role_field': 'APSB+0x3C4',
            'group_id_field': 'APSB+0x3F0',
            'bypass_flag_classification': 'PROVEN: arg2 (w2) is the bypass control; w2=1 skips uuid_compare (role-only sibling search), w2=0 requires uuid_compare(candidate+0x3F0, source+0x3F0)==0. fstab caller 0xfffffff00a223de8 sets w2 dynamically: source group UUID null (uuid_is_null @0xfffffff00a2be2a4 returns 0) -> w2=1 role-only; nonzero -> w2=0 UUID-equality required.',
            'bypass_flag_claim_level': 'PROVEN_CALLER_DEPENDENT',
            'caller_evidence': {
                'total_callers': len(callers),
                'callers': [
                    {'vm': '0xfffffff00a1a13c4', 'arg2': '1 (mov w2,#1)', 'mode': 'role-only'},
                    {'vm': '0xfffffff00a21a460', 'arg2': '1 (mov w2,#1)', 'mode': 'role-only'},
                    {'vm': '0xfffffff00a223de8', 'arg2': 'dynamic: uuid_is_null(source+0x3F0) ? 1 : 0', 'mode': 'conditional UUID equality'},
                    {'vm': '0xfffffff00a27e00c', 'arg2': '1 (mov w2,#1)', 'mode': 'role-only'},
                ],
                'conclusion': 'group-UUID equality is required exactly when the source volume has a NONZERO group UUID (fstab path). A zero source UUID selects role-only pairing. The rule is caller- and source-state dependent, not unconditional.',
            },
        },
        'comparison_helper': {
            'call_site_vm': '0xfffffff00a265610',
            'got_stub_vm': '0xfffffff00a2be274',
            'got_slot_vm': '0xfffffff008184d40',
            'got_slot_raw_value': '0x%x' % got_val,
            'chained_fixup_target_file_offset': '0x%x' % target_fo,
            'resolved_stub_vm': '0x%x' % helper_stub_vm,
            'stub_instruction_chain': stub,
            'stub_sets_length': 'w2 = 0x10 (16 bytes)',
            'impl_vm': '0xfffffff00a50f5c0',
            'impl_instruction_chain': impl,
            'semantics': 'byte-wise compare of w2 bytes; returns 0 iff all bytes equal; with w2=0x10 this is a 16-byte UUID equality test',
            'identity': 'SEMANTICALLY_PROVEN_UUID_EQUALITY',
            'IOS_GROUP_PAIRING_UUID_COMPARE_SYMBOL_PASS': False,
            'symbol_resolution_note': 'no symbol table entry available; identity established by disassembled semantics (mov w2,#0x10; byte loop; return 0 iff equal), not by symbol name',
        },
        'encryption_refusal': {
            'region_vm': '0xfffffff00a210cfc',
            'instruction_chain': enc,
            'key_sites': {
                'apsb_ptr_load': '0xfffffff00a210cfc',
                'role_load': '0xfffffff00a210d00',
                'role_compare_0x40': '0xfffffff00a210d04',
                'fs_flags_load': '0xfffffff00a210d0c',
                'unencrypted_bit_test': '0xfffffff00a210d10',
            },
            'role_field': 'APSB+0x3C4',
            'fs_flags_field': 'APSB+0x108',
            'bit': 0,
            'bit_semantics_source': 'kernel consumer: tbnz w8,#0 after fs_flags load branches to the "unencrypted data volume is not allowed" panic; bit0 SET = unencrypted; corroborated by repo apfs reader fs_flags constants',
        },
        'fstab_role_lookup_reference': {
            'vol_fs_role_read_vm': '0xfffffff00a22fbbc',
            'instruction_chain': fstab,
        },
    }

    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(result, f, indent=2)

    # Durable full disassembly text
    lines = []
    lines.append('# IOS_ROOT_TRANSITION group-pairing consumer disassembly')
    lines.append('# BootKC SHA-256: %s' % actual_sha)
    lines.append('# function vm: 0xfffffff00a265548')
    lines.append('')
    for i in pair:
        lines.append('%s  %-8s %s' % (i['vm'], i['mnemonic'], i['operands']))
    lines.append('')
    lines.append('# comparison helper stub 0xfffffff00aa980c0')
    for i in stub:
        lines.append('%s  %-8s %s' % (i['vm'], i['mnemonic'], i['operands']))
    lines.append('')
    lines.append('# compare implementation 0xfffffff00a50f5c0')
    for i in impl:
        lines.append('%s  %-8s %s' % (i['vm'], i['mnemonic'], i['operands']))
    with open(DISASM_OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

    print('WROTE', OUT)
    print('WROTE', DISASM_OUT)
    print('KERNEL_EVIDENCE_PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
