#!/usr/bin/env python3
"""57ZU transition-model negative controls.

Every mutation must make phase05f-evidence-consistency-check.ps1 exit
non-zero. Originals restored after each mutation. Final restored baseline
must exit 0.
"""

import json
import os
import shutil
import subprocess

TM = 'artifacts/evidence/05f/phase05f-ios-root-transition-model.json'
PROBE = 'artifacts/evidence/05f/phase05f-root-transition-probe-result.json'
PRE = 'artifacts/evidence/05f/phase05f-preboom-storage-contract.json'
KE = 'artifacts/evidence/05f/phase05f-root-transition-kernel-evidence.json'
CHECKER = 'scripts/phase05f-evidence-consistency-check.ps1'


def run_checker():
    return subprocess.run(
        ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', CHECKER],
        capture_output=True).returncode


def mutate(path, fn):
    shutil.copy(path, path + '.bak')
    data = json.load(open(path, encoding='utf-8'))
    fn(data)
    open(path, 'w', encoding='utf-8', newline='\n').write(json.dumps(data, indent=2) + '\n')


def restore(path):
    shutil.copy(path + '.bak', path)
    os.remove(path + '.bak')


def run(name, path, fn):
    global ran
    mutate(path, fn)
    code = run_checker()
    ran += 1
    ok = code != 0
    if not ok:
        failures.append(name)
    print('NEG_%s: EXIT=%d %s' % (name.upper(), code, 'OK' if ok else 'BROKEN'))
    restore(path)


ran = 0
failures = []

# Role constant mutations
run('role_system_changed', TM, lambda d: d['role_table']['roles'].__setitem__('0x0001', 'DATA'))
run('role_installer_changed', TM, lambda d: d['role_table']['roles'].__setitem__('0x0020', 'UPDATE'))
run('role_data_changed', TM, lambda d: d['role_table']['roles'].__setitem__('0x0040', 'SYSTEM'))
run('role_update_changed', TM, lambda d: d['role_table']['roles'].__setitem__('0x00C0', 'INSTALLER'))
run('role_offset_changed', TM, lambda d: d['role_table'].__setitem__('apfs_role_offset', 'APSB+0x3C8'))
run('group_offset_changed', TM, lambda d: d['role_table'].__setitem__('apfs_volume_group_id_offset', 'APSB+0x3E0'))

# Lookup semantics mutations
run('exact_lookup_site_changed', TM, lambda d: d['role_lookup_consumer']['key_sites'][2].__setitem__('vm', '0xfffffff00a22fc08'))
run('data_miss_fatal_overclaim', TM, lambda d: d['data_miss_behavior'].__setitem__('behavior', 'missing DATA-role volume is fatal'))
run('pairing_consumer_removed', TM, lambda d: d['group_pairing'].__setitem__('consumer_vm', '0x0000000000000000'))

# Overclaim mutations
run('pairing_pass_without_consumer', TM, lambda d: (d['group_pairing'].__setitem__('IOS_SYSTEM_DATA_GROUP_PAIRING_PASS', True), d['group_pairing'].__setitem__('IOS_SYSTEM_DATA_GROUP_PAIRING_CONSUMER_PASS', False)))
run('restore_assignment_overclaim', TM, lambda d: d['source_vs_runtime']['DEPLOYED_RUNTIME_SYSTEM_VOLUME'].__setitem__('volume_group_id', 'ASSIGNED_AT_RESTORE_DEPLOYMENT'))
run('runtime_data_identity_proven', TM, lambda d: d['static_vs_runtime_separation'].__setitem__('CONCRETE_DATA_VOLUME_IDENTITY', 'PROVEN'))
run('data_uuid_invented', TM, lambda d: d['source_vs_runtime']['DEPLOYED_RUNTIME_DATA_VOLUME'].__setitem__('volume_uuid', 'deadbeef-0000-0000-0000-000000000000'))
run('source_group_uuid_changed', TM, lambda d: d['source_vs_runtime']['SOURCE_SYSTEM_IMAGE'].__setitem__('volume_group_id', '11111111-2222-3333-4444-555555555555'))
run('source_paired_overclaim', TM, lambda d: d['source_vs_runtime']['SOURCE_SYSTEM_IMAGE'].__setitem__('volume_group_id', '9a503cf2-6d7a-4fda-a233-600dd13b4994'))

# Probe aggregation mutations
run('image_set_has_data_false_claim', PROBE, lambda d: d['answers'].__setitem__('data_volume_absent_from_available_image_set', False))
run('probe_container_data_true', PROBE, lambda d: d['answers']['data_role_by_container'].__setitem__('base_system', True))

# Runtime overclaims
run('data_mount_proven', TM, lambda d: d['mount_order']['order'][4].__setitem__('state', 'PROVEN'))
run('firmlink_composition_proven', TM, lambda d: d['transition_chain']['chain'][8].__setitem__('state', 'PROVEN_STATIC'))
run('userspace_proven', TM, lambda d: d['transition_chain']['chain'][9].__setitem__('state', 'PROVEN_STATIC'))
run('mountpoint_proven_overclaim', TM, lambda d: d['data_mountpoint'].__setitem__('IOS_DATA_MOUNTPOINT_CONTRACT', 'PROVEN'))
run('transition_pass_closed', TM, lambda d: d.__setitem__('certified', 'PASS_CLOSED'))

# Preboom transition-state mismatch
run('preboom_transition_state_mismatch', PRE, lambda d: d['storage_gates_open'].__setitem__('IOS_ROOT_TRANSITION_MODEL', 'BLOCKED'))

# 57ZV kernel-evidence instruction-level mutations
run('ke_consumer_vm_changed', KE, lambda d: d['group_pairing_consumer'].__setitem__('function_vm', '0xfffffff00a265549'))
run('ke_nx_array_offset_changed', KE, lambda d: d['group_pairing_consumer']['nx_fs_oid'].__setitem__('nx_fs_oid_array_container_offset', '0xBC'))
run('ke_nx_count_offset_changed', KE, lambda d: d['group_pairing_consumer']['nx_fs_oid'].__setitem__('nx_max_file_systems_container_offset', '0xB0'))
run('ke_role_field_changed', KE, lambda d: d['group_pairing_consumer'].__setitem__('role_field', 'APSB+0x3C8'))
run('ke_group_field_changed', KE, lambda d: d['group_pairing_consumer'].__setitem__('group_id_field', 'APSB+0x3E0'))
run('ke_compare_call_site_changed', KE, lambda d: d['group_pairing_consumer']['key_sites'].__setitem__('compare_call', '0xfffffff00a265614'))
run('ke_equal_cbz_changed', KE, lambda d: d['group_pairing_consumer']['key_sites'].__setitem__('equal_result_cbz', '0xfffffff00a265618'))
run('ke_sibling_mov_changed', KE, lambda d: d['group_pairing_consumer']['key_sites'].__setitem__('sibling_selected_mov', '0xfffffff00a26567c'))
run('ke_helper_identity_changed', KE, lambda d: d['comparison_helper'].__setitem__('identity', 'uuid_compare_symbol_resolved'))
run('ke_helper_impl_changed', KE, lambda d: d['comparison_helper'].__setitem__('impl_vm', '0xfffffff00a50f5c4'))
run('ke_enc_region_changed', KE, lambda d: d['encryption_refusal'].__setitem__('region_vm', '0xfffffff00a210cf0'))
run('ke_enc_flags_offset_changed', KE, lambda d: d['encryption_refusal'].__setitem__('fs_flags_field', 'APSB+0x10C'))
run('ke_enc_bit_changed', KE, lambda d: d['encryption_refusal'].__setitem__('bit', 1))
run('ke_enc_chain_flag_false', KE, lambda d: d['certified'].__setitem__('IOS_DATA_ENCRYPTION_INSTRUCTION_CHAIN_PASS', False))
run('ke_pairing_chain_flag_false', KE, lambda d: d['certified'].__setitem__('IOS_GROUP_PAIRING_INSTRUCTION_CHAIN_PASS', False))
run('ke_bypass_universal_overclaim', KE, lambda d: d['group_pairing_consumer'].__setitem__('bypass_flag_classification', 'PROVEN normal path'))
run('ke_bootkc_sha_changed', KE, lambda d: d.__setitem__('bootkc_sha256', 'deadbeef' * 8))

# Duplicate JSON key
shutil.copy(TM, TM + '.bak')
raw = open(TM, encoding='utf-8').read()
raw = raw.replace('"gate": "IOS_ROOT_TRANSITION_MODEL",', '"gate": "IOS_ROOT_TRANSITION_MODEL",\n  "gateX": "Y",', 1)
raw = raw.replace('"gateX"', '"gate"', 1)
open(TM, 'w', encoding='utf-8', newline='\n').write(raw)
code = run_checker()
ran += 1
ok = code != 0
if not ok:
    failures.append('duplicate_key')
print('NEG_DUPLICATE_KEY: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))
shutil.copy(TM + '.bak', TM)
os.remove(TM + '.bak')

# Restored baseline
code = run_checker()
ok = code == 0
if not ok:
    failures.append('restored_baseline')
print('RESTORED_BASELINE: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))

print('TOTAL_NEGATIVE_CONTROLS=%d' % ran)
if failures:
    print('FAILED_CONTROLS: %s' % ', '.join(failures))
    raise SystemExit(1)
print('ALL_NEGATIVE_CONTROLS_PASS')
