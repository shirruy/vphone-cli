#!/usr/bin/env python3
"""57ZO durable negative-control harness for IOS_ROOT_DEVICE_SELECTION.

Each mutation must make the evidence-consistency checker exit non-zero; after
every mutation the originals are restored. Final restored baseline must EXIT=0.
"""

import json
import os
import shutil
import subprocess
import sys

ART = 'artifacts/evidence/05f/phase05f-ios-root-device-selection.json'
PRE = 'artifacts/evidence/05f/phase05f-preboom-storage-contract.json'
CHECKER = 'scripts/phase05f-evidence-consistency-check.ps1'
REPARSE = 'scripts/phase05f-nxsb-reparse.py'


def run_checker():
    r = subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-File', CHECKER],
        capture_output=True,
    )
    return r.returncode


def tamper_json(path, mutations):
    shutil.copy(path, path + '.bak')
    data = json.load(open(path, encoding='utf-8'))
    for keys, value in mutations:
        node = data
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    open(path, 'w', encoding='utf-8', newline='\n').write(json.dumps(data, indent=2) + '\n')


def restore(path):
    shutil.copy(path + '.bak', path)
    os.remove(path + '.bak')


CONTROLS = [
    # 57ZQ state-seal controls
    ('current_count_43_verified_count_34', [
        (['negative_controls', 'current_verified_run', 'TOTAL_NEGATIVE_CONTROLS'], 34)]),
    ('current_note_mentions_34', [(['negative_controls', 'note'], '34 mutations')]),
    ('root_device_PASS_CLOSED', [(['certified'], 'PASS_CLOSED')]),
    # 57ZP restore-mode single-state controls
    ('restore_mode_xid_59392', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'xid'], 59392)]),
    ('restore_mode_xid_changed', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'nx_object_xid'], 8)]),
    ('restore_mode_block_count_changed', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'nx_block_count'], 12345)]),
    ('restore_mode_uuid_changed', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'nx_uuid'], 'deadbeef-0000-0000-0000-000000000000')]),
    ('restore_mode_block_offset_0x20', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'nxsb_block_offset'], '0x20')]),
    ('restore_mode_cross_section_mismatch', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'nx_object_xid'], 8)]),
    # 57ZO single-state / governance
    ('volume_group_pass_unresolved', [(['volume_group', 'IOS_ROOT_VOLUME_GROUP_SELECTION_PASS'], True)]),
    ('preboot_pass_deferred', [(['preboot_metadata', 'IOS_PREBOOT_ROOT_SELECTION_METADATA_PASS'], True)]),
    ('foreign_stale_as_checkpoint', [(['restore_nxsb', 'checkpoint_candidates_classification'], 'OLDER_CHECKPOINT_COPIES')]),
    ('foreign_stale_as_authoritative', [(['restore_nxsb', 'RESTORE_AUTHORITATIVE_NXSB_PASS'], True)]),
    ('block_count_as_xid', [(['restore_nxsb', 'authoritative_nxsb', 'NX_OBJECT_XID'], 59392)]),
    ('move_nx_uuid', [(['restore_nxsb', 'authoritative_nxsb', 'NX_UUID'], 'deadbeef-0000-0000-0000-000000000000')]),
    ('change_block_count', [(['restore_nxsb', 'authoritative_nxsb', 'NX_BLOCK_COUNT'], 12345)]),
    ('restore_container_uuid', [(['container_identity', 'restore_ramdisk_container', 'NX_UUID'], 'deadbeef-0000-0000-0000-000000000000')]),
    ('remove_checksum_proof', [(['restore_nxsb', 'authoritative_nxsb', 'checksum_valid'], False)]),
    ('swap_base_system_cryptex', [(['container_identity', 'base_system_container', 'NX_UUID'], 'bd649fe5-ae10-4b79-b7d8-92bb32bdef60')]),
    ('call_cryptex_base', [(['container_identity', 'base_system_container', 'NX_UUID'], 'bd649fe5-ae10-4b79-b7d8-92bb32bdef60')]),
    ('selected_nsid_integer', [(['selected_namespace', 'ROOT_ANS_NAMESPACE_NSID'], '7')]),
    ('selected_nsid_proven', [(['selected_namespace', 'ROOT_ANS_NAMESPACE_STATUS'], 'PROVEN')]),
    ('media_identity_proven', [(['claim_level', 'exact_root_media_identity'], 'PROVEN')]),
    ('runtime_association_proven', [(['root_identity_chain', 'links', 6, 'status'], 'PROVEN')]),
    # 57ZN/57ZM retained
    ('restore_root_matching_0x1', [(['device_tree_audit', 'booted_tree', 'root_matching_bytes'], '0x00000001')]),
    ('restore_expected_taken', [(['selector_control_flow', 'selectors', 4, 'fixture_classification'], 'EXPECTED_TAKEN')]),
    ('root_matching_class', [(['root_matching_semantics', 'classification'], 'BOOLEAN_ENABLE')]),
    ('media_class', [(['media_match_predicate', 'service_class'], 'IOBlockStorageDevice')]),
    ('media_match_property', [(['media_match_predicate', 'content_filter'], 'Apple_APFS')]),
    ('container_uuid', [(['container_identity', 'system_cryptex_container', 'NX_UUID'], 'deadbeef-0000-0000-0000-000000000000')]),
    ('system_uuid', [(['volume_enumeration', 'base_system_container_volumes', 0, 'volume_uuid'], 'deadbeef000000000000000000000000')]),
    ('system_role', [(['volume_enumeration', 'base_system_container_volumes', 0, 'role'], 2)]),
    ('volume_group', [(['volume_group', 'system_volume_uuid'], 'deadbeef000000000000000000000000')]),
    ('boot_manifest_role', [(['boot_manifest_role', 'classification'], 'ROOT_SELECTION_CRITICAL')]),
    ('ns_media_link', [(['namespace_to_media_map', 'IOS_ROOT_NAMESPACE_TO_MEDIA_MAP_PASS'], False)]),
    ('apfs_consumer', [(['root_identity_chain', 'no_implicit_transitions'], False)]),
    ('restore_fixture', [(['restore_mode', 'CURRENT_RESTORE_FIXTURE_BEHAVIOR', 'ramdisk_container_uuid'], 'deadbeef-0000-0000-0000-000000000000')]),
    ('claim_level', [(['claim_level', 'exact_root_namespace_identity'], 'PROVEN')]),
    ('certified', [(['certified'], 'PASS_CLOSED')]),
]


def main():
    failures = []
    ran = 0
    for name, muts in CONTROLS:
        tamper_json(ART, muts)
        code = run_checker()
        ran += 1
        ok = code != 0
        if not ok:
            failures.append(name)
        print('NEG_%s: EXIT=%d %s' % (name.upper(), code, 'OK' if ok else 'BROKEN'))
        restore(ART)

    # Parser-missing control: temporarily rename durable parser
    tmp = REPARSE + '.tmp'
    os.rename(REPARSE, tmp)
    code = run_checker()
    ran += 1
    ok = code != 0
    if not ok:
        failures.append('nxsb_parser_missing')
    print('NEG_NXSB_PARSER_MISSING: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))
    os.rename(tmp, REPARSE)

    # Harness-missing control: temporarily rename this file
    self_path = os.path.abspath(__file__)
    tmp2 = self_path + '.tmp'
    os.rename(self_path, tmp2)
    code = run_checker()
    ran += 1
    ok = code != 0
    if not ok:
        failures.append('negative_harness_missing')
    print('NEG_NEGATIVE_HARNESS_MISSING: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))
    os.rename(tmp2, self_path)

    # Preboom state mismatch
    shutil.copy(PRE, PRE + '.bak')
    data = json.load(open(PRE, encoding='utf-8'))
    data['certified']['IOS_ROOT_DEVICE_SELECTION'] = 'PASS_CLOSED'
    data['PREBOOM_ROOT_SELECTION_DEPENDENCY_SINGLE_STATE_PASS'] = False
    data['storage_gates_open']['IOS_ROOT_TRANSITION_MODEL'] = 'BLOCKED_PENDING_57ZQ'
    open(PRE, 'w', encoding='utf-8', newline='\n').write(json.dumps(data, indent=2) + '\n')
    code = run_checker()
    ran += 1
    ok = code != 0
    if not ok:
        failures.append('preboom_state')
    print('NEG_PREBOOM_STATE: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))
    shutil.copy(PRE + '.bak', PRE)
    os.remove(PRE + '.bak')

    # Duplicate JSON key
    shutil.copy(ART, ART + '.bak')
    raw = open(ART, encoding='utf-8').read()
    raw = raw.replace('"gate": "IOS_ROOT_DEVICE_SELECTION",', '"gate": "IOS_ROOT_DEVICE_SELECTION",\n  "gateX": "Y",', 1)
    raw = raw.replace('"gateX"', '"gate"', 1)
    open(ART, 'w', encoding='utf-8', newline='\n').write(raw)
    code = run_checker()
    ran += 1
    ok = code != 0
    if not ok:
        failures.append('duplicate_key')
    print('NEG_DUPLICATE_KEY: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))
    shutil.copy(ART + '.bak', ART)
    os.remove(ART + '.bak')

    # Restored baseline
    code = run_checker()
    ok = code == 0
    if not ok:
        failures.append('restored_baseline')
    print('RESTORED_BASELINE: EXIT=%d %s' % (code, 'OK' if ok else 'BROKEN'))

    print('TOTAL_NEGATIVE_CONTROLS=%d' % ran)
    if failures:
        print('FAILED_CONTROLS: %s' % ', '.join(failures))
        return 1
    print('ALL_NEGATIVE_CONTROLS_PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
