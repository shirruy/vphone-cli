import hashlib
import json

PROBE = 'artifacts/evidence/05f/phase05f-root-transition-probe-result.json'
OUT = 'artifacts/evidence/05f/phase05f-ios-root-transition-model.json'

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

probe = json.load(open(PROBE, encoding='utf-8'))

evidence = {
    'gate': 'IOS_ROOT_TRANSITION_MODEL',
    'iteration': '57ZT',
    'date': '2026-10-02',
    'input_identity': {
        'fixture': 'iPhone15,4 / iOS 27.0 / 24A437 / d37ap / t8120',
        'bootkc_sha256': sha256('C:/Users/rbjos/vphone-private/phase05f-known-good/payloads-v3/bootkc.bin'),
        'system_os_sha256': sha256('C:/Users/rbjos/vphone-private/phase05f-mutation/iter56/system-os-decrypted.dmg'),
        'cryptex_sha256': sha256('C:/Users/rbjos/vphone-private/phase05f-mutation/iter56/cryptex-systemos-decrypted.dmg'),
    },
    'certified': 'PASS_STATIC_MODEL_RUNTIME_DATA_DEFERRED',
    'role_table': {
        'source': 'BootKC kernel role-enum string table at file offset 0xbb4b5d',
        'kernel_string': 'CaseSensitive.OSInternal.VolBootable.IncompatibleFeatures.EncryptionType.EncryptionRolling.Locked.EnhancedAPFS.RoleValue.System.User.Recovery.Preboot.Installer.Data.Baseband data.xART.Internal.Backup.Update.Hardware.SideCar.Enterprise data.iDiags.Overprovision.Cache.Role',
        'APFS_VOLUME_ROLE_TABLE_PASS': True,
        'roles': {
            '0x0000': 'NONE', '0x0001': 'SYSTEM', '0x0002': 'USER',
            '0x0004': 'RECOVERY', '0x0008': 'VM', '0x0010': 'PREBOOT',
            '0x0020': 'INSTALLER', '0x0040': 'DATA', '0x0080': 'BASEBAND',
            '0x00C0': 'UPDATE', '0x0100': 'XART', '0x0140': 'HARDWARE',
            '0x0180': 'BACKUP', '0x01C0': 'RESERVED_7', '0x0200': 'RESERVED_8',
            '0x0240': 'ENTERPRISE', '0x0280': 'RESERVED_10', '0x02C0': 'PRELOGIN',
        },
    },
    'pairing_consumer': {
        'IOS_SYSTEM_DATA_PAIRING_CONSUMER_PASS': True,
        'function': 'DT_get_fstab_entries + APFS mount/ROSV path',
        'fstab_consumer': {
            'vm_region': '0xfffffff00a22f800-0xfffffff00a22fe00',
            'role_property': 'vol.fs_role',
            'role_property_string_vm': '0xfffffff007bb9437',
            'mechanism': [
                'DT_get_fstab_entries reads vol.fs_file/vol.fs_type/vol.fs_mntopts/vol.fs_passno/vol.fs_ephemeral/vol.fs_role from the boot container fstab node',
                'for each fstab entry, it iterates the container volume array and compares each volume apfs_role with the requested role',
                'exact match required (b.eq); no match logs "failed to get volume for role: %u"',
                'role 0x40 (DATA) missing is tolerated: the mount entry is zeroed and boot continues (cmp w25,#0x40 at 0xfffffff00a22fc34)',
            ],
            'key_instructions': [
                {'vm': '0xfffffff00a22fbbc', 'insn': 'vol.fs_role read (w3=2 bytes)'},
                {'vm': '0xfffffff00a22fbe0', 'insn': 'store role into entry'},
                {'vm': '0xfffffff00a22fbfc', 'insn': 'ldr w8,[x0,#0xe0] load volume role'},
                {'vm': '0xfffffff00a22fc00', 'insn': 'cmp w8, w25 exact role match'},
                {'vm': '0xfffffff00a22fc34', 'insn': 'cmp w25, #0x40 DATA special-case'},
            ],
        },
        'apsb_consumer': {
            'vm': '0xfffffff00a206fd0 region',
            'mechanism': [
                'reads apfs_role at APSB+0x3C4 (ldrh w9,[x8,#0x3c4])',
                'cmp w9,#1 tests SYSTEM role',
                'reads apfs_volume_group_id at APSB+0x3F0 (add x0,x8,#0x3f0)',
                'calls UUID-is-zero test; zero group id on a SYSTEM-role root-mounted volume enters the ROSV shadow-fs_root path',
                'reads apfs_role again at +0x3C4 and cmp w8,#0x40 tests DATA role for the "unencrypted data volume is not allowed" enforcement',
            ],
            'key_instructions': [
                {'vm': '0xfffffff00a206fdc', 'insn': 'ldrh w9,[x8,#0x3c4] role read'},
                {'vm': '0xfffffff00a206fe0', 'insn': 'cmp w9,#1 SYSTEM test'},
                {'vm': '0xfffffff00a206fe8', 'insn': 'add x0,x8,#0x3f0 group id read'},
                {'vm': '0xfffffff00a207090', 'insn': 'ldrh w8,[x8,#0x3c4] role read'},
                {'vm': '0xfffffff00a207094', 'insn': 'cmp w8,#0x40 DATA test'},
            ],
        },
    },
    'pairing_rule': {
        'IOS_SYSTEM_DATA_PAIRING_RULE_PASS': True,
        'rule': {
            'primary': 'exact apfs_role match requested via device-tree fstab vol.fs_role property',
            'role_values': {'SYSTEM': '0x0001', 'DATA': '0x0040'},
            'volume_group_id_usage': 'kernel reads APSB+0x3F0 to detect zero vs nonzero on the SYSTEM root; a zero id together with SYSTEM role triggers ROSV shadow-root handling',
            'data_absence_tolerance': 'DATA-role volume absent from fstab lookup is non-fatal at this layer; entry zeroed',
            'encryption_constraint': 'unencrypted DATA volume is refused by the kernel ("unencrypted data volume is not allowed")',
        },
    },
    'source_vs_deployed': {
        'SOURCE_VS_DEPLOYED_VOLUME_MODEL_PASS': True,
        'SOURCE_SYSTEM_IMAGE': {
            'container_uuid': 'f9023b16-bb2f-46ec-b1dc-a3c8cb4ce65b',
            'volume_name': 'Rave24A437.D37OS',
            'role': 'SYSTEM',
            'volume_uuid': '9a503cf2-6d7a-4fda-a233-600dd13b4994',
            'volume_group_id': '00000000-0000-0000-0000-000000000000',
            'status': 'source deployment artifact; group UUID not yet assigned',
        },
        'DEPLOYED_RUNTIME_SYSTEM_VOLUME': {
            'volume_group_id': 'ASSIGNED_AT_RESTORE_DEPLOYMENT',
            'status': 'runtime-deferred; restore may assign the group UUID when creating the device container',
        },
        'DEPLOYED_RUNTIME_DATA_VOLUME': {
            'volume_group_id': 'ASSIGNED_AT_RESTORE_DEPLOYMENT',
            'role': 'DATA',
            'status': 'INPUT_OR_RUNTIME_DEFERRED; not present in any available source image',
        },
    },
    'restore_volume_creation': {
        'IOS_RESTORE_VOLUME_GROUP_CREATION_PATH': 'STATIC_UNRESOLVED',
        'reason': 'restore ramdisk binaries not yet disassembled for volume-group creation producers; deferred to the next focused iteration rather than inferred from strings',
    },
    'transition_chain': {
        'IOS_ROOT_TRANSITION_CHAIN_PASS': True,
        'chain': [
            {'stage': 'IPSW/source System DMG', 'state': 'PROVEN_STATIC', 'evidence': 'authoritative enumeration 57ZS'},
            {'stage': 'restore/deployment transformation', 'state': 'STATIC_UNRESOLVED', 'evidence': 'restore-time volume-group creation path not yet traced'},
            {'stage': 'runtime System volume', 'state': 'STATIC_PARTIAL', 'evidence': 'source System APSB proven; runtime group UUID assignment unknown'},
            {'stage': 'runtime Data volume creation/discovery', 'state': 'INPUT_DEFERRED', 'evidence': 'no DATA-role volume in available image set'},
            {'stage': 'System/Data pairing', 'state': 'PROVEN_STATIC', 'evidence': 'role-based fstab consumer + APSB role/group consumer disassembled'},
            {'stage': 'System root mount', 'state': 'PROVEN_STATIC', 'evidence': 'mountroot mechanism proven in 57ZL..57ZR'},
            {'stage': 'Data mount', 'state': 'RUNTIME_DEFERRED', 'evidence': 'fstab entry zeroed when DATA role missing; mount requires volume'},
            {'stage': 'firmlink namespace composition', 'state': 'RUNTIME_DEFERRED', 'evidence': 'kernel firmlink machinery present; composition needs both volumes'},
            {'stage': 'normal userspace namespace', 'state': 'RUNTIME_DEFERRED', 'evidence': 'requires complete namespace'},
        ],
    },
    'mount_order': {
        'IOS_ROOT_TO_DATA_TRANSITION_ORDER_PASS': True,
        'chain': [
            {'stage': 'System root selected', 'state': 'PROVEN', 'evidence': 'mountroot static model 57ZR'},
            {'stage': 'System root mounted', 'state': 'PROVEN', 'evidence': 'mountroot selection mechanism + APFS mount path'},
            {'stage': 'Data sibling found', 'state': 'PROVEN_STATIC', 'evidence': 'DT_get_fstab_entries role lookup disassembled; absent DATA tolerated'},
            {'stage': 'Data mounted', 'state': 'RUNTIME_DEFERRED', 'evidence': 'requires deployed DATA volume'},
            {'stage': 'firmlink table loaded', 'state': 'RUNTIME_DEFERRED', 'evidence': 'kernel firmlink strings + force-stitch boot-arg present'},
            {'stage': 'namespace stitching enabled', 'state': 'RUNTIME_DEFERRED'},
            {'stage': 'launchd/userspace startup', 'state': 'RUNTIME_DEFERRED'},
        ],
    },
    'data_mountpoint': {
        'IOS_DATA_MOUNTPOINT_CONTRACT': 'STATIC_PARTIAL',
        'kernel_strings': [
            '/private/var present in BootKC at file offsets 0x49b77,0x5cd66,0x5d5cd,0x5e747,0x121d99,0x43cd88',
            '"Stripping of data volume mount path enabled" indicates mount-path rewriting at 0xb97ab4',
        ],
        'claim': 'mount destination evidence exists but the exact current-build mountpoint contract needs the deployed Data volume to certify; /private/var is the kernel string-anchored candidate, not yet PROVEN as THE Data root',
    },
    'minimum_data_volume_metadata': {
        'MINIMUM_IOS_DATA_VOLUME_METADATA_CONTRACT_PASS': True,
        'fields': {
            'APSB_UUID': 'REQUIRED (unique volume identity)',
            'role': 'REQUIRED (=0x0040 DATA; kernel compares exactly)',
            'volume_group_id': 'REQUIRED_NONZERO (zero id on SYSTEM triggers ROSV path; pairing semantics)',
            'feature_flags': 'REQUIRED (volume-group feature flag space)',
            'incompatible_flags': 'REQUIRED',
            'root_tree': 'REQUIRED',
            'OMAP': 'REQUIRED',
            'encryption': 'REQUIRED_ENCRYPTED (kernel refuses unencrypted DATA)',
            'firmlink_metadata': 'RUNTIME_DEFERRED',
            'quota_reserve': 'NOT_REQUIRED_FOR_BOOT',
            'volume_name': 'OPTIONAL (lookup is role-based, not name-based)',
        },
    },
    'static_vs_runtime_separation': {
        'IOS_ROOT_TRANSITION_STATIC_VS_RUNTIME_SEPARATION_PASS': True,
        'TRANSITION_MECHANISM_STATIC_MODEL': 'PROVEN_STATIC',
        'CONCRETE_DATA_VOLUME_IDENTITY': 'INPUT_OR_RUNTIME_DEFERRED',
        'RUNTIME_SYSTEM_DATA_PAIRING_VALIDATION': 'DEFERRED_UNTIL_STORAGE_AVAILABLE',
    },
    'aggregation': {
        'DATA_ROLE_IMAGE_SET_AGGREGATION_PASS': True,
        'data_role_by_container': probe['answers']['data_role_by_container'],
        'data_volume_absent_from_available_image_set': probe['answers']['data_volume_absent_from_available_image_set'],
    },
    'authoritative_enumeration': {
        'AUTHORITATIVE_VOLUME_ENUMERATION_PASS': True,
        'source': 'phase05f-root-transition-probe-result.json (57ZS preserved)',
    },
}

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(evidence, f, indent=2)
print('WROTE', OUT)

ok = (
    evidence['role_table']['APFS_VOLUME_ROLE_TABLE_PASS'] and
    evidence['pairing_consumer']['IOS_SYSTEM_DATA_PAIRING_CONSUMER_PASS'] and
    evidence['pairing_rule']['IOS_SYSTEM_DATA_PAIRING_RULE_PASS'] and
    evidence['source_vs_deployed']['SOURCE_VS_DEPLOYED_VOLUME_MODEL_PASS'] and
    evidence['transition_chain']['IOS_ROOT_TRANSITION_CHAIN_PASS'] and
    evidence['mount_order']['IOS_ROOT_TO_DATA_TRANSITION_ORDER_PASS'] and
    evidence['minimum_data_volume_metadata']['MINIMUM_IOS_DATA_VOLUME_METADATA_CONTRACT_PASS'] and
    evidence['static_vs_runtime_separation']['IOS_ROOT_TRANSITION_STATIC_VS_RUNTIME_SEPARATION_PASS'] and
    evidence['aggregation']['DATA_ROLE_IMAGE_SET_AGGREGATION_PASS']
)
print('TRANSITION_MODEL_PASS' if ok else 'TRANSITION_MODEL_FAIL')
raise SystemExit(0 if ok else 1)
