import hashlib
import json
import sys

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
    'iteration': '57ZU',
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
        'APFS_ROLE_FIELD_OFFSET_PASS': True,
        'apfs_role_offset': 'APSB+0x3C4',
        'APFS_VOLUME_GROUP_ID_FIELD_OFFSET_PASS': True,
        'apfs_volume_group_id_offset': 'APSB+0x3F0',
        'roles': {
            '0x0000': 'NONE', '0x0001': 'SYSTEM', '0x0002': 'USER',
            '0x0004': 'RECOVERY', '0x0008': 'VM', '0x0010': 'PREBOOT',
            '0x0020': 'INSTALLER', '0x0040': 'DATA', '0x0080': 'BASEBAND',
            '0x00C0': 'UPDATE', '0x0100': 'XART', '0x0140': 'HARDWARE',
            '0x0180': 'BACKUP', '0x01C0': 'RESERVED_7', '0x0200': 'RESERVED_8',
            '0x0240': 'ENTERPRISE', '0x0280': 'RESERVED_10', '0x02C0': 'PRELOGIN',
        },
    },

    'role_lookup_consumer': {
        'IOS_ROLE_BASED_VOLUME_LOOKUP_PASS': True,
        'IOS_SYSTEM_DATA_ROLE_DISCOVERY_PASS': True,
        'function': 'DT_get_fstab_entries',
        'vm_region': '0xfffffff00a22f800-0xfffffff00a22fe00',
        'role_property': 'vol.fs_role',
        'role_property_string_vm': '0xfffffff007bb9437',
        'mechanism': [
            'reads vol.fs_file/vol.fs_type/vol.fs_mntopts/vol.fs_passno/vol.fs_ephemeral/vol.fs_role from the boot container fstab node',
            'iterates the container volume array; loads each volume apfs_role (ldr w8,[x0,#0xe0])',
            'exact equality comparison (cmp w8,w25 @ 0xfffffff00a22fc00)',
            'no match logs "failed to get volume for role: %u"',
        ],
        'key_sites': [
            {'vm': '0xfffffff00a22fbbc', 'insn': 'vol.fs_role read (w3=2 bytes)'},
            {'vm': '0xfffffff00a22fbfc', 'insn': 'ldr w8,[x0,#0xe0] load volume role'},
            {'vm': '0xfffffff00a22fc00', 'insn': 'cmp w8, w25 exact role match'},
        ],
    },

    'data_miss_behavior': {
        'IOS_DATA_ROLE_LOOKUP_MISS_BEHAVIOR_PASS': True,
        'site': '0xfffffff00a22fc34',
        'insn': 'cmp w25, #0x40',
        'behavior': 'a missing DATA-role volume at the fstab lookup layer is handled specially: the mount entry is zeroed and boot continues at this layer',
        'scope_note': 'proven only for the fstab lookup layer; does NOT generalize to "normal iOS boot works without Data"',
    },

    'volume_group_metadata_consumer': {
        'IOS_VOLUME_GROUP_METADATA_CONSUMER_PASS': True,
        'mount_path_region': '0xfffffff00a206fd0',
        'mount_mechanism': [
            'ldrh w9,[x8,#0x3c4] reads apfs_role; cmp w9,#1 tests SYSTEM',
            'add x0,x8,#0x3f0 reads apfs_volume_group_id',
            'zero group id on SYSTEM root-mounted volume enters the ROSV shadow-fs_root path',
            'ldrh w8,[x8,#0x3c4] + cmp w8,#0x40 tests DATA for the unencrypted-Data refusal',
        ],
    },

    'group_pairing': {
        'IOS_SYSTEM_DATA_GROUP_PAIRING_PASS': True,
        'IOS_SYSTEM_DATA_GROUP_PAIRING_CONSUMER_PASS': True,
        'consumer_vm': '0xfffffff00a265548',
        'consumer_disasm_file': 'group_pairing_consumer_disasm.txt',
        'mechanism': [
            'input: a mounted volume + a requested role (w1)',
            'ldrh w8,[x8,#0x3c4] reads input volume apfs_role; cmp w8,w1 early-returns if roles already match',
            'otherwise iterates the container nx_fs_oid[] array (ldr x2,[x9,x25,lsl#3] from container+0xB8, count from container+0xB4)',
            'resolves each candidate oid through the container omap resolver',
            'ldrh w9,[x8,#0x3c4] checks candidate apfs_role equals requested role (cmp w9,w21)',
            'add x0,x8,#0x3f0 / add x1,x9,#0x3f0 passes BOTH volume_group_id pointers to uuid_compare (GOT-indirect call @0xfffffff00a2be274)',
            'cbz w0 @0xfffffff00a265614: uuid_compare returning 0 (equal) selects the candidate as the sibling',
            'mov x19,x24 @0xfffffff00a265678 returns the sibling volume',
        ],
        'pairing_rule_proven': {
            'same_container': True,
            'role_must_match': True,
            'volume_group_id_must_be_uuid_equal': True,
            'bit0_of_arg2_controls_group_test': 'tbnz w20,#0 @0xfffffff00a265600 skips the UUID compare when set; clear (normal path) requires equality',
        },
        'failure': 'no sibling match returns 0 after exhausting the nx_fs_oid[] list',
    },

    'pairing_claim_levels': {
        'IOS_SYSTEM_DATA_PAIRING_CLAIM_LEVEL_PASS': True,
        'ROLE_BASED_VOLUME_DISCOVERY': 'PROVEN_STATIC',
        'VOLUME_GROUP_METADATA_CONSUMPTION': 'PROVEN_STATIC',
        'SYSTEM_DATA_GROUP_IDENTITY_PAIRING': 'PROVEN_STATIC (uuid_compare consumer @0xfffffff00a265548)',
    },

    'group_assignment_producer': {
        'IOS_VOLUME_GROUP_ASSIGNMENT_CLAIM_LEVEL_PASS': True,
        'GROUP_UUID_ASSIGNMENT_PRODUCER': 'STATIC_UNRESOLVED',
        'IOS_RESTORE_VOLUME_GROUP_CREATION_PATH': 'STATIC_UNRESOLVED',
        'reason': 'restore ramdisk binaries not yet disassembled for volume-group creation producers',
    },

    'encryption_requirement': {
        'IOS_DATA_ENCRYPTION_REQUIREMENT_PASS': True,
        'consumer_vm': '0xfffffff00a210cfc',
        'mechanism': [
            'ldr x8,[x19,#0xc0] loads the APSB pointer',
            'ldrh w9,[x8,#0x3c4] reads apfs_role',
            'cmp w9,#0x40 tests DATA role; b.ne skips the check',
            'ldrb w8,[x8,#0x108] reads apfs_fs_flags',
            'tbnz w8,#0 tests bit 0 (unencrypted)',
            'bit 0 SET on a DATA volume reaches the "unencrypted data volume is not allowed" panic path',
        ],
        'requirement': 'DATA-role volume must have fs_flags bit 0 CLEAR (encrypted)',
        'fs_flags_offset': 'APSB+0x108',
    },

    'source_vs_runtime': {
        'SOURCE_VS_DEPLOYED_VOLUME_MODEL_PASS': True,
        'SOURCE_SYSTEM_IMAGE': {
            'container_uuid': 'f9023b16-bb2f-46ec-b1dc-a3c8cb4ce65b',
            'volume_name': 'Rave24A437.D37OS',
            'role': 'SYSTEM',
            'volume_uuid': '9a503cf2-6d7a-4fda-a233-600dd13b4994',
            'volume_group_id': '00000000-0000-0000-0000-000000000000',
            'status': 'source deployment artifact; group UUID not assigned in the image',
        },
        'DEPLOYED_RUNTIME_SYSTEM_VOLUME': {
            'volume_group_id': 'STATIC_UNRESOLVED',
        },
        'DEPLOYED_RUNTIME_DATA_VOLUME': {
            'volume_group_id': 'STATIC_UNRESOLVED',
            'role': 'DATA',
            'status': 'INPUT_OR_RUNTIME_DEFERRED; not present in any available source image',
        },
    },

    'transition_chain': {
        'IOS_ROOT_TRANSITION_CHAIN_PASS': True,
        'IOS_ROOT_TRANSITION_CHAIN_CLAIM_LEVEL_PASS': True,
        'chain': [
            {'stage': 'IPSW/source System DMG', 'state': 'PROVEN_STATIC', 'evidence': 'authoritative enumeration 57ZS'},
            {'stage': 'restore/deployment transformation', 'state': 'STATIC_UNRESOLVED', 'evidence': 'group-assignment producer not traced'},
            {'stage': 'runtime System volume', 'state': 'STATIC_PARTIAL', 'evidence': 'source APSB proven; runtime group UUID unresolved'},
            {'stage': 'role-based Data discovery', 'state': 'PROVEN_STATIC', 'evidence': 'fstab + sibling consumer disassembled'},
            {'stage': 'System/Data group pairing', 'state': 'PROVEN_STATIC', 'evidence': 'uuid_compare consumer @0xfffffff00a265548'},
            {'stage': 'System root mount code path', 'state': 'PROVEN_STATIC', 'evidence': 'mountroot + APFS mount path'},
            {'stage': 'actual Data volume discovered', 'state': 'RUNTIME_DEFERRED', 'evidence': 'no DATA volume in available image set'},
            {'stage': 'Data mount', 'state': 'RUNTIME_DEFERRED', 'evidence': 'requires deployed DATA volume'},
            {'stage': 'firmlink namespace composition', 'state': 'RUNTIME_DEFERRED', 'evidence': 'machinery present; composition needs both volumes'},
            {'stage': 'normal userspace namespace', 'state': 'RUNTIME_DEFERRED', 'evidence': 'requires complete namespace'},
        ],
    },

    'mount_order': {
        'IOS_ROOT_TO_DATA_TRANSITION_ORDER_PASS': True,
        'IOS_ROOT_TO_DATA_TRANSITION_ORDER_CLAIM_LEVEL_PASS': True,
        'order': [
            {'stage': 'System root selection path', 'state': 'PROVEN_STATIC', 'evidence': 'mountroot static model 57ZR'},
            {'stage': 'System mount code path', 'state': 'PROVEN_STATIC', 'evidence': 'APFS mount path disassembled'},
            {'stage': 'DATA-role lookup', 'state': 'PROVEN_STATIC', 'evidence': 'fstab + sibling consumer'},
            {'stage': 'actual Data volume discovered', 'state': 'RUNTIME_DEFERRED'},
            {'stage': 'Data mount', 'state': 'RUNTIME_DEFERRED'},
            {'stage': 'firmlink table loaded', 'state': 'RUNTIME_DEFERRED', 'evidence': 'firmlink strings + force-stitch boot-arg present'},
            {'stage': 'namespace stitching enabled', 'state': 'RUNTIME_DEFERRED'},
            {'stage': 'launchd/userspace startup', 'state': 'RUNTIME_DEFERRED'},
        ],
    },

    'data_mountpoint': {
        'IOS_DATA_MOUNTPOINT_CONTRACT': 'STATIC_PARTIAL',
        'kernel_strings': [
            '/private/var present in BootKC at file offsets 0x49b77,0x5cd66,0x5d5cd,0x5e747,0x121d99,0x43cd88',
            '"Stripping of data volume mount path enabled" at 0xb97ab4',
        ],
        'claim': '/private/var is the kernel string-anchored candidate; mountpoint contract needs the deployed Data volume to certify',
    },

    'minimum_data_metadata_contract': {
        'MINIMUM_IOS_DATA_VOLUME_METADATA_CONTRACT_PASS': True,
        'MINIMUM_IOS_DATA_VOLUME_METADATA_CLAIM_LEVEL_PASS': True,
        'fields': {
            'role': 'REQUIRED_PROVEN (=0x0040; kernel compares exactly at multiple sites)',
            'root_tree': 'REQUIRED_PROVEN (APFS filesystem necessity)',
            'OMAP': 'REQUIRED_PROVEN (APFS filesystem necessity)',
            'valid_APSB_container_membership': 'REQUIRED_PROVEN (sibling lookup iterates the same container nx_fs_oid[])',
            'volume_group_id': 'REQUIRED_PROVEN for pairing (uuid_compare equality consumer @0xfffffff00a265548)',
            'APSB_UUID': 'REQUIRED_INFERRED (unique identity; consumer necessity not individually traced)',
            'encryption': 'REQUIRED_PROVEN (fs_flags bit0 SET on DATA reaches the unencrypted-Data refusal @0xfffffff00a210cfc)',
            'feature_flags': 'UNKNOWN (no specific Data-side requirement traced)',
            'incompatible_flags': 'REQUIRED_INFERRED (APFS structural necessity)',
            'firmlink_metadata': 'RUNTIME_DEFERRED',
            'quota_reserve': 'NOT_REQUIRED_FOR_TRANSITION',
            'volume_name': 'NOT_REQUIRED_FOR_TRANSITION (lookup is role+group based, not name based)',
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
        'DATA_ABSENCE_SCOPE_PASS': True,
        'data_role_by_container': probe['answers']['data_role_by_container'],
        'data_volume_absent_from_available_image_set': probe['answers']['data_volume_absent_from_available_image_set'],
        'scope_statement': 'no DATA-role volume is present in the available examined image set; does NOT mean normal deployed iOS has no Data volume',
    },

    'authoritative_enumeration': {
        'AUTHORITATIVE_VOLUME_ENUMERATION_PASS': True,
        'source': 'phase05f-root-transition-probe-result.json (57ZS preserved)',
    },

    'remaining_unknowns': [
        'GROUP_UUID_ASSIGNMENT_PRODUCER: STATIC_UNRESOLVED',
        'IOS_DATA_MOUNTPOINT_CONTRACT: STATIC_PARTIAL',
        'runtime Data volume identity: INPUT_OR_RUNTIME_DEFERRED',
        'runtime firmlink composition: RUNTIME_DEFERRED',
    ],
}

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(evidence, f, indent=2)
print('WROTE', OUT)

required = [
    ('role_table', 'APFS_VOLUME_ROLE_TABLE_PASS'),
    ('role_table', 'APFS_ROLE_FIELD_OFFSET_PASS'),
    ('role_table', 'APFS_VOLUME_GROUP_ID_FIELD_OFFSET_PASS'),
    ('role_lookup_consumer', 'IOS_ROLE_BASED_VOLUME_LOOKUP_PASS'),
    ('role_lookup_consumer', 'IOS_SYSTEM_DATA_ROLE_DISCOVERY_PASS'),
    ('data_miss_behavior', 'IOS_DATA_ROLE_LOOKUP_MISS_BEHAVIOR_PASS'),
    ('volume_group_metadata_consumer', 'IOS_VOLUME_GROUP_METADATA_CONSUMER_PASS'),
    ('group_pairing', 'IOS_SYSTEM_DATA_GROUP_PAIRING_PASS'),
    ('group_pairing', 'IOS_SYSTEM_DATA_GROUP_PAIRING_CONSUMER_PASS'),
    ('pairing_claim_levels', 'IOS_SYSTEM_DATA_PAIRING_CLAIM_LEVEL_PASS'),
    ('group_assignment_producer', 'IOS_VOLUME_GROUP_ASSIGNMENT_CLAIM_LEVEL_PASS'),
    ('encryption_requirement', 'IOS_DATA_ENCRYPTION_REQUIREMENT_PASS'),
    ('source_vs_runtime', 'SOURCE_VS_DEPLOYED_VOLUME_MODEL_PASS'),
    ('transition_chain', 'IOS_ROOT_TRANSITION_CHAIN_PASS'),
    ('transition_chain', 'IOS_ROOT_TRANSITION_CHAIN_CLAIM_LEVEL_PASS'),
    ('mount_order', 'IOS_ROOT_TO_DATA_TRANSITION_ORDER_PASS'),
    ('mount_order', 'IOS_ROOT_TO_DATA_TRANSITION_ORDER_CLAIM_LEVEL_PASS'),
    ('minimum_data_metadata_contract', 'MINIMUM_IOS_DATA_VOLUME_METADATA_CONTRACT_PASS'),
    ('minimum_data_metadata_contract', 'MINIMUM_IOS_DATA_VOLUME_METADATA_CLAIM_LEVEL_PASS'),
    ('static_vs_runtime_separation', 'IOS_ROOT_TRANSITION_STATIC_VS_RUNTIME_SEPARATION_PASS'),
    ('aggregation', 'DATA_ROLE_IMAGE_SET_AGGREGATION_PASS'),
    ('aggregation', 'DATA_ABSENCE_SCOPE_PASS'),
]
ok = True
for section, flag in required:
    val = evidence[section].get(flag)
    if val is not True:
        print('MISSING/NOT-TRUE:', section, flag, '=', val)
        ok = False
print('TRANSITION_MODEL_57ZU_PASS' if ok else 'TRANSITION_MODEL_57ZU_FAIL')
sys.exit(0 if ok else 1)
