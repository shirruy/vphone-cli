# Deterministic evidence cross-file consistency checker (Iteration 57ZB).
# Cross-checks three ANS artifacts (dt contract, kernel-driver-match,
# preboom storage summary) for raw DT equality, provider/controller class
# equality, contract status, and the static match-value proof chain.
# Refuses ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS=true unless the static or
# runtime match value is proven. Non-zero exit on any mismatch.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$summaryPath = Join-Path $root 'artifacts\evidence\05f\phase05f-preboom-storage-contract.json'
$contractPath = Join-Path $root 'artifacts\evidence\05f\phase05f-ans-dt-contract.json'
$ansMatchPath = Join-Path $root 'artifacts\evidence\05f\phase05f-ans-kernel-driver-match.json'

$summaryRaw = Get-Content $summaryPath -Raw
$lbaRaw = Get-Content (Join-Path $root 'artifacts\evidence\05f\phase05f-ios-storage-lba-contract.json') -Raw
$contractRaw = Get-Content $contractPath -Raw
$ansMatchRaw = Get-Content $ansMatchPath -Raw
$script:failures = 0

function Assert-Equal($name, $a, $b) {
    if ("$a" -cne "$b") {
        Write-Host "MISMATCH $name : '$a' != '$b'"
        $script:failures++
    } else {
        Write-Host "OK $name"
    }
}

# --- stale-state refusal ---
$stalePatterns = @(
    'iter57r_open',
    'iter57r_closed',
    'iter57s_',
    'NOT_YET',
    '"SPRINGBOARD_EXECUTABLE_RECONSTRUCTED": "OPEN"',
    '"SPRINGBOARD_EXECUTABLE_SHA256": "NOT_YET"',
    'EXACT_WINNING_PROBE_UNRESOLVED',
    'EXACT_WINNING_PROBE_NOT_FULLY_RESOLVED',
    '"PENDING_COMMIT_SHA"',
    'u32 0 (PRESENT)',
    'ANS_IOP_NUB_REGISTRY_NAME_TRANSFORM_PASS',
    'ANS_IOP_NUB_MATCH_SOURCE.*RUNTIME_CONFIRMATION_REQUIRED',
    'ANS_IOP_NUB_PROVIDER_MATCH_RUNTIME_PROOF_REQUIRED'
)
$staleFound = $false
foreach ($p in $stalePatterns) {
    foreach ($raw in @($summaryRaw, $contractRaw, $ansMatchRaw, $lbaRaw)) {
        if ($raw -match [regex]::Escape($p)) {
            Write-Host "STALE_STATE_DETECTED: $p"
            $staleFound = $true
        }
    }
}
if ($staleFound) {
    $script:failures++
} else {
    Write-Host "OK no stale state markers"
}

$summary = $summaryRaw | ConvertFrom-Json
$contract = $contractRaw | ConvertFrom-Json
$ansMatch = $ansMatchRaw | ConvertFrom-Json

# --- iteration identity (57ZB) ---
Assert-Equal 'iteration' $summary.iteration '57ZH'
Assert-Equal 'ITERATION_57ZB' $summary.certified.ITERATION_57ZB 'PASS_CLOSED'
Assert-Equal 'ITERATION_57ZC' $summary.certified.ITERATION_57ZC 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57ZD' $summary.certified.ITERATION_57ZD 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57ZE' $summary.certified.ITERATION_57ZE 'PASS_CLOSED'
Assert-Equal 'ITERATION_57ZA' $summary.certified.ITERATION_57ZA 'PARTIAL_PASS_ACCEPTED'
Assert-Equal 'ITERATION_57Z' $summary.certified.ITERATION_57Z 'PARTIAL_PASS'
Assert-Equal 'ITERATION_57Y' $summary.certified.ITERATION_57Y 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57X' $summary.certified.ITERATION_57X 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57W' $summary.certified.ITERATION_57W 'PASS'
Assert-Equal 'ITERATION_57V' $summary.certified.ITERATION_57V 'PASS'
Assert-Equal '57T_certified' $summary.certified.ITERATION_57T_CERTIFIED_CLOSED 'YES'
Assert-Equal 'ANS contract certified' $summary.certified.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'PASS_CLOSED'

# --- single-state enforcement on the durable kernel-driver-match JSON ---
$topKeys = $ansMatch.PSObject.Properties.Name
foreach ($forbidden in @('probe_score_matrix','nub_chain','winner_matrix','provider_resolution','nub_publisher','endpoint_publisher','asc_rtbuddy_chain_exact','winning_probe_reconciliation','provider_chain','dt_match_map','probe_paths','class_hierarchy','class_inventory','runtime_milestones','namespace_use','external_reference_audit','open_unknowns','iokit_personalities')) {
    if ($topKeys -contains $forbidden) {
        Write-Host "MISMATCH durable artifact still carries legacy top-level section: $forbidden"
        $script:failures++
    } else {
        Write-Host "OK durable single-state (no top-level $forbidden)"
    }
}
if ($ansMatchRaw -match 'PENDING_COMMIT_SHA') {
    Write-Host "MISMATCH self-referential commit placeholder present"
    $script:failures++
} else {
    Write-Host "OK ANS_EVIDENCE_NON_SELF_REFERENTIAL_PASS"
}

$cs = $ansMatch.canonical_state
if ($null -eq $cs) {
    Write-Host "MISMATCH durable canonical_state section missing"
    $script:failures++
} else {
    Assert-Equal 'cs_predicate' $cs.ANS3_NVME_LINEAR_SQ_PREDICATE_PROVEN 'True'
    Assert-Equal 'cs_predicate_revalidation' $cs.ANS3_D37AP_PREDICATE_REVALIDATION_PASS 'True'
    Assert-Equal 'cs_exact_class' $cs.ANS_EXACT_CONTROLLER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_winning_probe' $cs.ANS_EXACT_WINNING_PROBE_PASS 'True'
    Assert-Equal 'cs_controller' $cs.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
    Assert-Equal 'cs_provider' $cs.CURRENT_PROVIDER_CLASS 'RTBuddyService'
    Assert-Equal 'cs_provider_proven' $cs.ANS_PROVIDER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_nub_publisher' $cs.ANS_IOP_NUB_PUBLISHER_PROVEN 'True'
    Assert-Equal 'cs_withreg' $cs.APPLEA7IOPNUB_WITHREGISTRYENTRY_FLOW_PASS 'True'
    Assert-Equal 'cs_sym1' $cs.APPLEA7IOPNUB_PROPERTY_SYMBOL_1_RESOLVED 'True'
    Assert-Equal 'cs_sym2' $cs.APPLEA7IOPNUB_PROPERTY_SYMBOL_2_RESOLVED 'True'
    Assert-Equal 'cs_match_source' $cs.ANS_IOP_NUB_MATCH_VALUE_SOURCE 'STATIC'
    Assert-Equal 'cs_match_static' $cs.ANS_IOP_NUB_MATCH_VALUE_STATIC_PROVEN 'True'
    Assert-Equal 'cs_provider_match' $cs.ANS_IOP_NUB_PROVIDER_MATCH_PASS 'True'
    Assert-Equal 'cs_transform' $cs.ANS_IOP_NUB_REGISTRY_NAME_TRANSFORM 'NOT_PROVEN_TO_BE_REQUIRED'
    Assert-Equal 'cs_ionamematch_semantics' $cs.ANS_IOP_NUB_IONAMEMATCH_SEMANTICS_PASS 'True'
    Assert-Equal 'cs_ionamematch_compatible' $cs.ANS_IOP_NUB_IONAMEMATCH_COMPATIBLE_PASS 'True'
    Assert-Equal 'cs_publication_flow' $cs.APPLEA7IOP_ANS_NUB_PUBLICATION_FLOW_PASS 'True'
    Assert-Equal 'cs_name_source' $cs.APPLEA7IOPNUB_PUBLISHED_NAME_SOURCE_PASS 'True'
    Assert-Equal 'cs_prop_propagation' $cs.APPLEA7IOPNUB_PROPERTY_PROPAGATION_PASS 'True'
    Assert-Equal 'cs_match_behavior' $cs.APPLEA7IOPNUB_MATCH_BEHAVIOR_AUDIT_PASS 'True'
    Assert-Equal 'cs_obj_origin' $cs.RTBUDDY_IONAMEMATCH_OBJECT_ORIGIN_PASS 'True'
    Assert-Equal 'cs_asc_chain' $cs.ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS 'True'
    Assert-Equal 'cs_contract' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'PASS_CLOSED'
    Assert-Equal 'cs_contract_pass' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_PASS 'True'
    Assert-Equal 'cs_durable' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_DURABLE_PASS 'True'
    Assert-Equal 'cs_next_gate' $cs.next_gate 'IOS_STORAGE_LBA_CONTRACT'
}

# --- ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK: chain PASS requires match proof ---
$sumKm = $summary.ans_kernel_driver_match
if ($sumKm.ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS -eq 'True') {
    $staticOk = $sumKm.ANS_IOP_NUB_MATCH_VALUE_STATIC_PROVEN -eq 'True'
    $runtimeOk = $false
    if ($sumKm.PSObject.Properties['ANS_IOP_NUB_MATCH_VALUE_RUNTIME_PROVEN']) {
        $runtimeOk = $sumKm.ANS_IOP_NUB_MATCH_VALUE_RUNTIME_PROVEN -eq 'True'
    }
    if (-not ($staticOk -or $runtimeOk)) {
        Write-Host "MISMATCH ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS=true without static or runtime match-value proof"
        $script:failures++
    } else {
        Write-Host "OK ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK_PASS"
    }
} else {
    Write-Host "OK chain not claimed (dependency gate not triggered)"
}

# --- three-artifact cross-consistency ---
$dtCanon = $contract.canonical_state
Assert-Equal 'x_dt_nls_len' $dtCanon.NVME_LINEAR_SQ_LENGTH 0
Assert-Equal 'x_km_nls_len' $cs.nvme_linear_sq.length 0
Assert-Equal 'x_dt_nls_raw' $dtCanon.NVME_LINEAR_SQ_RAW_HEX ''
Assert-Equal 'x_km_nls_raw' $cs.nvme_linear_sq.raw_hex ''
Assert-Equal 'x_dt_role' $dtCanon.role 'ANS2'
Assert-Equal 'x_km_role' $cs.role 'ANS2'
Assert-Equal 'x_sum_role' $summary.ans_device_tree.role 'ANS2'
Assert-Equal 'x_dt_child' $dtCanon.child_node 'iop-ans-nub'
Assert-Equal 'x_sum_child' $summary.ans_device_tree.child_node 'iop-ans-nub'
Assert-Equal 'x_dt_compat_booted' $dtCanon.child_compatible 'ABSENT'
Assert-Equal 'x_sum_compat_booted' $summary.ans_device_tree.child_compatible_booted 'ABSENT'
Assert-Equal 'x_dt_compat_auth' $dtCanon.child_compatible_authoritative 'iop-nub,rtbuddy-v2'
Assert-Equal 'x_sum_compat_auth' $summary.ans_device_tree.child_compatible_authoritative 'iop-nub,rtbuddy-v2'
Assert-Equal 'x_km_controller' $cs.CURRENT_CONTROLLER_CLASS $sumKm.CURRENT_CONTROLLER_CLASS
Assert-Equal 'x_km_controller_expected' $sumKm.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
Assert-Equal 'x_km_provider' $cs.CURRENT_PROVIDER_CLASS $sumKm.CURRENT_PROVIDER_CLASS
Assert-Equal 'x_km_provider_expected' $sumKm.CURRENT_PROVIDER_CLASS 'RTBuddyService'
Assert-Equal 'x_km_contract' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT $sumKm.ANS_KERNEL_DRIVER_MATCH_CONTRACT
Assert-Equal 'x_km_contract_expected' $sumKm.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'PASS_CLOSED'
Assert-Equal 'x_sum_gate_contract' $summary.storage_gates_open.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'PASS_CLOSED'
Assert-Equal 'x_sum_kernel_contract' $summary.kernel_driver.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'PASS_CLOSED'

if ($script:failures -eq 0) {
    Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_PASS"
}

# --- authoritative DT extraction + pruned-tree facts ---
Assert-Equal 'auth_size' $contract.authoritative.decompressed_size 269248
Assert-Equal 'auth_sha' $contract.authoritative.decompressed_sha256 '7560AA1E4AC07C0D9B57E73A81668DECB5969FE012208A199B58CCADA2CF5E7B'
Assert-Equal 'auth_extraction' $contract.authoritative.D37AP_AUTHORITATIVE_DT_EXTRACTION_PASS 'True'
Assert-Equal 'auth_child_compat' $contract.authoritative_ans_nub_child.D37AP_IOP_ANS_NUB_COMPATIBLE_AUTHORITATIVE 'iop-nub,rtbuddy-v2'
Assert-Equal 'pruned_repro' $contract.booted_pruned_tree.repro_pass 'True'
Assert-Equal 'pruned_sha' $contract.booted_pruned_tree.sha256 '9E84C9ADD25B99EDDD8B088B249E7CE348394B80A0DEF59949E9BB9C63A24E1B'
Assert-Equal 'booted_child_compat' $contract.iop_ans_nub_child.compatible.D37AP_IOP_ANS_NUB_COMPATIBLE 'ABSENT'
Assert-Equal 'booted_nprops' $contract.iop_ans_nub_child.nprops 9

# --- boot-tree pruned finding cross-check in km ---
Assert-Equal 'km_pruned_finding' $ansMatch.boot_tree_finding.DT_FIXUP_PRUNED_TREE_IDENTIFIED_PASS 'True'
Assert-Equal 'km_pruned_repro' $ansMatch.boot_tree_finding.regenerated_sha256 '9e84c9add25b99eddd8b088b249e7ce348394b80a0def59949e9bb9c63a24e1b'

# --- SpringBoard reconstruction + SHA ---
$sb = $summary.decmpfs_reconstruction.executables.springboard
if (-not $sb.reconstructed -or
    $sb.sha256 -cne
        'db2d73a61739417c14359db4415ac5eb0cc59f86611c158e7413d97b0458b55c') {
    Write-Host "MISMATCH SpringBoard reconstruction/SHA"
    $script:failures++
} else {
    Write-Host "OK SpringBoard reconstructed SHA"
}

$ds = $summary.decmpfs_reconstruction
Assert-Equal 'algo4' $ds.algorithm_table.'4' 'zlib resource fork (CMP_TypeZlib)'
Assert-Equal 'resourcefork_flags.observed' $ds.resourcefork_flags.observed 1
Assert-Equal 'dstream_descriptor_matrix' $ds.RESOURCEFORK_DSTREAM_DESCRIPTOR_NEGATIVE_MATRIX_PASS 'True'
Assert-Equal 'file_extent_matrix' $ds.RESOURCEFORK_FILE_EXTENT_NEGATIVE_MATRIX_PASS 'True'
Assert-Equal 'dstream_contract' $ds.RESOURCEFORK_DATA_STREAM_NEGATIVE_MATRIX_PASS 'True'
Assert-Equal 'extent_validator_shared' $ds.RESOURCEFORK_EXTENT_VALIDATOR_SHARED_PASS 'True'
Assert-Equal 'macho_fat_geometry' $ds.MACHO_FAT_CONTAINER_GEOMETRY_PASS 'True'
Assert-Equal 'macho_fat_slice' $ds.MACHO_FAT_SLICE_STRUCTURE_PASS 'True'
Assert-Equal 'macho_fat_slice_matrix' $ds.MACHO_FAT_REAL_SLICE_FIXTURE_MATRIX_PASS 'True'
Assert-Equal 'macho_zero_arch' $ds.MACHO_FAT_ZERO_ARCH_REFUSAL_PASS 'True'
Assert-Equal 'macho_meta_overlap' $ds.MACHO_FAT_METADATA_OVERLAP_REFUSAL_PASS 'True'
Assert-Equal 'macho_matrix' $ds.MACHO_STRUCTURAL_FIXTURE_MATRIX_PASS 'True'
Assert-Equal 'decmpfs_overflow' $ds.DECMPFS_LOGICAL_SIZE_OVERFLOW_REFUSAL_PASS 'True'
Assert-Equal 'sb_macho_cputype' $ds.SPRINGBOARD_MACHO_CPU_TYPE_PASS 'True'
Assert-Equal 'sb_macho_filetype' $ds.SPRINGBOARD_MACHO_FILETYPE_PASS 'True'
Assert-Equal 'type4_chunk_nonoverlap' $ds.DECMPFS_TYPE4_CHUNK_TO_CHUNK_NONOVERLAP_PASS 'True'
Assert-Equal 'type4_chunk_overlap' $ds.DECMPFS_TYPE4_TRUE_CHUNK_OVERLAP_REFUSED_PASS 'True'
Assert-Equal 'type4_mgmt_geometry' $ds.DECMPFS_TYPE4_MANAGEMENT_REGION_GEOMETRY_PASS 'True'
Assert-Equal 'macho_readok_impossible' $ds.MACHO_INVALID_OUTPUT_READ_OK_IMPOSSIBLE_PASS 'True'
Assert-Equal 'macho_fixture_cases' $ds.macho_fixture_cases.Count 15
Assert-Equal 'extent_matrix_cases' $ds.extent_matrix_cases.Count 16
Assert-Equal 'contract_cases' $ds.contract_cases.Count 8

$expected = @{
    springboard  = @{ cputype = 16777228; cpusubtype = 2147483650; filetype = 2; ncmds = 21; sizeofcmds = 1336 }
    backboardd   = @{ cputype = 16777228; cpusubtype = 2147483650; filetype = 2; ncmds = 65; sizeofcmds = 7960 }
    runningboardd = @{ cputype = 16777228; cpusubtype = 2147483650; filetype = 2; ncmds = 23; sizeofcmds = 1976 }
}
foreach ($exeName in $expected.Keys) {
    $exe = $summary.decmpfs_reconstruction.executables.$exeName
    if ($null -eq $exe -or -not $exe.macho_structure_valid) {
        Write-Host "MISMATCH $exeName macho_structure_valid"
        $script:failures++
        continue
    }
    $want = $expected[$exeName]
    Assert-Equal "$exeName cputype" $exe.macho_cputype $want.cputype
    Assert-Equal "$exeName cpusubtype" $exe.macho_cpusubtype $want.cpusubtype
    Assert-Equal "$exeName filetype" $exe.macho_filetype $want.filetype
    Assert-Equal "$exeName ncmds" $exe.macho_ncmds $want.ncmds
    Assert-Equal "$exeName sizeofcmds" $exe.macho_sizeofcmds $want.sizeofcmds
}

$summaryNs = $summary.ans_device_tree.namespace_records
$contractNs = $contract.ans_node.properties.namespaces.decoded
if ($summaryNs.Count -ne $contractNs.Count / 3) {
    Write-Host "MISMATCH namespace record count"
    $script:failures++
} else {
    for ($i = 0; $i -lt $summaryNs.Count; $i++) {
        $w0 = $contractNs[$i * 3]
        $w1 = $contractNs[$i * 3 + 1]
        $w2 = $contractNs[$i * 3 + 2]
        if ($summaryNs[$i].nsid -ne $w0 -or
            $summaryNs[$i].nstype -ne $w1 -or
            $summaryNs[$i].word2 -ne $w2) {
            Write-Host "MISMATCH namespace[$i]"
            $script:failures++
        }
    }
    if ($script:failures -eq 0) {
        Write-Host "OK namespaces ($($summaryNs.Count) records)"
    }
}

$decodedQ = $contract.ans_node.properties.'nvme-queue-entries'.decoded_ints[0]
Assert-Equal 'nvme_queue_entries' $summary.ans_device_tree.nvme_queue_entries $decodedQ
Assert-Equal 'nvme_queue_entries_raw' $summary.ans_device_tree.nvme_queue_entries_raw_hex '40000000'

$decodedInts = $contract.ans_node.properties.interrupts.decoded_ints
$summaryInts = $summary.ans_device_tree.interrupts
if (($decodedInts -join ',') -cne ($summaryInts -join ',')) {
    Write-Host "MISMATCH interrupts"
    $script:failures++
} else {
    Write-Host "OK interrupts"
}

$decodedClocks = $contract.ans_node.properties.'clock-ids'.decoded_ints
$summaryClocks = $summary.ans_device_tree.clock_ids
if (($decodedClocks -join ',') -cne ($summaryClocks -join ',')) {
    Write-Host "MISMATCH clock-ids"
    $script:failures++
} else {
    Write-Host "OK clock-ids"
}

$decodedIommu = $contract.ans_node.properties.'iommu-parent'.decoded_ints[0]
Assert-Equal 'iommu-parent' $summary.ans_device_tree.iommu_parent $decodedIommu
$decodedNvIdx = $contract.ans_node.properties.'nvme-interrupt-idx'.decoded_ints[0]
Assert-Equal 'nvme-interrupt-idx' $summary.ans_device_tree.nvme_interrupt_idx $decodedNvIdx

$regDecoded = $contract.ans_node.properties.reg.decoded
$regSummary = $summary.ans_device_tree.reg_mmio
if ($regDecoded.Count -ne $regSummary.Count) {
    Write-Host "MISMATCH reg tuple count"
    $script:failures++
} else {
    for ($i = 0; $i -lt $regDecoded.Count; $i++) {
        $expectedBase = '0x{0:x}' -f [uint64]$regDecoded[$i].base
        $expectedSize = '0x{0:x}' -f [uint64]$regDecoded[$i].size
        if ($regSummary[$i].base -cne $expectedBase -or
            $regSummary[$i].size -cne $expectedSize) {
            Write-Host "MISMATCH reg[$i]"
            $script:failures++
        }
    }
    if ($script:failures -eq 0) {
        Write-Host "OK reg ($($regDecoded.Count) tuples, base+size)"
    }
}


# ================= 57ZD: IOS_STORAGE_LBA_CONTRACT =================
$lba = $lbaRaw | ConvertFrom-Json

Assert-Equal 'lba_iteration' $lba.iteration '57ZE'
Assert-Equal 'lba_device' $lba.input_identity.device 'iPhone15,4'
Assert-Equal 'lba_board' $lba.input_identity.board 'd37ap'
Assert-Equal 'lba_soc' $lba.input_identity.soc 't8120'
Assert-Equal 'lba_build' $lba.input_identity.build '24A437'
Assert-Equal 'lba_bootkc_sha' $lba.input_identity.bootkc_sha256 'C01B133237EB9C5AA6C7ED38F54ED5DB924B4BA2E6465CD51F0245B4C823E800'
Assert-Equal 'lba_identity' $lba.input_identity.IOS_STORAGE_LBA_INPUT_IDENTITY_PASS 'True'

# --- APFS vs NVMe separation; host sector must be reclassified ---
Assert-Equal 'lba_apfs_nvme_sep' $lba.block_size_separation.APFS_VS_NVME_BLOCK_SIZE_SEPARATION_PASS 'True'
Assert-Equal 'lba_apfs_block' $lba.block_size_separation.APFS_CONTAINER_BLOCK_SIZE 4096
Assert-Equal 'lba_nvme_block' $lba.block_size_separation.NVME_NAMESPACE_LBA_SIZE 4096
Assert-Equal 'lba_nvme_shift' $lba.block_size_separation.NVME_NAMESPACE_LBA_SHIFT 12
Assert-Equal 'lba_host_vs_guest_sep' $lba.block_size_separation.HOST_BACKING_VS_GUEST_LBA_SEPARATION_PASS 'True'
# 57ZD rule: HOST_BACKING_SECTOR_SIZE must NOT claim 512 without proof
if ($lba.block_size_separation.HOST_BACKING_SECTOR_SIZE -eq 512) {
    Write-Host "MISMATCH HOST_BACKING_SECTOR_SIZE=512 claimed without backing-layer proof (57ZD rule)"
    $script:failures++
} else {
    Write-Host "OK HOST_BACKING_SECTOR_SIZE reclassified (no unproven 512 claim)"
}

# --- Identify path: 0x11 selector + NCAP field ---
Assert-Equal 'lba_identify_path' $lba.identify_path.ANS_IDENTIFY_NAMESPACE_LBA_PATH_PASS 'True'
Assert-Equal 'lba_capacity_offset_pass' $lba.identify_path.IDENTIFY_NAMESPACE_CAPACITY_FIELD_OFFSET_PASS 'True'
Assert-Equal 'lba_offset8_field' $lba.identify_path.offset_8_field 'NCAP'
Assert-Equal 'lba_selector_semantics' $lba.identify_path.APPLE_NVME_COMMAND_SELECTOR_0X11_SEMANTICS_PASS 'True'
Assert-Equal 'lba_selector_class' $lba.identify_path.selector_0x11.classification 'APPLE_INTERNAL_OPERATION_SELECTOR'
# 57ZD rule: "NSZE @ offset 8" is forbidden
$nszeAt8 = $lba.identify_path.fields | Where-Object { $_.name -eq 'NSZE' -and $_.offset -eq 8 }
if ($nszeAt8) {
    Write-Host "MISMATCH NSZE labeled at offset 8 (standard layout: NSZE@0, NCAP@8)"
    $script:failures++
} else {
    Write-Host "OK IDENTIFY_NAMESPACE_CAPACITY_FIELD_OFFSET (offset 8 = NCAP)"
}
# 57ZD rule: "Identify Namespace opcode 0x11" wording is forbidden without the selector classification
if ($lbaRaw -match 'Identify Namespace opcode 0x11') {
    Write-Host "MISMATCH 'Identify Namespace opcode 0x11' wording present without Apple-selector classification"
    $script:failures++
} else {
    Write-Host "OK 0x11 reclassified as APPLE_INTERNAL_OPERATION_SELECTOR"
}

# --- WORD2 = NCAP semantics ---
Assert-Equal 'lba_word2_field_identity' $lba.namespace_struct.ANS_NAMESPACE_WORD2_FIELD_IDENTITY_PASS 'True'
Assert-Equal 'lba_word2_semantics' $lba.namespace_struct.ANS_NAMESPACE_WORD2_SEMANTICS_PASS 'True'
Assert-Equal 'lba_word2_nvme_field' $lba.namespace_struct.word2_semantics.NVME_IDENTIFY_FIELD 'NCAP'
Assert-Equal 'lba_word2_unit' $lba.namespace_struct.word2_semantics.UNIT 'LBA'
Assert-Equal 'lba_struct_layout' $lba.namespace_struct.ANS_NAMESPACE_STRUCT_LAYOUT_PASS 'True'
Assert-Equal 'lba_ns_count' $lba.namespace_struct.records.Count 7

# Cross-check namespace records against the DT contract
$lbaRecords = $lba.namespace_struct.records
$summaryNs = $summary.ans_device_tree.namespace_records
Assert-Equal 'lba_ns_count_cross' $summaryNs.Count 7
for ($i = 0; $i -lt 7; $i++) {
    Assert-Equal "lba_ns$($i+1)_nsid" $lbaRecords[$i].nsid $summaryNs[$i].nsid
    Assert-Equal "lba_ns$($i+1)_nstype" $lbaRecords[$i].nstype $summaryNs[$i].nstype
    Assert-Equal "lba_ns$($i+1)_word2" $lbaRecords[$i].word2 $summaryNs[$i].word2
}

# --- publication state consistency ---
Assert-Equal 'lba_shared_pub_path' $lba.namespace_map.IOS_NAMESPACE_SHARED_PUBLICATION_PATH_PASS 'True'
Assert-Equal 'lba_per_nsid_runtime' $lba.namespace_map.PER_NSID_PUBLICATION_RUNTIME_CONFIRMED 'False'
Assert-Equal 'lba_pub_state_consistency' $lba.namespace_map.IOS_NAMESPACE_PUBLICATION_STATE_CONSISTENCY_PASS 'True'
# 57ZD rule: publication map must NOT claim PASS while records are PENDING_RUNTIME
if ($lba.namespace_map.IOS_NAMESPACE_PUBLICATION_MAP_PASS -eq 'True') {
    $anyPending = $false
    foreach ($rec in $lba.namespace_map.records) {
        if ($rec.published -eq 'PENDING_RUNTIME') { $anyPending = $true }
    }
    if ($anyPending) {
        Write-Host "MISMATCH IOS_NAMESPACE_PUBLICATION_MAP_PASS=true while records are PENDING_RUNTIME"
        $script:failures++
    } else {
        Write-Host "OK publication map consistent (static per-NSID proof)"
    }
} else {
    Write-Host "OK publication map not over-claimed (shared path only)"
}
# 57ZD rule: NSID1 driver_role must NOT contain 'root' while root selection is open
$nsid1Role = "$($lba.namespace_map.records[0].driver_role)"
if ($nsid1Role -match '^primary/root|primary / root|root namespace') {
    Write-Host "MISMATCH NSID1 driver_role contains 'root' while IOS_ROOT_DEVICE_SELECTION is open"
    $script:failures++
} else {
    Write-Host "OK NSID1 role reworded (large-capacity namespace candidate)"
}
Assert-Equal 'lba_system_candidate' $lba.system_namespace_candidate.IOS_SYSTEM_NAMESPACE_CANDIDATE_PASS 'True'
Assert-Equal 'lba_system_class' $lba.system_namespace_candidate.classification 'CANDIDATE'

# --- image reconciliation ---
Assert-Equal 'lba_image_recon' $lba.image_reconciliation.IOS_BACKING_IMAGE_LBA_RECONCILIATION_PASS 'True'
Assert-Equal 'lba_system_img_size' $lba.image_reconciliation.images[0].size 9615441920
Assert-Equal 'lba_system_img_lbas' $lba.image_reconciliation.images[0].lbas_4096 2347520
Assert-Equal 'lba_cryptex_img_size' $lba.image_reconciliation.images[1].size 6014631936
Assert-Equal 'lba_cryptex_img_lbas' $lba.image_reconciliation.images[1].lbas_4096 1468416
Assert-Equal 'lba_ramdisk_img_size' $lba.image_reconciliation.images[2].size 243269632
Assert-Equal 'lba_ramdisk_img_lbas' $lba.image_reconciliation.images[2].lbas_4096 59392
foreach ($img in $lba.image_reconciliation.images) {
    if (-not $img.aligned_4096) {
        Write-Host "MISMATCH image $($img.name) not 4096-aligned"
        $script:failures++
    }
}

# --- external reference audit ---
Assert-Equal 'lba_ext_audit' $lba.external_reference_audit.EXTERNAL_LBA_REFERENCE_AUDIT_PASS 'True'
$stdRef = $lba.external_reference_audit.standard_nvme_reference
Assert-Equal 'lba_std_nsze' $stdRef.identify_namespace_layout[0].offset 0
Assert-Equal 'lba_std_ncap' $stdRef.identify_namespace_layout[1].offset 8
Assert-Equal 'lba_std_nuse' $stdRef.identify_namespace_layout[2].offset 16
Assert-Equal 'lba_std_nlbaf' $stdRef.identify_namespace_layout[3].offset 25
Assert-Equal 'lba_std_flbas' $stdRef.identify_namespace_layout[4].offset 26
Assert-Equal 'lba_std_lbaf' $stdRef.identify_namespace_layout[5].offset 128
Assert-Equal 'lba_std_identify_opcode' $stdRef.admin_identify_opcode '0x06'

# --- LBA proof (preserved from 57ZC; not reopened) ---
Assert-Equal 'lba_guest_size' $lba.lba_proof.IOS_GUEST_VISIBLE_LBA_SIZE_PASS 'True'
Assert-Equal 'lba_guest_bytes' $lba.lba_proof.NVME_NAMESPACE_LBA_SIZE 4096
Assert-Equal 'lba_guest_shift' $lba.lba_proof.NVME_NAMESPACE_LBA_SHIFT 12
Assert-Equal 'lba_capacity_unit' $lba.lba_proof.IOS_NAMESPACE_CAPACITY_UNIT_PASS 'True'

# --- 4-artifact cross-consistency (LBA) ---
Assert-Equal 'x_lba_controller' $lba.input_identity.CURRENT_CONTROLLER_CLASS $sumKm.CURRENT_CONTROLLER_CLASS
Assert-Equal 'x_lba_provider' $lba.input_identity.CURRENT_PROVIDER_CLASS $sumKm.CURRENT_PROVIDER_CLASS
Assert-Equal 'x_lba_queue_depth' $lba.input_identity.nvme_queue_entries $summary.ans_device_tree.nvme_queue_entries
Assert-Equal 'x_lba_controller_expected' $lba.input_identity.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
Assert-Equal 'x_lba_provider_expected' $lba.input_identity.CURRENT_PROVIDER_CLASS 'RTBuddyService'
Assert-Equal 'x_lba_bootkc_sha_cross' $lba.input_identity.bootkc_sha256 $ansMatch.input_identity.bootkc_sha256
Assert-Equal 'x_lba_device_cross' $lba.input_identity.device $ansMatch.input_identity.device

# --- canonical close state ---
Assert-Equal 'lba_contract' $lba.canonical_state.IOS_STORAGE_LBA_CONTRACT 'PASS_CLOSED'
Assert-Equal 'lba_contract_pass' $lba.canonical_state.IOS_STORAGE_LBA_CONTRACT_PASS 'True'
Assert-Equal 'lba_contract_durable' $lba.canonical_state.IOS_STORAGE_LBA_CONTRACT_DURABLE_PASS 'True'
Assert-Equal 'lba_semantic_consistency' $lba.canonical_state.IOS_LBA_SEMANTIC_CONSISTENCY_PASS 'True'
Assert-Equal 'lba_capacity_field' $lba.canonical_state.IDENTIFY_NAMESPACE_CAPACITY_FIELD 'NCAP'
Assert-Equal 'lba_next_gate' $lba.canonical_state.next_gate 'SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK'

# --- preboom summary cross-check ---
Assert-Equal 'x_preboom_lba_contract' $summary.storage_gates_open.IOS_STORAGE_LBA_CONTRACT 'PASS_CLOSED'
Assert-Equal 'x_preboom_lba_next' $summary.storage_gates_open.SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK 'PASS_CLOSED'
$sumLba = $summary.ios_storage_lba
Assert-Equal 'x_preboom_lba_size' $sumLba.NVME_NAMESPACE_LBA_SIZE 4096
Assert-Equal 'x_preboom_lba_shift' $sumLba.NVME_NAMESPACE_LBA_SHIFT 12
Assert-Equal 'x_preboom_lba_apfs' $sumLba.APFS_CONTAINER_BLOCK_SIZE 4096
Assert-Equal 'x_preboom_lba_contract2' $sumLba.IOS_STORAGE_LBA_CONTRACT 'PASS_CLOSED'
Assert-Equal 'x_preboom_lba_queue' $sumLba.NVME_QUEUE_ENTRIES 64
Assert-Equal 'x_preboom_lba_controller' $sumLba.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
Assert-Equal 'x_preboom_lba_provider' $sumLba.CURRENT_PROVIDER_CLASS 'RTBuddyService'
Assert-Equal 'x_preboom_lba_next2' $sumLba.next_gate 'SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK'
Assert-Equal 'x_preboot_compat_action' $sumLba.PREBOOT_ANS_DEVICE_TREE_COMPAT_RESTORE 'OPEN_ACTION_ITEM'
if ($script:failures -eq 0) {
    Write-Host "IOS_LBA_CROSS_ARTIFACT_CONSISTENCY_PASS"
    Write-Host "IOS_LBA_SEMANTIC_CONSISTENCY_PASS"
}


# ================= 57ZE: stale-prose refusal + third-field + wire-opcode =================
# 1. LBA_ACTIVE_STATE_HAS_NO_STALE_NSZE_SEMANTICS_PASS: refuse stale active prose.
#    Allowed NSZE text is only the standard-reference documentation.
$staleProse = @(
    'expected NSZE comparison',
    'NSZE is compared directly against DT word2',
    'Identify NSZE (offset 8)',
    'compares Identify NSZE',
    'Identify Namespace (opcode 0x11',
    'Identify Namespace opcode 0x11'
)
$staleProseFound = $false
foreach ($phrase in $staleProse) {
    if ($lbaRaw -match [regex]::Escape($phrase)) {
        Write-Host "STALE_PROSE_DETECTED: $phrase"
        $staleProseFound = $true
    }
}
if ($staleProseFound) {
    Write-Host "MISMATCH LBA_ACTIVE_STATE_HAS_NO_STALE_NSZE_SEMANTICS"
    $script:failures++
} else {
    Write-Host "OK LBA_ACTIVE_STATE_HAS_NO_STALE_NSZE_SEMANTICS_PASS"
}
# 2. APPLE_SELECTOR_0X11_ACTIVE_WORDING_PASS: no active text may call 0x11 an opcode
if ($lba.identify_path.selector_0x11.classification -cne 'APPLE_INTERNAL_OPERATION_SELECTOR') {
    Write-Host "MISMATCH 0x11 not classified APPLE_INTERNAL_OPERATION_SELECTOR"
    $script:failures++
} else {
    Write-Host "OK APPLE_SELECTOR_0X11_ACTIVE_WORDING_PASS"
}
# 3. NVME_WIRE_OPCODE_NONBLOCKING_CLASSIFICATION_PASS
Assert-Equal 'lba_wire_opcode_status' $lba.identify_path.NVME_IDENTIFY_ADMIN_OPCODE_PROVEN 'PARTIAL_NON_BLOCKING'
Assert-Equal 'lba_wire_opcode_nonblocking' $lba.identify_path.NVME_WIRE_OPCODE_NONBLOCKING_CLASSIFICATION_PASS 'True'
# 4. ANS_NAMESPACE_THIRD_FIELD_RESOLVED_PASS (structured cross-artifact)
$thirdField = $summary.ans_device_tree.ANS_NAMESPACE_THIRD_FIELD
if ($null -eq $thirdField -or $thirdField -is [string]) {
    Write-Host "MISMATCH ANS_NAMESPACE_THIRD_FIELD not structured/RESOLVED"
    $script:failures++
} else {
    Assert-Equal 'lba_third_dt' $thirdField.DT_FIELD 'NSSize'
    Assert-Equal 'lba_third_nvme' $thirdField.NVME_FIELD 'NCAP'
    Assert-Equal 'lba_third_unit' $thirdField.UNIT 'LBA'
    Assert-Equal 'lba_third_status' $thirdField.STATUS 'RESOLVED'
    # cross-artifact: must match the LBA contract word2 semantics
    Assert-Equal 'lba_third_cross_nvme' $thirdField.NVME_FIELD $lba.namespace_struct.word2_semantics.NVME_IDENTIFY_FIELD
    Assert-Equal 'lba_third_cross_unit' $thirdField.UNIT $lba.namespace_struct.word2_semantics.UNIT
    if ($thirdField.STATUS -ne 'RESOLVED' -and $thirdField.NVME_FIELD -eq 'NCAP') {
        Write-Host "MISMATCH third field claims NCAP but STATUS != RESOLVED"
        $script:failures++
    } else {
        Write-Host "OK LBA_THIRD_FIELD_CROSS_ARTIFACT_PASS"
    }
}
# 5. Regression: unchanged technical facts
Assert-Equal 'lba_regress_ncap_off' $lba.identify_path.offset_8_field 'NCAP'
Assert-Equal 'lba_regress_nsze_std' $lba.external_reference_audit.standard_nvme_reference.identify_namespace_layout[0].offset 0
Assert-Equal 'lba_regress_ncap_std' $lba.external_reference_audit.standard_nvme_reference.identify_namespace_layout[1].offset 8

# ================= 57ZF: SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK =================
$cryptexPath = Join-Path $root 'artifacts\evidence\05f\phase05f-cryptex-authoritative-root-walk.json'
$cryptexRaw = Get-Content $cryptexPath -Raw
$cryptex = $cryptexRaw | ConvertFrom-Json

# 1. Input identity must agree across cryptex + preboom + LBA artifacts
Assert-Equal 'cryptex_identity_sha' $cryptex.input_identity.cryptex_image.sha256 $lba.input_identity.cryptex_image.sha256
Assert-Equal 'cryptex_identity_size' $cryptex.input_identity.cryptex_image.size $lba.input_identity.cryptex_image.size
Assert-Equal 'cryptex_identity_blocksize' $cryptex.input_identity.cryptex_image.apfs_block_size 4096
Assert-Equal 'cryptex_identity_lba4096' $cryptex.input_identity.cryptex_image.lba_4096_alignment $true

# 2. Scan-shortcut signatures must be absent from the durable cryptex artifact
$cryptexShortcuts = @(
    'magic scan only',
    'highest physical APSB block',
    'highest XID found globally',
    'string-search selected root',
    'known file path found without root-tree traversal'
)
$cryptexShortcutFound = $false
foreach ($sig in $cryptexShortcuts) {
    if ($cryptexRaw -match [regex]::Escape($sig)) {
        Write-Host "MISMATCH cryptex scan-shortcut signature present: $sig"
        $cryptexShortcutFound = $true
    }
}
if ($cryptexShortcutFound) { $script:failures++ } else { Write-Host "OK CRYPTEX_AUTHORITATIVE_WALK_FAIL_CLOSED_PASS" }

# 3. Closure gate: all 16 required PASS flags must be true
$cryptexRequired = @(
    'CRYPTEX_AUTHORITATIVE_NXSB_PASS',
    'CRYPTEX_AUTHORITATIVE_OBJECT_CHECKSUM_PASS',
    'CRYPTEX_CHECKPOINT_MAP_PASS',
    'CRYPTEX_CONTAINER_VOLUME_ENUMERATION_PASS',
    'CRYPTEX_SYSTEMOS_VOLUME_IDENTITY_PASS',
    'CRYPTEX_VOLUME_OMAP_PASS',
    'CRYPTEX_SNAPSHOT_METADATA_ENUMERATION_PASS',
    'CRYPTEX_AUTHORITATIVE_SNAPSHOT_PASS',
    'CRYPTEX_AUTHORITATIVE_ROOT_TREE_RESOLUTION_PASS',
    'CRYPTEX_AUTHORITATIVE_FILESYSTEM_WALK_PASS',
    'CRYPTEX_ROOT_WALK_KNOWN_FILE_PROOF_PASS',
    'CRYPTEX_SCAN_VS_AUTHORITATIVE_WALK_SEPARATION_PASS',
    'CRYPTEX_AUTHORITATIVE_WALK_FAIL_CLOSED_PASS',
    'CRYPTEX_AUTHORITATIVE_ROOT_WALK_DURABLE_PASS',
    'CRYPTEX_ROOT_WALK_CROSS_ARTIFACT_CONSISTENCY_PASS',
    'CRYPTEX_ROOT_WALK_INPUT_IDENTITY_PASS',
    'CRYPTEX_CHECKPOINT_MAPPING_STRIDE_PASS',
    'CRYPTEX_CHECKPOINT_MAP_REDECODE_PASS',
    'CRYPTEX_CHECKPOINT_MAP_GEOMETRY_PASS',
    'CRYPTEX_DURABLE_JSON_UNIQUE_KEYS_PASS',
    'CRYPTEX_JSON_DUPLICATE_KEY_REFUSAL_PASS',
    'CRYPTEX_OBJECT_INTEGRITY_POLICY_PASS',
    'CRYPTEX_NOHEADER_FAIL_CLOSED_POLICY_PASS',
    'CRYPTEX_ROOT_WALK_KNOWN_FILE_REGRESSION_PASS'
)
foreach ($flag in $cryptexRequired) {
    $val = $cryptex.canonical_state.$flag
    if ($val -ne $true) {
        Write-Host "MISMATCH cryptex gate flag false/missing: $flag = $val"
        $script:failures++
    } else {
        Write-Host "OK $flag"
    }
}

# 4. Volume identity + walk shape must match the recorded authoritative values
Assert-Equal 'cryptex_vol_name' $cryptex.systemos_volume_identity.volume_name 'Rave24A437.D37SystemCryptex'
Assert-Equal 'cryptex_vol_uuid' $cryptex.systemos_volume_identity.volume_uuid '7f74e822669746de878e1b0172ed0eb9'
Assert-Equal 'cryptex_root_tree_oid' $cryptex.root_tree_resolution.root_tree_oid 1291
Assert-Equal 'cryptex_root_block' $cryptex.root_tree_resolution.resolved_physical_block 61526
Assert-Equal 'cryptex_walk_nodes' $cryptex.filesystem_walk.nodes_walked 7011
Assert-Equal 'cryptex_walk_records' $cryptex.filesystem_walk.records_decoded 457595
Assert-Equal 'cryptex_walk_failures' $cryptex.filesystem_walk.checksum_or_structural_failures 0
Assert-Equal 'cryptex_known_file_cnid' $cryptex.known_file_proof.inode.cnid 132
Assert-Equal 'cryptex_known_file_sha' $cryptex.known_file_proof.reconstruction.sha256 '09B639889B59F53E04C70D81D627F892D411725E22295E3610F4B076E74F7AE1'
Assert-Equal 'cryptex_plist_build' $cryptex.known_file_proof.reconstruction.plist_contents.ProductBuildVersion '24A437'
Assert-Equal 'cryptex_plist_version' $cryptex.known_file_proof.reconstruction.plist_contents.ProductVersion '27.0'

# 5. Cross-artifact: preboom summary must also carry PASS_CLOSED
Assert-Equal 'cryptex_preboom_closed' $summary.sealed_container_walks.SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK 'PASS_CLOSED'
Assert-Equal 'cryptex_preboom_next' $summary.storage_gates_open.CRYPTEX_ATTACHMENT_MODEL 'PASS_CLOSED'
Assert-Equal 'cryptex_57ZF' $summary.certified.ITERATION_57ZF 'PASS_CLOSED'
Assert-Equal 'cryptex_57ZFA' $summary.certified.ITERATION_57ZFA 'PASS_CLOSED'
Assert-Equal 'cryptex_57ZE_closed' $summary.certified.ITERATION_57ZE 'PASS_CLOSED'

# 6. 57ZFA: checkpoint-map stride/geometry + integrity policy + duplicate-key refusal
# 6. 57ZFA: checkpoint-map stride/geometry + integrity policy + duplicate-key refusal
Assert-Equal 'cryptex_stride_used' $cryptex.checkpoint_map.CHECKPOINT_MAP_ENTRY_STRIDE_USED 40

# 57ZF/57ZFA reviewer-state synchronization (PASS_CLOSED)
Assert-Equal 'cryptex_cs_57ZF' $cryptex.canonical_state.ITERATION_57ZF 'PASS_CLOSED'
Assert-Equal 'cryptex_cs_57ZFA' $cryptex.canonical_state.ITERATION_57ZFA 'PASS_CLOSED'
Assert-Equal 'cryptex_cs_gate' $cryptex.canonical_state.SEALED_CRYPTEX_AUTHORITATIVE_ROOT_WALK 'PASS_CLOSED'
Assert-Equal 'cryptex_cs_next' $cryptex.canonical_state.next_gate 'CRYPTEX_ATTACHMENT_MODEL'
Assert-Equal 'cryptex_stride_first_offset' $cryptex.checkpoint_map.CHECKPOINT_MAP_FIRST_ENTRY_OFFSET 40
Assert-Equal 'cryptex_stride_count' $cryptex.checkpoint_map.CHECKPOINT_MAP_ENTRY_COUNT 5
Assert-Equal 'cryptex_stride_class' $cryptex.checkpoint_map.'57ZF_CHECKPOINT_STRIDE_ERROR' 'DURABLE_PROSE_ONLY'
Assert-Equal 'cryptex_geom_header' $cryptex.checkpoint_map.geometry.header_size_before_entries 40
Assert-Equal 'cryptex_geom_stride' $cryptex.checkpoint_map.geometry.entry_stride 40
Assert-Equal 'cryptex_geom_count' $cryptex.checkpoint_map.geometry.entry_count 5
Assert-Equal 'cryptex_geom_end' $cryptex.checkpoint_map.geometry.entries_end_byte 240
Assert-Equal 'cryptex_geom_within' $cryptex.checkpoint_map.geometry.within_block $true
if (($cryptex.checkpoint_map.CHECKPOINT_MAP_ENTRY_STRIDE_USED * $cryptex.checkpoint_map.CHECKPOINT_MAP_ENTRY_COUNT + $cryptex.checkpoint_map.CHECKPOINT_MAP_FIRST_ENTRY_OFFSET) -gt 4096) {
    Write-Host "MISMATCH checkpoint map geometry exceeds block size"
    $script:failures++
} else {
    Write-Host "OK CRYPTEX_CHECKPOINT_MAP_GEOMETRY_PASS"
}
Assert-Equal 'cryptex_redecode_0' $cryptex.checkpoint_map.independent_redecode[0].paddr 56168
Assert-Equal 'cryptex_redecode_1' $cryptex.checkpoint_map.independent_redecode[1].paddr 56169
Assert-Equal 'cryptex_redecode_2' $cryptex.checkpoint_map.independent_redecode[2].paddr 56170
Assert-Equal 'cryptex_redecode_3' $cryptex.checkpoint_map.independent_redecode[3].paddr 56171
Assert-Equal 'cryptex_redecode_4' $cryptex.checkpoint_map.independent_redecode[4].paddr 56172
$redecodeOids = ($cryptex.checkpoint_map.independent_redecode | ForEach-Object { $_.oid }) -join " "
Assert-Equal 'cryptex_redecode_oids' $redecodeOids '1025 1283 1286 1287 1288'
Assert-Equal 'cryptex_policy_headered' $cryptex.object_integrity_policy.CRYPTEX_OBJECT_INTEGRITY_POLICY_PASS $true

# headered-object checksum audit: every recorded entry must be VERIFIED
foreach ($obj in $cryptex.object_checksum_audit.verified_objects) {
    if ($obj.checksum -ne 'VERIFIED') {
        Write-Host "MISMATCH headered object checksum not VERIFIED: $($obj.object) @ block $($obj.block) = $($obj.checksum)"
        $script:failures++
    }
}
Assert-Equal 'cryptex_policy_noheader' $cryptex.fail_closed_rules.CRYPTEX_NOHEADER_FAIL_CLOSED_POLICY_PASS $true
$badChecksumWording = @('unverified checksum on any object in the authoritative chain')
foreach ($w in $badChecksumWording) {
    if ($cryptexRaw -match [regex]::Escape($w)) {
        Write-Host "MISMATCH stale broad checksum wording present: $w"
        $script:failures++
    }
}
Assert-Equal 'cryptex_known_file_regression' $cryptex.known_file_proof.reconstruction.CRYPTEX_ROOT_WALK_KNOWN_FILE_REGRESSION_PASS $true
Assert-Equal 'cryptex_json_unique' $cryptex.json_hygiene.CRYPTEX_DURABLE_JSON_UNIQUE_KEYS_PASS $true
Assert-Equal 'cryptex_json_dup_refusal' $cryptex.json_hygiene.CRYPTEX_JSON_DUPLICATE_KEY_REFUSAL_PASS $true

# 7. 57ZFA: run the duplicate-key validator BEFORE ConvertFrom-Json can hide duplicates
$dupValidator = Join-Path $PSScriptRoot 'phase05f-json-duplicate-key-check.py'
foreach ($artifact in @($cryptexPath, $summaryPath, (Join-Path $root 'artifacts\evidence\05f\phase05f-ios-storage-lba-contract.json'))) {
    & python $dupValidator $artifact
    if ($LASTEXITCODE -ne 0) {
        Write-Host "MISMATCH duplicate-key validator rejected $artifact"
        $script:failures++
    } else {
        Write-Host "OK CRYPTEX_JSON_DUPLICATE_KEY_REFUSAL_PASS ($artifact)"
    }
}

# ================= 57ZG: CRYPTEX_ATTACHMENT_MODEL =================
$attachPath = Join-Path $root 'artifacts\evidence\05f\phase05f-cryptex-attachment-model.json'
$attachRaw = Get-Content $attachPath -Raw
$attach = $attachRaw | ConvertFrom-Json

# 1. Iteration + gate state
Assert-Equal 'attach_preboom_iter' $summary.iteration '57ZH'
Assert-Equal 'attach_preboom_certified' $summary.certified.CRYPTEX_ATTACHMENT_MODEL 'PASS_CLOSED'
Assert-Equal 'attach_preboom_next_root' $summary.storage_gates_open.IOS_ROOT_DEVICE_SELECTION 'NEXT'
Assert-Equal 'attach_preboom_next_transition' $summary.storage_gates_open.IOS_ROOT_TRANSITION_MODEL 'NEXT'

# 2. All 11 required exit flags must be true
$attachRequired = @(
    'CRYPTEX_ATTACHMENT_INPUT_IDENTITY_PASS',
    'CRYPTEX_ATTACHMENT_ACTOR_PASS',
    'CRYPTEX_ATTACHMENT_SOURCE_PASS',
    'CRYPTEX_ATTACHMENT_TARGET_PASS',
    'CRYPTEX_ATTACHMENT_MECHANISM_PASS',
    'CRYPTEX_ATTACHMENT_TIMING_PASS',
    'CRYPTEX_ATTACHMENT_METADATA_PASS',
    'CRYPTEX_ATTACHMENT_PATH_PROVENANCE_PASS',
    'CRYPTEX_ATTACHMENT_ORDERING_PASS',
    'CRYPTEX_ATTACHMENT_MODEL_DURABLE_PASS',
    'CRYPTEX_ATTACHMENT_CROSS_ARTIFACT_CONSISTENCY_PASS'
)
foreach ($flag in $attachRequired) {
    $val = $attach.canonical_state.$flag
    if ($val -ne $true) {
        Write-Host "MISMATCH attachment gate flag false/missing: $flag = $val"
        $script:failures++
    } else {
        Write-Host "OK $flag"
    }
}

# 3. Volume identities must agree with the cryptex + preboom artifacts
Assert-Equal 'attach_cryptex_uuid' $attach.volume_identity.system_cryptex_volume.uuid $cryptex.systemos_volume_identity.volume_uuid
Assert-Equal 'attach_cryptex_name' $attach.volume_identity.system_cryptex_volume.name $cryptex.systemos_volume_identity.volume_name
Assert-Equal 'attach_base_name' $attach.volume_identity.base_system_volume.name 'Rave24A437.D37OS'
Assert-Equal 'attach_base_uuid' $attach.volume_identity.base_system_volume.uuid '9a503cf26d7a4fdaa233600dd13b4994'
Assert-Equal 'attach_prov_sv_sha' $attach.path_provenance.example.cryptex_sha256 $cryptex.known_file_proof.reconstruction.sha256

# 4. Fail-closed: attachment model must not be based on weak shortcuts
$attachShortcuts = @(
    'matching directory names alone',
    'image contents alone',
    'historical iOS behavior',
    'public implementations without current-build evidence',
    'guessed mount paths'
)
foreach ($sig in $attachShortcuts) {
    if ($attachRaw -match [regex]::Escape("based only on") -and $attachRaw -match [regex]::Escape($sig)) {
        # allowed only inside the explicit rejection list; verify the rejection list exists
        if ($attach.current_build_evidence.not_used_as_proof -notcontains $sig) {
            Write-Host "MISMATCH attachment shortcut present outside rejection list: $sig"
            $script:failures++
        }
    }
}
$attachRejectList = $attach.current_build_evidence.not_used_as_proof
foreach ($required in $attachShortcuts) {
    if ($attachRejectList -notcontains $required) {
        Write-Host "MISMATCH attachment rejection list missing: $required"
        $script:failures++
    }
}
if ($attach.current_build_evidence.CRYPTEX_ATTACHMENT_CROSS_ARTIFACT_CONSISTENCY_PASS -ne $true) {
    Write-Host "MISMATCH attachment cross-artifact consistency flag not true"
    $script:failures++
}

# 5. Duplicate-key validation for the attachment artifact
& python (Join-Path $PSScriptRoot 'phase05f-json-duplicate-key-check.py') $attachPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "MISMATCH attachment artifact duplicate keys"
    $script:failures++
} else {
    Write-Host "OK CRYPTEX_ATTACHMENT_DURABLE_JSON_UNIQUE"
}


# ================= 57ZH: CRYPTEX_NAMESPACE_BINDING =================
$bindPath = Join-Path $root 'artifacts\evidence\05f\phase05f-cryptex-namespace-binding.json'
$bindRaw = Get-Content $bindPath -Raw
$bind = $bindRaw | ConvertFrom-Json

Assert-Equal 'bind_preboom_iter' $summary.iteration '57ZH'
Assert-Equal 'bind_preboom_certified' $summary.certified.CRYPTEX_NAMESPACE_BINDING 'PASS_CLOSED'

$bindRequired = @(
    'CRYPTEX_BINDING_INPUT_IDENTITY_PASS',
    'CRYPTEX_MAPPING_TABLE_SOURCE_PASS',
    'CRYPTEX_CONSUMER_FUNCTION_PASS',
    'CRYPTEX_SOURCE_PATH_PASS',
    'CRYPTEX_DESTINATION_PATH_PASS',
    'CRYPTEX_END_TO_END_BINDING_PASS',
    'CRYPTEX_FEXT_INTEGRITY_ROLE_PASS',
    'CRYPTEX_BINDING_TIMING_PASS',
    'CRYPTEX_BINDING_CHECKER_PASS'
)
foreach ($flag in $bindRequired) {
    $val = $bind.canonical_state.$flag
    if ($val -ne $true) {
        Write-Host "MISMATCH binding gate flag false/missing: $flag = $val"
        $script:failures++
    } else {
        Write-Host "OK $flag"
    }
}

# exact consumer function + xrefs must be present
if ($bind.exact_consumer_function.function -notmatch '^apfs_mount') { Write-Host 'MISMATCH binding consumer function'; $script:failures++ } else { Write-Host 'OK CRYPTEX_CONSUMER_FUNCTION_PASS' }
if ($bind.exact_consumer_function.verified_branch_sequence.Count -lt 8) {
    Write-Host "MISMATCH binding consumer branch sequence incomplete"
    $script:failures++
} else {
    Write-Host "OK CRYPTEX_CONSUMER_FUNCTION_PASS"
}
Assert-Equal 'bind_mapping_pairtable' $bind.mapping_table_source.sources[0].location 'bootkc.bin __PRELINK_TEXT fileoff 0xa5a793'
Assert-Equal 'bind_source_path' $bind.source_path.source '/private/preboot/Cryptexes/OS'
Assert-Equal 'bind_dest_path' $bind.destination_runtime_path.destination '/System and /usr on the base system volume via firmlink composition (visible alias /System/Cryptexes/OS)'
Assert-Equal 'bind_e2e_sha' $bind.end_to_end_binding.example.sha256 '09B639889B59F53E04C70D81D627F892D411725E22295E3610F4B076E74F7AE1'
Assert-Equal 'bind_fext_oid' $bind.fext_integrity_role.fext_tree.oid 61503
Assert-Equal 'bind_integrity_oid' $bind.fext_integrity_role.integrity_meta.oid 1289

# duplicate-key validation
& python (Join-Path $PSScriptRoot 'phase05f-json-duplicate-key-check.py') $bindPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "MISMATCH binding artifact duplicate keys"
    $script:failures++
} else {
    Write-Host "OK CRYPTEX_BINDING_DURABLE_JSON_UNIQUE"
}

if ($script:failures -gt 0) {
    Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_FAIL"
    Write-Host "EVIDENCE_STALE_STATE_REFUSAL_FAIL"
    Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_FAIL"
    Write-Host "ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK_FAIL"
    Write-Host "IOS_LBA_CROSS_ARTIFACT_CONSISTENCY_FAIL"
    exit 1
}
Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_PASS"
Write-Host "EVIDENCE_STALE_STATE_REFUSAL_PASS"
Write-Host "ANS_DURABLE_ARTIFACT_SINGLE_STATE_PASS"
Write-Host "ANS_EVIDENCE_NON_SELF_REFERENTIAL_PASS"
Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_PASS"
Write-Host "ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK_PASS"
Write-Host "IOS_LBA_CROSS_ARTIFACT_CONSISTENCY_PASS"
exit 0
