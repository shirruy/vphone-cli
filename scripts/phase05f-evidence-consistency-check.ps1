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
    foreach ($raw in @($summaryRaw, $contractRaw, $ansMatchRaw)) {
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
Assert-Equal 'iteration' $summary.iteration '57ZB'
Assert-Equal 'ITERATION_57ZB' $summary.certified.ITERATION_57ZB 'PASS_PENDING_REVIEW'
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

if ($script:failures -gt 0) {
    Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_FAIL"
    Write-Host "EVIDENCE_STALE_STATE_REFUSAL_FAIL"
    Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_FAIL"
    Write-Host "ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK_FAIL"
    exit 1
}
Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_PASS"
Write-Host "EVIDENCE_STALE_STATE_REFUSAL_PASS"
Write-Host "ANS_DURABLE_ARTIFACT_SINGLE_STATE_PASS"
Write-Host "ANS_EVIDENCE_NON_SELF_REFERENTIAL_PASS"
Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_PASS"
Write-Host "ANS_NUB_MATCH_PROOF_DEPENDENCY_CHECK_PASS"
exit 0
