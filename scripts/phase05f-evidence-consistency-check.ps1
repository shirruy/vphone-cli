# Deterministic evidence cross-file consistency checker (Iteration 57ZA).
# Cross-checks three ANS artifacts (dt contract, kernel-driver-match,
# preboom storage summary) for raw DT equality, provider/controller class
# equality, and contract-status equality. Refuses the pre-57ZA
# length-0 vs length-4 nvme-linear-sq contradiction. Non-zero exit on
# any mismatch.

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
    'ANS_IOP_NUB_REGISTRY_NAME_TRANSFORM_PASS'
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

# --- iteration identity (57ZA) ---
Assert-Equal 'iteration' $summary.iteration '57ZA'
Assert-Equal 'ITERATION_57ZA' $summary.certified.ITERATION_57ZA 'PARTIAL_PASS'
Assert-Equal 'ITERATION_57Z' $summary.certified.ITERATION_57Z 'PARTIAL_PASS'
Assert-Equal 'ITERATION_57Y' $summary.certified.ITERATION_57Y 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57X' $summary.certified.ITERATION_57X 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57W' $summary.certified.ITERATION_57W 'PASS'
Assert-Equal 'ITERATION_57V' $summary.certified.ITERATION_57V 'PASS'
Assert-Equal '57T_certified' $summary.certified.ITERATION_57T_CERTIFIED_CLOSED 'YES'

# --- single-state enforcement on the durable kernel-driver-match JSON ---
$topKeys = $ansMatch.PSObject.Properties.Name
foreach ($forbidden in @('probe_score_matrix','nub_chain','winner_matrix','provider_resolution','nub_publisher','endpoint_publisher','asc_rtbuddy_chain_exact','winning_probe_reconciliation')) {
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
    Assert-Equal 'cs_predicate_result' $cs.nvme_linear_sq.ANS3_D37AP_PREDICATE_RESULT 'MATCH'
    Assert-Equal 'cs_predicate_revalidation' $cs.nvme_linear_sq.ANS3_D37AP_PREDICATE_REVALIDATION_PASS 'True'
    Assert-Equal 'cs_exact_class' $cs.ANS_EXACT_CONTROLLER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_winning_probe' $cs.ANS_EXACT_WINNING_PROBE_PASS 'True'
    Assert-Equal 'cs_controller' $cs.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
    Assert-Equal 'cs_provider' $cs.CURRENT_PROVIDER_CLASS 'RTBuddyService'
    Assert-Equal 'cs_provider_proven' $cs.ANS_PROVIDER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_nub_publisher' $cs.iop_ans_nub.ANS_IOP_NUB_PUBLISHER_PROVEN 'True'
    Assert-Equal 'cs_nub_match_source' $cs.iop_ans_nub.ANS_IOP_NUB_MATCH_SOURCE 'RUNTIME_CONFIRMATION_REQUIRED'
    Assert-Equal 'cs_nub_runtime_required' $cs.iop_ans_nub.ANS_IOP_NUB_PROVIDER_MATCH_RUNTIME_PROOF_REQUIRED 'True'
    Assert-Equal 'cs_ionamematch_compatible' $cs.iop_ans_nub.ANS_IOP_NUB_IONAMEMATCH_COMPATIBLE_PASS 'False'
    Assert-Equal 'cs_endpoint_publisher' $cs.endpoint.ANS2ENDPOINT1_PUBLISHER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_endpoint_args' $cs.endpoint.ANS2ENDPOINT1_EXACT_CALLSITE_ARGUMENTS 'NON_BLOCKING_IMPLEMENTATION_DETAIL'
    Assert-Equal 'cs_asc_chain' $cs.asc_rtbuddy_chain.ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS 'False'
    Assert-Equal 'cs_contract' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'
    Assert-Equal 'cs_contract_pass' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_PASS 'False'
    Assert-Equal 'cs_durable' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_DURABLE_PASS 'True'
    Assert-Equal 'cs_blocker' $cs.blocker 'ANS_IOP_NUB_PROVIDER_MATCH_RUNTIME_PROOF_REQUIRED: the exact 24A437 iop-ans-nub child exposes no IONameMatch-compatible static value and no static publication path was proven; runtime IORegistry evidence is the next blocker'
}

# --- three-artifact cross-consistency (57ZA core gate) ---
$dtCanon = $contract.canonical_state
$sumAns = $summary.ans_device_tree
$sumKm = $summary.ans_kernel_driver_match

Assert-Equal 'x_dt_nls_len' $dtCanon.NVME_LINEAR_SQ_LENGTH 0
Assert-Equal 'x_km_nls_len' $cs.nvme_linear_sq.length 0
Assert-Equal 'x_sum_nls_len' $sumAns.nvme_linear_sq_length 0
Assert-Equal 'x_dt_nls_raw' $dtCanon.NVME_LINEAR_SQ_RAW_HEX ''
Assert-Equal 'x_km_nls_raw' $cs.nvme_linear_sq.raw_hex ''
Assert-Equal 'x_sum_nls_raw' $sumAns.nvme_linear_sq_raw_hex ''
# explicit len0-vs-len4 contradiction refusal
if ($dtCanon.NVME_LINEAR_SQ_LENGTH -eq $cs.nvme_linear_sq.length -and $cs.nvme_linear_sq.length -eq 0) {
    Write-Host "OK NVME_LINEAR_SQ_RAW_DT_RECONCILIATION_PASS (all three artifacts agree length=0)"
} else {
    Write-Host "MISMATCH nvme-linear-sq length contradiction across artifacts"
    $script:failures++
}
Assert-Equal 'x_dt_role' $dtCanon.role 'ANS2'
Assert-Equal 'x_km_role' $cs.role 'ANS2'
Assert-Equal 'x_sum_role' $sumAns.role 'ANS2'
Assert-Equal 'x_dt_child' $dtCanon.child_node 'iop-ans-nub'
Assert-Equal 'x_km_child' $cs.child_node 'iop-ans-nub'
Assert-Equal 'x_sum_child' $sumAns.child_node 'iop-ans-nub'
Assert-Equal 'x_dt_compat' $dtCanon.child_compatible 'ABSENT'
Assert-Equal 'x_km_compat' $cs.child_compatible 'ABSENT'
Assert-Equal 'x_sum_compat' $sumAns.child_compatible 'ABSENT'
Assert-Equal 'x_km_controller' $cs.CURRENT_CONTROLLER_CLASS $sumKm.CURRENT_CONTROLLER_CLASS
Assert-Equal 'x_km_controller_expected' $sumKm.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
Assert-Equal 'x_km_provider' $cs.CURRENT_PROVIDER_CLASS $sumKm.CURRENT_PROVIDER_CLASS
Assert-Equal 'x_km_provider_expected' $sumKm.CURRENT_PROVIDER_CLASS 'RTBuddyService'
Assert-Equal 'x_km_contract' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT $sumKm.ANS_KERNEL_DRIVER_MATCH_CONTRACT
Assert-Equal 'x_km_contract_expected' $sumKm.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'
Assert-Equal 'x_sum_gate_contract' $summary.storage_gates_open.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'

if ($script:failures -eq 0) {
    Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_PASS"
}

# --- raw DT fixture child facts (57ZA reparse gate) ---
$childInfo = $contract.iop_ans_nub_child
Assert-Equal 'child_nprops' $childInfo.nprops 9
Assert-Equal 'child_compatible_present' $childInfo.compatible.present 'False'
Assert-Equal 'child_device_type_present' $childInfo.device_type.present 'False'
Assert-Equal 'child_name' $childInfo.name.decoded_string 'iop-ans-nub'
Assert-Equal 'D37AP_IOP_ANS_NUB_COMPATIBLE' $childInfo.compatible.D37AP_IOP_ANS_NUB_COMPATIBLE 'ABSENT'
Assert-Equal 'D37AP_IOP_ANS_NUB_DEVICE_TYPE' $childInfo.device_type.D37AP_IOP_ANS_NUB_DEVICE_TYPE 'ABSENT'
Assert-Equal 'D37AP_ANS_CHILD_RAW_REPARSE_PASS' $contract.reparse.D37AP_ANS_CHILD_RAW_REPARSE_PASS 'True'
Assert-Equal 'ans_nls_len0' $contract.ans_node.'nvme-linear-sq'.length 0
Assert-Equal 'ans_nls_raw_empty' $contract.ans_node.'nvme-linear-sq'.raw_hex ''

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

# --- decmpfs algo table + resourcefork flags ---
Assert-Equal 'algo4' $summary.decmpfs_reconstruction.algorithm_table.'4' 'zlib resource fork (CMP_TypeZlib)'
Assert-Equal 'resourcefork_flags.observed' $summary.decmpfs_reconstruction.resourcefork_flags.observed 1

$ds = $summary.decmpfs_reconstruction
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

# --- Mach-O identity fields ---
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

# --- namespaces ---
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

# --- nvme_queue_entries + raw hex ---
$decodedQ = $contract.ans_node.properties.'nvme-queue-entries'.decoded_ints[0]
Assert-Equal 'nvme_queue_entries' $summary.ans_device_tree.nvme_queue_entries $decodedQ
Assert-Equal 'nvme_queue_entries_raw' $summary.ans_device_tree.nvme_queue_entries_raw_hex '40000000'

# --- interrupts ---
$decodedInts = $contract.ans_node.properties.interrupts.decoded_ints
$summaryInts = $summary.ans_device_tree.interrupts
if (($decodedInts -join ',') -cne ($summaryInts -join ',')) {
    Write-Host "MISMATCH interrupts"
    $script:failures++
} else {
    Write-Host "OK interrupts"
}

# --- clock IDs ---
$decodedClocks = $contract.ans_node.properties.'clock-ids'.decoded_ints
$summaryClocks = $summary.ans_device_tree.clock_ids
if (($decodedClocks -join ',') -cne ($summaryClocks -join ',')) {
    Write-Host "MISMATCH clock-ids"
    $script:failures++
} else {
    Write-Host "OK clock-ids"
}

# --- iommu-parent + nvme-interrupt-idx ---
$decodedIommu = $contract.ans_node.properties.'iommu-parent'.decoded_ints[0]
Assert-Equal 'iommu-parent' $summary.ans_device_tree.iommu_parent $decodedIommu
$decodedNvIdx = $contract.ans_node.properties.'nvme-interrupt-idx'.decoded_ints[0]
Assert-Equal 'nvme-interrupt-idx' $summary.ans_device_tree.nvme_interrupt_idx $decodedNvIdx

# --- reg tuples ---
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
    exit 1
}
Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_PASS"
Write-Host "EVIDENCE_STALE_STATE_REFUSAL_PASS"
Write-Host "ANS_DURABLE_ARTIFACT_SINGLE_STATE_PASS"
Write-Host "ANS_EVIDENCE_NON_SELF_REFERENTIAL_PASS"
Write-Host "ANS_THREE_ARTIFACT_CROSS_CONSISTENCY_PASS"
exit 0
