# Deterministic evidence cross-file consistency checker (Iteration 57Z).
# Compares duplicated fields between the summary and the durable
# ANS DT contract, and refuses stale gate names or contradictory
# statuses. Non-zero exit on any mismatch.

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

# Stale-state refusal: leftover markers from prior repair iterations,
# plus 57Z refusal patterns for contradictory internal states.
$stalePatterns = @(
    'iter57r_open',
    'iter57r_closed',
    'iter57s_',
    'NOT_YET',
    '"SPRINGBOARD_EXECUTABLE_RECONSTRUCTED": "OPEN"',
    '"SPRINGBOARD_EXECUTABLE_SHA256": "NOT_YET"',
    'EXACT_WINNING_PROBE_UNRESOLVED',
    'EXACT_WINNING_PROBE_NOT_FULLY_RESOLVED'
)
$staleFound = $false
foreach ($p in $stalePatterns) {
    if ($summaryRaw -match [regex]::Escape($p)) {
        Write-Host "STALE_STATE_DETECTED: $p"
        $staleFound = $true
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

# 1. Iteration identifier.
Assert-Equal 'iteration' $summary.iteration '57Z'
Assert-Equal 'ITERATION_57Z' $summary.certified.ITERATION_57Z 'PARTIAL_PASS'
Assert-Equal 'ITERATION_57Y' $summary.certified.ITERATION_57Y 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57X' $summary.certified.ITERATION_57X 'PARTIAL_PASS_REPAIR_REQUIRED'
Assert-Equal 'ITERATION_57W' $summary.certified.ITERATION_57W 'PASS'
Assert-Equal 'ITERATION_57V' $summary.certified.ITERATION_57V 'PASS'
Assert-Equal '57T_certified' $summary.certified.ITERATION_57T_CERTIFIED_CLOSED 'YES'

# 1b. ANS kernel driver match contract (57X) gates.
$ansMatchSummary = $summary.ans_kernel_driver_match
Assert-Equal 'ans_identity' $ansMatchSummary.ANS_MATCH_INPUT_IDENTITY_PASS 'True'
Assert-Equal 'ans_inventory' $ansMatchSummary.ANS_BOOTKC_CLASS_INVENTORY_PASS 'True'
Assert-Equal 'ans_hierarchy' $ansMatchSummary.ANS_CONTROLLER_CLASS_HIERARCHY_PASS 'True'
Assert-Equal 'ans_probe' $ansMatchSummary.ANS_CONTROLLER_PROBE_PATH_PASS 'True'
Assert-Equal 'ans_start' $ansMatchSummary.ANS_CONTROLLER_START_PATH_PASS 'True'
Assert-Equal 'ans_dt_map' $ansMatchSummary.ANS_DT_TO_DRIVER_MATCH_MAP_PASS 'True'
Assert-Equal 'ans_milestones' $ansMatchSummary.ANS_DRIVER_RUNTIME_MILESTONE_MAP_PASS 'True'
Assert-Equal 'ans_namespace' $ansMatchSummary.ANS_NAMESPACE_DRIVER_USE_PASS 'True'
Assert-Equal 'ans_predicate' $ansMatchSummary.ANS3_NVME_LINEAR_SQ_PREDICATE_PROVEN 'True'
Assert-Equal 'ans_exact_class' $ansMatchSummary.ANS_EXACT_CONTROLLER_CLASS_PROVEN 'True'
Assert-Equal 'ans_winning_probe' $ansMatchSummary.ANS_EXACT_WINNING_PROBE_PASS 'True'
Assert-Equal 'ans_controller_class' $ansMatchSummary.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
Assert-Equal 'ans_provider_proven' $ansMatchSummary.ANS_PROVIDER_CLASS_PROVEN 'True'
Assert-Equal 'ans_provider_class' $ansMatchSummary.CURRENT_PROVIDER_CLASS 'RTBuddyService'
Assert-Equal 'ans_personality_extraction' $ansMatchSummary.ANS_IOKIT_PERSONALITY_EXTRACTION_PASS 'True'
Assert-Equal 'ans_match_matrix' $ansMatchSummary.ANS_D37AP_PERSONALITY_MATCH_MATRIX_PASS 'True'
Assert-Equal 'ans_endpoint_publisher' $ansMatchSummary.ANS2ENDPOINT1_PUBLISHER_CLASS_PROVEN 'True'
Assert-Equal 'ans_nub_publisher' $ansMatchSummary.ANS_IOP_NUB_PUBLISHER_PROVEN 'PARTIAL'
Assert-Equal 'ans_nub_transform' $ansMatchSummary.ANS_IOP_NUB_REGISTRY_NAME_TRANSFORM_PASS 'False'
Assert-Equal 'ans_endpoint_creation' $ansMatchSummary.ANS2ENDPOINT1_CREATION_PATH_PASS 'PARTIAL'
Assert-Equal 'ans_asc_chain_pass' $ansMatchSummary.ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS 'False'
Assert-Equal 'ans_contract' $ansMatchSummary.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'
Assert-Equal 'ans_contract_pass' $ansMatchSummary.ANS_KERNEL_DRIVER_MATCH_CONTRACT_PASS 'False'
Assert-Equal 'ans_next' $ansMatchSummary.next_gate 'IOS_STORAGE_LBA_CONTRACT'

# kernel_driver canonical state must reconcile with ans_kernel_driver_match
Assert-Equal 'kernel_driver_contract' $summary.kernel_driver.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'
if ($summary.storage_gates_open.PSObject.Properties['ANS_KERNEL_DRIVER_MATCH_CONTRACT']) {
    Write-Host "OK ANS present in storage_gates_open (OPEN)"
} else {
    Write-Host "MISMATCH ANS missing from storage_gates_open"
    $script:failures++
}

# 57Z: durable contract single-state check. The durable JSON must not
# contain contradictory PASS/OPEN pairs. Canonical is OPEN because the
# nub registry-name transform remains unproven.
$cs = $ansMatch.canonical_state
if ($null -eq $cs) {
    Write-Host "MISMATCH durable canonical_state section missing"
    $script:failures++
} else {
    Assert-Equal 'cs_predicate' $cs.ANS3_NVME_LINEAR_SQ_PREDICATE_PROVEN 'True'
    Assert-Equal 'cs_exact_class' $cs.ANS_EXACT_CONTROLLER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_winning_probe' $cs.ANS_EXACT_WINNING_PROBE_PASS 'True'
    Assert-Equal 'cs_controller' $cs.CURRENT_CONTROLLER_CLASS 'AppleANS3NVMeController'
    Assert-Equal 'cs_provider' $cs.CURRENT_PROVIDER_CLASS 'RTBuddyService'
    Assert-Equal 'cs_nub_publisher' $cs.ANS_IOP_NUB_PUBLISHER_PROVEN 'PARTIAL'
    Assert-Equal 'cs_nub_transform' $cs.ANS_IOP_NUB_REGISTRY_NAME_TRANSFORM_PASS 'False'
    Assert-Equal 'cs_endpoint_publisher' $cs.ANS2ENDPOINT1_PUBLISHER_CLASS_PROVEN 'True'
    Assert-Equal 'cs_endpoint_creation' $cs.ANS2ENDPOINT1_CREATION_PATH_PASS 'PARTIAL'
    Assert-Equal 'cs_asc_chain' $cs.ANS_ASC_RTBUDDY_PROVIDER_CHAIN_PASS 'False'
    Assert-Equal 'cs_contract' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT 'OPEN'
    Assert-Equal 'cs_contract_pass' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_PASS 'False'
    Assert-Equal 'cs_durable' $cs.ANS_KERNEL_DRIVER_MATCH_CONTRACT_DURABLE_PASS 'False'
}

# Refusal patterns: no contradictory PASS_CLOSED / family-level /
# IOService-provider placeholders anywhere in either file.
foreach ($pat in @(
    'CURRENT_CONTROLLER_CLASS.*family',
    'CURRENT_PROVIDER_CLASS.*IOService provider',
    'ANS_KERNEL_DRIVER_MATCH_CONTRACT_PASS.*true'
)) {
    if ($ansMatchRaw -match $pat) {
        Write-Host "MISMATCH refusal pattern: $pat"
        $script:failures++
    }
}

# 2. SpringBoard reconstruction + SHA.
$sb = $summary.decmpfs_reconstruction.executables.springboard
if (-not $sb.reconstructed -or
    $sb.sha256 -cne
        'db2d73a61739417c14359db4415ac5eb0cc59f86611c158e7413d97b0458b55c') {
    Write-Host "MISMATCH SpringBoard reconstruction/SHA"
    $script:failures++
} else {
    Write-Host "OK SpringBoard reconstructed SHA"
}

# 3. decmpfs algo 4 = zlib resource fork.
Assert-Equal 'algo4' $summary.decmpfs_reconstruction.algorithm_table.'4' 'zlib resource fork (CMP_TypeZlib)'

# 4. ResourceFork flags exact.
Assert-Equal 'resourcefork_flags.observed' $summary.decmpfs_reconstruction.resourcefork_flags.observed 1

# 4b. DATA_STREAM descriptor/extent/contract + Mach-O / type-4
#     hardening markers (separate, non-collapsed gates).
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

# 4c. Mach-O identity fields for all three reconstructed executables.
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

# 5. namespaces word0/word1/word2 vs durable contract.
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
    if (-not $script:failures) {
        Write-Host "OK namespaces ($($summaryNs.Count) records)"
    }
}

# 6. nvme_queue_entries + raw hex.
$decodedQ = $contract.ans_node.properties.'nvme-queue-entries'.decoded_ints[0]
Assert-Equal 'nvme_queue_entries' $summary.ans_device_tree.nvme_queue_entries $decodedQ
Assert-Equal 'nvme_queue_entries_raw' $summary.ans_device_tree.nvme_queue_entries_raw_hex '40000000'

# 7. interrupts.
$decodedInts = $contract.ans_node.properties.interrupts.decoded_ints
$summaryInts = $summary.ans_device_tree.interrupts
if (($decodedInts -join ',') -cne ($summaryInts -join ',')) {
    Write-Host "MISMATCH interrupts"
    $script:failures++
} else {
    Write-Host "OK interrupts"
}

# 8. clock IDs.
$decodedClocks = $contract.ans_node.properties.'clock-ids'.decoded_ints
$summaryClocks = $summary.ans_device_tree.clock_ids
if (($decodedClocks -join ',') -cne ($summaryClocks -join ',')) {
    Write-Host "MISMATCH clock-ids"
    $script:failures++
} else {
    Write-Host "OK clock-ids"
}

# 9. iommu-parent + nvme-interrupt-idx.
$decodedIommu = $contract.ans_node.properties.'iommu-parent'.decoded_ints[0]
Assert-Equal 'iommu-parent' $summary.ans_device_tree.iommu_parent $decodedIommu
$decodedNvIdx = $contract.ans_node.properties.'nvme-interrupt-idx'.decoded_ints[0]
Assert-Equal 'nvme-interrupt-idx' $summary.ans_device_tree.nvme_interrupt_idx $decodedNvIdx

# 10. ALL reg tuples (base + size).
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
    if (-not $script:failures) {
        Write-Host "OK reg ($($regDecoded.Count) tuples, base+size)"
    }
}

if ($script:failures -gt 0) {
    Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_FAIL"
    Write-Host "EVIDENCE_STALE_STATE_REFUSAL_FAIL"
    exit 1
}
Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_PASS"
Write-Host "EVIDENCE_STALE_STATE_REFUSAL_PASS"
exit 0
