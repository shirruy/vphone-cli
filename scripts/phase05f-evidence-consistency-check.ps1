# Deterministic evidence cross-file consistency checker (Iteration 57W).
# Compares duplicated fields between the summary and the durable
# ANS DT contract, and refuses stale gate names or contradictory
# statuses. Non-zero exit on any mismatch.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$summaryPath = Join-Path $root 'artifacts\evidence\05f\phase05f-preboom-storage-contract.json'
$contractPath = Join-Path $root 'artifacts\evidence\05f\phase05f-ans-dt-contract.json'

$summaryRaw = Get-Content $summaryPath -Raw
$contractRaw = Get-Content $contractPath -Raw
$script:failures = 0

function Assert-Equal($name, $a, $b) {
    if ("$a" -cne "$b") {
        Write-Host "MISMATCH $name : '$a' != '$b'"
        $script:failures++
    } else {
        Write-Host "OK $name"
    }
}

# Stale-state refusal: leftover markers from prior repair iterations.
$stalePatterns = @(
    'iter57r_open',
    'iter57r_closed',
    'iter57s_',
    'NOT_YET',
    '"SPRINGBOARD_EXECUTABLE_RECONSTRUCTED": "OPEN"',
    '"SPRINGBOARD_EXECUTABLE_SHA256": "NOT_YET"'
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

# 1. Iteration identifier.
Assert-Equal 'iteration' $summary.iteration '57W'
Assert-Equal 'ITERATION_57W' $summary.certified.ITERATION_57W 'PASS'
Assert-Equal 'ITERATION_57V' $summary.certified.ITERATION_57V 'PASS'
Assert-Equal '57T_certified' $summary.certified.ITERATION_57T_CERTIFIED_CLOSED 'YES'

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
