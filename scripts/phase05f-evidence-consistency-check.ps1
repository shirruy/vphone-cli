# Deterministic evidence cross-file consistency checker (Iteration 57U).
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
Assert-Equal 'iteration' $summary.iteration '57U'

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
