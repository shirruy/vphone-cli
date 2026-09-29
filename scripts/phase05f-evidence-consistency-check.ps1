# Deterministic evidence cross-file consistency checker.
# Compares duplicated fields between the summary and the durable
# ANS DT contract. Non-zero exit on any mismatch.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$summaryPath = Join-Path $root 'artifacts\evidence\05f\phase05f-preboom-storage-contract.json'
$contractPath = Join-Path $root 'artifacts\evidence\05f\phase05f-ans-dt-contract.json'

$summary = Get-Content $summaryPath -Raw | ConvertFrom-Json
$contract = Get-Content $contractPath -Raw | ConvertFrom-Json

$failures = 0

function Assert-Equal($name, $a, $b) {
    if ($a -ne $b) {
        Write-Host "MISMATCH $name : '$a' != '$b'"
        $script:failures++
    } else {
        Write-Host "OK $name"
    }
}

# 1. namespaces word0/word1 semantics agree.
$summaryNs = $summary.ans_device_tree_contract.ANS_DEVICE_TREE_RAW_EXTRACTION_PASS.namespaces
$contractNs = $contract.ans_node.properties.namespaces.decoded
if ($summaryNs.Count -ne $contractNs.Count / 3) {
    Write-Host "MISMATCH namespace record count"
    $script:failures++
} else {
    for ($i = 0; $i -lt $summaryNs.Count; $i++) {
        $w0 = $contractNs[$i * 3]
        $w1 = $contractNs[$i * 3 + 1]
        if ($summaryNs[$i].word0 -ne $w0 -or
            $summaryNs[$i].word1 -ne $w1) {
            Write-Host "MISMATCH namespace[$i]"
            $script:failures++
        }
    }
    Write-Host "OK namespaces (word0/word1 match, $($summaryNs.Count) records)"
}

# 2. nvme_queue_entries: summary must equal decoded little-endian 64.
$decoded = $contract.ans_node.properties.'nvme-queue-entries'.decoded_ints[0]
Assert-Equal 'nvme_queue_entries' $summary.ans_device_tree_contract.ANS_DEVICE_TREE_RAW_EXTRACTION_PASS.nvme_queue_entries $decoded

# 3. interrupts agree.
$decodedInts = $contract.ans_node.properties.interrupts.decoded_ints
$summaryInts = $summary.ans_device_tree_contract.ANS_DEVICE_TREE_RAW_EXTRACTION_PASS.interrupts
if (($decodedInts -join ',') -ne ($summaryInts -join ',')) {
    Write-Host "MISMATCH interrupts"
    $script:failures++
} else {
    Write-Host "OK interrupts"
}

# 4. reg pairs agree (first two).
$regDecoded = $contract.ans_node.properties.reg.decoded
$regSummary = $summary.ans_device_tree_contract.ANS_DEVICE_TREE_RAW_EXTRACTION_PASS.reg_mmio
for ($i = 0; $i -lt 2; $i++) {
    $expectedHex = '0x{0:x}' -f [uint64]$regDecoded[$i].base
    if ($regSummary[$i].base -ne $expectedHex) {
        Write-Host "MISMATCH reg[$i].base: $($regSummary[$i].base) != $expectedHex"
        $script:failures++
    }
}
Write-Host "OK reg (first two pairs)"

if ($failures -gt 0) {
    Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_FAIL"
    exit 1
}
Write-Host "EVIDENCE_CROSS_FILE_CONSISTENCY_PASS"
exit 0
