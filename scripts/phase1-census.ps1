param(
    [string]$OutputDirectory = "artifacts/evidence/phase1"
)

$ErrorActionPreference = "Stop"

Set-Location (Resolve-Path (Join-Path $PSScriptRoot ".."))

$extensions = @(".swift", ".c", ".cc", ".cpp", ".cxx", ".m", ".mm")

function Classify-CompileUnit([string]$Path) {
    $p = $Path.Replace("\", "/")

    if ($p.StartsWith("windows/")) {
        return @("PORTABLE", "windows", "Windows-native scaffold/test source")
    }
    if ($p.StartsWith("Research/")) {
        return @("APPLE_ONLY", "research", "Research spike imports Apple Virtualization/private APIs; reference only")
    }
    if ($p.StartsWith("VPhoneDaemon/")) {
        return @("APPLE_ONLY", "VPhoneDaemon", "Guest daemon is built for Apple guest/iOS runtime, not Windows host")
    }
    if ($p.StartsWith("VPhoneGuestComponents/")) {
        return @("APPLE_ONLY", "VPhoneGuestComponents", "Guest-side iOS/Objective-C/C component; remains guest artifact")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneVirtualization/")) {
        return @("REWRITE", "VPhoneVirtualization", "macOS host runtime/UI is coupled to AppKit and Virtualization.framework")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneEscalator/")) {
        return @("APPLE_ONLY", "VPhoneEscalator", "macOS host security/escalation helper; not valid Windows runtime surface")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/FirmwarePatcherTestFixtures/DylibInjection/")) {
        return @("APPLE_ONLY", "FirmwarePatcherFixtures", "Apple-target Objective-C fixture used by firmware patch tests")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/FirmwarePatcherTests/")) {
        return @("SHIMMABLE", "FirmwarePatcherTests", "Swift tests are reusable but need Windows toolchain/fixture/path adaptation")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/FirmwarePatcher/")) {
        if ($p.Contains("/CryptexFilesystem/")) {
            return @("REWRITE", "FirmwarePatcher", "Firmware logic invokes Apple APFS/cryptex host tooling and needs a replacement backend")
        }
        return @("SHIMMABLE", "FirmwarePatcher", "Core patching logic is algorithmic Swift but requires Windows build/dependency adaptation")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneCommand/")) {
        return @("SHIMMABLE", "VPhoneCommand", "CLI/orchestration semantics can be retained behind platform adapters")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneRestore/MobileRestoreCore/") -or
        $p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneRestore/MobileRecoveryCore/")) {
        return @("SHIMMABLE", "MobileRestoreCore", "Portable C lineage with POSIX/external-library dependencies and existing Windows conditionals")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneRestore/VPhoneRestoreTests/")) {
        return @("SHIMMABLE", "VPhoneRestoreTests", "Restore tests can be reused after Windows backend/dependency shims")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneRestore/VPhoneRestore/")) {
        return @("SHIMMABLE", "VPhoneRestore", "Restore orchestration is reusable with platform/dependency adapters")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneSignTestFixtures/Sources/")) {
        return @("PORTABLE", "VPhoneSignFixtures", "Small standards-based C signing fixtures")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneSignTests/")) {
        return @("SHIMMABLE", "VPhoneSignTests", "Signing tests require Windows Swift/Crypto/Security substitutions")
    }
    if ($p.StartsWith("VPhoneExecutable/VPhoneCommand/VPhoneSign/")) {
        return @("SHIMMABLE", "VPhoneSign", "Mach-O/signing logic is reusable but Apple Security/Crypto APIs need adapters")
    }
    if ($p.StartsWith("VPhoneKit/VPhoneArchiveKitTests/")) {
        return @("SHIMMABLE", "VPhoneArchiveKitTests", "Archive tests are conceptually portable; Windows filesystem/permission semantics need adaptation")
    }
    if ($p.StartsWith("VPhoneKit/VPhoneArchiveKit/")) {
        return @("SHIMMABLE", "VPhoneArchiveKit", "Archive logic is portable in intent but uses Swift/Foundation/libarchive behavior that must be proven on Windows")
    }
    if ($p -eq "VPhoneKit/VPhoneCoreKit/Support/VPhoneNetworking.swift" -or
        $p -eq "VPhoneKit/VPhoneCoreKitTests/Support/NetworkingTests.swift") {
        return @("REWRITE", "VPhoneCoreKit", "Direct Virtualization.framework networking dependency")
    }
    if ($p -eq "VPhoneKit/VPhoneCoreKit/Firmware/VPhoneAPFSSnapshot.swift" -or
        $p -eq "VPhoneKit/VPhoneCoreKitTests/Firmware/APFSSnapshotTests.swift") {
        return @("REWRITE", "VPhoneCoreKit", "APFS snapshot workflow depends on Apple host facilities and needs Windows replacement")
    }
    if ($p.StartsWith("VPhoneKit/VPhoneCoreKitTests/")) {
        return @("SHIMMABLE", "VPhoneCoreKitTests", "Core tests are reusable after platform adapters and Windows Swift support")
    }
    if ($p.StartsWith("VPhoneKit/VPhoneCoreKit/")) {
        return @("SHIMMABLE", "VPhoneCoreKit", "Core orchestration/data models are reusable but mix Foundation/Security/process/filesystem host assumptions")
    }
    if ($p.StartsWith("VPhoneKit/VPhoneExternalAccessKit/")) {
        return @("REWRITE", "VPhoneExternalAccessKit", "Current client directly references Apple virtualization transport; API semantics can remain while transport changes")
    }

    return @("UNKNOWN", "unmapped", "No explicit census rule matched")
}

$files = git ls-files
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed."
}

$rows = @()

foreach ($path in $files) {
    $extension = [IO.Path]::GetExtension($path).ToLowerInvariant()
    if ($extensions -notcontains $extension) {
        continue
    }

    $classification = Classify-CompileUnit $path

    $rows += [PSCustomObject]@{
        path = $path.Replace("\", "/")
        target = $classification[1]
        category = $classification[0]
        extension = $extension.TrimStart(".")
        reason = $classification[2]
    }
}

$unknown = @($rows | Where-Object category -eq "UNKNOWN")
$counts = @{}
foreach ($group in ($rows | Group-Object category)) {
    $counts[$group.Name] = $group.Count
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$csvPath = Join-Path $OutputDirectory "compile_unit_census.runtime.csv"
$jsonPath = Join-Path $OutputDirectory "census_results.runtime.json"

$rows | Sort-Object path | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

$result = [ordered]@{
    branch = (git branch --show-current).Trim()
    head = (git rev-parse HEAD).Trim()
    compile_units = $rows.Count
    categories = $counts
    unknown_count = $unknown.Count
}

$result | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8

Write-Host "Compile units : $($rows.Count)"
Write-Host "PORTABLE      : $($counts["PORTABLE"])"
Write-Host "SHIMMABLE     : $($counts["SHIMMABLE"])"
Write-Host "REWRITE       : $($counts["REWRITE"])"
Write-Host "APPLE_ONLY    : $($counts["APPLE_ONLY"])"
Write-Host "UNKNOWN       : $($unknown.Count)"

if ($unknown.Count -ne 0) {
    Write-Host ""
    Write-Host "Unclassified compile units:" -ForegroundColor Red
    $unknown | Format-Table path, target, reason -AutoSize
    exit 1
}

Write-Host ""
Write-Host "PORTABILITY CENSUS PASS: every tracked compile unit has an explicit category." -ForegroundColor Green
exit 0
