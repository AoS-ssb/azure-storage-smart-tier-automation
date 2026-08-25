[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$runbookPath = Join-Path $repositoryRoot 'src/Enable-AzStorageSmartTier.ps1'
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    $runbookPath,
    [ref] $tokens,
    [ref] $parseErrors
)

if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { Write-Error $_.ToString() }
    throw "PowerShell parsing failed with $($parseErrors.Count) error(s)."
}

$content = Get-Content -LiteralPath $runbookPath -Raw
$requiredSafetyMarkers = @(
    "[ValidateSet('GET', 'PATCH')]",
    '"accessTier":"Smart"',
    'BlockedScopeLock',
    'INTENT ',
    'patchesSubmitted',
    'SkippedExcluded',
    'SkippedNotOptedIn',
    'WriteOutcomeUnknown',
    'Deferred',
    'ExpectedChanges',
    'AllowUntaggedRemediation',
    'MaxChangesExceeded',
    'SUMMARY '
)

foreach ($marker in $requiredSafetyMarkers) {
    if (-not $content.Contains($marker)) {
        throw "Required safety marker is missing: $marker"
    }
}

$forbiddenMarkers = @(
    "-Method DELETE",
    "'DELETE'",
    'listKeys',
    'Remove-Az',
    'az storage account delete'
)

foreach ($marker in $forbiddenMarkers) {
    if ($content.Contains($marker)) {
        throw "Forbidden destructive marker found: $marker"
    }
}

Write-Output 'PowerShell parsing and static safety checks passed.'
