[CmdletBinding()]
param(
    [string]$Collector,
    [string]$OutputDirectory,
    [string]$ReportDirectory,
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 2700
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CollectorProcess {
    param([string]$Executable, [string]$WorkingDirectory, [int]$Timeout,
          [string]$Stdout, [string]$Stderr)
    $process = Start-Process -FilePath $Executable -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -PassThru
    try {
        if (-not $process.WaitForExit($Timeout * 1000)) {
            # Kill descendants too: the collector may be running external tools.
            $process.Kill($true)
            $process.WaitForExit()
            throw 'Collector exceeded its execution timeout.'
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Collector exited with code $($process.ExitCode)."
        }
    } finally {
        if (-not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $process.Dispose()
    }
}

# Dot sourcing exposes the process helper for tests without collecting this host.
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Collection validation requires a disposable GitHub-hosted Windows runner.'
}
if (-not $Collector -or -not $OutputDirectory -or -not $ReportDirectory) {
    throw 'Collector, OutputDirectory and ReportDirectory are required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Collection validation requires Administrator privileges.'
}

$Collector = (Resolve-Path -LiteralPath $Collector).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$ReportDirectory = [IO.Path]::GetFullPath($ReportDirectory)
if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'OutputDirectory must be new so stale collections cannot pass validation.'
}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$reportPath = Join-Path $ReportDirectory 'validation-report.json'
$report = @{ valid = $false; stage = 'starting' }
$exitCode = 1
try {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Collector).Hash.ToLowerInvariant()
    $report.collector_sha256 = $hash
    $localCollector = Join-Path $OutputDirectory 'Velociraptor_Triage_Collector.exe'
    Copy-Item -LiteralPath $Collector -Destination $localCollector
    $report.stage = 'execution'
    # No arguments: use the exact embedded production collection configuration.
    Invoke-CollectorProcess -Executable $localCollector -WorkingDirectory $OutputDirectory `
        -Timeout $TimeoutSeconds -Stdout (Join-Path $OutputDirectory 'process.stdout.log') `
        -Stderr (Join-Path $OutputDirectory 'process.stderr.log')
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $localCollector).Hash.ToLowerInvariant() -ne $hash) {
        throw 'Collector bytes changed during execution.'
    }
    $report.stage = 'container-validation'
    $collections = @(Get-ChildItem -LiteralPath $OutputDirectory -File -Filter 'Triage-*.zip')
    if ($collections.Count -ne 1) { throw 'Expected exactly one new Triage collection ZIP.' }
    $report.stage = 'source-metadata-check'
    $factsPath = Join-Path $OutputDirectory '.live-source-facts.json'
    & python -B (Join-Path $PSScriptRoot 'windows_source_facts.py') `
        $collections[0].FullName --output $factsPath
    if ($LASTEXITCODE -ne 0) { throw 'Windows source metadata checks failed.' }
    $report.stage = 'container-validation'
    & python -B (Join-Path $PSScriptRoot 'validate_windows_collection.py') `
        $collections[0].FullName --report $reportPath --live-source-facts $factsPath
    $validatorExit = $LASTEXITCODE
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -AsHashtable
    $report.collector_sha256 = $hash
    $report.stage = 'container-validation'
    if ($validatorExit -ne 0) { throw 'Collection container validation failed.' }
    if ($report.valid -ne $true) { throw 'Collection validator did not report success.' }
    $report.collector_sha256 = $hash
    $report.stage = 'complete'
    $exitCode = 0
} catch {
    # Keep evidence-bearing exception/log text on the ephemeral runner only.
    Write-Warning "Windows validation failed at stage: $($report.stage)"
    $report.valid = $false
} finally {
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding utf8
    if (Test-Path -LiteralPath $OutputDirectory) {
        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }
}
exit $exitCode
