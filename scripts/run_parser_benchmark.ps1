[CmdletBinding()]
param([string]$Inputs = 'benchmark-inputs', [string]$ReportDirectory = 'parser-benchmark-report',
      [ValidateSet('paired', 'baseline', 'parsers')][string]$Variant = 'paired')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Benchmark requires a disposable GitHub-hosted Windows runner.'
}
$Inputs = (Resolve-Path -LiteralPath $Inputs).Path
$ReportDirectory = [IO.Path]::GetFullPath($ReportDirectory)
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$reportPath = Join-Path $ReportDirectory 'benchmark.json'
$results = [Collections.Generic.List[object]]::new()
$report = @{
    valid = $false
    methodology = $(if ($Variant -eq 'paired') { 'Three paired runs on one hosted VM; order baseline/parsers, parsers/baseline, baseline/parsers. Process wall time excludes ZIP validation and cleanup.' } else { 'One first collection on a fresh hosted runner; process wall time excludes ZIP validation and cleanup.' })
    mode = $Variant
    repeat = $env:BENCHMARK_REPEAT
    validator_revision = 'eebda5037e7c91f8408cc10470da404ab44e3a64'
    runner_image = $env:ImageOS
    runner_image_version = $env:ImageVersion
    logical_processors = [Environment]::ProcessorCount
    run_id = $env:GITHUB_RUN_ID
    commit = $env:GITHUB_SHA
    inputs = (Get-Content (Join-Path $Inputs 'metadata.json') -Raw | ConvertFrom-Json -AsHashtable)
    runs = $results
}
try {
    foreach ($line in Get-Content (Join-Path $Inputs 'SHA256SUMS')) {
        if ($line -notmatch '^([a-f0-9]{64})  ([a-z]+\.exe)$') { throw 'Invalid benchmark manifest.' }
        $expected = $Matches[1]
        $file = Join-Path $Inputs $Matches[2]
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -ne $expected) {
            throw 'Benchmark executable hash mismatch.'
        }
    }
    $orders = @(@('baseline', 'parsers'), @('parsers', 'baseline'), @('baseline', 'parsers'))
    if ($Variant -ne 'paired') { $orders = @(,@($Variant)) }
    for ($pair = 0; $pair -lt $orders.Count; $pair++) {
        foreach ($variant in $orders[$pair]) {
            $name = "pair-$($pair + 1)-$variant"
            Write-Host "Starting $name"
            $trialReport = Join-Path $ReportDirectory $name
            $metrics = Join-Path $ReportDirectory "$name-metrics.json"
            $overall = [Diagnostics.Stopwatch]::StartNew()
            & (Join-Path $PSScriptRoot 'run_windows_collection.ps1') `
                -Collector (Join-Path $Inputs "$variant.exe") `
                -OutputDirectory (Join-Path $env:RUNNER_TEMP "parser-benchmark-$name") `
                -ReportDirectory $trialReport -TimeoutSeconds 600 `
                -MetricsFile $metrics -BenchmarkVariant $variant
            $executionExit = $LASTEXITCODE
            $overall.Stop()
            $validation = Get-Content (Join-Path $trialReport 'validation-report.json') -Raw | ConvertFrom-Json -AsHashtable
            $measurements = Get-Content $metrics -Raw | ConvertFrom-Json -AsHashtable
            $results.Add(@{ pair = $pair + 1; variant = $variant;
                execution_seconds = $validation.execution_seconds;
                validation_and_cleanup_seconds = $overall.Elapsed.TotalSeconds - $validation.execution_seconds;
                valid = $validation.valid; collector_sha256 = $validation.collector_sha256;
                result_rows = $validation.result_rows; verified_triage_uploads = $validation.verified_triage_uploads;
                parser_rows = $measurements.parser_rows; parser_result_bytes = $measurements.parser_result_bytes;
                zip_bytes = $measurements.zip_bytes })
            $report | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $reportPath -Encoding utf8
            if ($executionExit -ne 0 -or $validation.valid -ne $true) {
                throw 'Benchmark collection failed validation.'
            }
            Write-Host "$name completed in $([Math]::Round($validation.execution_seconds, 3)) seconds"
        }
    }
    $report.valid = $true
} finally {
    $report | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $reportPath -Encoding utf8
}
