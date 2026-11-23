[CmdletBinding()]
param([string]$Collector, [string]$OutputDirectory, [string]$ReportDirectory,
      [int]$TimeoutSeconds = 2700)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Qualification requires a disposable GitHub-hosted Windows runner.'
}

# These are fresh, owned fixture paths, never an existing user profile or hive.
$token = 'triage-qualification-' + [guid]::NewGuid().ToString('N')
$root = Join-Path 'C:\Users\Public' $token
$outside = Join-Path $env:RUNNER_TEMP $token
$rootFile = Join-Path 'C:\Users\Public' ($token + '.bin')
$reportPath = Join-Path $ReportDirectory 'validation-report.json'
$trials = [Collections.Generic.List[object]]::new()
$report = @{valid=$false; stage='qualification-seeding'; trials=$trials}
$exitCode = 1
$owned = @()

function Add-StreamSeed {
    param([string]$File, [byte[]]$Bytes, [bool]$Include, [string]$Stream='Zone.Identifier')
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($File)) | Out-Null
    [IO.File]::WriteAllText($File, 'benign synthetic parent')
    $ads = $File + ':' + $Stream
    [IO.File]::WriteAllBytes($ads, $Bytes)
    # Verify the fixture itself through Win32 before testing raw NTFS discovery.
    $actual = [IO.File]::ReadAllBytes($ads)
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($actual)).ToLowerInvariant() -ne $sha) {
        throw 'Synthetic ADS fixture verification failed.'
    }
    $modified = [datetime]::SpecifyKind([datetime]'2020-01-02T03:04:05', [DateTimeKind]::Utc)
    [IO.File]::SetLastWriteTimeUtc($File, $modified)
    $seeds.Add(@{path=$ads; size=$Bytes.Length; sha256=$sha; include=$Include;
                 modified='2020-01-02T03:04:05Z'})
}

try {
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'Qualification output must be new.' }
    foreach ($path in @($root, $outside, $rootFile)) {
        if (Test-Path -LiteralPath $path) { throw 'Qualification fixture path already exists.' }
    }
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $root, $outside | Out-Null
    $owned = @($root, $outside, $rootFile)
    $seeds = [Collections.Generic.List[object]]::new()
    $content = [Text.Encoding]::UTF8.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/fixture`r`n")
    Add-StreamSeed -File $rootFile -Bytes $content -Include $true
    Add-StreamSeed -File (Join-Path $root 'empty.bin') -Bytes ([byte[]]@()) -Include $true
    Add-StreamSeed -File (Join-Path $root 'binary.bin') -Bytes ([byte[]]@(0,255,254,1)) -Include $true
    Add-StreamSeed -File (Join-Path $root 'zone1.bin') -Bytes ([Text.Encoding]::UTF8.GetBytes('[ZoneTransfer]ZoneId=1')) -Include $true
    foreach ($size in @(65535,65536,65537)) {
        $bytes = [byte[]]::new($size)
        [Array]::Fill[byte]($bytes,65)
        [Array]::Copy($content,$bytes,$content.Length)
        Add-StreamSeed -File (Join-Path $root "size-$size.bin") -Bytes $bytes -Include ($size -le 65536)
    }
    # root is one directory below the profile; 19 more reach depth 20.
    $deep = $root
    1..19 | ForEach-Object { $deep = Join-Path $deep 'd' }
    Add-StreamSeed -File (Join-Path $deep 'depth20.bin') -Bytes $content -Include $true
    Add-StreamSeed -File (Join-Path (Join-Path $deep 'd') 'depth21.bin') -Bytes $content -Include $false
    Add-StreamSeed -File (Join-Path $root 'other.bin') -Bytes $content -Include $false -Stream 'UnrelatedStream'
    # Models a redirected profile location outside C:\Users. It is deliberately
    # a negative control: the current production glob does not discover it.
    Add-StreamSeed -File (Join-Path $outside 'redirected-profile\download.bin') -Bytes $content -Include $false
    $manifest = Join-Path $outside 'seeds.json'
    @{version=1; streams=$seeds} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifest -Encoding utf8
    $workload = Join-Path $root 'traversal'
    $runner = Join-Path $PSScriptRoot 'run_windows_collection.ps1'
    # Same exact production executable and seed set in ABBA order. Only the
    # synthetic tree breadth changes. This measures full-collector scaling,
    # not isolated MOTW overhead or a bound for arbitrary workstations.
    foreach ($count in @(1000,10000,10000,1000)) {
        if (Test-Path -LiteralPath $workload) { Remove-Item -LiteralPath $workload -Recurse -Force }
        0..99 | ForEach-Object {
            $directory = Join-Path $workload ("d" + $_)
            [IO.Directory]::CreateDirectory($directory) | Out-Null
            for ($file=0; $file -lt ($count / 100); $file++) {
                [IO.File]::WriteAllText((Join-Path $directory ("f$file.dat")), 'synthetic')
            }
        }
        $index = $trials.Count + 1
        $trialDirectory = Join-Path $outside "report-$index"
        & $runner -Collector $Collector -OutputDirectory ($OutputDirectory + "-$index") `
            -ReportDirectory $trialDirectory -TimeoutSeconds ([Math]::Min($TimeoutSeconds,600)) `
            -ValidateWindowsEvidence -MotwSeeds $manifest
        $code = $LASTEXITCODE
        $trial = Get-Content (Join-Path $trialDirectory 'validation-report.json') -Raw | ConvertFrom-Json -AsHashtable
        $trial.synthetic_files = $count
        $trials.Add($trial)
        $report = @{valid=$false; stage='qualification'; trials=$trials}
        if ($code -ne 0 -or $trial.valid -ne $true) { throw 'Seeded Windows qualification failed.' }
    }
    $report = $trials[-1].Clone()
    $report.trials = $trials.ToArray()
    $report.valid = $true
    $report.stage = 'complete'
    $report.qualification = 'same production collector; 1000/10000/10000/1000 synthetic files; seeded ADS boundaries'
    $report.source_revision = $env:GITHUB_SHA
    $report.runner_image_version = $env:ImageVersion
    $report.logical_processors = [Environment]::ProcessorCount
    $exitCode = 0
} catch {
    Write-Warning 'Seeded Windows qualification failed; details remain on the disposable runner.'
    $report.valid = $false
} finally {
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
    $report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $reportPath -Encoding utf8
    foreach ($path in $owned) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
exit $exitCode
