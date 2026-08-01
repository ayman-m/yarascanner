<#
.SYNOPSIS
  Open-loop CPU load generator (Windows) for the YARA scanner throttle PoC.

.DESCRIPTION
  Runs DIRECTLY on the endpoint, NOT as a Cortex Action Center payload, so it is
  not subject to the agent's payload CPU-affinity cap (measured: agent payloads are
  pinned to 2 of 8 cores) and can create realistic system-wide pressure the way
  ordinary user/service workloads do.

  PowerShell rather than Python because the Windows test endpoint has NO Python
  installed - the Cortex agent carries its own embedded interpreter, which is not
  usable from outside the agent.

  OPEN-LOOP BY DESIGN: the duty cycle is fixed. It deliberately does NOT adapt to
  hold a system-CPU setpoint - a closed loop would back off as the scanner ramps up
  and we would measure the control loop instead of the scanner's throttle.

  Load runs in background JOBS (separate processes), so there is no single-process
  threading ceiling and the OS schedules them across all cores.

.EXAMPLE
  .\loadgen.ps1 -Profile "30:0,120:55,120:85,30:0" -Out C:\temp\loadgen.json

.EXAMPLE
  .\loadgen.ps1 -Calibrate -Out C:\temp\calibration.json
#>
[CmdletBinding()]
param(
    [string]$Profile = "30:0,120:55,120:85,30:0",
    [switch]$Calibrate,
    [string]$Out,
    [double]$HardDeadlineSecs = 900
)

$ErrorActionPreference = "Stop"
$cores = [Environment]::ProcessorCount
$workersN = [Math]::Max(1, $cores - 1)   # headroom so the box stays responsive

# Each worker hashes a ~1 MiB buffer. Size matters: small buffers make hashing
# cheap relative to loop overhead and the duty cycle loses resolution.
$workerScript = {
    param($DutyFile, $StopFile)
    $buf = New-Object byte[] 1048576
    (New-Object Random).NextBytes($buf)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $units = 0
    $window = 0.1
    while (-not (Test-Path $StopFile)) {
        $duty = 0.0
        try { $duty = [double](Get-Content $DutyFile -Raw -ErrorAction Stop) } catch { $duty = 0.0 }
        $busy = $window * ($duty / 100.0)
        if ($busy -gt 0) {
            $end = (Get-Date).AddSeconds($busy)
            while ((Get-Date) -lt $end) { $null = $sha.ComputeHash($buf); $units++ }
        }
        $sleep = $window - $busy
        if ($sleep -gt 0) { Start-Sleep -Milliseconds ([int]($sleep * 1000)) }
    }
    $units
}

function Get-SystemCpu {
    try {
        (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
    } catch { -1.0 }
}

function Parse-Profile([string]$spec) {
    if ([string]::IsNullOrWhiteSpace($spec)) { throw "profile is empty" }
    $stages = @()
    foreach ($chunk in $spec.Split(",")) {
        if ([string]::IsNullOrWhiteSpace($chunk)) { continue }
        $parts = $chunk.Split(":")
        $secs = [double]$parts[0].Trim()
        $duty = [double]$parts[1].Trim()
        if ($duty -lt 0 -or $duty -gt 100) { throw "duty must be 0-100, got $duty" }
        if ($secs -le 0) { throw "stage duration must be > 0, got $secs" }
        $stages += , @($secs, $duty)
    }
    if ($stages.Count -eq 0) { throw "profile is empty" }
    $stages
}

$dutyFile = Join-Path $env:TEMP "yara_loadgen_duty.txt"
$stopFile = Join-Path $env:TEMP "yara_loadgen_stop.txt"
Remove-Item $stopFile -ErrorAction SilentlyContinue
Set-Content -Path $dutyFile -Value "0.0"

Write-Host "cores=$cores workers=$workersN" -ForegroundColor Cyan
$jobs = 1..$workersN | ForEach-Object {
    Start-Job -ScriptBlock $workerScript -ArgumentList $dutyFile, $stopFile
}

$started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
$deadline = (Get-Date).AddSeconds($HardDeadlineSecs)
$samples = @()
$sweep = @()

try {
    if ($Calibrate) {
        foreach ($duty in @(20, 35, 50, 65, 80, 95)) {
            Set-Content -Path $dutyFile -Value ([string]$duty)
            Start-Sleep -Seconds 3                       # settle before sampling
            $readings = @()
            for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Seconds 1; $readings += (Get-SystemCpu) }
            $mean = [Math]::Round(($readings | Measure-Object -Average).Average, 1)
            $sweep += [pscustomobject]@{ duty = $duty; cpu_mean = $mean }
            Write-Host ("  duty={0,5:N1}% -> system_cpu={1,5:N1}%" -f $duty, $mean) -ForegroundColor Yellow
        }
    } else {
        $stages = Parse-Profile $Profile
        for ($s = 0; $s -lt $stages.Count; $s++) {
            $secs = $stages[$s][0]; $duty = $stages[$s][1]
            Set-Content -Path $dutyFile -Value ([string]$duty)
            $stageEnd = (Get-Date).AddSeconds($secs)
            while ((Get-Date) -lt $stageEnd -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 1
                $samples += [pscustomobject]@{
                    t     = [Math]::Round([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0, 3)
                    cpu   = [Math]::Round((Get-SystemCpu), 1)
                    stage = $s
                    duty  = $duty
                }
            }
            if ((Get-Date) -ge $deadline) { break }
        }
    }
} finally {
    # Hard stop: the file sentinel guarantees workers exit even if this script dies.
    Set-Content -Path $stopFile -Value "stop"
    Start-Sleep -Seconds 2
    $totalUnits = 0
    foreach ($j in $jobs) {
        try { $totalUnits += [int](Receive-Job -Job $j -Wait -ErrorAction SilentlyContinue) } catch {}
        Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $stopFile, $dutyFile -ErrorAction SilentlyContinue
}

# Work units are counted per job and only returned at exit, so per-second work
# rate is not available on Windows - CPU trace plus the total is what we get.
$moderate = ($sweep | Where-Object { $_.cpu_mean -le 55 } | Sort-Object duty -Descending | Select-Object -First 1)
$heavy = ($sweep | Where-Object { $_.cpu_mean -le 72 } | Sort-Object duty -Descending | Select-Object -First 1)

$result = [pscustomobject]@{
    mode          = if ($Calibrate) { "calibrate" } else { "run" }
    host          = $env:COMPUTERNAME
    platform      = "Windows"
    cores         = $cores
    workers       = $workersN
    started_at    = $started
    ended_at      = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    samples       = $samples
    sweep         = $sweep
    moderate_duty = if ($moderate) { $moderate.duty } else { $null }
    heavy_duty    = if ($heavy) { $heavy.duty } else { $null }
    totals        = [pscustomobject]@{ work = $totalUnits }
}

$json = $result | ConvertTo-Json -Depth 6
if ($Out) { $json | Set-Content -Path $Out -Encoding UTF8; Write-Host "wrote $Out" -ForegroundColor Green }
$json
