# ADR-0070, step 0 of the Windows CI job: runs the install script a server
# hands out against a stand-in server on this machine, and proves the order
# (create, lock down, verify, exclude, and only then download), that nothing
# is downloaded before the exclusion, and that a forced failure at each of
# the first four steps downloads nothing and leaves no folder or exclusion
# the script made. The agent it "downloads" cannot enroll (the stand-in has
# no enrollment), so the script's own failure path is the one that runs last.
#
#   defender-install-order.ps1 -Script install.ps1 -Agent easyrmm-agent-windows-amd64.exe
#
# Needs an elevated Windows PowerShell with Microsoft Defender as the active
# antivirus; where it is not, the exclusion assertions are skipped and said so.
param(
    [Parameter(Mandatory = $true)][string] $Script,
    [Parameter(Mandatory = $true)][string] $Agent
)
$ErrorActionPreference = 'Stop'
$port = 18080
$work = Join-Path $env:RUNNER_TEMP ('order-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$requests = Join-Path $work 'requests.txt'
New-Item -ItemType File -Path $requests | Out-Null

# The script is the server's own, pointed at the stand-in.
$text = (Get-Content -Raw -LiteralPath $Script).Replace("`$Server = 'https://rmm.example.com'", "`$Server = 'http://127.0.0.1:$port'")
if ($text -notmatch "127\.0\.0\.1:$port") { throw 'the script has no $Server line to point at the stand-in' }
$ps1 = Join-Path $work 'install.ps1'
[IO.File]::WriteAllText($ps1, $text, (New-Object Text.UTF8Encoding($false)))

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Agent).Hash.ToLowerInvariant()
$sums = "$sha  easyrmm-agent-windows-amd64.exe`n$sha  easyrmm-agent-windows-arm64.exe`n"
$job = Start-Job -ArgumentList $port, $Agent, $sums, $requests -ScriptBlock {
    param($port, $agent, $sums, $requests)
    $l = New-Object Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$port/")
    $l.Start()
    while ($true) {
        $c = $l.GetContext()
        Add-Content -LiteralPath $requests -Value ('{0} {1}' -f [DateTime]::UtcNow.Ticks, $c.Request.Url.AbsolutePath)
        $body = $null
        if ($c.Request.Url.AbsolutePath -like '*/download/SHA256SUMS') { $body = [Text.Encoding]::ASCII.GetBytes($sums) }
        elseif ($c.Request.Url.AbsolutePath -like '*/download/easyrmm-agent-windows-*.exe') { $body = [IO.File]::ReadAllBytes($agent) }
        if ($body) { $c.Response.OutputStream.Write($body, 0, $body.Length) } else { $c.Response.StatusCode = 404 }
        $c.Response.Close()
    }
}
Start-Sleep -Seconds 2

$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EasyRMM'
$filesRoot = Join-Path ($(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })) 'EasyRMM'
$defender = $null
try { $defender = Get-MpComputerStatus } catch { }
$active = $defender -and $defender.AMRunningMode -eq 'Normal' -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled
if (-not $active) { Write-Output '::warning::Microsoft Defender is not the active antivirus here; the exclusion assertions are skipped.' }

function Invoke-Install([string]$FailAt) {
    # The script's errors reach this one's error stream; they are read, not thrown.
    $ErrorActionPreference = 'Continue'
    $trace = Join-Path $work ('trace-' + [guid]::NewGuid().ToString('N') + '.txt')
    $before = @(Get-Content -LiteralPath $requests).Count
    $env:EASYRMM_INSTALL_TRACE = $trace
    if ($FailAt) { $env:EASYRMM_INSTALL_FAIL_AT = $FailAt } else { Remove-Item Env:EASYRMM_INSTALL_FAIL_AT -ErrorAction SilentlyContinue }
    $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ps1 -Token 'ert_ci' 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item Env:EASYRMM_INSTALL_TRACE, Env:EASYRMM_INSTALL_FAIL_AT -ErrorAction SilentlyContinue
    $steps = [ordered]@{}
    if (Test-Path -LiteralPath $trace) {
        foreach ($l in Get-Content -LiteralPath $trace) { $n, $t = $l -split ' '; $steps[$n] = [int64]$t }
    }
    $got = @(Get-Content -LiteralPath $requests)
    return [pscustomobject]@{ Code = $code; Out = $out; Steps = $steps; Downloads = $got.Count - $before; Requests = $got[$before..($got.Count - 1)] }
}

function Assert-Clean([string]$When) {
    foreach ($p in @($dataRoot, $filesRoot)) {
        if (Test-Path -LiteralPath $p) { throw "${When}: the script left $p behind" }
    }
    if ($active) {
        $pref = Get-MpPreference
        foreach ($l in @($pref.ExclusionPath, $pref.ExclusionProcess, $pref.AttackSurfaceReductionOnlyExclusions, $pref.ControlledFolderAccessAllowedApplications)) {
            foreach ($e in @($l)) { if ($e -like "*\EasyRMM\*" -or $e -like "*\EasyRMM") { throw "${When}: the script left the exclusion $e behind" } }
        }
    }
}

try {
    foreach ($p in @($dataRoot, $filesRoot)) { if (Test-Path -LiteralPath $p) { throw "$p exists already; this job needs a runner without EasyRMM" } }

    # The order, and nothing downloaded before the exclusion.
    $r = Invoke-Install ''
    if ($r.Code -eq 0) { throw 'the stand-in cannot enroll an agent, yet the script succeeded' }
    $order = 'create', 'lock', 'verify', 'exclude', 'download'
    foreach ($s in $order) { if (-not $r.Steps.Contains($s)) { throw "step $s did not run:`n$($r.Out)" } }
    for ($i = 1; $i -lt $order.Count; $i++) {
        if ($r.Steps[$order[$i]] -lt $r.Steps[$order[$i - 1]]) { throw "$($order[$i]) ran before $($order[$i - 1])" }
    }
    if ($r.Downloads -lt 1) { throw 'nothing was downloaded' }
    $first = [int64](($r.Requests[0]) -split ' ')[0]
    if ($first -lt $r.Steps['exclude']) { throw 'a download began before the exclusion step' }
    Write-Output "order: create, lock, verify, exclude, download, $($r.Downloads) request(s) after the exclusion step"
    # The enrollment failed, so the script undid what it made.
    Assert-Clean 'after a failed install'

    # A forced failure at each of the first four steps downloads nothing and leaves nothing.
    foreach ($step in 'create', 'lock', 'verify', 'exclude') {
        $r = Invoke-Install $step
        if ($r.Code -eq 0) { throw "forced failure at $step did not fail the script" }
        if ($r.Downloads -ne 0) { throw "forced failure at $step still downloaded ($($r.Downloads) request(s))" }
        if ($r.Steps.Contains('download')) { throw "forced failure at $step still reached the download step" }
        Assert-Clean "after a failure at $step"
        Write-Output "failure at ${step}: nothing downloaded, nothing left behind"
    }
} finally {
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
}
