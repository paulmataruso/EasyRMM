#Requires -Version 5.1
<#
.SYNOPSIS
  ADR-0070 slice B on a real Windows with Microsoft Defender running (CI only): steps 1 to 5 and 8 for the EasyPatch agent.
.DESCRIPTION
  Installs the MSI built by the job, checks what the install added, what the agent reports, the removal, the
  not-locked case, the moved work folders and the .NET extraction folders, then uninstalls. Run elevated. Where the image
  does not keep Defender active (real-time off, passive mode) the checks that need it are skipped with a stated reason.
#>
param([Parameter(Mandatory = $true)][string]$Msi)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$install = Join-Path $env:ProgramFiles 'EasyPatch Agent'
$data = Join-Path $env:ProgramData 'EasyPatch'
$exe = Join-Path $install 'EasyPatch.Agent.exe'
$keep = 'C:\ep-ci-keep'
$failures = @()

function Check([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "ok:   $Message" } else { Write-Host "FAIL: $Message"; $script:failures += $Message }
}
function Lists { $p = Get-MpPreference; @{ path = @($p.ExclusionPath); process = @($p.ExclusionProcess); asr = @($p.AttackSurfaceReductionOnlyExclusions); cfa = @($p.ControlledFolderAccessAllowedApplications) } }
function Listed($list, [string]$path) { @($list | Where-Object { $_ -ieq $path }).Count -gt 0 }
function Status { $out = & $exe defender status | Out-String; $out.Substring($out.IndexOf('{')) | ConvertFrom-Json }
function Msi([string[]]$MsiArguments, [string]$Log) {
    $p = Start-Process -FilePath msiexec.exe -ArgumentList $MsiArguments -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { Get-Content $Log -Tail 60 | Write-Host; throw "msiexec $($MsiArguments -join ' ') exited with $($p.ExitCode)" }
}

$mode = (Get-MpComputerStatus).AMRunningMode
$active = $mode -eq 'Normal' -and (Get-MpComputerStatus).AntivirusEnabled -and (Get-MpComputerStatus).RealTimeProtectionEnabled
Write-Host "Defender running mode: $mode; active: $active"
Add-MpPreference -ExclusionPath $keep # an administrator's own exclusion, which must survive

# Step 1, add. The install may not enroll (there is no server): the service keeps retrying, which is all these checks need.
$log = Join-Path $env:RUNNER_TEMP 'ep-install.log'
Msi @('/i', $Msi, '/qn', '/norestart', 'SERVERURL=https://ci.invalid', "/l*v", $log) $log
$order = (Select-String -Path $log -Pattern 'Action start .*: (CreateFolders|DefenderPreExclude|InstallFiles|ServiceBundleEnvironment|DefenderExclude)\.' | ForEach-Object { $_.Matches[0].Groups[1].Value })
Check (($order -join ',') -eq 'CreateFolders,DefenderPreExclude,InstallFiles,ServiceBundleEnvironment,DefenderExclude') "the MSI runs create, lock/verify/exclude, files, then the agent's own add (saw: $($order -join ','))"
Check ((Test-Path (Join-Path $data 'work')) -and (Test-Path (Join-Path $data 'bundle\defender'))) 'the work and extraction folders exist'
$acl = (Get-Acl $install).Access | Where-Object { $_.IdentityReference.Value -match 'Users' -and ($_.FileSystemRights -band 0x40116) }
Check (-not $acl) 'Users cannot write the program folder'
if ($active) {
    $l = Lists
    Check ((Listed $l.path $install) -and (Listed $l.path $data)) 'both folders are in ExclusionPath'
    Check ((Listed $l.asr $install) -and (Listed $l.asr $data)) 'both folders are in AttackSurfaceReductionOnlyExclusions'
    Check ((Listed $l.process $exe) -and (Listed $l.cfa $exe)) 'the program is in ExclusionProcess and ControlledFolderAccessAllowedApplications'
    Check (-not ((Listed $l.path $env:TEMP) -or (Listed $l.process "$env:SystemRoot\System32\msiexec.exe") -or (Listed $l.path 'C:\Windows\Temp'))) '%TEMP% and msiexec are not excluded'
    $record = Get-Content -Raw (Join-Path $data 'state\defender-exclusions.json') | ConvertFrom-Json
    Check ($record.version -eq 1 -and @($record.entries).Count -ge 6) 'the record lists what was added'
    Check (Listed (Lists).path $keep) 'the administrator''s own exclusion is still listed'

    # Step 2, check.
    $s = Status
    Check ($s.state -eq 'effective' -or $s.state -eq 'present_not_effective') "defender status says $($s.state)"
    $dlam = (Get-MpPreference).DisableLocalAdminMerge
    if (-not $dlam) {
        try {
            Set-MpPreference -DisableLocalAdminMerge $true
            $s = Status
            Check ($s.state -eq 'present_not_effective' -and $s.reason -match 'DisableLocalAdminMerge') 'DisableLocalAdminMerge is reported'
        } catch { Write-Host "skipped: DisableLocalAdminMerge cannot be set on this image ($($_.Exception.Message))" }
        finally { Set-MpPreference -DisableLocalAdminMerge $false }
    }
} else {
    $s = Status
    Check ($s.state -eq 'not_applicable' -and $s.reason) "Defender is not active, so the state is not_applicable ($($s.reason))"
}

# Step 4, not locked: a parent that Users may write cannot be verified, so nothing is excluded for it and what was added is removed.
if ($active) {
    & icacls "$env:ProgramData" /grant 'Users:(OI)(CI)M' | Out-Null
    try {
        & $exe defender add | Out-Null
        $s = Status
        Check ($s.state -eq 'not_locked') "a writable parent gives not_locked ($($s.reason))"
        $l = Lists
        Check (-not (Listed $l.path $data) -and -not (Listed $l.asr $data)) 'the exclusion of the folder that became writable was removed'
    } finally { & icacls "$env:ProgramData" /remove:g Users | Out-Null }
    & $exe defender add | Out-Null
    Check ((Status).state -eq 'effective' -or (Status).state -eq 'present_not_effective') 'the exclusions are back once the folder verifies again'
}

# Step 5, moved work: the agent's own work folder is in the locked, verified tree, and the installer's runs left nothing of theirs outside it.
Check (-not (Get-ChildItem $env:TEMP, "$env:SystemRoot\Temp" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'EasyPatch*' })) 'no EasyPatch file is in %TEMP% or C:\Windows\Temp'
Write-Host 'note: winget and agent-update runs through the work folder are tested by hand (docs/notes/defx-b.md), not here.'

# Step 8, the .NET extraction folders: the service's own value only, never machine-wide.
$env64 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EasyPatchAgent' -Name Environment).Environment
Check (@($env64) -contains "DOTNET_BUNDLE_EXTRACT_BASE_DIR=$data\bundle\EasyPatchAgent") 'the service has its own extraction folder'
Check (-not [Environment]::GetEnvironmentVariable('DOTNET_BUNDLE_EXTRACT_BASE_DIR', 'Machine')) 'the variable is not set machine-wide'
Start-Sleep -Seconds 20
$extracted = @(Get-ChildItem (Join-Path $data 'bundle\EasyPatchAgent') -Recurse -ErrorAction SilentlyContinue).Count
Write-Host "recorded for the ADR: the service extracted $extracted items into bundle\EasyPatchAgent"

# Step 3, remove: exactly what was added goes, the administrator's own stays.
$log = Join-Path $env:RUNNER_TEMP 'ep-remove.log'
Msi @('/x', $Msi, '/qn', '/norestart', '/l*v', $log) $log
$l = Lists
Check (-not ((Listed $l.path $install) -or (Listed $l.path $data) -or (Listed $l.asr $install) -or (Listed $l.asr $data) -or (Listed $l.process $exe) -or (Listed $l.cfa $exe))) 'uninstall removed every exclusion it added'
Check (Listed $l.path $keep) 'the administrator''s own exclusion survived the uninstall'
Check (-not (Test-Path (Join-Path $data 'state\defender-exclusions.json'))) 'the record is deleted'
Remove-MpPreference -ExclusionPath $keep

if ($failures.Count) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
