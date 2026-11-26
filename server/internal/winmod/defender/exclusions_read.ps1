Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 8))
}
function Get-Prop($o, $name) {
    if ($null -ne $o -and $null -ne $o.PSObject.Properties[$name]) { return $o.$name }
    return $null
}
function Get-Flag($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v) { return $null }
    return [bool]$v
}
function Get-Days($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v -or [int64]$v -gt 100000) { return $null }
    return [int]$v
}

$gpoRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$mdmRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Policy Manager'
# Who owns a setting: a value under the Group Policy key, or under the Defender CSP's Policy Manager key. An unreadable
# key is 'unknown_owner', never silently "nobody".
function Get-PolicyOwner($subkey, $valueName) {
    foreach ($r in @(@('group_policy', $gpoRoot), @('mdm', $mdmRoot))) {
        $key = $r[1]
        if ($subkey) { $key = $key + '\' + $subkey }
        try {
            if (Test-Path -LiteralPath $key) {
                if ((Get-Item -LiteralPath $key).GetValueNames() -contains $valueName) { return $r[0] }
            }
        } catch { return 'unknown_owner' }
    }
    return $null
}
$ownerMsg = @{
    group_policy = 'This is managed by Group Policy on the computer, so it is not changed from here.'
    mdm = 'This is managed by device management (Intune), so it is not changed from here.'
    defender_for_endpoint = 'This is managed by Defender for Endpoint, so it is not changed from here.'
    configmgr = 'This is managed by Configuration Manager, so it is not changed from here.'
    tamper_protection = 'Tamper Protection is on and blocks this change; change it in the Windows Security app, Intune or the Defender portal.'
}
function Get-TamperOn {
    try { return [bool](Get-Prop (Get-MpComputerStatus) 'IsTamperProtected') } catch { return $false }
}
function Test-Passive {
    try {
        $m = [string](Get-Prop (Get-MpComputerStatus) 'AMRunningMode')
        return ($m -like '*Passive*' -or $m -eq 'Not running')
    } catch { return $false }
}

$pfDir = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name 'ProgramFilesDir')
$sysRoot = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'SystemRoot')
$pdDir = $sysRoot.Substring(0, 2) + '\ProgramData'
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class EasyRmmPath {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint GetLongPathName(string s, StringBuilder b, uint n);
    public static string Long(string s) {
        var b = new StringBuilder(1024);
        uint r = GetLongPathName(s, b, 1024);
        return (r == 0 || r > 1024) ? s : b.ToString();
    }
}
'@
# A path as it is compared: variables expanded, short names made long, normalised, lower case (ADR-0074 section 5).
function Get-Norm($v) {
    $s = [string]$v
    $s = $s -replace '(?i)%ProgramFiles%', $pfDir -replace '(?i)%ProgramData%', $pdDir -replace '(?i)%SystemRoot%', $sysRoot -replace '(?i)%SystemDrive%', $sysRoot.Substring(0, 2)
    $s = $s.Trim().Replace('/', '\')
    if ($s.Contains('~')) { $s = [EasyRmmPath]::Long($s) }
    try { $s = [System.IO.Path]::GetFullPath($s) } catch { $s = [string]$v }
    while ($s.Length -gt 3 -and $s.EndsWith('\')) { $s = $s.Substring(0, $s.Length - 1) }
    return $s.ToLowerInvariant()
}
# What is ours: the fixed set of ADR-0070 and both agents' records. A record that cannot be read leaves the fixed set.
$ours = @{ path = @{}; asr_only = @{}; process = @{}; cfa_app = @{} }
foreach ($f in @("$pfDir\EasyRMM\Agent", "$pfDir\EasyRMM\MeshAgent", "$pfDir\EasyPatch Agent", "$pdDir\EasyRMM\Agent", "$pdDir\EasyPatch")) {
    $ours['path'][(Get-Norm $f)] = $true
    $ours['asr_only'][(Get-Norm $f)] = $true
}
foreach ($e in @("$pfDir\EasyRMM\Agent\easyrmm-agent.exe", "$pfDir\EasyRMM\MeshAgent\meshagent.exe", "$pfDir\EasyPatch Agent\EasyPatch.Agent.exe")) {
    $ours['process'][(Get-Norm $e)] = $true
    $ours['cfa_app'][(Get-Norm $e)] = $true
}
$recordKinds = @{ path = 'path'; asr = 'asr_only'; process = 'process'; cfa = 'cfa_app' }
foreach ($rf in @("$pdDir\EasyRMM\Agent\defender-exclusions.json", "$pdDir\EasyPatch\defender-exclusions.json")) {
    try {
        if (Test-Path -LiteralPath $rf) {
            $rec = Get-Content -LiteralPath $rf -Raw | ConvertFrom-Json
            foreach ($e in @($rec.entries)) {
                $k = [string](Get-Prop $e 'kind')
                $v = [string](Get-Prop $e 'path')
                if ($recordKinds.ContainsKey($k) -and $v) { $ours[$recordKinds[$k]][(Get-Norm $v)] = $true }
            }
        }
    } catch { $rec = $null }
}
function Test-Ours($kind, $value) { return $ours[$kind].ContainsKey((Get-Norm $value)) }
function Get-OursPaths($kind) { return @($ours[$kind].Keys) }

function Test-ListAvailable($pref, $name) {
    if ($null -eq $pref -or $null -eq $pref.PSObject.Properties[$name]) { return $false }
    $v = $pref.$name
    if ($null -eq $v) { return $true }
    return (@($v | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'N/A:*' }).Count -eq 0)
}
# Defender answers "N/A: Must be an administrator or have Tamper Protection..." for what it will not show: unavailable, not empty.
function Get-List($pref, $name) {
    # A list that is empty is $null on a real computer, though its property is there: only a missing property, or
    # the "N/A" text, makes a list unavailable (Test-ListAvailable).
    $v = Get-Prop $pref $name
    if ($null -eq $v) { return $null }
    $items = @($v | ForEach-Object { [string]$_ })
    if ($items.Count -gt 0 -and @($items | Where-Object { $_ -like 'N/A:*' }).Count -gt 0) { return $null }
    return $items
}
$listSpec = @{
    path = @{ pref = 'ExclusionPath'; key = 'Exclusions\Paths' }
    process = @{ pref = 'ExclusionProcess'; key = 'Exclusions\Processes' }
    extension = @{ pref = 'ExclusionExtension'; key = 'Exclusions\Extensions' }
    asr_only = @{ pref = 'AttackSurfaceReductionOnlyExclusions'; key = 'Windows Defender Exploit Guard\ASR\ASROnlyExclusions' }
}

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender

    $pref = Get-MpPreference
    $tamper = Get-TamperOn
    $out = [ordered]@{ path = @(); process = @(); extension = @(); asrOnly = @() }
    $outKey = @{ path = 'path'; process = 'process'; extension = 'extension'; asr_only = 'asrOnly' }
    $unavailable = @()
    foreach ($kind in @('path', 'process', 'extension', 'asr_only')) {
        $spec = $listSpec[$kind]
        if (-not (Test-ListAvailable $pref $spec.pref)) { $unavailable += $kind; continue }
        $items = @(Get-List $pref $spec.pref)
        $rows = @()
        foreach ($v in $items) {
            if (-not $v) { continue }
            $isOurs = $false
            if ($kind -ne 'extension') { $isOurs = Test-Ours $kind $v }
            $owner = Get-PolicyOwner $spec.key $v
            if ($null -eq $owner -and $tamper -and -not $isOurs) { $owner = 'tamper_protection' }
            $rows += , ([ordered]@{ value = $v; ours = $isOurs; managedBy = $owner })
        }
        $out[$outKey[$kind]] = $rows
    }
    $merge = $null
    if ($pref.PSObject.Properties.Name -contains 'DisableLocalAdminMerge') { $merge = [bool]$pref.DisableLocalAdminMerge }
    Write-Result $true ([ordered]@{ path = $out['path']; process = $out['process']; extension = $out['extension']; asrOnly = $out['asrOnly']; unavailable = $unavailable; localMergeDisabled = $merge; tamperProtected = $tamper }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('The Defender action failed: ' + $_.Exception.GetType().Name)
}
