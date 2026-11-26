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

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender

    $pref = Get-MpPreference
    $ids = Get-Prop $pref 'AttackSurfaceReductionRules_Ids'
    $acts = Get-Prop $pref 'AttackSurfaceReductionRules_Actions'
    if ($null -eq $pref.PSObject.Properties['AttackSurfaceReductionRules_Ids']) {
        Write-Result $true ([ordered]@{ supported = $false; rules = @() }) $null $null
        exit 0
    }
    $ids = @(@($ids) | Where-Object { $null -ne $_ })
    $acts = @(@($acts) | Where-Object { $null -ne $_ })
    $modes = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode'; '6' = 'Warn' }
    $rules = @()
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $m = [string]$acts[$i]
        if ($modes.ContainsKey($m)) { $m = $modes[$m] }
        $rules += , ([ordered]@{ id = ([string]$ids[$i]).ToLowerInvariant(); mode = $m; managedBy = (Get-PolicyOwner 'Windows Defender Exploit Guard\ASR\Rules' ([string]$ids[$i])) })
    }
    Write-Result $true ([ordered]@{ supported = $true; rules = $rules }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('The Defender action failed: ' + $_.Exception.GetType().Name)
}
