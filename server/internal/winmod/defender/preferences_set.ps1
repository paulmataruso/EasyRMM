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

$enumNames = @{
    'PUAProtection' = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode' }
    'EnableNetworkProtection' = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode' }
    'CloudBlockLevel' = @{ '0' = 'Default'; '1' = 'Moderate'; '2' = 'High'; '4' = 'HighPlus'; '6' = 'ZeroTolerance' }
    'LowThreatDefaultAction' = @{ '1' = 'Clean'; '2' = 'Quarantine'; '3' = 'Remove'; '6' = 'Allow'; '8' = 'UserDefined'; '9' = 'NoAction' }
}
$enumNames['ModerateThreatDefaultAction'] = $enumNames['LowThreatDefaultAction']
$enumNames['HighThreatDefaultAction'] = $enumNames['LowThreatDefaultAction']
$enumNames['SevereThreatDefaultAction'] = $enumNames['LowThreatDefaultAction']
# A preference as the console shows and compares it: true/false text, a number, an enum's name, or minutes after midnight.
function ConvertTo-Canon($name, $kind, $raw) {
    if ($null -eq $raw) { return $null }
    switch ($kind) {
        'bool' { return ([string][bool]$raw).ToLowerInvariant() }
        'minutes' {
            if ($raw -is [datetime]) { return [string][int]$raw.TimeOfDay.TotalMinutes }
            if ($raw -is [timespan]) { return [string][int]$raw.TotalMinutes }
            return [string][int]$raw
        }
        'int' { return [string][int]$raw }
        default {
            $s = [string]$raw
            if ($enumNames.ContainsKey($name) -and $enumNames[$name].ContainsKey($s)) { return $enumNames[$name][$s] }
            return $s
        }
    }
}

$fields = [ordered]@{
    'DisableRealtimeMonitoring' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Real-Time Protection'; value = 'DisableRealtimeMonitoring'; min = 0; max = 0; values = '' }
    'DisableBehaviorMonitoring' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Real-Time Protection'; value = 'DisableBehaviorMonitoring'; min = 0; max = 0; values = '' }
    'DisableIOAVProtection' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Real-Time Protection'; value = 'DisableIOAVProtection'; min = 0; max = 0; values = '' }
    'DisableScriptScanning' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Real-Time Protection'; value = 'DisableScriptScanning'; min = 0; max = 0; values = '' }
    'DisableBlockAtFirstSeen' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Spynet'; value = 'DisableBlockAtFirstSeen'; min = 0; max = 0; values = '' }
    'DisableArchiveScanning' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Scan'; value = 'DisableArchiveScanning'; min = 0; max = 0; values = '' }
    'DisableEmailScanning' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Scan'; value = 'DisableEmailScanning'; min = 0; max = 0; values = '' }
    'DisableRemovableDriveScanning' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Scan'; value = 'DisableRemovableDriveScanning'; min = 0; max = 0; values = '' }
    'DisableScanningNetworkFiles' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Scan'; value = 'DisableScanningNetworkFiles'; min = 0; max = 0; values = '' }
    'DisableScanningMappedNetworkDrivesForFullScan' = @{ kind = 'bool'; group = 'protection'; tamper = $true; key = 'Scan'; value = 'DisableScanningMappedNetworkDrivesForFullScan'; min = 0; max = 0; values = '' }
    'MAPSReporting' = @{ kind = 'int'; group = 'cloud'; tamper = $true; key = 'Spynet'; value = 'SpynetReporting'; min = 0; max = 2; values = '' }
    'SubmitSamplesConsent' = @{ kind = 'int'; group = 'cloud'; tamper = $true; key = 'Spynet'; value = 'SubmitSamplesConsent'; min = 0; max = 3; values = '' }
    'CloudBlockLevel' = @{ kind = 'enum'; group = 'cloud'; tamper = $true; key = 'MpEngine'; value = 'MpCloudBlockLevel'; min = 0; max = 0; values = 'Default,Moderate,High,HighPlus,ZeroTolerance' }
    'CloudExtendedTimeout' = @{ kind = 'int'; group = 'cloud'; tamper = $true; key = 'MpEngine'; value = 'MpBafsExtendedTimeout'; min = 0; max = 50; values = '' }
    'PUAProtection' = @{ kind = 'enum'; group = 'features'; tamper = $true; key = ''; value = 'PUAProtection'; min = 0; max = 0; values = 'Disabled,Enabled,AuditMode' }
    'EnableNetworkProtection' = @{ kind = 'enum'; group = 'features'; tamper = $true; key = 'Windows Defender Exploit Guard\Network Protection'; value = 'EnableNetworkProtection'; min = 0; max = 0; values = 'Disabled,Enabled,AuditMode' }
    'LowThreatDefaultAction' = @{ kind = 'enum'; group = 'threats'; tamper = $true; key = 'Threats\Threats_ThreatSeverityDefaultAction'; value = '1'; min = 0; max = 0; values = 'Clean,Quarantine,Remove,Allow,UserDefined,NoAction' }
    'ModerateThreatDefaultAction' = @{ kind = 'enum'; group = 'threats'; tamper = $true; key = 'Threats\Threats_ThreatSeverityDefaultAction'; value = '2'; min = 0; max = 0; values = 'Clean,Quarantine,Remove,Allow,UserDefined,NoAction' }
    'HighThreatDefaultAction' = @{ kind = 'enum'; group = 'threats'; tamper = $true; key = 'Threats\Threats_ThreatSeverityDefaultAction'; value = '4'; min = 0; max = 0; values = 'Clean,Quarantine,Remove,Allow,UserDefined,NoAction' }
    'SevereThreatDefaultAction' = @{ kind = 'enum'; group = 'threats'; tamper = $true; key = 'Threats\Threats_ThreatSeverityDefaultAction'; value = '5'; min = 0; max = 0; values = 'Clean,Quarantine,Remove,Allow,UserDefined,NoAction' }
    'QuarantinePurgeItemsAfterDelay' = @{ kind = 'int'; group = 'retention'; tamper = $false; key = 'Quarantine'; value = 'PurgeItemsAfterDelay'; min = 0; max = 365; values = '' }
    'ScanPurgeItemsAfterDelay' = @{ kind = 'int'; group = 'retention'; tamper = $false; key = 'Scan'; value = 'PurgeItemsAfterDelay'; min = 0; max = 365; values = '' }
    'ScanScheduleDay' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'ScheduleDay'; min = 0; max = 8; values = '' }
    'ScanScheduleTime' = @{ kind = 'minutes'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'ScheduleTime'; min = 0; max = 1439; values = '' }
    'ScanScheduleQuickScanTime' = @{ kind = 'minutes'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'ScheduleQuickScanTime'; min = 0; max = 1439; values = '' }
    'ScanParameters' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'ScanParameters'; min = 1; max = 2; values = '' }
    'RemediationScheduleDay' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Remediation'; value = 'Scan_ScheduleDay'; min = 0; max = 8; values = '' }
    'RemediationScheduleTime' = @{ kind = 'minutes'; group = 'schedule'; tamper = $false; key = 'Remediation'; value = 'Scan_ScheduleTime'; min = 0; max = 1439; values = '' }
    'DisableCatchupFullScan' = @{ kind = 'bool'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'DisableCatchupFullScan'; min = 0; max = 0; values = '' }
    'DisableCatchupQuickScan' = @{ kind = 'bool'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'DisableCatchupQuickScan'; min = 0; max = 0; values = '' }
    'SignatureScheduleDay' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'ScheduleDay'; min = 0; max = 8; values = '' }
    'SignatureScheduleTime' = @{ kind = 'minutes'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'ScheduleTime'; min = 0; max = 1439; values = '' }
    'SignatureUpdateInterval' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'SignatureUpdateInterval'; min = 1; max = 24; values = '' }
    'SignatureUpdateCatchupInterval' = @{ kind = 'int'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'SignatureUpdateCatchupInterval'; min = 1; max = 30; values = '' }
    'RandomizeScheduleTaskTimes' = @{ kind = 'bool'; group = 'schedule'; tamper = $false; key = 'Scan'; value = 'RandomizeScheduleTaskTimes'; min = 0; max = 0; values = '' }
    'CheckForSignaturesBeforeRunningScan' = @{ kind = 'bool'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'CheckAlertsBeforeScan'; min = 0; max = 0; values = '' }
    'MeteredConnectionUpdates' = @{ kind = 'bool'; group = 'schedule'; tamper = $false; key = 'Signature Updates'; value = 'MeteredConnectionUpdates'; min = 0; max = 0; values = '' }
    'ScanAvgCPULoadFactor' = @{ kind = 'int'; group = 'performance'; tamper = $false; key = 'Scan'; value = 'AvgCPULoadFactor'; min = 0; max = 100; values = '' }
    'ScanOnlyIfIdleEnabled' = @{ kind = 'bool'; group = 'performance'; tamper = $false; key = 'Scan'; value = 'ScanOnlyIfIdle'; min = 0; max = 0; values = '' }
    'EnableLowCpuPriority' = @{ kind = 'bool'; group = 'performance'; tamper = $false; key = 'Scan'; value = 'LowCpuPriority'; min = 0; max = 0; values = '' }
    'DisableCpuThrottleOnIdleScans' = @{ kind = 'bool'; group = 'performance'; tamper = $false; key = ''; value = 'DisableCpuThrottleOnIdleScans'; min = 0; max = 0; values = '' }
    'EnableFullScanOnBatteryPower' = @{ kind = 'bool'; group = 'performance'; tamper = $false; key = 'Scan'; value = 'DisableScanningOnBattery'; min = 0; max = 0; values = '' }
    'DisableRestorePoint' = @{ kind = 'bool'; group = 'performance'; tamper = $false; key = 'Scan'; value = 'DisableRestorePoint'; min = 0; max = 0; values = '' }
    'DisableAutoExclusions' = @{ kind = 'bool'; group = 'servers'; tamper = $false; key = 'Exclusions'; value = 'DisableAutoExclusions'; min = 0; max = 0; values = '' }
}

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender

    $entry = $null
    $fname = $null
    foreach ($k in $fields.Keys) { if ($k -ceq $p.field) { $entry = $fields[$k]; $fname = $k } }
    if ($null -eq $entry) {
        Write-Result $false $null 'not_allowed' 'This preference cannot be set from the module.'
        exit 0
    }
    if ($entry.group -in @('protection', 'cloud', 'features', 'threats') -and (Test-Passive)) {
        Write-Result $false $null 'passive_mode' 'Defender is not the active antivirus on this computer.'
        exit 0
    }
    $owner = Get-PolicyOwner $entry.key $entry.value
    if ($null -eq $owner -and $entry.tamper -and (Get-TamperOn)) { $owner = 'tamper_protection' }
    if ($null -ne $owner -and $owner -ne 'unknown_owner') {
        Write-Result $false $null 'managed_by_policy' $ownerMsg[$owner]
        exit 0
    }
    $pref = Get-MpPreference
    if (-not ($pref.PSObject.Properties.Name -contains $fname)) {
        Write-Result $false $null 'unsupported' 'This computer does not have this preference.'
        exit 0
    }
    $before = ConvertTo-Canon $fname $entry.kind $pref.$fname
    $want = [string]$p.value
    switch ($entry.kind) {
        'bool' { $arg = ($want -eq 'true') }
        'int' { $arg = [int]$want }
        'minutes' { $arg = [datetime]::Today.AddMinutes([int]$want) }
        default { $arg = $want }
    }
    $splat = @{}
    $splat[$fname] = $arg
    Set-MpPreference @splat
    $after = ConvertTo-Canon $fname $entry.kind (Get-MpPreference).$fname
    $applied = ($after -eq $want)
    $reason = ''
    if (-not $applied) { $reason = 'The value did not change. Tamper Protection or a policy that appeared since the read may have blocked it.' }
    Write-Result $true ([ordered]@{ applied = $applied; reason = $reason; before = $before; after = $after }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('The Defender action failed: ' + $_.Exception.GetType().Name)
}
