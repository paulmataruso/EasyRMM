Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 6))
}
function Get-Prop($o, $name) {
    if ($o.PSObject.Properties.Name -contains $name) { return $o.$name }
    return $null
}
function Get-Flag($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v) { return $null }
    return [bool]$v
}
# Ages are days; Defender reports 4294967295 for "never".
function Get-Days($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v -or [int64]$v -gt 100000) { return $null }
    return [int]$v
}
function Get-Text($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v) { return '' }
    return [string]$v
}

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender
    $s = Get-MpComputerStatus
    $updated = Get-Prop $s 'AntivirusSignatureLastUpdated'
    $state = Get-Prop $s 'ComputerState'
    $data = [ordered]@{
        antivirusEnabled          = Get-Flag $s 'AntivirusEnabled'
        antispywareEnabled        = Get-Flag $s 'AntispywareEnabled'
        realTimeProtectionEnabled = Get-Flag $s 'RealTimeProtectionEnabled'
        behaviorMonitorEnabled    = Get-Flag $s 'BehaviorMonitorEnabled'
        ioavProtectionEnabled     = Get-Flag $s 'IoavProtectionEnabled'
        onAccessProtectionEnabled = Get-Flag $s 'OnAccessProtectionEnabled'
        nisEnabled                = Get-Flag $s 'NISEnabled'
        tamperProtected           = Get-Flag $s 'IsTamperProtected'
        runningMode               = Get-Text $s 'AMRunningMode'
        computerState             = $(if ($null -eq $state) { $null } else { [int]$state })
        engineVersion             = Get-Text $s 'AMEngineVersion'
        productVersion            = Get-Text $s 'AMProductVersion'
        serviceVersion            = Get-Text $s 'AMServiceVersion'
        signatureVersion          = Get-Text $s 'AntivirusSignatureVersion'
        signatureUpdatedAt        = $(if ($null -eq $updated) { $null } else { ([datetime]$updated).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') })
        signatureAgeDays          = Get-Days $s 'AntivirusSignatureAge'
        quickScanAgeDays          = Get-Days $s 'QuickScanAge'
        fullScanAgeDays           = Get-Days $s 'FullScanAge'
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the Defender state failed: ' + $_.Exception.GetType().Name)
}
