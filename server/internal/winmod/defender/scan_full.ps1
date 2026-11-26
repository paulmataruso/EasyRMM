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
    if ($null -ne $o -and $o.PSObject.Properties.Name -contains $name) { return $o.$name }
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

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender

    Start-MpScan -ScanType FullScan
    Write-Result $true ([ordered]@{ scanType = 'full'; finishedAt = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('The Defender action failed: ' + $_.Exception.GetType().Name)
}
