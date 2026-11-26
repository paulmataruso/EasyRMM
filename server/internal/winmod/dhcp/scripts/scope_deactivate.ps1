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
    if ($o.PSObject.Properties.Name -contains $name) { return $o.$name }
    return $null
}
function Get-ServiceState([string]$name) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $s) { return 'absent' }
    return ([string]$s.Status).ToLowerInvariant()
}
function Get-NextOffset($fx_off, $fx_count, $fx_total) {
    if ($fx_off + $fx_count -lt $fx_total) { return $fx_off + $fx_count }
    return $null
}
function Get-Utc($t) {
    if ($null -eq $t) { return $null }
    return ([datetime]$t).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function ConvertTo-UInt([string]$fx_ip) {
    $fx_b = ([System.Net.IPAddress]::Parse($fx_ip)).GetAddressBytes()
    return ([uint32]$fx_b[0] -shl 24) + ([uint32]$fx_b[1] -shl 16) + ([uint32]$fx_b[2] -shl 8) + [uint32]$fx_b[3]
}
function ConvertTo-ClientId([string]$fx_mac) {
    $fx_h = ($fx_mac -replace '[-:]', '').ToLowerInvariant()
    return ($fx_h -replace '(..)(?=.)', '$1-')
}
function Convert-Scope($fx_s, $fx_st) {
    $fx_free = 0; $fx_used = 0; $fx_pct = 0
    if ($null -ne $fx_st) {
        $fx_free = [int64]$fx_st.Free; $fx_used = [int64]$fx_st.InUse; $fx_pct = [int][math]::Round([double]$fx_st.PercentageInUse)
    }
    return [ordered]@{
        scopeId              = $fx_s.ScopeId.IPAddressToString
        name                 = [string]$fx_s.Name
        description          = [string]$fx_s.Description
        state                = [string]$fx_s.State
        startRange           = $fx_s.StartRange.IPAddressToString
        endRange             = $fx_s.EndRange.IPAddressToString
        subnetMask           = $fx_s.SubnetMask.IPAddressToString
        leaseDurationSeconds = [int64]$fx_s.LeaseDuration.TotalSeconds
        free                 = $fx_free
        inUse                = $fx_used
        percentageInUse      = $fx_pct
    }
}
function Get-ScopeRow([string]$fx_scopeId) {
    $fx_s = Get-DhcpServerv4Scope -ScopeId $fx_scopeId
    $fx_st = Get-DhcpServerv4ScopeStatistics -ScopeId $fx_scopeId -ErrorAction SilentlyContinue
    return Convert-Scope $fx_s $fx_st
}
function Test-InFailover([string]$fx_scopeId) {
    $fx_f = Get-DhcpServerv4Failover -ScopeId $fx_scopeId -ErrorAction SilentlyContinue
    return ($null -ne $fx_f)
}

try {
    if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
        Write-Result $false $null 'module_missing' 'The DhcpServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DhcpServer
    $scopeId = [string](Get-Prop $p 'scopeId')

    if ($null -eq (Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction SilentlyContinue)) { Write-Result $false $null 'scope_not_found' 'There is no scope of this ID on this server.'; exit 0 }

    Set-DhcpServerv4Scope -ScopeId $scopeId -State 'InActive'
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Deactivating the DHCP scope failed: ' + $_.Exception.GetType().Name)
}
