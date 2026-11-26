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
    if ($null -ne $o.PSObject.Properties[$name]) { return $o.$name }
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

function Convert-Zone($fx_z) {
    $fx_ds = [bool]$fx_z.IsDsIntegrated
    $fx_scope = ''
    if ($fx_ds) { $fx_scope = ([string](Get-Prop $fx_z 'ReplicationScope')).ToLowerInvariant() }
    return [ordered]@{
        name            = [string]$fx_z.ZoneName
        type            = ([string]$fx_z.ZoneType).ToLowerInvariant()
        adIntegrated    = $fx_ds
        replicationScope = $fx_scope
        dynamicUpdate   = [string](Get-Prop $fx_z 'DynamicUpdate')
        reverse         = [bool]$fx_z.IsReverseLookupZone
        paused          = [bool]$fx_z.IsPaused
        shutdown        = [bool]$fx_z.IsShutdown
        signed          = [bool]$fx_z.IsSigned
        agingEnabled    = [bool](Get-Prop $fx_z 'AgingEnabled')
    }
}

try {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Result $false $null 'module_missing' 'The DnsServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DnsServer
    $zones = @(Get-DnsServerZone | Where-Object { $_.ZoneName -ne 'TrustAnchors' } | Sort-Object ZoneName)
    $rows = @($zones | Select-Object -First 300 | ForEach-Object { Convert-Zone $_ })
    Write-Result $true ([ordered]@{ zones = $rows; truncated = ($zones.Count -gt 300) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the DNS zones failed: ' + $_.Exception.GetType().Name)
}
