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

try {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Result $false $null 'module_missing' 'The DnsServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DnsServer
    $state = Get-ServiceState 'DNS'
    $data = [ordered]@{
        serviceState     = $state
        zoneCount        = 0
        adIntegratedCount = 0
        recursionEnabled = $null
        forwarders       = @()
        listenAddresses  = @()
        scavengingHours  = $null
        transferAnyZones = @()
    }
    if ($state -eq 'running') {
        $zones = @(Get-DnsServerZone)
        $data.zoneCount = $zones.Count
        $data.adIntegratedCount = @($zones | Where-Object { $_.IsDsIntegrated }).Count
        $data.transferAnyZones = @($zones | Where-Object { [string](Get-Prop $_ 'SecureSecondaries') -eq 'TransferAnyServer' } | ForEach-Object { [string]$_.ZoneName } | Select-Object -First 50)
        $data.recursionEnabled = [bool](Get-DnsServerRecursion).Enable
        $data.forwarders = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { $_.IPAddressToString })
        $data.listenAddresses = @((Get-DnsServerSetting).ListeningIPAddress | ForEach-Object { $_.IPAddressToString })
        $data.scavengingHours = [int](Get-DnsServerScavenging).ScavengingInterval.TotalHours
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the DNS server state failed: ' + $_.Exception.GetType().Name)
}
