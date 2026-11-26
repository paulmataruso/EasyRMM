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

function Get-ZoneFile([string]$fx_zone) { return $fx_zone.TrimEnd('.') + '.dns' }
function Test-ProtectedZone([string]$fx_zone) {
    $fx_zl = Get-Labels $fx_zone
    if ($fx_zl.Count -gt 0 -and @('_msdcs', 'domaindnszones', 'forestdnszones') -contains $fx_zl[0]) { return $true }
    $fx_z = $fx_zone.TrimEnd('.').ToLowerInvariant()
    $fx_cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($fx_cs.PartOfDomain -and ([string]$fx_cs.Domain).ToLowerInvariant() -eq $fx_z) { return $true }
    try {
        $fx_forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name.ToLowerInvariant()
        if ($fx_forest -eq $fx_z -or ('_msdcs.' + $fx_forest) -eq $fx_z) { return $true }
    } catch { return $false }
    return $false
}
function Get-Labels([string]$fx_n) {
    return @($fx_n.TrimEnd('.').ToLowerInvariant().Split('.') | Where-Object { $_ -ne '' })
}

try {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Result $false $null 'module_missing' 'The DnsServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DnsServer
    $zone = [string](Get-Prop $p 'zone')
    if (Test-ProtectedZone $zone) {
        Write-Result $false $null 'protected_zone' 'This zone holds what Active Directory needs to find its domain controllers; this console does not remove it.'
        exit 0
    }
    if ($null -eq (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) { Write-Result $false $null 'zone_not_found' 'There is no zone of this name on this server.'; exit 0 }
    Remove-DnsServerZone -Name $zone -Force
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the DNS zone failed: ' + $_.Exception.GetType().Name)
}
