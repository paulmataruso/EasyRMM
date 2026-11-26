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
    $storage = [string](Get-Prop $p 'storage')
    $mode = [string](Get-Prop $p 'dynamicUpdate')
    if ($null -ne (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) { Write-Result $false $null 'zone_exists' 'A zone of this name already exists.'; exit 0 }
    if ($mode -eq 'Secure' -and $storage -eq 'file') { Write-Result $false $null 'secure_needs_ad' 'Secure dynamic updates need an Active Directory-integrated zone.'; exit 0 }
    $q = @{ Name = $zone; DynamicUpdate = $mode }
    switch ($storage) {
        'file' { $q.ZoneFile = Get-ZoneFile $zone }
        'ad_domain' { $q.ReplicationScope = 'Domain' }
        'ad_forest' { $q.ReplicationScope = 'Forest' }
        'ad_legacy' { $q.ReplicationScope = 'Legacy' }
    }
    Add-DnsServerPrimaryZone @q
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Creating the DNS zone failed: ' + $_.Exception.GetType().Name)
}
