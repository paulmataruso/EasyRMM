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
    $zone = [string](Get-Prop $p 'zone')
    $mode = [string](Get-Prop $p 'mode')
    $z = Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue
    if ($null -eq $z) { Write-Result $false $null 'zone_not_found' 'There is no zone of this name on this server.'; exit 0 }
    $ds = [bool]$z.IsDsIntegrated
    if ($mode -eq 'None' -and $ds) { Write-Result $false $null 'updates_required' 'Domain computers register their names in an Active Directory-integrated zone; turning updates off would stop that.'; exit 0 }
    if ($mode -eq 'Secure' -and -not $ds) { Write-Result $false $null 'secure_needs_ad' 'Secure dynamic updates need an Active Directory-integrated zone.'; exit 0 }
    Set-DnsServerPrimaryZone -Name $zone -DynamicUpdate $mode
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Changing the zone dynamic update setting failed: ' + $_.Exception.GetType().Name)
}
