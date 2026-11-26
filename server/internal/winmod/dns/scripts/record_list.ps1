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

function Get-Labels([string]$fx_n) {
    return @($fx_n.TrimEnd('.').ToLowerInvariant().Split('.') | Where-Object { $_ -ne '' })
}
# The name relative to the zone: '@' for the apex, '' when an absolute name is outside the zone.
function Get-RelName([string]$fx_zone, [string]$fx_name) {
    $fx_z = $fx_zone.TrimEnd('.').ToLowerInvariant()
    if ($fx_name -eq '@') { return '@' }
    if (-not $fx_name.EndsWith('.')) { return $fx_name }
    $fx_n = $fx_name.TrimEnd('.').ToLowerInvariant()
    if ($fx_n -eq $fx_z) { return '@' }
    if ($fx_n.EndsWith('.' + $fx_z)) { return $fx_n.Substring(0, $fx_n.Length - $fx_z.Length - 1) }
    return ''
}
function Get-FullName([string]$fx_zone, [string]$fx_rel) {
    $fx_z = $fx_zone.TrimEnd('.').ToLowerInvariant()
    if ($fx_rel -eq '@') { return $fx_z }
    return $fx_rel.ToLowerInvariant() + '.' + $fx_z
}
# ADR-0076 section 4: the records that let computers find domain controllers. The server refuses the same names
# before a job exists; this is the second guard, and the one that knows whether the zone is in Active Directory.
function Test-ProtectedRecord([string]$fx_zone, [string]$fx_rel, [string]$fx_type, [bool]$fx_ds) {
    $fx_special = @('_msdcs', 'domaindnszones', 'forestdnszones')
    $fx_zl = Get-Labels $fx_zone
    if ($fx_zl.Count -gt 0 -and $fx_special -contains $fx_zl[0]) { return $true }
    $fx_fl = Get-Labels (Get-FullName $fx_zone $fx_rel)
    foreach ($fx_l in $fx_fl) { if ($fx_special -contains $fx_l) { return $true } }
    if ($fx_ds) {
        $fx_srv = @('_ldap', '_kerberos', '_kpasswd', '_gc')
        if ($fx_fl.Count -ge 2 -and $fx_srv -contains $fx_fl[0] -and @('_tcp', '_udp') -contains $fx_fl[1]) { return $true }
        if ($fx_fl.Count -ge 1 -and $fx_srv -contains $fx_fl[0] -and $fx_fl -contains '_sites') { return $true }
        if ($fx_rel -eq '@' -and @('A', 'AAAA', 'NS', 'SOA') -contains $fx_type.ToUpperInvariant()) { return $true }
    }
    return $false
}
function Format-Data($fx_r) {
    $fx_d = $fx_r.RecordData
    switch ([string]$fx_r.RecordType) {
        'A' { return $fx_d.IPv4Address.IPAddressToString }
        'AAAA' { return $fx_d.IPv6Address.IPAddressToString }
        'CNAME' { return [string]$fx_d.HostNameAlias }
        'NS' { return [string]$fx_d.NameServer }
        'PTR' { return [string]$fx_d.PtrDomainName }
        'MX' { return ([string]$fx_d.Preference) + ' ' + [string]$fx_d.MailExchange }
        'SRV' { return ([string]$fx_d.Priority) + ' ' + ([string]$fx_d.Weight) + ' ' + ([string]$fx_d.Port) + ' ' + [string]$fx_d.DomainName }
        'TXT' { return (@($fx_d.DescriptiveText) -join ' ') }
        'SOA' { return ([string]$fx_d.PrimaryServer) + ' ' + ([string]$fx_d.ResponsiblePerson) + ' ' + ([string]$fx_d.SerialNumber) }
        default { return '' }
    }
}
function Convert-Record($fx_r) {
    $fx_data = [string](Format-Data $fx_r)
    if ($fx_data.Length -gt 300) { $fx_data = $fx_data.Substring(0, 300) }
    return [ordered]@{
        name      = [string]$fx_r.HostName
        type      = [string]$fx_r.RecordType
        ttl       = [int]$fx_r.TimeToLive.TotalSeconds
        data      = $fx_data
        timestamp = Get-Utc $fx_r.Timestamp
        static    = ($null -eq $fx_r.Timestamp)
    }
}
function Find-Record([string]$fx_zone, [string]$fx_rel, [string]$fx_type, [string]$fx_data) {
    $fx_all = @(Get-DnsServerResourceRecord -ZoneName $fx_zone -Name $fx_rel -RRType $fx_type -ErrorAction SilentlyContinue)
    foreach ($fx_r in $fx_all) {
        if ((Format-Data $fx_r) -ieq $fx_data) { return $fx_r }
    }
    return $null
}
function Set-RecordData($fx_rec, [string]$fx_type, [string]$fx_data) {
    $fx_d = $fx_rec.RecordData
    switch ($fx_type) {
        'A' { $fx_d.IPv4Address = [System.Net.IPAddress]::Parse($fx_data) }
        'AAAA' { $fx_d.IPv6Address = [System.Net.IPAddress]::Parse($fx_data) }
        'CNAME' { $fx_d.HostNameAlias = $fx_data }
        'NS' { $fx_d.NameServer = $fx_data }
        'PTR' { $fx_d.PtrDomainName = $fx_data }
        'MX' { $fx_f = $fx_data -split ' ', 2; $fx_d.Preference = [uint16]$fx_f[0]; $fx_d.MailExchange = $fx_f[1] }
        'SRV' { $fx_f = $fx_data -split ' ', 4; $fx_d.Priority = [uint16]$fx_f[0]; $fx_d.Weight = [uint16]$fx_f[1]; $fx_d.Port = [uint16]$fx_f[2]; $fx_d.DomainName = $fx_f[3] }
        'TXT' { $fx_d.DescriptiveText = $fx_data }
    }
}
function Get-AddArgs([string]$fx_zone, [string]$fx_rel, [string]$fx_type, [string]$fx_data, [int]$fx_ttl) {
    $fx_q = @{ ZoneName = $fx_zone; Name = $fx_rel; TimeToLive = [timespan]::FromSeconds($fx_ttl) }
    switch ($fx_type) {
        'A' { $fx_q.A = $true; $fx_q.IPv4Address = $fx_data }
        'AAAA' { $fx_q.AAAA = $true; $fx_q.IPv6Address = $fx_data }
        'CNAME' { $fx_q.CName = $true; $fx_q.HostNameAlias = $fx_data }
        'NS' { $fx_q.NS = $true; $fx_q.NameServer = $fx_data }
        'PTR' { $fx_q.Ptr = $true; $fx_q.PtrDomainName = $fx_data }
        'MX' { $fx_f = $fx_data -split ' ', 2; $fx_q.MX = $true; $fx_q.Preference = [uint16]$fx_f[0]; $fx_q.MailExchange = $fx_f[1] }
        'SRV' { $fx_f = $fx_data -split ' ', 4; $fx_q.Srv = $true; $fx_q.Priority = [uint16]$fx_f[0]; $fx_q.Weight = [uint16]$fx_f[1]; $fx_q.Port = [uint16]$fx_f[2]; $fx_q.DomainName = $fx_f[3] }
        'TXT' { $fx_q.Txt = $true; $fx_q.DescriptiveText = $fx_data }
    }
    return $fx_q
}

try {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Result $false $null 'module_missing' 'The DnsServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DnsServer
    $zone = [string](Get-Prop $p 'zone')
    $name = Get-Prop $p 'name'
    $type = Get-Prop $p 'type'
    $offset = 0
    if ($null -ne (Get-Prop $p 'offset')) { $offset = [int](Get-Prop $p 'offset') }
    if ($null -eq (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) { Write-Result $false $null 'zone_not_found' 'There is no zone of this name on this server.'; exit 0 }
    $q = @{ ZoneName = $zone }
    if ($null -ne $name) {
        $rel = Get-RelName $zone ([string]$name)
        if ($rel -eq '') { Write-Result $false $null 'name_outside_zone' 'The name is not inside the zone.'; exit 0 }
        $q.Name = $rel
    }
    if ($null -ne $type) { $q.RRType = [string]$type }
    $all = @(Get-DnsServerResourceRecord @q | Sort-Object HostName, RecordType)
    $page = @($all | Select-Object -Skip $offset -First 80)
    $rows = @($page | ForEach-Object { Convert-Record $_ })
    $next = Get-NextOffset $offset $rows.Count $all.Count
    Write-Result $true ([ordered]@{ total = $all.Count; offset = $offset; next = $next; records = $rows }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the DNS records failed: ' + $_.Exception.GetType().Name)
}
