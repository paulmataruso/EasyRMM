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
    if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
        Write-Result $false $null 'module_missing' 'The DhcpServer PowerShell module is not installed on this computer.'
        exit 0
    }
    Import-Module DhcpServer
    $state = Get-ServiceState 'DHCPServer'
    $data = [ordered]@{
        serviceState              = $state
        domainJoined              = $null
        authorized                = $null
        conflictDetectionAttempts = $null
        bindings                  = @()
        scopeCount                = 0
        activeScopeCount          = 0
    }
    if ($state -eq 'running') {
        $s = Get-DhcpServerSetting
        $joined = [bool](Get-Prop $s 'IsDomainJoined')
        $data.domainJoined = $joined
        if ($joined) { $data.authorized = [bool](Get-Prop $s 'IsAuthorized') }
        $data.conflictDetectionAttempts = [int](Get-Prop $s 'ConflictDetectionAttempts')
        $data.bindings = @(Get-DhcpServerv4Binding | ForEach-Object {
            [ordered]@{ interface = [string]$_.InterfaceAlias; address = $_.IPAddress.IPAddressToString; enabled = [bool]$_.BindingState }
        })
        $scopes = @(Get-DhcpServerv4Scope)
        $data.scopeCount = $scopes.Count
        $data.activeScopeCount = @($scopes | Where-Object { [string]$_.State -eq 'Active' }).Count
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the DHCP server state failed: ' + $_.Exception.GetType().Name)
}
