function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 8))
}
function Stop-Result($code, $message) {
    Write-Result $false $null $code $message
    exit 0
}
function Get-Prop($o, $name) {
    if ($null -ne $o -and $null -ne $o.PSObject.Properties[$name]) { return $o.$name }
    return $null
}
function Get-Number($v) {
    if ($null -eq $v) { return $null }
    try { return [int64]$v } catch { return $null }
}
function Assert-Smb {
    if (-not (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)) {
        Stop-Result 'module_missing' 'The SMB share cmdlets are not available on this computer.'
    }
    $svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Stop-Result 'module_missing' 'The Server service is not installed on this computer.' }
    if ($svc.Status -ne 'Running') { Stop-Result 'service_stopped' 'The Server service is not running.' }
}
# ADR-0076 "Protected shares": SYSVOL, NETLOGON, print$, IPC$, ADMIN$ and every share whose name ends in $.
function Test-ProtectedShare([string]$Name) {
    if ($Name.EndsWith('$')) { return $true }
    return (@('SYSVOL', 'NETLOGON') -contains $Name.ToUpperInvariant())
}
function Assert-Unprotected([string]$Name) {
    if (Test-ProtectedShare $Name) { Stop-Result 'protected_share' 'This share is protected: the console shows it and does not change it.' }
}
function Get-ShareOrStop([string]$Name) {
    $s = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $s) { Stop-Result 'not_found' 'There is no share of this name.' }
    return $s
}
function Resolve-AccountSid([string]$Account) {
    try {
        if ($Account -match '^S-1-') { return (New-Object System.Security.Principal.SecurityIdentifier($Account)) }
        return ((New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]))
    } catch {
        Stop-Result 'account_not_found' 'That account or group was not found.'
    }
}
function Get-AccountName($Sid) {
    try { return $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { return $Sid.Value }
}
# The accounts a share must never be opened to with write rights (ADR-0076): Everyone, Anonymous Logon,
# Authenticated Users; and Users for Full.
function Test-WeakGrant($Sid, [string]$Right) {
    $v = $Sid.Value
    if (@('S-1-1-0', 'S-1-5-7', 'S-1-5-11') -contains $v) { return ($Right -eq 'Full' -or $Right -eq 'Change') }
    if ($v -eq 'S-1-5-32-545') { return ($Right -eq 'Full') }
    return $false
}
function Test-CoreAccount($Sid) {
    return (@('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-544', 'S-1-5-18') -contains $Sid.Value)
}
function Test-PathUnder([string]$Child, [string]$Parent) {
    $c = $Child.TrimEnd('\')
    $q = $Parent.TrimEnd('\')
    return ($c.Equals($q, [System.StringComparison]::OrdinalIgnoreCase) -or $c.StartsWith($q + '\', [System.StringComparison]::OrdinalIgnoreCase))
}
function Get-SystemRoot { return [string]$env:SystemRoot }
# A path a share may be made on: an existing folder on a local fixed volume that is not a drive root, not the
# Windows folder or below, and not SYSVOL.
function Assert-ShareablePath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full.Length -le 2) { Stop-Result 'protected_path' 'A drive root cannot be shared.' }
    $root = Get-SystemRoot
    if ($root -and (Test-PathUnder $full $root)) { Stop-Result 'protected_path' 'The Windows folder cannot be shared.' }
    foreach ($seg in $full.Split('\')) {
        if ($seg -ieq 'SYSVOL') { Stop-Result 'protected_path' 'SYSVOL cannot be shared again.' }
    }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { Stop-Result 'path_not_found' 'That folder does not exist on this computer.' }
    $letter = $full.Substring(0, 2)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $letter }
    if ($null -eq $disk -or [int]$disk.DriveType -ne 3) { Stop-Result 'protected_path' 'Only a folder on a local fixed disk can be shared.' }
    return $full
}
