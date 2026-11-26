Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $name = [string]$p.name
    Assert-Unprotected $name
    $null = Get-ShareOrStop $name
    $set = @{ Name = $name; Force = $true }
    $changed = 0
    foreach ($pair in @(@('description', 'Description'), @('caching', 'CachingMode'), @('enumeration', 'FolderEnumerationMode'))) {
        $v = Get-Prop $p $pair[0]
        if ($null -ne $v) { $set[$pair[1]] = [string]$v; $changed++ }
    }
    $lim = Get-Prop $p 'concurrentLimit'
    if ($null -ne $lim) { $set['ConcurrentUserLimit'] = [uint32]$lim; $changed++ }
    $enc = Get-Prop $p 'encrypt'
    if ($null -ne $enc) { $set['EncryptData'] = [bool]$enc; $changed++ }
    if ($changed -eq 0) { Stop-Result 'nothing_to_do' 'No change was asked for.' }
    Set-SmbShare @set | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Changing the share failed: ' + $_.Exception.GetType().Name)
}
