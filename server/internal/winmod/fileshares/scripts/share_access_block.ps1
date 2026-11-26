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
    $sid = Resolve-AccountSid ([string]$p.account)
    if (Test-CoreAccount $sid) { Stop-Result 'would_lock_out' 'Blocking this account could lock everyone, or the administrators, out of the share.' }
    Block-SmbShareAccess -Name $name -AccountName (Get-AccountName $sid) -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Blocking access failed: ' + $_.Exception.GetType().Name)
}
