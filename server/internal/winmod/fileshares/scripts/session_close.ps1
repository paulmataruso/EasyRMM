Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $id = [uint64]([string]$p.id)
    if ($null -eq (Get-SmbSession -SessionId $id -ErrorAction SilentlyContinue)) { Stop-Result 'not_found' 'That session has already ended.' }
    Close-SmbSession -SessionId $id -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Closing the session failed: ' + $_.Exception.GetType().Name)
}
