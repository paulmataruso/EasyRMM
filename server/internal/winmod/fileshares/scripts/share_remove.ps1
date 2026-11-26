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
    Remove-SmbShare -Name $name -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the share failed: ' + $_.Exception.GetType().Name)
}
