Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    if ($null -eq (Get-Policy $false)) { Stop-Result 'no_policy' 'There is no backup policy.' }
    Remove-WBPolicy -All -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the backup policy failed: ' + $_.Exception.GetType().Name)
}
