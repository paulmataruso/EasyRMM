Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $pol = Get-Policy $false
    if ($null -eq $pol) { Stop-Result 'no_policy' 'No backup policy is set on this computer.' }
    Start-WBBackup -Policy $pol -Async -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Starting the backup failed: ' + $_.Exception.GetType().Name)
}
