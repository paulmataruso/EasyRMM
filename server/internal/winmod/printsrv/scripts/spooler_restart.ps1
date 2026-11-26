Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    if ($null -eq (Get-Service -Name Spooler -ErrorAction SilentlyContinue)) { Stop-Result 'module_missing' 'The Print Spooler is not installed on this computer.' }
    Stop-Service -Name Spooler -Force
    Start-Service -Name Spooler
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Restarting the Print Spooler failed: ' + $_.Exception.GetType().Name)
}
