Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    Write-Result $true (Get-Hardening) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the Point and Print state failed: ' + $_.Exception.GetType().Name)
}
