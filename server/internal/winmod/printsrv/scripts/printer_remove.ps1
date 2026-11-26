Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    Remove-Printer -Name $printer
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the printer failed: ' + $_.Exception.GetType().Name)
}
