Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $name = [string]$p.name
    if ($null -eq (Get-PrinterDriver -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'not_found' 'There is no driver of this name.' }
    $users = @(Get-Printer | Where-Object { $_.DriverName -eq $name })
    if ($users.Count -gt 0) { Stop-Result 'in_use' 'A printer uses this driver.' }
    Remove-PrinterDriver -Name $name
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the driver failed: ' + $_.Exception.GetType().Name)
}
