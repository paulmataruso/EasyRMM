Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $name = [string]$p.name
    if ($null -eq (Get-PrinterPort -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'not_found' 'There is no port of this name.' }
    $users = @(Get-Printer | Where-Object { $_.PortName -eq $name })
    if ($users.Count -gt 0) { Stop-Result 'in_use' 'A printer uses this port.' }
    Remove-PrinterPort -Name $name
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the port failed: ' + $_.Exception.GetType().Name)
}
