Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $name = [string]$p.name
    $driver = [string]$p.driverName
    $port = [string]$p.portName
    if ($null -ne (Get-Printer -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'exists' 'A printer of this name already exists.' }
    if ($null -eq (Get-PrinterDriver -Name $driver -ErrorAction SilentlyContinue)) { Stop-Result 'driver_not_installed' 'That driver is not installed. Only a driver already on this computer is used.' }
    if ($null -eq (Get-PrinterPort -Name $port -ErrorAction SilentlyContinue)) { Stop-Result 'port_not_found' 'There is no port of this name.' }
    Add-Printer -Name $name -DriverName $driver -PortName $port
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Adding the printer failed: ' + $_.Exception.GetType().Name)
}
