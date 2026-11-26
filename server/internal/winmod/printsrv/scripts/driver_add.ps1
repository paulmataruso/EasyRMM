Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $name = [string]$p.name
    if ($null -ne (Get-PrinterDriver -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'exists' 'That driver is already installed.' }
    Add-PrinterDriver -Name $name
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Adding the driver failed. Only a driver already in the driver store can be added: ' + $_.Exception.GetType().Name)
}
