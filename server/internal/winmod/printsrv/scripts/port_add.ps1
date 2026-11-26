Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $name = [string]$p.name
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$p.address, [ref]$addr)) { Stop-Result 'invalid_address' 'That is not an IP address.' }
    $number = [int]$p.port
    if ($null -ne (Get-PrinterPort -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'exists' 'A port of this name already exists.' }
    Add-PrinterPort -Name $name -PrinterHostAddress $addr.ToString() -PortNumber $number
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Adding the port failed: ' + $_.Exception.GetType().Name)
}
