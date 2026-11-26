Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $out = @()
    foreach ($pt in @(Get-PrinterPort | Select-Object -First 300)) {
        $out += [ordered]@{
            name = [string](Get-Prop $pt 'Name')
            address = [string](Get-Prop $pt 'PrinterHostAddress')
            portNumber = [int64](Get-Number (Get-Prop $pt 'PortNumber'))
            description = [string](Get-Prop $pt 'Description')
        }
    }
    Write-Result $true ([ordered]@{ ports = @($out); truncated = (@(Get-PrinterPort).Count -gt 300) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the ports failed: ' + $_.Exception.GetType().Name)
}
