Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $out = @()
    foreach ($d in @(Get-PrinterDriver | Select-Object -First 300)) {
        $prov = [string](Get-Prop $d 'Provider')
        $mfr = [string](Get-Prop $d 'Manufacturer')
        $inbox = ($prov -match 'Microsoft' -or $mfr -match 'Microsoft')
        $out += [ordered]@{
            name = [string](Get-Prop $d 'Name')
            version = [string](Get-Prop $d 'DriverVersion')
            manufacturer = $mfr
            environment = [string](Get-Prop $d 'PrinterEnvironment')
            inbox = [bool]$inbox
        }
    }
    Write-Result $true ([ordered]@{ drivers = @($out); truncated = (@(Get-PrinterDriver).Count -gt 300) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the drivers failed: ' + $_.Exception.GetType().Name)
}
