Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    $jobs = @(Get-PrintJob -PrinterName $printer -ErrorAction SilentlyContinue)
    $n = 0
    foreach ($j in $jobs) {
        Remove-PrintJob -InputObject $j
        $n++
    }
    Write-Result $true ([ordered]@{ count = $n }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Clearing the queue failed: ' + $_.Exception.GetType().Name)
}
