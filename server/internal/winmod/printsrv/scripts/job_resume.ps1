Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    $n = 0
    foreach ($id in (Get-JobIds ([string]$p.ids))) {
        $job = Get-PrintJob -PrinterName $printer -ID $id -ErrorAction SilentlyContinue
        if ($null -eq $job) { continue }
        Resume-PrintJob -PrinterName $printer -ID $id
        $n++
    }
    if ($n -eq 0) { Stop-Result 'not_found' 'None of those jobs is in the queue.' }
    Write-Result $true ([ordered]@{ count = $n }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Resuming the print jobs failed: ' + $_.Exception.GetType().Name)
}
