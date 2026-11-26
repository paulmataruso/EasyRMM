Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    $all = @(Get-PrintJob -PrinterName $printer -ErrorAction SilentlyContinue)
    $out = @()
    foreach ($j in @($all | Select-Object -First 300)) {
        $out += [ordered]@{
            id = [int64](Get-Number (Get-Prop $j 'Id'))
            status = [string](Get-Prop $j 'JobStatus')
            sizeBytes = [int64](Get-Number (Get-Prop $j 'Size'))
            pages = [int64](Get-Number (Get-Prop $j 'TotalPages'))
            submitted = Get-Utc (Get-Prop $j 'SubmittedTime')
            ageMinutes = Get-AgeMinutes (Get-Prop $j 'SubmittedTime')
        }
    }
    Write-Result $true ([ordered]@{ printer = $printer; jobs = @($out); total = $all.Count }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the print jobs failed: ' + $_.Exception.GetType().Name)
}
