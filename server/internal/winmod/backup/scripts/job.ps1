Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $n = 1
    $prev = Get-Prop $p 'previous'
    if ($null -ne $prev) { $n = [int]$prev }
    $jobs = @()
    $running = Get-RunningJob
    if ($null -ne $running) { $jobs += Convert-Job $running }
    if ($n -gt 0) {
        foreach ($j in @(Get-WBJob -Previous $n -ErrorAction SilentlyContinue)) { $jobs += Convert-Job $j }
    }
    Write-Result $true ([ordered]@{ running = ($null -ne $running); jobs = @($jobs) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the backup jobs failed: ' + $_.Exception.GetType().Name)
}
