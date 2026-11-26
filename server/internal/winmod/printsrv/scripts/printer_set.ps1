Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $cur = Get-PrinterOrStop $printer
    $set = @{ Name = $printer }
    $n = 0
    foreach ($pair in @(@('comment', 'Comment'), @('location', 'Location'), @('shareName', 'ShareName'))) {
        $v = Get-Prop $p $pair[0]
        if ($null -ne $v) { $set[$pair[1]] = [string]$v; $n++ }
    }
    foreach ($pair in @(@('shared', 'Shared'), @('published', 'Published'))) {
        $v = Get-Prop $p $pair[0]
        if ($null -ne $v) { $set[$pair[1]] = [bool]$v; $n++ }
    }
    if ($n -eq 0) { Stop-Result 'nothing_to_do' 'No change was asked for.' }
    if ($set.ContainsKey('Shared') -and $set['Shared'] -and -not $set.ContainsKey('ShareName') -and [string](Get-Prop $cur 'ShareName') -eq '') {
        Stop-Result 'share_name_required' 'A share name is needed to share this printer.'
    }
    Set-Printer @set
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Changing the printer failed: ' + $_.Exception.GetType().Name)
}
