Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    $byPrinter = @{}
    foreach ($c in @(Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue)) {
        $nm = [string](Get-Prop $c 'Name')
        $i = $nm.LastIndexOf(',')
        if ($i -le 0) { continue }
        $pn = $nm.Substring(0, $i)
        if (-not $byPrinter.ContainsKey($pn)) { $byPrinter[$pn] = @{} }
        $byPrinter[$pn][[int64](Get-Number (Get-Prop $c 'JobId'))] = [string](Get-Prop $c 'HostPrintQueue')
    }
    $clients = @{}
    if ($byPrinter.ContainsKey($printer)) { $clients = $byPrinter[$printer] }
    $all = @(Get-PrintJob -PrinterName $printer -ErrorAction SilentlyContinue)
    $out = @()
    foreach ($j in @($all | Select-Object -First 300)) {
        $id = Get-Number (Get-Prop $j 'Id')
        $client = ''
        if ($clients.ContainsKey([int64]$id)) { $client = [string]$clients[[int64]$id] }
        $out += [ordered]@{
            id = [int64]$id
            document = [string](Get-Prop $j 'DocumentName')
            owner = [string](Get-Prop $j 'UserName')
            client = $client
        }
    }
    Write-Result $true ([ordered]@{ jobs = @($out) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the print job documents failed: ' + $_.Exception.GetType().Name)
}
