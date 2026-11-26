Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $cim = @{}
    foreach ($c in @(Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue)) { $cim[[string]$c.Name] = $c }
    $jobsByPrinter = @{}
    foreach ($j in @(Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue)) {
        $pn = ([string]$j.Name)
        $i = $pn.LastIndexOf(',')
        if ($i -gt 0) { $pn = $pn.Substring(0, $i) }
        if (-not $jobsByPrinter.ContainsKey($pn)) { $jobsByPrinter[$pn] = @() }
        $jobsByPrinter[$pn] += $j
    }
    $out = @()
    foreach ($pr in @(Get-Printer | Select-Object -First 200)) {
        $name = [string]$pr.Name
        $jobs = @()
        if ($jobsByPrinter.ContainsKey($name)) { $jobs = @($jobsByPrinter[$name]) }
        $oldest = $null
        $errors = 0
        foreach ($j in $jobs) {
            $age = Get-AgeMinutes (Get-Prop $j 'TimeSubmitted')
            if ($null -ne $age -and ($null -eq $oldest -or $age -gt $oldest)) { $oldest = $age }
            $st = [string](Get-Prop $j 'JobStatus') + ' ' + [string](Get-Prop $j 'Status')
            if ($st -match 'Error|Offline|Paper|Intervention') { $errors++ }
        }
        $c = $null
        if ($cim.ContainsKey($name)) { $c = $cim[$name] }
        $status = [string](Get-Prop $pr 'PrinterStatus')
        $out += [ordered]@{
            name = $name
            driver = [string](Get-Prop $pr 'DriverName')
            port = [string](Get-Prop $pr 'PortName')
            shared = [bool](Get-Prop $pr 'Shared')
            shareName = [string](Get-Prop $pr 'ShareName')
            published = [bool](Get-Prop $pr 'Published')
            status = $status
            paused = ($status -eq 'Paused')
            offline = [bool](Get-Prop $c 'WorkOffline')
            isDefault = [bool](Get-Prop $c 'Default')
            jobCount = $jobs.Count
            jobsInError = $errors
            oldestJobAgeMinutes = $oldest
        }
    }
    Write-Result $true ([ordered]@{ printers = @($out); truncated = (@(Get-Printer).Count -gt 200) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the printers failed: ' + $_.Exception.GetType().Name)
}
