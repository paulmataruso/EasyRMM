Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Stop-Result 'module_missing' 'The Print Spooler is not installed on this computer.' }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $data = [ordered]@{
        serviceState = ([string]$svc.Status).ToLowerInvariant()
        printerCount = 0; sharedCount = 0; jobCount = 0
        domainController = ([int]$os.ProductType -eq 2)
    }
    if ($svc.Status -eq 'Running' -and (Get-Command -Name Get-Printer -ErrorAction SilentlyContinue)) {
        $printers = @(Get-Printer)
        $data.printerCount = $printers.Count
        $data.sharedCount = @($printers | Where-Object { [bool](Get-Prop $_ 'Shared') }).Count
        $data.jobCount = @(Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue).Count
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the print server state failed: ' + $_.Exception.GetType().Name)
}
