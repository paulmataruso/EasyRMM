Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $printer = [string]$p.printer
    $null = Get-PrinterOrStop $printer
    $c = Get-CimInstance -ClassName Win32_Printer | Where-Object { $_.Name -eq $printer } | Select-Object -First 1
    if ($null -eq $c) { Stop-Result 'not_found' 'There is no printer of this name.' }
    $r = Invoke-CimMethod -InputObject $c -MethodName Pause
    if ([int](Get-Prop $r 'ReturnValue') -ne 0) { Stop-Result 'command_failed' 'Windows refused: Pausing the printer failed.' }
    Write-Result $true ([ordered]@{ count = 1 }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Pausing the printer failed: ' + $_.Exception.GetType().Name)
}
