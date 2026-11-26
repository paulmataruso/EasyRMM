Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $id = Get-Prop $p 'id'
    $serial = [string](Get-Prop $p 'serial')
    if ($null -ne $id) { $restrict = Get-IdRestriction ([int]$id) }
    elseif ($serial -ne '') { $restrict = Get-SerialRestriction $serial }
    else { Stop-Result 'invalid_request' 'Give a request number or a serial number.' }
    $rows = @(Invoke-View $restrict (Get-RequestColumns))
    if ($rows.Count -eq 0) { Stop-Result 'not_found' 'There is no such request or certificate.' }
    Write-Result $true ([ordered]@{ request = (Convert-RequestRow $rows[0]) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the request failed: ' + $_.Exception.GetType().Name)
}
