Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $id = [int]$p.id
    if ((Get-RequestDisposition $id) -ne 'pending') { Stop-Result 'not_pending' 'That request is not waiting for approval.' }
    $r = Invoke-Certutil @('-resubmit', [string]$id)
    if ($r.Code -ne 0) { Stop-Result 'command_failed' 'The CA did not approve the request.' }
    Write-Result $true ([ordered]@{ id = [int64]$id; disposition = (Get-RequestDisposition $id) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Approving the request failed: ' + $_.Exception.GetType().Name)
}
