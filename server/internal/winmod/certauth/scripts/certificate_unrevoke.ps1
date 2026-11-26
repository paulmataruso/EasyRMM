Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $serial = [string]$p.serial
    $rows = @(Invoke-View (Get-SerialRestriction $serial) (Get-RequestColumns))
    if ($rows.Count -eq 0) { Stop-Result 'not_found' 'There is no certificate with that serial number.' }
    $row = Convert-RequestRow $rows[0]
    if ($row.disposition -ne 'revoked' -or $row.revokedReason -ne 6) { Stop-Result 'not_on_hold' 'Only a certificate on hold can be reinstated; any other revocation is final.' }
    $r = Invoke-Certutil @('-revoke', $serial, 'unrevoke')
    if ($r.Code -ne 0) { Stop-Result 'command_failed' 'The CA did not reinstate the certificate.' }
    Write-Result $true ([ordered]@{ serial = $serial; disposition = 'issued' }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reinstating the certificate failed: ' + $_.Exception.GetType().Name)
}
