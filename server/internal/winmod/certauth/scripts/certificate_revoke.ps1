Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $serial = [string]$p.serial
    $restrict = Get-SerialRestriction $serial
    $rows = @(Invoke-View $restrict (Get-RequestColumns))
    if ($rows.Count -eq 0) { Stop-Result 'not_found' 'There is no certificate with that serial number.' }
    $row = Convert-RequestRow $rows[0]
    if ($row.disposition -ne 'issued') { Stop-Result 'not_issued' 'Only an issued certificate can be revoked.' }
    $code = Get-RevocationReasonCode ([string]$p.reason)
    $r = Invoke-Certutil @('-revoke', $serial, $code)
    if ($r.Code -ne 0) { Stop-Result 'command_failed' 'The CA did not revoke the certificate.' }
    Write-Result $true ([ordered]@{ serial = $serial; disposition = 'revoked' }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Revoking the certificate failed: ' + $_.Exception.GetType().Name)
}
