Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    if ([string]$p.kind -eq 'delta') { $r = Invoke-Certutil @('-CRL', 'delta') }
    else { $r = Invoke-Certutil @('-CRL') }
    if ($r.Code -ne 0) { Stop-Result 'command_failed' 'The CA did not publish the revocation list.' }
    $crl = Get-CrlInfo $ca
    Write-Result $true ([ordered]@{ base = $crl.base; delta = $crl.delta }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Publishing the revocation list failed: ' + $_.Exception.GetType().Name)
}
