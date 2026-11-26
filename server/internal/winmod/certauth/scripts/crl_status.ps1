Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    $crl = Get-CrlInfo $ca
    Write-Result $true ([ordered]@{ base = $crl.base; delta = $crl.delta }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the revocation lists failed: ' + $_.Exception.GetType().Name)
}
