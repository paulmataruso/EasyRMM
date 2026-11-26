Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Write-Result $true ([ordered]@{ certificates = @(Get-CaCertificates $ca) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the CA certificate failed: ' + $_.Exception.GetType().Name)
}
