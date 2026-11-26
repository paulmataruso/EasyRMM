Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    $data = [ordered]@{
        caName = $ca.Name; caType = $ca.Type; enterprise = [bool]$ca.Enterprise
        serviceState = (Get-ServiceState)
        certificate = $null; crl = $null; counts = $null
    }
    $certs = @(Get-CaCertificates $ca | Sort-Object { $_.notAfter } -Descending)
    if ($certs.Count -gt 0) {
        $c = $certs[0]
        $data.certificate = [ordered]@{ subject = $c.subject; thumbprint = $c.thumbprint; notAfter = $c.notAfter; daysLeft = $c.daysLeft; signatureAlgorithm = $c.signatureAlgorithm; keyLength = $c.keyLength }
    }
    $crl = Get-CrlInfo $ca
    if ($null -ne $crl.base) {
        $dn = $null
        if ($null -ne $crl.delta) { $dn = $crl.delta.nextUpdate }
        $data.crl = [ordered]@{ baseThisUpdate = $crl.base.thisUpdate; baseNextUpdate = $crl.base.nextUpdate; hoursToBaseExpiry = $crl.base.hoursToNextUpdate; deltaNextUpdate = $dn }
    }
    if ($data.serviceState -eq 'running') {
        $counts = [ordered]@{}
        foreach ($d in @('pending', 'issued', 'revoked', 'failed')) {
            $counts[$d] = @(Invoke-View (Get-DispositionRestriction $d 0) @('RequestID')).Count
        }
        $data.counts = $counts
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the certificate authority state failed: ' + $_.Exception.GetType().Name)
}
