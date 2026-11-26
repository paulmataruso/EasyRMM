Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    $findings = @()
    $notes = @()
    if ($ca.Enterprise) {
        $templates = Read-Templates
        if ($null -eq $templates) { $notes += 'The certificate templates could not be read from the directory, so ESC1 to ESC4 were not checked.' }
        else { foreach ($t in $templates) { $findings += @(Get-TemplateFindings $t) } }
    }
    $policy = Get-ItemProperty -LiteralPath ($ca.Key + '\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy') -ErrorAction SilentlyContinue
    $flags = Get-Number (Get-Prop $policy 'EditFlags')
    if ($null -ne $flags) { $findings += @(Get-EditFlagsFindings $flags $ca.Name) }
    else { $notes += 'The CA edit flags could not be read, so ESC6 was not checked.' }
    $sec = Get-Prop $ca.Config 'Security'
    if ($sec -is [byte[]]) {
        $aces = @()
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sec, 0)
        foreach ($ace in @($sd.DiscretionaryAcl)) {
            $aces += [pscustomobject]@{ sid = [string]$ace.SecurityIdentifier.Value; mask = [int]$ace.AccessMask; allow = ([string]$ace.AceQualifier -eq 'AccessAllowed') }
        }
        $findings += @(Get-CaAclFindings $aces $ca.Name)
    } else { $notes += 'The CA permissions could not be read, so ESC7 was not checked.' }
    try {
        $req = [System.Net.WebRequest]::Create('http://localhost/certsrv/')
        $req.Timeout = 5000
        $req.AllowAutoRedirect = $false
        $resp = $null
        try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
        if ($null -ne $resp) {
            $code = [int]$resp.StatusCode
            $resp.Close()
            if ($code -eq 200 -or $code -eq 401) { $findings += @(New-Finding 'ESC8' $ca.Name 'Web enrollment answers over plain HTTP, where a relayed login can obtain a certificate.') }
        }
    } catch { $notes += 'Web enrollment could not be probed, so ESC8 was not checked.' }
    $notes += 'ESC5 (permissions on the other certificate objects in the directory) is not checked.'
    Write-Result $true ([ordered]@{ caName = $ca.Name; findings = @($findings); notes = @($notes) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Checking the CA for misconfiguration failed: ' + $_.Exception.GetType().Name)
}
