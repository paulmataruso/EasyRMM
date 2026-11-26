function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 8))
}
function Stop-Result($code, $message) {
    Write-Result $false $null $code $message
    exit 0
}
function Get-Prop($o, $name) {
    if ($o -is [System.Collections.IDictionary]) {
        if ($o.Contains($name)) { return $o[$name] }
        return $null
    }
    if ($null -ne $o -and $null -ne $o.PSObject.Properties[$name]) { return $o.$name }
    return $null
}
function Get-Number($v) {
    if ($null -eq $v) { return $null }
    try { return [int64]$v } catch { return $null }
}
function Get-Utc($d) {
    if ($null -eq $d) { return $null }
    try {
        $t = [datetime]$d
        if ($t.Year -lt 2000) { return $null }
        return $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { return $null }
}
function Get-Utc2([string]$Text) {
    if (-not $Text) { return $null }
    try { return (Get-Utc ([datetime]::Parse($Text, [System.Globalization.CultureInfo]::CurrentCulture))) } catch { return $null }
}
# The CA's configuration key (ADR-0076 section 3). A computer without a configured CA has none.
function Get-CaKey { return 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' }
function Get-CaConfig {
    $key = Get-CaKey
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $root = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    $name = [string](Get-Prop $root 'Active')
    if (-not $name) { return $null }
    $sub = $key + '\' + $name
    $cfg = Get-ItemProperty -LiteralPath $sub -ErrorAction SilentlyContinue
    if ($null -eq $cfg) { return $null }
    $type = [int](Get-Number (Get-Prop $cfg 'CAType'))
    $typeName = 'unknown'
    if ($type -eq 0) { $typeName = 'enterprise_root' }
    elseif ($type -eq 1) { $typeName = 'enterprise_subordinate' }
    elseif ($type -eq 3) { $typeName = 'standalone_root' }
    elseif ($type -eq 4) { $typeName = 'standalone_subordinate' }
    return [pscustomobject]@{ Name = $name; Key = $sub; Type = $typeName; Enterprise = ($type -eq 0 -or $type -eq 1); Config = $cfg }
}
function Assert-Ca {
    $ca = Get-CaConfig
    if ($null -eq $ca) { Stop-Result 'module_missing' 'No certification authority is configured on this computer.' }
    return $ca
}
function Assert-CaRunning {
    $svc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc -or $svc.Status -ne 'Running') { Stop-Result 'service_stopped' 'The Certificate Services service is not running.' }
}
# certutil.exe, the one way this module reaches it: the call operator and an argument array, never a command string
# (ADR-0076). Only the verbs on the allowlist in the Go test (view, resubmit, deny, revoke, CRL, dump) are used.
function Invoke-Certutil([string[]]$Arguments) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& certutil.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    return [pscustomobject]@{ Code = $code; Lines = $lines }
}
# What a -view restriction may be: fixed fragments and a typed number or a hexadecimal serial, never free text.
function Get-IdRestriction([int]$Id) { return ('RequestID=' + $Id) }
function Get-SerialRestriction([string]$Serial) {
    if ($Serial -notmatch '^[0-9A-Fa-f]{2,40}$') { Stop-Result 'invalid_serial' 'That is not a certificate serial number.' }
    return ('SerialNumber=' + $Serial)
}
function Get-DispositionRestriction([string]$Name, [int]$From) {
    $map = @{ pending = 9; issued = 20; revoked = 21; failed = 30; denied = 31 }
    if (-not $map.ContainsKey($Name)) { Stop-Result 'invalid_disposition' 'That kind of request is not known.' }
    return ('Disposition=' + $map[$Name] + ',RequestID>=' + $From)
}
function Get-DispositionName([int]$Code) {
    $map = @{ 9 = 'pending'; 20 = 'issued'; 21 = 'revoked'; 30 = 'failed'; 31 = 'denied' }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return 'other'
}
# certutil -view ... csv: a header line, then one record per line; lines that do not start with a number are noise.
function Invoke-View([string]$Restrict, [string[]]$Columns) {
    $r = Invoke-Certutil @('-view', '-restrict', $Restrict, '-out', ($Columns -join ','), 'csv')
    $rows = @()
    foreach ($line in @($r.Lines | Select-Object -Skip 1)) {
        if ($line -notmatch '^"?\d') { continue }
        $fields = @(($line | ConvertFrom-Csv -Header $Columns))
        if ($fields.Count -eq 1) { $rows += $fields[0] }
    }
    return @($rows)
}
function Get-CaCertificates($Ca) {
    $out = @()
    $hashes = @(Get-Prop $Ca.Config 'CACertHash')
    foreach ($h in $hashes) {
        $thumb = ($h | ForEach-Object { if ($_ -is [byte]) { $_.ToString('X2') } else { [string]$_ } }) -join ''
        # CACertHash is a string array of hex bytes with spaces ("94 ca 94 ..."), not a byte array (found on a real CA).
        $thumb = $thumb -replace '\s', ''
        if (-not $thumb) { continue }
        $c = Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if ($null -eq $c) { continue }
        $bits = $null
        try { $bits = [int][System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c).KeySize } catch { $bits = $null }
        $left = [int][math]::Floor(($c.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays)
        $out += [ordered]@{
            subject = [string]$c.Subject
            issuer = [string]$c.Issuer
            thumbprint = [string]$c.Thumbprint
            notBefore = Get-Utc $c.NotBefore
            notAfter = Get-Utc $c.NotAfter
            daysLeft = $left
            signatureAlgorithm = [string]$c.SignatureAlgorithm.FriendlyName
            keyLength = $bits
        }
    }
    return @($out)
}
# The CRL files the CA publishes: the base CRL is <name>.crl and the delta CRL <name>+.crl.
function Get-CrlInfo($Ca) {
    $dir = Join-Path ([string]$env:SystemRoot) 'System32\CertSrv\CertEnroll'
    $base = $null
    $delta = $null
    if (Test-Path -LiteralPath $dir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Extension -eq '.crl' })) {
            $r = Invoke-Certutil @('-dump', $f.FullName)
            $thisUp = $null
            $next = $null
            foreach ($l in $r.Lines) {
                if ($l -match '^\s*ThisUpdate:\s*(.+?)\s*$') { $thisUp = Get-Utc2 $Matches[1] }
                if ($l -match '^\s*NextUpdate:\s*(.+?)\s*$') { $next = Get-Utc2 $Matches[1] }
            }
            $hours = $null
            if ($next) { $hours = [int][math]::Floor(([datetime]::Parse($next).ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalHours) }
            $info = [ordered]@{ thisUpdate = $thisUp; nextUpdate = $next; hoursToNextUpdate = $hours; sizeBytes = [int64]$f.Length }
            if ($f.BaseName.EndsWith('+')) { $delta = $info } else { $base = $info }
        }
    }
    return [ordered]@{ base = $base; delta = $delta }
}
function Get-ServiceState {
    $svc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return 'absent' }
    return ([string]$svc.Status).ToLowerInvariant()
}

# Templates, read from the directory: the CA cmdlets give only a name (ADR-0076, ca_findings).
function Get-EkuOid([string]$Name) {
    $map = @{ clientAuth = '1.3.6.1.5.5.7.3.2'; smartcard = '1.3.6.1.4.1.311.20.2.2'; pkinit = '1.3.6.1.5.2.3.4'; any = '2.5.29.37.0'; agent = '1.3.6.1.4.1.311.20.2.1' }
    return $map[$Name]
}
function Test-LowPriv([string]$Sid) {
    if (@('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545') -contains $Sid) { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$')
}
function Test-AuthEku([string[]]$Ekus) {
    if ($Ekus.Count -eq 0) { return $true }
    foreach ($e in $Ekus) {
        if (@((Get-EkuOid 'clientAuth'), (Get-EkuOid 'smartcard'), (Get-EkuOid 'pkinit'), (Get-EkuOid 'any')) -contains $e) { return $true }
    }
    return $false
}
function Test-AnyPurpose([string[]]$Ekus) {
    return ($Ekus.Count -eq 0 -or ($Ekus -contains (Get-EkuOid 'any')))
}
# A template as the checks below take it: name, display name, nameFlag, enrollFlag, raSignatures, schemaVersion, ekus
# (strings), enrollSids and writeSids (the security identifiers holding enroll rights and write rights).
function Get-TemplateRisk($T) {
    $ekus = @(Get-Prop $T 'ekus' | Where-Object { $_ })
    $nameFlag = [int](Get-Number (Get-Prop $T 'nameFlag'))
    $enrollFlag = [int](Get-Number (Get-Prop $T 'enrollFlag'))
    $ra = [int](Get-Number (Get-Prop $T 'raSignatures'))
    $enrollLow = @(@(Get-Prop $T 'enrollSids') | Where-Object { $_ -and (Test-LowPriv ([string]$_)) })
    $supplies = (($nameFlag -band 1) -ne 0)
    $approval = (($enrollFlag -band 2) -ne 0)
    $open = ((-not $approval) -and ($ra -eq 0) -and ($enrollLow.Count -gt 0))
    return [ordered]@{
        enrolleeSuppliesSubject = $supplies
        authenticationEku = (Test-AuthEku $ekus)
        anyPurpose = (Test-AnyPurpose $ekus)
        managerApproval = $approval
        raSignatures = $ra
        lowPrivilegeEnroll = ($enrollLow.Count -gt 0)
        open = $open
        risky = ($supplies -and (Test-AuthEku $ekus))
    }
}
function New-Finding([string]$Class, [string]$Subject, [string]$Evidence) {
    return [ordered]@{ id = ($Class + ':' + $Subject); class = $Class; subject = $Subject; evidence = $Evidence }
}
function Get-TemplateFindings($T) {
    $name = [string](Get-Prop $T 'name')
    $ekus = @(Get-Prop $T 'ekus' | Where-Object { $_ })
    $risk = Get-TemplateRisk $T
    $out = @()
    if ($risk.open -and $risk.enrolleeSuppliesSubject -and $risk.authenticationEku) {
        $out += New-Finding 'ESC1' $name 'The enrollee names the certificate subject, the certificate can authenticate, no approval is needed, and a low-privilege group may enroll.'
    }
    if ($risk.open -and $risk.anyPurpose) {
        $out += New-Finding 'ESC2' $name 'The certificate may be used for any purpose (or has no purpose limit), no approval is needed, and a low-privilege group may enroll.'
    }
    if ($risk.open -and ($ekus -contains (Get-EkuOid 'agent'))) {
        $out += New-Finding 'ESC3' $name 'The certificate is an enrollment agent certificate, no approval is needed, and a low-privilege group may enroll.'
    }
    $writeLow = @(@(Get-Prop $T 'writeSids') | Where-Object { $_ -and (Test-LowPriv ([string]$_)) })
    if ($writeLow.Count -gt 0) {
        $out += New-Finding 'ESC4' $name 'A low-privilege group can change this template.'
    }
    return @($out)
}
# The CA's own permissions: ACEs as {sid, mask, allow}. ManageCA is 1 and ManageCertificates is 2.
function Get-CaAclFindings($Aces, [string]$CaName) {
    $out = @()
    foreach ($a in @($Aces)) {
        $sid = [string](Get-Prop $a 'sid')
        $mask = [int](Get-Number (Get-Prop $a 'mask'))
        if (-not [bool](Get-Prop $a 'allow') -or -not (Test-LowPriv $sid)) { continue }
        if (($mask -band 1) -ne 0 -or ($mask -band 2) -ne 0) {
            $out += New-Finding 'ESC7' $CaName 'A low-privilege group can manage the CA or its certificates.'
            break
        }
    }
    return @($out)
}
function Get-EditFlagsFindings([int64]$Flags, [string]$CaName) {
    if (($Flags -band 0x40000) -ne 0) {
        return @(New-Finding 'ESC6' $CaName 'The CA accepts a subject alternative name from the request (EDITF_ATTRIBUTESUBJECTALTNAME2).')
    }
    return @()
}
function Get-RightsIsEnroll([int]$Rights, [string]$ObjectType) {
    $isGeneric = (($Rights -band 0x10000000) -ne 0)
    $isExtended = (($Rights -band 0x100) -ne 0)
    return ($isGeneric -or ($isExtended -and ($ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' -or $ObjectType -eq '00000000-0000-0000-0000-000000000000')))
}
function Get-RightsIsWrite([int]$Rights, [string]$ObjectType = '') {
    # The Enroll and AutoEnroll ACEs of every default template carry WriteProperty (mask 0x130) limited to their own
    # right's GUID: that is permission to enroll, not to change the template (found on a real CA, where each default
    # template was flagged ESC4 because of it).
    $enrollOnly = ($ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' -or $ObjectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
    return ((($Rights -band 0x10000000) -ne 0) -or (($Rights -band 0x40000000) -ne 0) -or (($Rights -band 0x40000) -ne 0) -or (($Rights -band 0x80000) -ne 0) -or ((($Rights -band 0x20) -ne 0) -and -not $enrollOnly))
}
function Get-ConfigPath {
    try {
        $nc = [string]([ADSI]'LDAP://RootDSE').configurationNamingContext
        if ($nc) { return $nc }
    } catch { return $null }
    return $null
}
function Read-Templates {
    $nc = Get-ConfigPath
    if (-not $nc) { return $null }
    $base = 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $nc
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($base)
    $s.Filter = '(objectClass=pKICertificateTemplate)'
    $s.PageSize = 200
    $out = @()
    foreach ($res in @($s.FindAll())) {
        $e = $res.GetDirectoryEntry()
        $ekus = @($e.Properties['pKIExtendedKeyUsage'] | ForEach-Object { [string]$_ })
        if ($ekus.Count -eq 0) { $ekus = @($e.Properties['msPKI-Certificate-Application-Policy'] | ForEach-Object { [string]$_ }) }
        $enrollSids = @()
        $writeSids = @()
        try {
            foreach ($rule in @($e.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
                if ([string]$rule.AccessControlType -ne 'Allow') { continue }
                $sid = [string]$rule.IdentityReference.Value
                $rights = [int]$rule.ActiveDirectoryRights
                if (Get-RightsIsEnroll $rights ([string]$rule.ObjectType)) { $enrollSids += $sid }
                if (Get-RightsIsWrite $rights ([string]$rule.ObjectType)) { $writeSids += $sid }
            }
        } catch { $enrollSids = @(); $writeSids = @() }
        $out += [pscustomobject]@{
            name = [string]$e.Properties['cn'][0]
            displayName = [string]($e.Properties['displayName'] | Select-Object -First 1)
            schemaVersion = [int](Get-Number ($e.Properties['msPKI-Template-Schema-Version'] | Select-Object -First 1))
            nameFlag = [int](Get-Number ($e.Properties['msPKI-Certificate-Name-Flag'] | Select-Object -First 1))
            enrollFlag = [int](Get-Number ($e.Properties['msPKI-Enrollment-Flag'] | Select-Object -First 1))
            raSignatures = [int](Get-Number ($e.Properties['msPKI-RA-Signature'] | Select-Object -First 1))
            ekus = @($ekus)
            enrollSids = @($enrollSids)
            writeSids = @($writeSids)
        }
    }
    return @($out)
}
function Get-PublishedNames {
    if (-not (Get-Command -Name Get-CATemplate -ErrorAction SilentlyContinue)) { return $null }
    return @(Get-CATemplate | ForEach-Object { [string]$_.Name })
}
# Every template of the directory with whether this CA publishes it and what is risky about it.
function Get-TemplateInfos {
    $all = Read-Templates
    $published = Get-PublishedNames
    if ($null -eq $all -or $null -eq $published) { return $null }
    $out = @()
    foreach ($t in $all) {
        $risk = Get-TemplateRisk $t
        $out += [ordered]@{
            name = [string]$t.name
            displayName = [string]$t.displayName
            schemaVersion = [int]$t.schemaVersion
            published = ($published -contains [string]$t.name)
            enrolleeSuppliesSubject = [bool]$risk.enrolleeSuppliesSubject
            authenticationEku = [bool]$risk.authenticationEku
            anyPurpose = [bool]$risk.anyPurpose
            managerApproval = [bool]$risk.managerApproval
            lowPrivilegeEnroll = [bool]$risk.lowPrivilegeEnroll
            risky = [bool]$risk.risky
        }
    }
    return @($out)
}
function Get-RequestColumns {
    return @('RequestID', 'Request.RequesterName', 'CertificateTemplate', 'Request.SubmittedWhen', 'SerialNumber', 'NotAfter', 'CommonName', 'Request.RevokedWhen', 'Request.RevokedReason', 'Request.Disposition')
}
function Convert-RequestRow($Row) {
    $disp = $null
    if ([string](Get-Prop $Row 'Request.Disposition') -match '^\s*(\d+)') { $disp = [int]$Matches[1] }
    $reason = $null
    $reinstated = $false
    if ([string](Get-Prop $Row 'Request.RevokedReason') -match '^\s*(\d+)') {
        # A certificate taken off hold shows the reason 4294967295 ("Unrevoke") and a revocation date (found on a real
        # CA): it is not revoked, so it has neither.
        if ([int64]$Matches[1] -gt 10) { $reinstated = $true } else { $reason = [int]$Matches[1] }
    }
    return [ordered]@{
        id = [int64](Get-Number (Get-Prop $Row 'RequestID'))
        requester = [string](Get-Prop $Row 'Request.RequesterName')
        # A version 2 or later template shows as "<OID> <display name>"; a version 1 one by its name. EMPTY is certutil's
        # word for no value (found on a real CA).
        template = ([string](Get-Prop $Row 'CertificateTemplate') -replace '^\d+(\.\d+)+\s+', '')
        submitted = Get-Utc2 ([string](Get-Prop $Row 'Request.SubmittedWhen'))
        serial = $(if ([string](Get-Prop $Row 'SerialNumber') -ceq 'EMPTY') { '' } else { [string](Get-Prop $Row 'SerialNumber') })
        notAfter = Get-Utc2 ([string](Get-Prop $Row 'NotAfter'))
        commonName = [string](Get-Prop $Row 'CommonName')
        revokedWhen = $(if ($reinstated) { $null } else { Get-Utc2 ([string](Get-Prop $Row 'Request.RevokedWhen')) })
        revokedReason = $reason
        disposition = $(if ($null -ne $disp) { Get-DispositionName $disp } else { 'other' })
    }
}
# A request or certificate by its number, with its disposition ('' when there is none).
function Get-RequestDisposition([int]$Id) {
    $rows = @(Invoke-View (Get-IdRestriction $Id) @('RequestID', 'Request.Disposition'))
    if ($rows.Count -eq 0) { return '' }
    if ([string](Get-Prop $rows[0] 'Request.Disposition') -match '^\s*(\d+)') { return (Get-DispositionName ([int]$Matches[1])) }
    return 'other'
}
function Get-RevocationReasonCode([string]$Name) {
    $map = @{ unspecified = 0; key_compromise = 1; ca_compromise = 2; affiliation_changed = 3; superseded = 4; cessation_of_operation = 5; certificate_hold = 6 }
    if (-not $map.ContainsKey($Name)) { Stop-Result 'invalid_reason' 'That revocation reason is not known.' }
    return [string]$map[$Name]
}
function Assert-TemplateCmdlets {
    if (-not (Get-Command -Name Add-CATemplate -ErrorAction SilentlyContinue)) {
        Stop-Result 'module_missing' 'The certificate authority administration module is not installed on this computer.'
    }
}
function Assert-EnterpriseCa($Ca) {
    if (-not $Ca.Enterprise) { Stop-Result 'not_enterprise' 'A standalone CA has no templates.' }
}
