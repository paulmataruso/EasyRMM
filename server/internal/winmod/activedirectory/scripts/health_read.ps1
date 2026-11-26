Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($fn_ok, $fn_data, $fn_code, $fn_message) {
    $fn_r = [ordered]@{ ok = $fn_ok; version = $version; data = $fn_data; error = $null }
    if (-not $fn_ok) { $fn_r.error = [ordered]@{ code = $fn_code; message = $fn_message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $fn_r -Compress -Depth 8))
}
function Stop-With($fn_code, $fn_message) {
    Write-Result $false $null $fn_code $fn_message
    exit 0
}
function Test-Param($fn_name) {
    return ($null -ne $p.PSObject.Properties[$fn_name])
}
function Get-Prop($fn_o, $fn_name) {
    if ($null -ne $fn_o -and $null -ne $fn_o.PSObject.Properties[$fn_name]) { return $fn_o.$fn_name }
    return $null
}
function Get-List($fn_o, $fn_name) {
    $fn_v = Get-Prop $fn_o $fn_name
    if ($null -eq $fn_v) { return @() }
    return @($fn_v)
}
function Get-Text($fn_o, $fn_name) {
    $fn_v = Get-Prop $fn_o $fn_name
    if ($null -eq $fn_v) { return '' }
    return [string]$fn_v
}
function Get-UtcText($fn_v) {
    if ($null -eq $fn_v) { return $null }
    return ([datetime]$fn_v).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
function Get-First($fn_o, $fn_name) {
    $fn_v = Get-Prop $fn_o $fn_name
    if ($null -eq $fn_v) { return '' }
    $fn_a = @($fn_v)
    if ($fn_a.Count -eq 0) { return '' }
    return [string]$fn_a[0]
}
function Join-Text([string]$fn_Left, [string]$fn_Right) { return $fn_Left + $fn_Right }
function Test-UnderDn([string]$fn_Dn, [string]$fn_Root) {
    return ($fn_Dn.Equals($fn_Root, 'OrdinalIgnoreCase') -or $fn_Dn.EndsWith(',' + $fn_Root, 'OrdinalIgnoreCase'))
}
function Test-ServiceConfirm([string]$fn_GivenText, [string]$fn_AccountName) {
    return ($fn_GivenText -ceq ('service-account:' + $fn_AccountName))
}
function Import-DirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Stop-With 'module_missing' 'The ActiveDirectory PowerShell module is not installed on this computer. Install the RSAT-AD-PowerShell feature.'
    }
    Import-Module ActiveDirectory
}
# The controller this script runs on: every cmdlet addresses it by name, so a change never lands on another one.
function Get-Context([bool]$fn_Write) {
    $fn_dc = Get-ADDomainController -Identity ([System.Net.Dns]::GetHostName())
    $fn_domain = Get-ADDomain -Server ([string]$fn_dc.HostName)
    $fn_forest = Get-ADForest -Server ([string]$fn_dc.HostName)
    $fn_readOnly = ($fn_dc.IsReadOnly -eq $true)
    if ($fn_Write -and $fn_readOnly) { Stop-With 'read_only_dc' 'This is a read-only domain controller; nothing is changed through it.' }
    $fn_rootSid = [string]$fn_domain.DomainSID.Value
    if ($fn_forest.RootDomain -ne $fn_domain.DNSRoot) {
        $fn_rootSid = [string](Get-ADDomain -Identity ([string]$fn_forest.RootDomain) -Server ([string]$fn_dc.HostName)).DomainSID.Value
    }
    $fn_ctxCommon = @{ Server = [string]$fn_dc.HostName }
    $fn_ctxCred = $null
    $fn_hasUser = Test-Param 'credUser'
    $fn_hasPass = Test-Param 'credPassword'
    if ($fn_hasUser -ne $fn_hasPass) { Stop-With 'conflict' 'A credential needs both a user name and a password.' }
    if ($fn_hasUser) {
        $fn_ctxCred = New-Object System.Management.Automation.PSCredential([string]$p.credUser, (ConvertTo-Secure ([string]$p.credPassword)))
        $fn_ctxCommon['Credential'] = $fn_ctxCred
    }
    return @{
        Server = [string]$fn_dc.HostName; Common = $fn_ctxCommon; ReadOnly = $fn_readOnly; Gc = [string]$fn_dc.HostName
        DomainSid = $fn_domain.DomainSID.Value; DomainDn = [string]$fn_domain.DistinguishedName; DomainName = [string]$fn_domain.DNSRoot
        ForestSid = $fn_rootSid; ControllersDn = [string]$fn_domain.DomainControllersContainer
        Forest = $fn_forest; Domain = $fn_domain; Dc = $fn_dc
    }
}
# A SecureString from text without ConvertTo-SecureString -AsPlainText: the text is only ever a variable.
function ConvertTo-Secure([string]$fn_Text) {
    $fn_s = New-Object System.Security.SecureString
    foreach ($fn_ch in $fn_Text.ToCharArray()) { $fn_s.AppendChar($fn_ch) }
    $fn_s.MakeReadOnly()
    return $fn_s
}
function Stop-ForError($fn_err) {
    $fn_t = $fn_err.Exception.GetType().Name
    switch -Regex ($fn_t) {
        'ADIdentityNotFoundException' { Stop-With 'not_found' 'The directory has no such object.' }
        'ADIdentityAlreadyExistsException' { Stop-With 'conflict' 'An object with that name already exists.' }
        'ADPasswordComplexityException|ADInvalidPasswordException|PasswordException' { Stop-With 'password_policy' 'The domain refused the password (length, complexity or history).' }
        'UnauthorizedAccessException|ADException' {
            if ($fn_err.Exception.Message -match 'denied|authoriz|access') { Stop-With 'access_denied' 'The directory refused the change: this computer is not allowed to make it.' }
            Stop-With 'command_failed' 'The directory returned an error.'
        }
        'ADServerDownException|ADWS|ADServerDown' { Stop-With 'adws_unavailable' 'Active Directory Web Services is not running on this controller.' }
        'ADDefaultDomainPasswordPolicy' { Stop-With 'command_failed' 'The directory returned an error.' }
    }
    if ($fn_err.Exception.Message -match 'object not found|does not exist|Cannot find an object') { Stop-With 'not_found' 'The directory has no such object.' }
    if ($fn_err.Exception.Message -match 'Web Services|ADWS|9389') { Stop-With 'adws_unavailable' 'Active Directory Web Services is not running on this controller.' }
    Stop-With 'command_failed' ('The action failed: ' + $fn_t)
}

function New-Check([string]$Name, [string]$State, [string]$Detail) {
    return [ordered]@{ name = $Name; state = $State; detail = $Detail }
}
try {
    Import-DirectoryModule
    $c = Get-Context $false
    $common = $c.Common
    $checks = @()
    $failureCount = 0
    $oldest = $null
    $partners = @()
    # Replication: the failures the directory itself reports, and when each partner last succeeded.
    try {
        $failures = @(Get-ADReplicationFailure -Scope Domain -Target ([string]$c.DomainName) @common)
        $failureCount = $failures.Count
        foreach ($f in $failures) {
            $when = Get-Prop $f 'FirstFailureTime'
            if ($null -ne $when -and ($null -eq $oldest -or [datetime]$when -lt $oldest)) { $oldest = [datetime]$when }
        }
        $lag = $false
        foreach ($m in @(Get-ADReplicationPartnerMetadata -Target ([string]$c.Server) -Scope Server @common)) {
            if ($partners.Count -ge 20) { break }
            $ok = Get-Prop $m 'LastReplicationSuccess'
            $partnerName = ([string](Get-Prop $m 'Partner') -split ',')[1]
            if ($null -ne $ok -and [datetime]$ok -lt (Get-Date).AddMinutes(-15)) { $lag = $true }
            $partners += [ordered]@{ partner = ([string]$partnerName -replace '^CN=', ''); lastSuccessAt = Get-UtcText $ok; lastResult = [int](Get-Prop $m 'LastReplicationResult') }
        }
        if ($failureCount -gt 0) { $checks += New-Check 'replication' 'critical' 'The directory reports replication failures.' }
        elseif ($lag) { $checks += New-Check 'replication' 'warning' 'A replication partner has not succeeded in the last 15 minutes.' }
        elseif ($partners.Count -eq 0) { $checks += New-Check 'replication' 'not_applicable' 'This controller has no replication partners.' }
        else { $checks += New-Check 'replication' 'ok' 'Replication is succeeding.' }
    } catch {
        $checks += New-Check 'replication' 'could_not_run' 'The replication check could not run.'
    }
    # The five operations masters.
    try {
        $roles = @([string]$c.Domain.PDCEmulator, [string]$c.Domain.RIDMaster, [string]$c.Domain.InfrastructureMaster, [string]$c.Forest.SchemaMaster, [string]$c.Forest.DomainNamingMaster)
        $missing = @($roles | Where-Object { [string]::IsNullOrEmpty($_) })
        if ($missing.Count -gt 0) { $checks += New-Check 'fsmo' 'critical' 'An operations master role has no holder.' }
        else { $checks += New-Check 'fsmo' 'ok' 'All five operations master roles have a holder.' }
    } catch {
        $checks += New-Check 'fsmo' 'could_not_run' 'The operations master check could not run.'
    }
    # The services a controller needs.
    try {
        $need = @('NTDS', 'ADWS', 'Netlogon', 'Kdc')
        $want = @('DNS', 'DFSR', 'W32Time')
        $bad = 0
        $soft = 0
        foreach ($name in $need) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -ne 'Running') { $bad++ }
        }
        foreach ($name in $want) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.Status -ne 'Running') { $soft++ }
        }
        if ($bad -gt 0) { $checks += New-Check 'services' 'critical' 'A service a domain controller needs is not running.' }
        elseif ($soft -gt 0) { $checks += New-Check 'services' 'warning' 'DNS, DFS Replication or Windows Time is installed but not running.' }
        else { $checks += New-Check 'services' 'ok' 'The directory services are running.' }
    } catch {
        $checks += New-Check 'services' 'could_not_run' 'The service check could not run.'
    }
    # SYSVOL and NETLOGON are shared.
    try {
        $names = @(Get-CimInstance -ClassName Win32_Share | ForEach-Object { [string]$_.Name })
        if ($names -contains 'SYSVOL' -and $names -contains 'NETLOGON') { $checks += New-Check 'sysvol' 'ok' 'SYSVOL and NETLOGON are shared.' }
        else { $checks += New-Check 'sysvol' 'critical' 'SYSVOL or NETLOGON is not shared.' }
    } catch {
        $checks += New-Check 'sysvol' 'could_not_run' 'The SYSVOL check could not run.'
    }
    # How many accounts are locked out now.
    $locked = $null
    try { $locked = @(Search-ADAccount -LockedOut -UsersOnly @common).Count } catch { $locked = $null }
    $data = [ordered]@{
        controller = [string]$c.Dc.HostName
        domain = [string]$c.DomainName
        checks = @($checks)
        lockedOutCount = $locked
        replication = [ordered]@{ failureCount = $failureCount; oldestFailureAt = Get-UtcText $oldest; partners = @($partners) }
    }
    Write-Result $true $data $null $null
} catch {
    Stop-ForError $_
}
