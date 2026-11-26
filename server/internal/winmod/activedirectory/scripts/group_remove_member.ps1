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

# The protected targets (ADR-0075 section 4): the privileged groups and everything nested in them, counted through the
# Global Catalog by SID, never by name. A member that cannot be resolved, or a set that is too large, refuses the request.
function Find-Group([string]$fn_Sid, [bool]$fn_ForestWide, [bool]$fn_Required, [hashtable]$fn_c) {
    $fn_common = @{ Server = $fn_c.Server }
    if ($fn_c.Common.ContainsKey('Credential')) { $fn_common['Credential'] = $fn_c.Common['Credential'] }
    if ($fn_ForestWide -and $fn_c.ForestSid -ne $fn_c.DomainSid) { $fn_common['Server'] = Join-Text $fn_c.Server ':3268' }
    try {
        return Get-ADGroup -Identity $fn_Sid -Properties member, whenChanged @common
    } catch {
        if ($_.Exception.GetType().Name -eq 'ADIdentityNotFoundException' -and -not $fn_Required) { return $null }
        throw
    }
}
function Get-ProtectedSet([hashtable]$fn_c) {
    $fn_set = @{}
    $fn_dom = [string]$fn_c.DomainSid
    $fn_for = [string]$fn_c.ForestSid
    $fn_set[(Join-Text $fn_dom '-500')] = 'the built-in Administrator'
    $fn_set[(Join-Text $fn_dom '-502')] = 'the krbtgt account'
    $fn_roots = @(
        @((Join-Text $fn_dom '-512'), $false, $true), @((Join-Text $fn_for '-519'), $true, $true), @((Join-Text $fn_for '-518'), $true, $true),
        @('S-1-5-32-544', $false, $true), @('S-1-5-32-548', $false, $false), @('S-1-5-32-549', $false, $false),
        @('S-1-5-32-550', $false, $false), @('S-1-5-32-551', $false, $false), @('S-1-5-32-552', $false, $false),
        @((Join-Text $fn_dom '-516'), $false, $false), @((Join-Text $fn_dom '-520'), $false, $false), @((Join-Text $fn_dom '-521'), $false, $false),
        @((Join-Text $fn_dom '-526'), $false, $false), @((Join-Text $fn_for '-527'), $true, $false)
    )
    $fn_queue = New-Object System.Collections.Queue
    foreach ($fn_root in $fn_roots) {
        $fn_g = Find-Group ([string]$fn_root[0]) ([bool]$fn_root[1]) ([bool]$fn_root[2]) $fn_c
        if ($null -eq $fn_g) { continue }
        $fn_set[[string]$fn_g.SID.Value] = 'it is, or is inside, a privileged group'
        $fn_queue.Enqueue($fn_g)
    }
    $fn_dns = $null
    try { $fn_dns = Get-ADGroup -Identity 'DnsAdmins' -Properties member -Server $fn_c.Server } catch { $fn_dns = $null }
    if ($null -ne $fn_dns) { $fn_set[[string]$fn_dns.SID.Value] = 'it is, or is inside, a privileged group'; $fn_queue.Enqueue($fn_dns) }
    while ($fn_queue.Count -gt 0) {
        $fn_g = $fn_queue.Dequeue()
        foreach ($fn_dn in (Get-List $fn_g 'member')) {
            if ($fn_set.Count -gt 5000) { throw 'The set of privileged accounts is too large to check.' }
            $fn_srv = $fn_c.Server
            if (-not (Test-UnderDn ([string]$fn_dn) ([string]$fn_c.DomainDn))) { $fn_srv = Join-Text $fn_c.Server ':3268' }
            $fn_m = Get-ADObject -Identity $fn_dn -Properties objectSid, objectClass -Server $fn_srv
            $fn_sid = [string]$fn_m.objectSid.Value
            $fn_kind = [string]$fn_m.objectClass
            if ($fn_set.ContainsKey($fn_sid) -and $fn_kind -ne 'foreignSecurityPrincipal') { continue }
            $fn_set[$fn_sid] = 'it is, or is inside, a privileged group'
            if ($fn_kind -eq 'group') {
                $fn_queue.Enqueue((Get-ADGroup -Identity $fn_dn -Properties member -Server $fn_srv))
            } elseif ($fn_kind -eq 'foreignSecurityPrincipal') {
                $fn_fg = Find-Group $fn_sid $true $false $fn_c
                if ($null -ne $fn_fg) { $fn_queue.Enqueue($fn_fg) }
            }
        }
    }
    return $fn_set
}
# 'protected', 'service' or 'none', with why.
function Get-Protection($fn_o, [hashtable]$fn_Set, [string]$fn_DomainSid) {
    $fn_sid = [string]$fn_o.SID.Value
    $fn_cls = Get-Text $fn_o 'objectClass'
    if ($fn_Set.ContainsKey($fn_sid)) { return @{ level = 'protected'; reason = [string]$fn_Set[$fn_sid] } }
    if ($fn_cls -eq 'computer') { return @{ level = 'protected'; reason = 'it is a computer account' } }
    if ($fn_cls -eq 'msDS-GroupManagedServiceAccount' -or $fn_cls -eq 'msDS-ManagedServiceAccount') { return @{ level = 'protected'; reason = 'it is a managed service account' } }
    $fn_admin = Get-Prop $fn_o 'adminCount'
    if ($null -ne $fn_admin -and [int]$fn_admin -eq 1) { return @{ level = 'protected'; reason = 'adminCount is set (this can be left over from a past membership)' } }
    $fn_pg = Get-Prop $fn_o 'primaryGroupID'
    if ($null -ne $fn_pg -and $fn_Set.ContainsKey((Join-Text (Join-Text $fn_DomainSid '-') ([string]$fn_pg)))) { return @{ level = 'protected'; reason = 'its primary group is a privileged group' } }
    $fn_spn = Get-Prop $fn_o 'servicePrincipalName'
    if ($null -ne $fn_spn -and @($fn_spn).Count -gt 0) { return @{ level = 'service'; reason = 'it has a service principal name' } }
    $fn_uac = Get-Prop $fn_o 'userAccountControl'
    if ($null -ne $fn_uac -and (([int]$fn_uac -band 0x10000) -ne 0)) {
        $fn_last = Get-Prop $fn_o 'lastLogonTimestamp'
        if ($null -eq $fn_last -or [int64]$fn_last -le 0 -or [datetime]::FromFileTimeUtc([int64]$fn_last) -lt (Get-Date).ToUniversalTime().AddDays(-180)) {
            return @{ level = 'service'; reason = 'its password never expires and nobody has signed in with it for 180 days (a guess)' }
        }
    }
    return @{ level = 'none'; reason = '' }
}
function Assert-Writable($fn_o, [hashtable]$fn_Set, [hashtable]$fn_c, [string]$fn_Confirm) {
    $fn_verdict = Get-Protection $fn_o $fn_Set ([string]$fn_c.DomainSid)
    if ($fn_verdict.level -eq 'protected') { Stop-With 'protected_target' ('This target is protected: ' + $fn_verdict.reason + '.') }
    if ($fn_verdict.level -eq 'service' -and -not (Test-ServiceConfirm $fn_Confirm (Get-Text $fn_o 'SamAccountName'))) {
        Stop-With 'service_account_confirmation_required' ('This looks like a service account (' + $fn_verdict.reason + '); changing it can stop the services that run as it.')
    }
}
function Get-TargetUser([string]$fn_Id, [hashtable]$fn_c) {
    $fn_common = $fn_c.Common
    return Get-ADUser -Identity $fn_Id -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled, LockedOut, PasswordLastSet, PasswordNeverExpires, CannotChangePassword, adminCount, primaryGroupID, servicePrincipalName, userAccountControl, lastLogonTimestamp, objectClass, ProtectedFromAccidentalDeletion @common
}
function Get-TargetGroup([string]$fn_Id, [hashtable]$fn_c) {
    $fn_common = $fn_c.Common
    return Get-ADGroup -Identity $fn_Id -Properties SamAccountName, adminCount, objectClass, ProtectedFromAccidentalDeletion @common
}
function Assert-Ou([string]$fn_Dn, [hashtable]$fn_c) {
    $fn_common = $fn_c.Common
    if (-not (Test-UnderDn $fn_Dn ([string]$fn_c.DomainDn))) { Stop-With 'not_found' 'That container is not in this domain.' }
    if (Test-UnderDn $fn_Dn ([string]$fn_c.ControllersDn)) { Stop-With 'protected_target' 'Nothing is created in, moved into or moved out of the Domain Controllers container.' }
    $fn_o = Get-ADObject -Identity $fn_Dn -Properties objectClass @common
    if (@('organizationalUnit', 'container', 'domainDNS') -notcontains [string]$fn_o.objectClass) { Stop-With 'not_found' 'That is not an organizational unit or a container.' }
}

try {
    Import-DirectoryModule
    $c = Get-Context $true
    $common = $c.Common
    $set = Get-ProtectedSet $c
    $g = Get-TargetGroup ([string]$p.id) $c
    Assert-Writable $g $set $c ''
    Remove-ADGroupMember -Identity $g -Members ([string]$p.member) -Confirm:$false @common
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Stop-ForError $_
}
