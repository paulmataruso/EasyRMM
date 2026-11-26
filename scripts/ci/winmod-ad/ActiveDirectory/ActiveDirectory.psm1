# A small stand-in for the ActiveDirectory module, for the tests of the catalogue scripts on a computer with no
# directory. It holds one fixed domain and records what the scripts ask it to change in $env:FAKEAD_LOG (one line per
# call; the text of a password is never written, only its length). $env:FAKEAD_READONLY=1 makes the controller
# read-only; $env:FAKEAD_FAIL="Cmdlet:ExceptionTypeName" makes that cmdlet throw an exception of that type name.
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) {} }
public class ADPasswordComplexityException : System.Exception { public ADPasswordComplexityException(string m) : base(m) {} }
public class ADServerDownException : System.Exception { public ADServerDownException(string m) : base(m) {} }
public class ADFakeFailureException : System.Exception { public ADFakeFailureException(string m) : base(m) {} }
'@

$script:DomainSid = 'S-1-5-21-1-2-3'
$script:DomainDn = 'DC=corp,DC=test'

function New-Sid([string]$v) { [pscustomobject]@{ Value = $v } }
function New-Entry($name, $sam, $rid, $class, $extra) {
    $o = [ordered]@{
        Name = $name; SamAccountName = $sam; SID = (New-Sid ($script:DomainSid + '-' + $rid)); objectSid = (New-Sid ($script:DomainSid + '-' + $rid))
        DistinguishedName = ('CN=' + $name + ',OU=Staff,' + $script:DomainDn); objectClass = $class
        Enabled = $true; LockedOut = $false; PasswordExpired = $false; PasswordNeverExpires = $false; CannotChangePassword = $false
        PasswordLastSet = [datetime]'2026-10-01'; UserPrincipalName = ($sam + '@corp.test'); ProtectedFromAccidentalDeletion = $false
    }
    foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] }
    [pscustomobject]$o
}
$script:Users = @(
    (New-Entry 'Ann Ordinary' 'ann' 1104 'user' @{})
    (New-Entry 'Bob Locked' 'bob' 1105 'user' @{ Enabled = $false; LockedOut = $true })
    (New-Entry 'Dave Nested' 'dave' 1106 'user' @{})
    (New-Entry 'Admin Two' 'admin2' 1107 'user' @{})
    (New-Entry 'Primary Group' 'pgu' 1108 'user' @{ primaryGroupID = 512 })
    (New-Entry 'Old Admin' 'oldadmin' 1109 'user' @{ adminCount = 1 })
    (New-Entry 'Service Acct' 'svc_backup' 1110 'user' @{ servicePrincipalName = @('MSSQLSvc/db1') })
    (New-Entry 'Never Expires' 'neverexp' 1111 'user' @{ PasswordNeverExpires = $true })
    (New-Entry 'Managed' 'gmsa1$' 1112 'msDS-GroupManagedServiceAccount' @{})
    (New-Entry 'Computer One' 'comp1$' 1113 'computer' @{})
    (New-Entry 'Locked Prot' 'protdel' 1114 'user' @{ ProtectedFromAccidentalDeletion = $true })
)
function New-Group($name, $sam, $sid, $members) {
    [pscustomobject]@{ Name = $name; SamAccountName = $sam; SID = (New-Sid $sid); objectSid = (New-Sid $sid); objectClass = 'group'
        DistinguishedName = ('CN=' + $name + ',OU=Staff,' + $script:DomainDn); member = @($members); GroupScope = 'Global'; GroupCategory = 'Security'
        Description = 'd'; ProtectedFromAccidentalDeletion = $false }
}
$userDn = @{}
foreach ($u in $script:Users) { $userDn[$u.SamAccountName] = $u.DistinguishedName }
$script:Groups = @(
    (New-Group 'Domain Admins' 'Domain Admins' ($script:DomainSid + '-512') @($userDn['admin2'], 'CN=Helpdesk Admins,OU=Staff,DC=corp,DC=test'))
    (New-Group 'Enterprise Admins' 'Enterprise Admins' ($script:DomainSid + '-519') @())
    (New-Group 'Schema Admins' 'Schema Admins' ($script:DomainSid + '-518') @())
    (New-Group 'Administrators' 'Administrators' 'S-1-5-32-544' @('CN=Domain Admins,OU=Staff,DC=corp,DC=test'))
    (New-Group 'Helpdesk Admins' 'Helpdesk Admins' ($script:DomainSid + '-1201') @($userDn['dave']))
    (New-Group 'Sales' 'Sales' ($script:DomainSid + '-1300') @($userDn['ann']))
)

function Write-Log([string]$Line) {
    if ($env:FAKEAD_LOG) { Add-Content -LiteralPath $env:FAKEAD_LOG -Value $Line }
}
function Test-Fail([string]$Cmdlet) {
    if ($env:FAKEAD_FAIL -and $env:FAKEAD_FAIL.StartsWith($Cmdlet + ':')) {
        $t = $env:FAKEAD_FAIL.Substring($Cmdlet.Length + 1)
        $ex = switch ($t) {
            'ADPasswordComplexityException' { New-Object ADPasswordComplexityException 'fake' }
            'ADServerDownException' { New-Object ADServerDownException 'fake' }
            default { New-Object ADFakeFailureException 'fake' }
        }
        throw $ex
    }
}
function Find-Entry($Identity) {
    if ($Identity -isnot [string]) { return $Identity }
    foreach ($e in @($script:Users) + @($script:Groups)) {
        if ($e.SID.Value -eq $Identity -or $e.DistinguishedName -eq $Identity -or $e.SamAccountName -eq $Identity) { return $e }
    }
    throw (New-Object ADIdentityNotFoundException 'not found')
}
function Show-Call([string]$Cmd, $Identity, [hashtable]$Extra) {
    $sam = ''
    if ($Identity -isnot [string]) { $sam = $Identity.SamAccountName } else { $sam = $Identity }
    $line = $Cmd + ' ' + $sam
    foreach ($k in ($Extra.Keys | Sort-Object)) {
        $v = $Extra[$k]
        if ($null -eq $v) { continue }
        if ($v -is [System.Security.SecureString]) { $v = 'secure(' + $v.Length + ')' }
        elseif ($v -is [pscredential]) { $v = 'credential' }
        $line += ' ' + $k + '=' + ($v -join ',')
    }
    Write-Log $line
}

function Get-ADDomainController {
    [CmdletBinding()] param($Identity, $Server)
    [pscustomobject]@{ HostName = 'dc1.corp.test'; IsReadOnly = ($env:FAKEAD_READONLY -eq '1'); IsGlobalCatalog = $true }
}
function Get-ADDomain {
    [CmdletBinding()] param($Identity, $Server)
    [pscustomobject]@{ DomainSID = (New-Sid $script:DomainSid); DNSRoot = 'corp.test'; DistinguishedName = $script:DomainDn
        DomainControllersContainer = 'OU=Domain Controllers,DC=corp,DC=test'; PDCEmulator = 'dc1.corp.test'; RIDMaster = 'dc1.corp.test'
        InfrastructureMaster = 'dc1.corp.test'; DomainMode = 'Windows2016Domain' }
}
function Get-ADForest {
    [CmdletBinding()] param($Server)
    [pscustomobject]@{ RootDomain = 'corp.test'; Name = 'corp.test'; ForestMode = 'Windows2016Forest'; SchemaMaster = 'dc1.corp.test'; DomainNamingMaster = 'dc1.corp.test' }
}
function Get-ADDefaultDomainPasswordPolicy {
    [CmdletBinding()] param($Server, $Credential)
    [pscustomobject]@{ MinPasswordLength = 7; ComplexityEnabled = $true; PasswordHistoryCount = 24; MaxPasswordAge = [timespan]::FromDays(42)
        LockoutThreshold = 0; LockoutDuration = [timespan]::FromMinutes(30); LockoutObservationWindow = [timespan]::FromMinutes(30) }
}
function Get-ADOptionalFeature {
    [CmdletBinding()] param($Filter, $Server, $Credential)
    [pscustomobject]@{ EnabledScopes = @() }
}
function Get-ADGroup {
    [CmdletBinding()] param($Identity, $Properties, $Server, $Credential, $SearchBase, $SearchScope, $Filter, $ResultSetSize)
    if ($PSBoundParameters.ContainsKey('Filter')) { return @($script:Groups) }
    Test-Fail 'Get-ADGroup'
    foreach ($g in $script:Groups) {
        if ($g.SID.Value -eq $Identity -or $g.DistinguishedName -eq $Identity) { return $g }
    }
    throw (New-Object ADIdentityNotFoundException 'not found')
}
function Get-ADObject {
    [CmdletBinding()] param($Identity, $Properties, $Server, $Credential, $SearchBase, $SearchScope, $Filter)
    if ($PSBoundParameters.ContainsKey('Filter')) {
        return @([pscustomobject]@{ Name = 'Staff'; DistinguishedName = 'OU=Staff,DC=corp,DC=test'; objectClass = 'organizationalUnit'; ProtectedFromAccidentalDeletion = $true },
            [pscustomobject]@{ Name = 'Domain Controllers'; DistinguishedName = 'OU=Domain Controllers,DC=corp,DC=test'; objectClass = 'organizationalUnit'; ProtectedFromAccidentalDeletion = $true })
    }
    Test-Fail 'Get-ADObject'
    if ($Identity -like 'OU=*') { return [pscustomobject]@{ Name = 'ou'; DistinguishedName = $Identity; objectClass = 'organizationalUnit' } }
    return Find-Entry $Identity
}
function Get-ADUser {
    [CmdletBinding()] param($Identity, $Properties, $Server, $Credential, $SearchBase, $SearchScope, $Filter, $ResultSetSize)
    if ($PSBoundParameters.ContainsKey('Filter')) { return @($script:Users) }
    return Find-Entry $Identity
}
function Get-ADGroupMember {
    [CmdletBinding()] param($Identity, $Server, $Credential)
    $g = Find-Entry $Identity
    foreach ($dn in $g.member) { Find-Entry $dn }
}
function Disable-ADAccount { [CmdletBinding()] param($Identity, $Server, $Credential) Test-Fail 'Disable-ADAccount'; Show-Call 'Disable-ADAccount' $Identity @{ Server = $Server; Credential = $Credential } }
function Enable-ADAccount { [CmdletBinding()] param($Identity, $Server, $Credential) Show-Call 'Enable-ADAccount' $Identity @{ Server = $Server } }
function Unlock-ADAccount { [CmdletBinding()] param($Identity, $Server, $Credential) Test-Fail 'Unlock-ADAccount'; Show-Call 'Unlock-ADAccount' $Identity @{ Server = $Server } }
function Set-ADAccountPassword { [CmdletBinding()] param($Identity, [switch]$Reset, $NewPassword, $Server, $Credential) Test-Fail 'Set-ADAccountPassword'; Show-Call 'Set-ADAccountPassword' $Identity @{ NewPassword = $NewPassword; Server = $Server; Credential = $Credential } }
function Set-ADUser { [CmdletBinding()] param($Identity, $Server, $Credential, $ChangePasswordAtLogon, $GivenName, $Surname, $DisplayName, $Description, $EmailAddress, $OfficePhone, $Title, $Department, $Company, $Office, $Clear)
    Test-Fail 'Set-ADUser'
    $x = @{}
    foreach ($k in $PSBoundParameters.Keys) { if ($k -ne 'Identity') { $x[$k] = $PSBoundParameters[$k] } }
    Show-Call 'Set-ADUser' $Identity $x }
function Move-ADObject { [CmdletBinding()] param($Identity, $TargetPath, $Server, $Credential) Show-Call 'Move-ADObject' $Identity @{ TargetPath = $TargetPath } }
function Remove-ADUser { [CmdletBinding()] param($Identity, $Confirm, $Server, $Credential) Show-Call 'Remove-ADUser' $Identity @{} }
function Remove-ADGroup { [CmdletBinding()] param($Identity, $Confirm, $Server, $Credential) Show-Call 'Remove-ADGroup' $Identity @{} }
function Add-ADGroupMember { [CmdletBinding()] param($Identity, $Members, $Server, $Credential) Show-Call 'Add-ADGroupMember' $Identity @{ Members = $Members } }
function Remove-ADGroupMember { [CmdletBinding()] param($Identity, $Members, $Confirm, $Server, $Credential) Show-Call 'Remove-ADGroupMember' $Identity @{ Members = $Members } }
function New-ADUser {
    [CmdletBinding()] param($Name, $SamAccountName, $Path, $AccountPassword, $Enabled, $ChangePasswordAtLogon, [switch]$PassThru, $UserPrincipalName, $GivenName, $Surname, $DisplayName, $Server, $Credential)
    Test-Fail 'New-ADUser'
    Show-Call 'New-ADUser' $SamAccountName @{ Path = $Path; AccountPassword = $AccountPassword; Enabled = $Enabled; ChangePasswordAtLogon = $ChangePasswordAtLogon }
    New-Entry $Name $SamAccountName 2001 'user' @{}
}
function New-ADGroup {
    [CmdletBinding()] param($Name, $SamAccountName, $Path, $GroupScope, $GroupCategory, [switch]$PassThru, $Description, $Server, $Credential)
    Show-Call 'New-ADGroup' $SamAccountName @{ Path = $Path; GroupScope = $GroupScope; GroupCategory = $GroupCategory }
    New-Group $Name $SamAccountName ($script:DomainSid + '-2002') @()
}
function Get-ADReplicationFailure { [CmdletBinding()] param($Scope, $Target, $Server, $Credential) @() }
function Get-ADReplicationPartnerMetadata { [CmdletBinding()] param($Target, $Scope, $Server, $Credential) @() }
Export-ModuleMember -Function *-AD*
