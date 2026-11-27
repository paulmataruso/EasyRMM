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
            Stop-With 'command_failed' ('The directory returned an error: ' + $fn_err.Exception.Message)
        }
        'ADServerDownException|ADWS|ADServerDown' { Stop-With 'adws_unavailable' 'Active Directory Web Services is not running on this controller.' }
        'ADDefaultDomainPasswordPolicy' { Stop-With 'command_failed' ('The directory returned an error: ' + $fn_err.Exception.Message) }
    }
    if ($fn_err.Exception.Message -match 'object not found|does not exist|Cannot find an object') { Stop-With 'not_found' 'The directory has no such object.' }
    if ($fn_err.Exception.Message -match 'Web Services|ADWS|9389') { Stop-With 'adws_unavailable' 'Active Directory Web Services is not running on this controller.' }
    Stop-With 'command_failed' ('The action failed: ' + $fn_t + ': ' + $fn_err.Exception.Message)
}

try {
    Import-DirectoryModule
    $c = Get-Context $false
    $common = $c.Common
    $base = [string]$c.DomainDn
    if (Test-Param 'container') { $base = [string]$p.container }
    if (-not (Test-UnderDn $base ([string]$c.DomainDn))) { Stop-With 'not_found' 'That container is not in this domain.' }
    $scope = 'OneLevel'
    if ((Test-Param 'scope') -and [string]$p.scope -eq 'subtree') { $scope = 'Subtree' }
    $all = @(Get-ADComputer -SearchBase $base -SearchScope $scope -Filter '*' -ResultSetSize 20001 -Properties SamAccountName, DNSHostName, OperatingSystem, Enabled, primaryGroupID @common)
    if ($all.Count -gt 20000) { Stop-With 'too_many' 'More than 20,000 computers are in this container; narrow it to an organizational unit.' }
    $match = ''
    if (Test-Param 'match') { $match = [string]$p.match }
    $after = ''
    if (Test-Param 'after') { $after = [string]$p.after }
    $size = 100
    if (Test-Param 'pageSize') { $size = [int]$p.pageSize }
    $rows = @()
    $more = $false
    foreach ($o in ($all | Sort-Object { [string]$_.SamAccountName })) {
        $sam = [string]$o.SamAccountName
        if ($after.Length -gt 0 -and [string]::Compare($sam, $after, $true) -le 0) { continue }
        if ($match.Length -gt 0 -and -not $sam.StartsWith($match, 'OrdinalIgnoreCase')) { continue }
        if ($rows.Count -ge $size) { $more = $true; break }
        $isDc = (Get-Prop $o 'primaryGroupID') -eq 516 -or (Get-Prop $o 'primaryGroupID') -eq 521
        $rows += [ordered]@{
            id = [string]$o.SID.Value; sam = $sam; name = [string]$o.Name; dnsName = Get-Text $o 'DNSHostName'
            os = Get-Text $o 'OperatingSystem'; enabled = ($o.Enabled -eq $true); controller = [bool]$isDc
        }
    }
    while ($rows.Count -gt 1 -and (ConvertTo-Json -InputObject $rows -Compress -Depth 4).Length -gt 58000) {
        $rows = @($rows[0..($rows.Count - 2)]); $more = $true
    }
    $next = $null
    if ($more -and $rows.Count -gt 0) { $next = [string]$rows[$rows.Count - 1].sam }
    Write-Result $true ([ordered]@{ items = @($rows); next = $next; scanned = $all.Count }) $null $null
} catch {
    Stop-ForError $_
}
