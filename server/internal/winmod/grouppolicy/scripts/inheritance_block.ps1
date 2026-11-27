Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($fn_ok, $fn_data, $fn_code, $fn_message) {
    $fn_r = [ordered]@{ ok = $fn_ok; version = $version; data = $fn_data; error = $null }
    if (-not $fn_ok) { $fn_r.error = [ordered]@{ code = $fn_code; message = $fn_message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $fn_r -Compress -Depth 12))
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
function Get-Text($fn_o, $fn_name) {
    $fn_v = Get-Prop $fn_o $fn_name
    if ($null -eq $fn_v) { return '' }
    return [string]$fn_v
}
function Get-UtcText($fn_v) {
    if ($null -eq $fn_v) { return $null }
    return ([datetime]$fn_v).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
function Join-Text([string]$fn_Left, [string]$fn_Right) { return $fn_Left + $fn_Right }
function Format-Text([string]$fn_Template, [string]$fn_A, [string]$fn_B) { return [string]::Format($fn_Template, $fn_A, $fn_B) }
function Test-UnderDn([string]$fn_Dn, [string]$fn_Root) {
    return ($fn_Dn.Equals($fn_Root, 'OrdinalIgnoreCase') -or $fn_Dn.EndsWith(',' + $fn_Root, 'OrdinalIgnoreCase'))
}
# The two Default policies (ADR-0083 section 7): their identifiers are fixed by Microsoft. A script never deletes, renames,
# unlinks or disables them, whatever the server sent.
function Test-DefaultPolicy([string]$fn_Id) {
    return (@('31b2f340-016d-11d2-945f-00c04fb984f9', '6ac1786c-016f-11d2-945f-00c04fb984f9') -contains $fn_Id.ToLowerInvariant())
}
function Assert-NotDefault([string]$fn_Id, [string]$fn_What) {
    if (Test-DefaultPolicy $fn_Id) { Stop-With 'protected_policy' (Format-Text 'A Default policy is never {0} here.' $fn_What '') }
}
function Import-GroupPolicyModule {
    # Import by name and nothing else: Get-Module -ListAvailable scans every module folder on the computer first (seconds).
    Import-Module -Name GroupPolicy -ErrorAction SilentlyContinue
    if ($null -eq (Get-Module -Name GroupPolicy)) {
        Stop-With 'module_missing' 'The GroupPolicy PowerShell module is not installed on this computer. Install the Group Policy Management feature (GPMC).'
    }
}
# The controller this script runs on: every cmdlet addresses it and its domain by name, so a change never lands on another one.
function Get-Context {
    $fn_dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    $fn_dcName = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
    $fn_root = 'DC=' + ($fn_dom.Name -replace '\.', ',DC=')
    $fn_common = @{ Server = [string]$fn_dcName; Domain = [string]$fn_dom.Name }
    return @{ Server = [string]$fn_dcName; Domain = [string]$fn_dom.Name; DomainDn = [string]$fn_root; ControllersDn = ('OU=Domain Controllers,' + $fn_root); Common = $fn_common }
}
function Get-TargetKind([string]$fn_Dn, [hashtable]$fn_c) {
    if ($fn_Dn.Equals([string]$fn_c.DomainDn, 'OrdinalIgnoreCase')) { return 'domain' }
    if ($fn_Dn.Equals([string]$fn_c.ControllersDn, 'OrdinalIgnoreCase')) { return 'dc_ou' }
    if ($fn_Dn.IndexOf(',CN=Sites,CN=Configuration,', [System.StringComparison]::OrdinalIgnoreCase) -gt 0) { return 'site' }
    return 'ou'
}
function Test-SensitiveKind([string]$fn_Kind) { return (@('domain', 'dc_ou', 'site') -contains $fn_Kind) }
function Assert-InDomain([string]$fn_Dn, [hashtable]$fn_c) {
    $fn_kind = Get-TargetKind $fn_Dn $fn_c
    if ($fn_kind -eq 'site') { return }
    if (-not (Test-UnderDn $fn_Dn ([string]$fn_c.DomainDn))) { Stop-With 'not_found' 'That container is not in this domain.' }
}
function Get-Versions($fn_g) {
    return [ordered]@{
        computer = [ordered]@{ directory = [int]$fn_g.Computer.DSVersion; sysvol = [int]$fn_g.Computer.SysvolVersion }
        user     = [ordered]@{ directory = [int]$fn_g.User.DSVersion; sysvol = [int]$fn_g.User.SysvolVersion }
    }
}
# Optimistic concurrency (ADR-0083 section 4): the page read the GPO at these versions; if they moved, nothing is written.
function Assert-Versions($fn_g) {
    if ((Test-Param 'expectComputerVersion') -and [int]$p.expectComputerVersion -ne [int]$fn_g.Computer.DSVersion) {
        Stop-With 'changed_meanwhile' 'The GPO was changed by someone else since it was read. Reload it and try again.'
    }
    if ((Test-Param 'expectUserVersion') -and [int]$p.expectUserVersion -ne [int]$fn_g.User.DSVersion) {
        Stop-With 'changed_meanwhile' 'The GPO was changed by someone else since it was read. Reload it and try again.'
    }
}
function ConvertTo-GpoRow($fn_g) {
    $fn_wmi = ''
    $fn_f = Get-Prop $fn_g 'WmiFilter'
    if ($null -ne $fn_f) { $fn_wmi = Get-Text $fn_f 'Name' }
    $fn_id = ([string]$fn_g.Id).ToLowerInvariant()
    return [ordered]@{
        id          = $fn_id
        name        = [string]$fn_g.DisplayName
        status      = [string]$fn_g.GpoStatus
        description = [string]$fn_g.Description
        owner       = [string]$fn_g.Owner
        created     = (Get-UtcText $fn_g.CreationTime)
        modified    = (Get-UtcText $fn_g.ModificationTime)
        computer    = [ordered]@{ directory = [int]$fn_g.Computer.DSVersion; sysvol = [int]$fn_g.Computer.SysvolVersion }
        user        = [ordered]@{ directory = [int]$fn_g.User.DSVersion; sysvol = [int]$fn_g.User.SysvolVersion }
        wmiFilter   = $fn_wmi
        default     = (Test-DefaultPolicy $fn_id)
        linkCount   = 0
        links       = @()
    }
}
function Get-DirSearcher([string]$fn_Base, [hashtable]$fn_c) {
    $fn_s = New-Object System.DirectoryServices.DirectorySearcher
    $fn_s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry((Join-Text (Join-Text 'LDAP://' ([string]$fn_c.Server)) (Join-Text '/' $fn_Base)))
    $fn_s.PageSize = 500
    return $fn_s
}
# Every container a GPO can be linked to: the domain, its OUs and the forest's sites, by name, in a fixed order.
# The list is built from plain rows (no directory needed) so it runs the same on a runner. The result is an array made by
# ToArray(): in Windows PowerShell 5.1, @(<List[object]>) of hashtables throws "Argument types do not match".
function Build-LinkTargetList([hashtable]$fn_c, $fn_ouRows, $fn_siteNames, [string]$fn_ConfigDn) {
    $fn_list = New-Object System.Collections.Generic.List[object]
    $fn_list.Add(@{ dn = [string]$fn_c.DomainDn; name = [string]$fn_c.Domain; kind = 'domain' })
    foreach ($fn_o in ($fn_ouRows | Sort-Object { $_.dn })) {
        $fn_list.Add(@{ dn = [string]$fn_o.dn; name = [string]$fn_o.name; kind = (Get-TargetKind ([string]$fn_o.dn) $fn_c) })
    }
    foreach ($fn_site in @($fn_siteNames | Sort-Object)) {
        $fn_list.Add(@{ dn = (Join-Text (Join-Text 'CN=' ([string]$fn_site)) (Join-Text ',CN=Sites,' $fn_ConfigDn)); name = [string]$fn_site; kind = 'site' })
    }
    return $fn_list.ToArray()
}
function Get-LinkTargets([hashtable]$fn_c) {
    $fn_s = Get-DirSearcher ([string]$fn_c.DomainDn) $fn_c
    $fn_s.Filter = '(objectCategory=organizationalUnit)'
    [void]$fn_s.PropertiesToLoad.Add('distinguishedName')
    [void]$fn_s.PropertiesToLoad.Add('name')
    $fn_rows = New-Object System.Collections.Generic.List[object]
    $fn_found = $fn_s.FindAll()
    try {
        foreach ($fn_r in $fn_found) {
            $fn_rows.Add(@{ dn = [string]$fn_r.Properties['distinguishedname'][0]; name = [string]$fn_r.Properties['name'][0] })
        }
    } finally { $fn_found.Dispose() }
    $fn_rootDse = New-Object System.DirectoryServices.DirectoryEntry((Join-Text (Join-Text 'LDAP://' ([string]$fn_c.Server)) '/RootDSE'))
    $fn_config = [string]$fn_rootDse.Properties['configurationNamingContext'][0]
    $fn_sites = @([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | ForEach-Object { [string]$_.Name })
    return (Build-LinkTargetList $fn_c $fn_rows.ToArray() $fn_sites $fn_config)
}
function Get-TargetLinks($fn_t, [hashtable]$fn_c) {
    $fn_common = $fn_c.Common
    $fn_inh = Get-GPInheritance -Target ([string]$fn_t.dn) @fn_common
    $fn_links = @()
    foreach ($fn_l in @($fn_inh.GpoLinks)) {
        $fn_links += [ordered]@{
            gpoId = ([string]$fn_l.GpoId).ToLowerInvariant(); gpoName = [string]$fn_l.DisplayName; target = [string]$fn_t.dn; targetName = [string]$fn_t.name
            kind = [string]$fn_t.kind; enabled = ($fn_l.Enabled -eq $true); enforced = ($fn_l.Enforced -eq $true); order = [int]$fn_l.Order
        }
    }
    return @{ links = $fn_links; blocked = ($fn_inh.GpoInheritanceBlocked -eq $true) }
}
# The staging folder lives in the agent's own protected folder under ProgramData; a folder older than two hours is a leftover.
function Get-StagingBase {
    $fn_base = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('CommonApplicationData'), 'EasyRMM', 'gpo-staging')
    [void](New-Item -ItemType Directory -Path $fn_base -Force)
    $fn_cut = (Get-Date).AddHours(-2)
    foreach ($fn_d in @(Get-ChildItem -LiteralPath $fn_base -Directory)) {
        if ($fn_d.LastWriteTime -lt $fn_cut) { Remove-Item -LiteralPath $fn_d.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    }
    return $fn_base
}
function Get-HexHash([byte[]]$fn_Bytes) {
    $fn_sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([System.BitConverter]::ToString($fn_sha.ComputeHash($fn_Bytes))).Replace('-', '').ToLowerInvariant()) } finally { $fn_sha.Dispose() }
}
# The automatic backup (ADR-0083 section 7): Microsoft's Backup-GPO into a fresh folder, zipped and returned in base64 for the
# server to keep. A backup too large to travel in a result stops the change before anything is written.
function Save-GpoBackup($fn_g, [string]$fn_Why, [hashtable]$fn_c) {
    $fn_common = $fn_c.Common
    $fn_root = [System.IO.Path]::Combine((Get-StagingBase), [guid]::NewGuid().ToString('N'))
    $fn_files = [System.IO.Path]::Combine($fn_root, 'files')
    [void](New-Item -ItemType Directory -Path $fn_files -Force)
    $fn_b = Backup-GPO -Guid ([string]$fn_g.Id) -Path $fn_files -Comment (Join-Text 'EasyRMM backup before ' $fn_Why) @fn_common
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $fn_zip = [System.IO.Path]::Combine($fn_root, 'backup.zip')
    [System.IO.Compression.ZipFile]::CreateFromDirectory($fn_files, $fn_zip)
    $fn_bytes = [System.IO.File]::ReadAllBytes($fn_zip)
    Remove-Item -LiteralPath $fn_root -Recurse -Force
    if ($fn_bytes.Length -gt 36000) { Stop-With 'backup_too_large' 'The backup of this GPO is too large for EasyRMM to keep, so nothing was changed. Change it in the Group Policy Management Console.' }
    $fn_v = Get-Versions $fn_g
    return [ordered]@{
        backupId = ([string]$fn_b.Id).ToLowerInvariant(); gpoId = ([string]$fn_g.Id).ToLowerInvariant(); gpoName = [string]$fn_g.DisplayName
        domain = [string]$fn_c.Domain; size = [int]$fn_bytes.Length; sha256 = (Get-HexHash $fn_bytes); computer = $fn_v.computer; user = $fn_v.user
        zip = [System.Convert]::ToBase64String($fn_bytes)
    }
}
function Write-Changed([string]$fn_Summary, $fn_Before, $fn_After, $fn_G, $fn_Backup, $fn_Vb, $fn_Va) {
    $fn_data = [ordered]@{
        summary = $fn_Summary; before = $fn_Before; after = $fn_After; gpoId = ''; gpoName = ''; backup = $fn_Backup; versionBefore = $fn_Vb; versionAfter = $fn_Va
    }
    if ($null -ne $fn_G) { $fn_data.gpoId = ([string]$fn_G.Id).ToLowerInvariant(); $fn_data.gpoName = [string]$fn_G.DisplayName }
    Write-Result $true $fn_data $null $null
}
function Stop-ForError($fn_err) {
    $fn_t = $fn_err.Exception.GetType().Name
    $fn_m = [string]$fn_err.Exception.Message
    # A command called with a parameter it does not have, or a value it refuses, is a script error, not a missing GPO: its
    # message ("A parameter cannot be found ...") must not be read as not_found.
    if ($fn_t -match 'ParameterBinding' -or [string]$fn_err.FullyQualifiedErrorId -match 'NamedParameterNotFound|AmbiguousParameter|ParameterArgumentValidation') {
        Stop-With 'command_failed' (Join-Text 'The action failed: a command in the script was called with a parameter or value it does not accept: ' $fn_t)
    }
    if ($fn_m -match 'already exists|already linked') { Stop-With 'conflict' 'A GPO or a link with that name or target already exists.' }
    if ($fn_m -match 'cannot be found|was not found|does not exist|No GPO|not found') { Stop-With 'not_found' 'The domain has no such GPO or container.' }
    if ($fn_m -match 'denied|not authorized|authoriz|Access is denied|0x80070005') { Stop-With 'access_denied' 'The domain refused the change: this computer is not allowed to make it (ADR-0083 section 1).' }
    if ($fn_t -match 'UnauthorizedAccess') { Stop-With 'access_denied' 'The domain refused the change: this computer is not allowed to make it (ADR-0083 section 1).' }
    if ($fn_m -match 'ActiveDirectoryObjectNotFound|ActiveDirectoryOperationException|domain controller') { Stop-With 'directory_unavailable' 'The domain controller did not answer.' }
    Stop-With 'command_failed' (Join-Text 'The action failed: ' $fn_t)
}
function Get-Sum([int]$fn_A, [int]$fn_B) { return ($fn_A + $fn_B) }
function Get-XmlChild($fn_node, [string]$fn_Name) {
    foreach ($fn_k in $fn_node.ChildNodes) { if ($fn_k.LocalName -ceq $fn_Name) { return [string]$fn_k.InnerText } }
    return ''
}
# The GPMC COM object model (GPMgmt.GPM): the one route to WMI filters. The module has no cmdlet for them.
function Get-GpmDomain([hashtable]$fn_c) {
    $fn_gpm = New-Object -ComObject GPMgmt.GPM
    $fn_const = $fn_gpm.GetConstants()
    return @{ Gpm = $fn_gpm; Domain = $fn_gpm.GetDomain([string]$fn_c.Domain, [string]$fn_c.Server, $fn_const.UseAnyDC) }
}
function Get-WmiFilterList($fn_gd) {
    $fn_found = $fn_gd.Domain.SearchWmiFilters($fn_gd.Gpm.CreateSearchCriteria())
    $fn_out = @()
    foreach ($fn_f in $fn_found) { $fn_out += $fn_f }
    return $fn_out
}
# A SID's name and kind, for Set-GPPermission, which takes a name and a type. A well-known principal outside the directory
# (Authenticated Users) is a group.
function Resolve-Trustee([string]$fn_Sid, [hashtable]$fn_c) {
    $fn_acct = ''
    try {
        $fn_acct = (New-Object System.Security.Principal.SecurityIdentifier($fn_Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch { Stop-With 'not_found' 'That principal does not exist.' }
    $fn_short = $fn_acct.Substring($fn_acct.IndexOf('\') + 1)
    $fn_type = 'Group'
    if ($fn_Sid.StartsWith('S-1-5-21-')) {
        try {
            $fn_e = New-Object System.DirectoryServices.DirectoryEntry((Join-Text (Join-Text (Join-Text 'LDAP://' ([string]$fn_c.Server)) '/<SID=') (Join-Text $fn_Sid '>')))
            $fn_classes = @($fn_e.Properties['objectClass'] | ForEach-Object { [string]$_ })
            if ($fn_classes -contains 'computer') { $fn_type = 'Computer' } elseif ($fn_classes -contains 'group') { $fn_type = 'Group' } else { $fn_type = 'User' }
        } catch { Stop-With 'not_found' 'That principal does not exist in this domain.' }
    }
    return @{ Name = $fn_short; Type = $fn_type }
}
# After a security filtering change somebody must still be able to read the GPO as a computer or user: Read or Apply (the
# edit rights do not count), or the GPO stops applying (MS16-072). ADR-0083 section 7.
function Test-AppliesToSomeone($fn_perms, [string]$fn_ExceptSid, [bool]$fn_KeepRead) {
    foreach ($fn_e in @($fn_perms)) {
        if ((Get-Prop $fn_e 'Denied') -eq $true) { continue }
        $fn_level = [string]$fn_e.Permission
        if ($fn_e.Trustee.Sid.Value -eq $fn_ExceptSid) {
            if ($fn_KeepRead -and ($fn_level -eq 'GpoApply' -or $fn_level -eq 'GpoRead')) { return $true }
            continue
        }
        if ($fn_level -eq 'GpoApply' -or $fn_level -eq 'GpoRead') { return $true }
    }
    return $false
}

try {
    Import-GroupPolicyModule
    $c = Get-Context
    $common = $c.Common
    Assert-InDomain ([string]$p.target) $c
    $kind = Get-TargetKind ([string]$p.target) $c
    if ($kind -eq 'site') { Stop-With 'invalid_target' 'Inheritance is blocked on the domain or an organizational unit, not on a site.' }
    $cur = Get-GPInheritance -Target ([string]$p.target) @common
    $want = 'No'
    if ($p.blocked -eq $true) { $want = 'Yes' }
    $new = Set-GPInheritance -Target ([string]$p.target) -IsBlocked $want @common
    Write-Changed (Format-Text 'Changed whether {0} blocks inheritance.' ([string]$p.target) '') ([ordered]@{ blocked = [string]($cur.GpoInheritanceBlocked -eq $true) }) ([ordered]@{ blocked = [string]($new.GpoInheritanceBlocked -eq $true) }) $null $null $null $null
} catch {
    Stop-ForError $_
}
