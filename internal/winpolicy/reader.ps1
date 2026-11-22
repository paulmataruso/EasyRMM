# EasyRMM's reader of who owns a Windows setting (ADR-0054, "Policy
# ownership: one reader, built here"). This file defines functions and does
# nothing else. Windows hardening's script includes it; followed by
# query.ps1 it is a script of its own, which the agent is to carry and
# start for log collection, the registry editor and the event viewer
# (ADR-0060, ADR-0067, ADR-0068). Windows PowerShell 5.1, Full Language
# Mode, no Add-Type. The only module it imports is the computer's own copy
# of OSConfig's, by its full path under Program Files or System32, and only
# after checking that no one but SYSTEM, Administrators and TrustedInstaller
# can change it (Read-ErOSConfig). Accounts, subcategories and fields by
# SID, GUID and XML name, never by translated names.
#
# For each registry value, security setting and audit subcategory it gives
# exactly one of three results (Resolve-ErRegistryOwner and the others):
#   owner        who holds the value (group_policy, tamper_protection,
#                security_product), the policy's name, the owner's value
#   none         no owner holds it: only then may a feature change it
#   cannot_tell  an owner may hold it whose settings the reader cannot read
#                yet, with fixed reasons (internal/winpolicy's Reasons):
#     group_policy_record_off   Group Policy's record of what it applied
#                               (the resultant set of policy) is turned off
#                               or cannot be read
#     group_policy_preferences  Group Policy carries registry preference
#                               items, which can set any registry value
#     mdm                       enrolled in an MDM: every value no other
#                               owner holds (Group Policy wins over the MDM
#                               unless the MDM set MDMWinsOverGP, which does
#                               not cover attack surface reduction rules),
#                               since the reader of the Policy CSP's Config
#                               node is not proven on a real enrolled
#                               computer yet
#     defender_for_endpoint     onboarded to Defender for Endpoint, whose
#                               security settings management may apply
#                               Intune's Defender, attack surface reduction
#                               and firewall policies
#     configmgr                 a Configuration Manager client
#     dsc                       PowerShell DSC correcting drift
#     azure_machine_configuration
#     osconfig                  an OSConfig scenario is active, whose settings
#                               are named, not given as registry values; or
#                               OSConfig was used here and its module cannot
#                               be trusted or is gone
#     unexplained_policy        a value under HKLM\SOFTWARE\Policies that
#                               none of the readers explains
#     other_firewall            a server, where Security Center does not
#                               report firewalls, with another vendor's
#                               filtering platform provider filtering inbound
#                               traffic (firewall values only)
#     unreadable                a record the reader needs could not be read:
#                               the MDM enrolments or DSC's configuration
#                               (every value); the preferences' history, the
#                               local Group Policy object, whether local
#                               policy is processed, or the value asked about
#                               under Policies (registry values); the audit
#                               policy extension's history or copy, or
#                               whether subcategories override categories
#                               (audit subcategories); whether this is a
#                               workstation, Security Center or the
#                               filtering platform (antivirus or firewall
#                               values); Defender for Endpoint's onboarding
#                               (Defender values); Defender's status (values
#                               Tamper Protection guards); the notes say
#                               which. Where whether Group Policy's record is
#                               turned off cannot be read, the record is not
#                               read either (group_policy_record_off)
#
# Owners it reads, once per run (Get-ErPolicyContext):
# * Group Policy, from the domain or the local Group Policy object: the
#   resultant set of policy in WMI (root\rsop\computer): registry-based
#   policy (RSOP_RegistryPolicySetting, the winning policy, precedence 1,
#   values it deletes among them), the security settings
#   (RSOP_SecuritySetting*, RSOP_RegistryValue) and legacy audit categories
#   (RSOP_AuditPolicy); gpresult's XML for advanced audit policy, which
#   Group Policy applies through an extension of its own, for the policies'
#   names, and for registry preference items. Where gpresult names that
#   extension without its settings (seen on a domain member of Windows
#   Server 2025), the extension's own record: the policies in its history
#   and the merged copy it keeps in %SystemRoot%\security\audit\audit.csv.
#   The local Group Policy object's Registry.pol, read from the file
#   itself, whatever the resultant set of policy records of it.
# * MDM: enrolment under HKLM\SOFTWARE\Microsoft\Enrollments; the Policy
#   CSP's Config node through the MDM Bridge WMI provider
#   (root\cimv2\mdm\dmmap, MDM_Policy_Config01_<Area>02), the value in
#   effect from its Result node (MDM_Policy_Result01_<Area>02), and the
#   provider Windows records as winning under PolicyManager\current\device;
#   MDMWinsOverGP (Microsoft: it "doesn't apply for all settings, such as
#   attack surface reduction (ASR) rules", so for those Group Policy wins
#   whatever it says). Security settings and audit subcategories by the
#   Policy CSP's DeviceLock, LocalPoliciesSecurityOptions and Audit areas.
# * Defender for Endpoint's onboarding; a Configuration Manager client;
#   DSC's Local Configuration Manager; Azure's machine configuration by its
#   services; OSConfig's active scenarios; Tamper Protection; another
#   antivirus or firewall, from Security Center on workstations and, for
#   firewalls on servers, from the filtering platform's providers.

# What the reader read; one per run.
function Get-ErPolicyContext {
    param([string]$WorkFolder)
    $c = New-ErPolicyContext $WorkFolder

    # A workstation's other products are Security Center's, a server's
    # firewalls the filtering platform's.
    $type = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'InstallationType'
    $c.Client = $type.Exists -and "$($type.Data)" -eq 'Client'
    if ($type.Error) { Add-ErUnreadable $c @('antivirus', 'firewall') $type.Error }

    # Group Policy's record turned off: the policy "Turn off Resultant Set
    # of Policy logging".
    $off = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'RSoPLogging'
    if ($off.Exists -and "$($off.Data)" -eq '0') { $c.GpRecordOff = $true }

    # With the record off, WMI keeps the last record written before it was
    # turned off (seen on a domain member), which may name policies no
    # longer applied; so neither it nor gpresult, which reports from it, is
    # read, nor where whether it is off cannot be read. The extensions' own
    # history and the audit copy are kept.
    if ($off.Error) {
        $c.Notes.Add($off.Error)
    } elseif (-not $c.GpRecordOff) {
        Read-ErRsop $c
        Read-ErGpresult $c $WorkFolder
    }
    Read-ErLocalGpo $c
    Read-ErAuditCopy $c
    Read-ErPreferencesHistory $c

    # "Audit: Force audit policy subcategory settings to override audit
    # policy category settings", Enabled unless set to 0.
    $force = Get-ErRegistryValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    $c.SubcategoriesOverride = -not ($force.Exists -and "$($force.Data)" -eq '0')
    if ($force.Error) { Add-ErUnreadable $c @('audit') $force.Error }

    $m = Get-ErMdmProviders
    $c.Mdm = $m.Providers.Count -gt 0
    if ($m.Error) { Add-ErUnreadable $c @('all') $m.Error }
    # Where MDMWinsOverGP cannot be read, the MDM may win (Test-ErMdmWins).
    $wins = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict' 'MDMWinsOverGP'
    if ($wins.Exists -and "$($wins.Data)" -eq '1') { $c.MdmWinsOverGp = $true }
    if ($wins.Error) { Add-ErUnreadable $c @('mdmWins') $wins.Error }

    $atp = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState'
    if ($atp.Exists -and "$($atp.Data)" -eq '1') { $c.DefenderForEndpoint = $true }
    if ($atp.Error) { Add-ErUnreadable $c @('defender') $atp.Error }

    $ccm = Get-ErService 'CcmExec'
    if ($ccm.Service) { $c.ConfigMgr = $true }
    if ($ccm.Error) { Add-ErUnreadable $c @('all') "Whether Configuration Manager's client is installed could not be read: $($ccm.Error)" }

    # DSC corrects drift only in ApplyAndAutoCorrect, and only with a
    # configuration to apply.
    $dscFolder = Join-Path $env:SystemRoot 'System32\Configuration'
    $meta = Join-Path $dscFolder 'MetaConfig.mof'
    if ((Test-Path -LiteralPath $meta) -and (Test-Path -LiteralPath (Join-Path $dscFolder 'Current.mof'))) {
        try {
            $text = Get-Content -LiteralPath $meta -Raw -ErrorAction Stop
            if ($text -match 'ConfigurationMode\s*=\s*"ApplyAndAutoCorrect"') { $c.Dsc = $true }
        } catch {
            Add-ErUnreadable $c @('all') "DSC's configuration $meta could not be read: $($_.Exception.Message)"
        }
    }

    # Azure machine configuration, by its services, which only an
    # administrator can register: the Arc agent's on an Azure Arc server,
    # the guest configuration extension's on an Azure virtual machine.
    foreach ($name in 'GCArcService', 'GCService') {
        $gc = Get-ErService $name
        if ($gc.Service) { $c.AzureMachineConfiguration = $true }
        if ($gc.Error) { Add-ErUnreadable $c @('all') "Whether Azure machine configuration's service $name is installed could not be read: $($gc.Error)" }
    }

    Read-ErOSConfig $c

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.IsTamperProtected) { $c.TamperProtected = $true }
    } catch {
        Add-ErUnreadable $c @('tamper') "Microsoft Defender did not report its status, so whether Tamper Protection is on is not known: $($_.Exception.Message)"
    }
    if ($c.Client) { Read-ErSecurityProducts $c }
    return $c
}

# Add-ErUnreadable: a record the reader could not read, for the values it
# concerns (Get-ErReasons: all, registry, security, audit, antivirus,
# firewall, defender, tamper; mdmWins, Test-ErMdmWins), and why.
function Add-ErUnreadable {
    param($Context, [string[]]$Kinds, [string]$Note)
    foreach ($k in $Kinds) { $Context.Unreadable[$k] = $true }
    $Context.Notes.Add($Note)
}

# New-ErPolicyContext: a context in which nothing has been read yet.
function New-ErPolicyContext {
    param([string]$WorkFolder)
    return @{
        Notes                     = New-Object 'System.Collections.Generic.List[string]'
        WorkFolder                = $WorkFolder
        Client                    = $false
        Gpos                      = @{}
        GpRegistry                = @{}
        GpDeletedKeys             = @{}
        GpSecurity                = @{}
        GpSecurityRegistry        = @{}
        GpAudit                   = @{}
        GpLegacyAudit             = @{}
        GpRecordOff               = $false
        GpRecordRead              = $false
        GpPreferences             = $false
        SubcategoriesOverride     = $true
        Mdm                       = $false
        MdmWinsOverGp             = $false
        MdmCache                  = @{}
        DefenderForEndpoint       = $false
        ConfigMgr                 = $false
        Dsc                       = $false
        AzureMachineConfiguration = $false
        OSConfig                  = $false
        OSConfigScenarios         = @()
        TamperProtected           = $false
        Products                  = @{ antivirus = @(); firewall = @() }
        Wfp                       = $null
        Unreadable                = @{}
    }
}

# Get-ErMdmProviders: the MDMs the computer is enrolled in, and an error
# where the enrolments could not be read. Windows keeps enrolments of its
# own under the same key on every computer (providers "Local Authority",
# "Deploy Authority", "Cloud Authority", "WMI_Bridge_SCCM_Server", and some
# without a provider, seen on Windows Server 2025); an MDM's enrolment is
# enrolled (EnrollmentState 1) and records the discovery service it was
# found through. Intune's provider is "MS DM Server". Uses cmdlets only, so
# that it runs in Constrained Language Mode too.
function Get-ErMdmProviders {
    $out = @{ Providers = @(); Error = '' }
    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    # Test-Path is true for a key that exists and cannot be read.
    if (-not (Test-Path -LiteralPath $root)) { return $out }
    $failed = $null
    $keys = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue -ErrorVariable failed)
    if ($failed) {
        $out.Error = "The MDM enrolments could not be read: $($failed[0].Exception.Message)"
        return $out
    }
    foreach ($e in $keys) {
        $failed = $null
        $p = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction SilentlyContinue -ErrorVariable failed
        if ($failed) {
            $out.Error = "The MDM enrolment $($e.PSChildName) could not be read: $($failed[0].Exception.Message)"
            continue
        }
        if ($p -and $p.ProviderID -and "$($p.EnrollmentState)" -eq '1' -and $p.DiscoveryServiceFullURL) {
            $out.Providers += [string]$p.ProviderID
        }
    }
    return $out
}

# Read-ErRsop: the resultant set of policy Group Policy recorded in WMI.
function Read-ErRsop {
    param($c)
    try {
        foreach ($g in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_GPO -ErrorAction Stop -OperationTimeoutSec 60)) {
            $c.Gpos[[string]$g.id] = [string]$g.name
        }
        foreach ($s in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_RegistryPolicySetting -Filter 'precedence = 1' -ErrorAction Stop -OperationTimeoutSec 60)) {
            Add-ErGpRegistry $c ([string]$s.registryKey) ([string]$s.valueName) $s.valueType $s.value ([bool]$s.deleted) (Get-ErGpoName $c $s.GPOID) $false
        }
        foreach ($class in 'RSOP_SecuritySettingNumeric', 'RSOP_SecuritySettingBoolean', 'RSOP_SecuritySettingString') {
            foreach ($s in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName $class -Filter 'precedence = 1' -ErrorAction Stop -OperationTimeoutSec 60)) {
                $v = $s.Setting
                if ($v -is [bool]) { $v = [int]$v }
                $c.GpSecurity[([string]$s.KeyName).ToLowerInvariant()] = @{ Value = "$v"; Policy = Get-ErGpoName $c $s.GPOID }
            }
        }
        foreach ($s in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_RegistryValue -Filter 'precedence = 1' -ErrorAction Stop -OperationTimeoutSec 60)) {
            # Path is MACHINE\<key>\<value name>, as a security template has it.
            $p = [string]$s.Path
            $i = $p.LastIndexOf('\')
            if (-not $p.StartsWith('MACHINE\', 'OrdinalIgnoreCase') -or $i -lt 8) { continue }
            $c.GpSecurityRegistry[(Get-ErRegistryKey ('HKLM\' + $p.Substring(8, $i - 8)) $p.Substring($i + 1))] = @{
                Value = [string]$s.Data; Policy = Get-ErGpoName $c $s.GPOID
            }
        }
        foreach ($s in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_AuditPolicy -Filter 'precedence = 1' -ErrorAction Stop -OperationTimeoutSec 60)) {
            $c.GpLegacyAudit[[string]$s.Category] = @{ Success = [bool]$s.Success; Failure = [bool]$s.Failure; Policy = Get-ErGpoName $c $s.GPOID }
        }
        $c.GpRecordRead = $true
    } catch {
        $c.Notes.Add("The resultant set of policy could not be read: $($_.Exception.Message)")
    }
}

# Add-ErGpRegistry: one registry policy entry, from the resultant set of
# policy or a Registry.pol, in the reader's tables. Group Policy's special
# value names delete values (**del.<name>, **DeleteValues with the names as
# data, or a deleted entry), a key's values (**delvals.) or keys
# (**DeleteKeys); **soft.<name> sets a value only where it is absent. A
# value Group Policy deletes is owned by it with the value "deleted". With
# Keep, what is there already stays (the local Group Policy object loses to
# every other).
function Add-ErGpRegistry {
    param($Context, [string]$Key, [string]$Name, $Type, [byte[]]$Data, [bool]$Deleted, [string]$Policy, [bool]$Keep)
    $k = ($Key -replace '^(HKLM|HKEY_LOCAL_MACHINE|MACHINE)(:)?\\', '').TrimEnd('\')
    if (-not $k) { return }
    $values = @()
    $keys = @()
    $lower = $Name.ToLowerInvariant()
    if ($lower.StartsWith('**del.')) {
        $values += , @($Name.Substring(6), 'deleted')
    } elseif ($lower.StartsWith('**delvals')) {
        $keys += , @($k, $false)
    } elseif ($lower -eq '**deletevalues') {
        foreach ($n in ((ConvertFrom-ErRegistryBytes 1 $Data) -split ';')) { $values += , @($n.Trim(), 'deleted') }
    } elseif ($lower -eq '**deletekeys') {
        foreach ($n in ((ConvertFrom-ErRegistryBytes 1 $Data) -split ';')) { $keys += , @($n.Trim(), $true) }
    } elseif ($lower.StartsWith('**soft.')) {
        $values += , @($Name.Substring(7), (ConvertFrom-ErRegistryBytes $Type $Data))
    } elseif ($lower.StartsWith('**') -or $Name -eq '') {
        # **SecureKey and the like set no value; an empty name makes the key.
        return
    } elseif ($Deleted) {
        $values += , @($Name, 'deleted')
    } else {
        $values += , @($Name, (ConvertFrom-ErRegistryBytes $Type $Data))
    }
    foreach ($v in $values) {
        if (-not $v[0]) { continue }
        $id = Get-ErRegistryKey $k $v[0]
        if ($Keep -and $Context.GpRegistry.ContainsKey($id)) { continue }
        $Context.GpRegistry[$id] = @{ Value = [string]$v[1]; Policy = $Policy }
    }
    foreach ($d in $keys) {
        $id = ([string]$d[0] -replace '^(HKLM|HKEY_LOCAL_MACHINE|MACHINE)(:)?\\', '').TrimEnd('\').ToLowerInvariant()
        if (-not $id -or ($Keep -and $Context.GpDeletedKeys.ContainsKey($id))) { continue }
        $Context.GpDeletedKeys[$id] = @{ Policy = $Policy; Subkeys = [bool]$d[1] }
    }
}

# Find-ErGpRegistry: the registry policy that sets or deletes a value, or
# $null.
function Find-ErGpRegistry {
    param($Context, [string]$Path, [string]$Name)
    $id = Get-ErRegistryKey $Path $Name
    foreach ($table in $Context.GpRegistry, $Context.GpSecurityRegistry) {
        if ($table.ContainsKey($id)) { return $table[$id] }
    }
    $k = ($Path -replace '^(HKLM|HKEY_LOCAL_MACHINE|MACHINE)(:)?\\', '').TrimEnd('\').ToLowerInvariant()
    foreach ($d in $Context.GpDeletedKeys.Keys) {
        $e = $Context.GpDeletedKeys[$d]
        if ($k -eq $d -or ($e.Subkeys -and $k.StartsWith($d + '\'))) { return @{ Value = 'deleted'; Policy = $e.Policy } }
    }
    return $null
}

# Read-ErLocalGpo: the local Group Policy object's registry policy, from its
# Registry.pol. Whether Windows records the local object in the resultant
# set of policy on a computer in a workgroup was not settled in W1, so the
# file itself is read, which holds either way; unless domain policy turns
# local policy processing off. A file that is not there is no policy; one
# that cannot be read, or whether local policy is processed, makes registry
# values unreadable.
function Read-ErLocalGpo {
    param($Context)
    $off = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'DisableLGPOProcessing'
    if ($off.Error) {
        Add-ErUnreadable $Context @('registry') $off.Error
        return
    }
    if ($off.Exists -and "$($off.Data)" -eq '1') { return }
    $file = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Registry.pol'
    try {
        $entries = ConvertFrom-ErRegistryPol ([IO.File]::ReadAllBytes($file))
    } catch {
        $e = $_.Exception
        if ($e.InnerException) { $e = $e.InnerException }
        if ($e -is [IO.FileNotFoundException] -or $e -is [IO.DirectoryNotFoundException]) { return }
        Add-ErUnreadable $Context @('registry') "The local Group Policy object's Registry.pol could not be read: $($e.Message)"
        return
    }
    foreach ($e in $entries) {
        Add-ErGpRegistry $Context $e.Key $e.Name $e.Type $e.Data $false 'Local Group Policy' $true
    }
}

# ConvertFrom-ErRegistryPol: a Registry.pol file's entries (MS-GPREG 2.2.1):
# the header PReg and version 1, then [key;value;type;size;data], the
# strings and separators in UTF-16LE, the strings ending in a null. Throws
# where the file is not in that form.
function ConvertFrom-ErRegistryPol {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'PReg' -or [BitConverter]::ToUInt32($Bytes, 4) -ne 1) {
        throw 'it is not a Registry.pol file (PReg, version 1)'
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    $n = $Bytes.Length
    $i = 8
    while ($i -lt $n) {
        $fields = @()
        $want = [char]'['
        foreach ($part in 'key', 'name') {
            if ($i + 2 -gt $n -or [BitConverter]::ToChar($Bytes, $i) -ne $want) { throw "no '$want' at byte $i" }
            $i += 2
            $end = $i
            while ($end + 1 -lt $n -and ($Bytes[$end] -ne 0 -or $Bytes[$end + 1] -ne 0)) { $end += 2 }
            if ($end + 1 -ge $n) { throw "the $part at byte $i does not end" }
            $fields += [Text.Encoding]::Unicode.GetString($Bytes, $i, $end - $i)
            $i = $end + 2
            $want = [char]';'
        }
        $numbers = @()
        foreach ($part in 'type', 'size') {
            if ($i + 6 -gt $n -or [BitConverter]::ToChar($Bytes, $i) -ne ';') { throw "no ';' before the $part at byte $i" }
            $numbers += [BitConverter]::ToUInt32($Bytes, $i + 2)
            $i += 6
        }
        if ($i + 2 -gt $n -or [BitConverter]::ToChar($Bytes, $i) -ne ';') { throw "no ';' before the data at byte $i" }
        $i += 2
        $size = [int]$numbers[1]
        if ($i + $size + 2 -gt $n) { throw "the data at byte $i is longer than the file" }
        $data = New-Object byte[] $size
        [Array]::Copy($Bytes, $i, $data, 0, $size)
        $i += $size
        if ([BitConverter]::ToChar($Bytes, $i) -ne ']') { throw "no ']' at byte $i" }
        $i += 2
        $out.Add(@{ Key = $fields[0]; Name = $fields[1]; Type = $numbers[0]; Data = $data })
    }
    return , $out
}

# Group Policy's own report: advanced audit policy (applied by an
# extension of its own, not as registry policy), the policies' names, and
# whether registry preference items are among what it applied.
function Read-ErGpresult {
    param($Context, [string]$WorkFolder)
    if (-not $WorkFolder) { return }
    $file = Join-Path $WorkFolder 'gpresult.xml'
    $exe = Join-Path $env:SystemRoot 'System32\gpresult.exe'
    $run = Invoke-ErProgram $exe @('/scope', 'computer', '/x', $file, '/f') 120
    # It may end with exit code 0 and write no report (seen on GitHub's
    # Windows 11 runner); what it printed is kept in the note.
    $said = Limit-ErText ("$($run.Output) $($run.Error)") 160
    if ($run.ExitCode -ne 0) {
        $Context.Notes.Add("gpresult failed with exit code $($run.ExitCode): $said")
        return
    }
    if (-not (Test-Path -LiteralPath $file)) {
        $Context.Notes.Add("gpresult ended with exit code 0 and wrote no report: $said")
        return
    }
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($file)
    } catch {
        $Context.Notes.Add('gpresult''s report could not be read.')
        return
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
    $names = @{}
    foreach ($g in @($xml.SelectNodes("//*[local-name()='ComputerResults']/*[local-name()='GPO']"))) {
        $id = $g.SelectSingleNode("*[local-name()='Path']/*[local-name()='Identifier']")
        $n = $g.SelectSingleNode("*[local-name()='Name']")
        if ($id -and $n) { $names[$id.InnerText.ToLowerInvariant()] = $n.InnerText }
    }
    foreach ($a in @($xml.SelectNodes("//*[local-name()='AuditSetting']"))) {
        $guid = $a.SelectSingleNode("*[local-name()='SubcategoryGuid']")
        $value = $a.SelectSingleNode("*[local-name()='SettingValue']")
        $prec = $a.SelectSingleNode("*[local-name()='Precedence']")
        if (-not $guid -or -not $value -or ($prec -and $prec.InnerText -ne '1')) { continue }
        $id = $a.SelectSingleNode("*[local-name()='GPO']/*[local-name()='Identifier']")
        $policy = ''
        if ($id) {
            $policy = $names[$id.InnerText.ToLowerInvariant()]
            if (-not $policy) { $policy = $id.InnerText }
        }
        # gpresult writes the GUID in braces; the table and callers do not.
        $Context.GpAudit[$guid.InnerText.Trim('{', '}').ToLowerInvariant()] = @{ Value = [int]$value.InnerText; Policy = $policy }
    }
    if ($xml.SelectSingleNode("//*[local-name()='ComputerResults']//*[local-name()='RegistrySettings']")) {
        $Context.GpPreferences = $true
    }
}

# Read-ErAuditCopy: advanced audit policy from the Audit Policy
# Configuration extension's own record, for the subcategories gpresult did
# not report. Its history lists the policies it applied; with none there,
# the merged copy is not Group Policy's. The copy does not say which
# policy set which subcategory, so the policy is every one in the history.
# A history that cannot be read, or one that lists policies while the copy
# is missing, cannot be read or is not in auditpol's form (its header, and
# a GUID with a setting of 0 to 3 on each subcategory's row; the rows of
# options and global SACLs have no GUID), makes audit subcategories
# unreadable.
function Read-ErAuditCopy {
    param($Context)
    $history = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'
    $names = @()
    $k = $null
    try {
        $k = Open-ErRegistryKey $history
        if ($null -eq $k) { return }
        foreach ($s in @($k.GetSubKeyNames())) {
            # Listed, so a $null is a read that failed (Open-ErRegistryKey).
            $sub = $k.OpenSubKey($s, $false)
            if ($null -eq $sub) { throw "HKLM\$history\$s is listed but could not be opened." }
            try { $n = [string]$sub.GetValue('DisplayName') } finally { $sub.Close() }
            if ($n -and $names -notcontains $n) { $names += $n }
        }
    } catch {
        Add-ErUnreadable $Context @('audit') "The audit policy extension's history could not be read: $($_.Exception.Message)"
        return
    } finally {
        if ($k) { $k.Close() }
    }
    if ($names.Count -eq 0) { return }
    $policy = ($names | Sort-Object) -join ', '
    $file = Join-Path $env:SystemRoot 'security\audit\audit.csv'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Add-ErUnreadable $Context @('audit') "The audit policy extension's history lists $policy, but its copy $file is missing."
        return
    }
    try {
        $header = [string](Get-Content -LiteralPath $file -TotalCount 1 -ErrorAction Stop)
        $rows = @(Import-Csv -LiteralPath $file -ErrorAction Stop)
    } catch {
        Add-ErUnreadable $Context @('audit') "The audit policy extension's copy could not be read: $($_.Exception.Message)"
        return
    }
    if ($header -notmatch '(^|,)"?Subcategory GUID"?(,|$)' -or $header -notmatch '(^|,)"?Setting Value"?(,|$)') {
        Add-ErUnreadable $Context @('audit') "The audit policy extension's copy $file is not in auditpol's form (no Subcategory GUID and Setting Value columns)."
        return
    }
    $found = @{}
    foreach ($r in $rows) {
        $guid = ([string]$r.'Subcategory GUID').Trim().Trim('{', '}').ToLowerInvariant()
        if (-not $guid) { continue }
        $value = ([string]$r.'Setting Value').Trim()
        if ($guid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $value -notmatch '^[0-3]$') {
            Add-ErUnreadable $Context @('audit') ("The audit policy extension's copy $file has a row it cannot read: " + (Limit-ErText "$guid $value" 80) + '.')
            return
        }
        if (-not $found.ContainsKey($guid)) { $found[$guid] = [int]$value }
    }
    foreach ($guid in $found.Keys) {
        if (-not $Context.GpAudit.ContainsKey($guid)) {
            $Context.GpAudit[$guid] = @{ Value = $found[$guid]; Policy = $policy }
        }
    }
}

# Read-ErPreferencesHistory: Group Policy Preferences' registry extension
# keeps a history of the policies that carried registry items.
function Read-ErPreferencesHistory {
    param($Context)
    $history = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{B087BE9D-ED37-454f-AF9C-04291E351182}'
    if (-not (Test-Path -LiteralPath $history)) { return }
    $failed = $null
    $entries = @(Get-ChildItem -LiteralPath $history -ErrorAction SilentlyContinue -ErrorVariable failed)
    if ($failed) {
        Add-ErUnreadable $Context @('registry') "The history of Group Policy's registry preference items could not be read: $($failed[0].Exception.Message)"
    } elseif ($entries.Count -gt 0) {
        $Context.GpPreferences = $true
    }
}

# Read-ErSecurityProducts: antivirus and firewall products other than
# Microsoft's that Security Center reports on (workstations only; Microsoft
# says it is not supported on servers).
function Read-ErSecurityProducts {
    param($Context)
    foreach ($kind in @(@('AntiVirusProduct', 'antivirus'), @('FirewallProduct', 'firewall'))) {
        $names = @()
        try {
            foreach ($p in @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName $kind[0] -ErrorAction Stop -OperationTimeoutSec 30)) {
                $on = (([int64]$p.productState -shr 12) -band 0xF) -eq 1
                $ms = ([string]$p.pathToSignedProductExe) -match '(?i)windows defender|windowsdefender:|%ProgramFiles%\\Windows Defender'
                $name = Limit-ErText ([string]$p.displayName) 80
                if ($on -and -not $ms -and $name -and $names -notcontains $name) { $names += $name }
            }
        } catch {
            Add-ErUnreadable $Context @($kind[1]) "Windows Security Center did not list $($kind[1]) products: $($_.Exception.Message)"
        }
        $Context.Products[$kind[1]] = $names
    }
}

# Read-ErFilteringPlatform: on a server, another vendor's providers in the
# Windows Filtering Platform that filter inbound traffic, from the state
# netsh writes. Windows' own providers have built-in keys, Windows' services
# or Microsoft's name; filters at the inbound layers (connections accepted,
# ports listened on, inbound packets) are what a firewall adds. Read once,
# when a firewall value is first asked about.
function Read-ErFilteringPlatform {
    param($Context)
    $Context.Wfp = @{ Providers = @() }
    if (-not $Context.WorkFolder) {
        Add-ErUnreadable $Context @('firewall') 'The filtering platform''s state was not read: the reader has no work folder.'
        return
    }
    $file = Join-Path $Context.WorkFolder 'wfpstate.xml'
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\netsh.exe') @('wfp', 'show', 'state', "file=$file") 120
    try {
        if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw ("netsh ended with exit code $($run.ExitCode) and wrote no state: " + (Limit-ErText "$($run.Output) $($run.Error)" 160))
        }
        $xml = ConvertFrom-ErWfpState ([IO.File]::ReadAllText($file))
    } catch {
        Add-ErUnreadable $Context @('firewall') "The filtering platform's state could not be read: $($_.Exception.Message)"
        return
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
    $Context.Wfp.Providers = Get-ErOtherFirewalls $xml
    if ($Context.Wfp.Providers.Count -gt 0) {
        $Context.Notes.Add('Another vendor''s filtering platform providers filter inbound traffic: ' + ($Context.Wfp.Providers -join ', ') + '.')
    }
}

# ConvertFrom-ErWfpState: netsh's state as XML. netsh writes more after the
# document's end (seen on Windows Server 2022 and 2025), so only the
# document is read; no DTD, nothing fetched.
function ConvertFrom-ErWfpState {
    param([string]$Text)
    $end = $Text.IndexOf('</wfpstate>')
    if ($end -lt 0) { throw 'netsh wrote no wfpstate document' }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($Text.Substring(0, $end + '</wfpstate>'.Length))), $settings)
    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
    } finally {
        $reader.Close()
    }
    return $xml
}

# Get-ErOtherFirewalls: the names of other vendors' providers with filters
# at the inbound layers.
function Get-ErOtherFirewalls {
    param([System.Xml.XmlDocument]$Xml)
    $own = @('mpssvc', 'bfe', 'ikeext', 'policyagent', 'ndu')
    $providers = @{}
    foreach ($p in @($Xml.SelectNodes("/*[local-name()='wfpstate']/*[local-name()='providers']/*[local-name()='item']"))) {
        $key = Get-ErXmlText $p 'providerKey'
        $name = Get-ErXmlText $p 'displayData/name'
        $description = Get-ErXmlText $p 'displayData/description'
        $service = Get-ErXmlText $p 'serviceName'
        $windows = $key -like 'FWPM_PROVIDER_*' -or $own -contains $service.ToLowerInvariant() -or
            $name -eq 'Microsoft Corporation' -or $description -like 'Microsoft Windows*'
        if (-not $windows) { $providers[$key.ToLowerInvariant()] = $(if ($name) { $name } else { $key }) }
    }
    $inbound = '^FWPM_LAYER_(ALE_AUTH_RECV_ACCEPT|ALE_AUTH_LISTEN|INBOUND_TRANSPORT|INBOUND_IPPACKET)_V[46]$'
    $found = @()
    foreach ($f in @($Xml.SelectNodes("/*[local-name()='wfpstate']/*[local-name()='layers']/*[local-name()='item']/*[local-name()='filters']/*[local-name()='item']"))) {
        $key = (Get-ErXmlText $f 'providerKey').ToLowerInvariant()
        if (-not $key -or -not $providers.ContainsKey($key) -or (Get-ErXmlText $f 'layerKey') -notmatch $inbound) { continue }
        $name = Limit-ErText $providers[$key] 80
        if ($name -and $found -notcontains $name) { $found += $name }
    }
    return , @($found | Sort-Object)
}

function Get-ErXmlText {
    param($Node, [string]$Path)
    $xpath = (($Path -split '/') | ForEach-Object { "*[local-name()='$_']" }) -join '/'
    $n = $Node.SelectSingleNode($xpath)
    if ($n) { return [string]$n.InnerText }
    return ''
}

# Read-ErOSConfig (Windows Server 2025). A baseline can only have been
# applied through OSConfig where its module was installed, so the reader
# asks the computer's own copy, which EasyRMM never installs, for its active
# scenarios. It imports that copy only by its full path, from Program Files'
# or System32's module folder, and only when no one but SYSTEM,
# Administrators and TrustedInstaller can change it or the folders above it
# (Test-ErTrustedTree); with commands found in System32's modules alone
# while it runs. A copy found elsewhere, one that fails the check or whose
# folder cannot be listed, or OSConfig's own registry record of a scenario
# without its module, makes every value cannot_tell (osconfig): a baseline
# may be applied that the reader cannot see; a record that cannot be read,
# cannot_tell (unreadable). OSConfig names its settings
# (AfdDisableAddressSharing) and gives no registry value for them, so an
# active scenario does too. Its read-only scenario (SecuredCoreState) sets
# nothing.
function Read-ErOSConfig {
    param($Context)
    $roots = @((Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'), (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'))
    $module = $null
    foreach ($r in $roots) {
        $base = Join-Path $r 'Microsoft.OSConfig'
        if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
        $failed = $null
        $versions = @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable failed |
            Where-Object { $_.Name -match '^\d+(\.\d+){1,3}$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'Microsoft.OSConfig.psd1') -PathType Leaf) } |
            Sort-Object { [version]$_.Name } -Descending)
        if ($failed) {
            $Context.OSConfig = $true
            $Context.Notes.Add("OSConfig's module folder $base could not be listed: $($failed[0].Exception.Message). Whether a baseline is active is not known.")
            return
        }
        if ($versions.Count -gt 0) {
            $module = @{ Root = $r; Folder = $versions[0].FullName }
        } elseif (Test-Path -LiteralPath (Join-Path $base 'Microsoft.OSConfig.psd1') -PathType Leaf) {
            $module = @{ Root = $r; Folder = $base }
        }
        if ($module) { break }
    }
    if (-not $module) {
        $elsewhere = @()
        foreach ($d in @("$env:PSModulePath" -split ';')) {
            if (-not $d.Trim()) { continue }
            try { $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($d.Trim())).TrimEnd('\') } catch { continue }
            if (@($roots | Where-Object { $_.TrimEnd('\') -eq $full }).Count -gt 0) { continue }
            if (Test-Path -LiteralPath (Join-Path $full 'Microsoft.OSConfig')) { $elsewhere += $full }
        }
        $metadata = 'HKLM:\SOFTWARE\Microsoft\OSConfig\Metadata'
        $recorded = @()
        $failed = $null
        # Test-Path is true for a key that exists and cannot be read.
        if (Test-Path -LiteralPath $metadata) { $recorded = @(Get-ChildItem -LiteralPath $metadata -ErrorAction SilentlyContinue -ErrorVariable failed) }
        if ($elsewhere.Count -gt 0) {
            $Context.OSConfig = $true
            $Context.Notes.Add("OSConfig's module is installed only outside Program Files and System32 (" + ($elsewhere -join ', ') + '), where the reader does not import it: whether a baseline is active is not known.')
        } elseif ($failed) {
            Add-ErUnreadable $Context @('all') "OSConfig's record of its scenarios could not be read: $($failed[0].Exception.Message)"
        } elseif ($recorded.Count -gt 0) {
            $Context.OSConfig = $true
            $Context.Notes.Add('OSConfig recorded scenarios here and its module is not installed: whether a baseline is active is not known.')
        }
        return
    }
    try {
        $why = Test-ErTrustedTree $module.Root $module.Folder
    } catch {
        $why = "it could not be checked: $($_.Exception.Message)"
    }
    if ($why) {
        $Context.OSConfig = $true
        $Context.Notes.Add("OSConfig's module in $($module.Folder) is not imported, since $why. Whether a baseline is active is not known.")
        return
    }
    $saved = $env:PSModulePath
    try {
        $env:PSModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
        Import-Module -Name (Join-Path $module.Folder 'Microsoft.OSConfig.psd1') -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null
        $Context.OSConfigScenarios = @(Get-OSConfigMetadata -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null |
            Where-Object { [string]$_.Status -eq 'Active' -and [string]$_.Name -ne 'SecuredCoreState' } |
            ForEach-Object { Limit-ErText ([string]$_.Name) 128 } | Select-Object -First 20)
        $Context.OSConfig = $Context.OSConfigScenarios.Count -gt 0
    } catch {
        $Context.OSConfig = $true
        $Context.Notes.Add("OSConfig's module did not list its scenarios: $($_.Exception.Message)")
    } finally {
        $env:PSModulePath = $saved
    }
}

# Test-ErTrustedTree: '' when no one but SYSTEM, Administrators and
# TrustedInstaller can change Folder, the folders from Root down to it, and
# everything in it; otherwise what fails. Root is a folder Windows makes
# (Program Files' or System32's modules), so the folders above it are not
# checked. Nothing is followed: a junction, link or other reparse point
# fails.
function Test-ErTrustedTree {
    param([string]$Root, [string]$Folder)
    $chain = @()
    $p = $Folder.TrimEnd('\')
    while ($p -ne $Root.TrimEnd('\')) {
        $chain = @($p) + $chain
        $parent = Split-Path -Parent $p
        if (-not $parent -or $parent -eq $p) { return "$Folder is not under $Root" }
        $p = $parent
    }
    $chain = @($p) + $chain
    foreach ($c in $chain) {
        $why = Test-ErTrustedItem (Get-Item -LiteralPath $c -Force -ErrorAction Stop)
        if ($why) { return $why }
    }
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($Folder)
    while ($pending.Count -gt 0) {
        foreach ($i in @(Get-ChildItem -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop)) {
            $why = Test-ErTrustedItem $i
            if ($why) { return $why }
            if ($i -is [IO.DirectoryInfo]) { $pending.Enqueue($i.FullName) }
        }
    }
    return ''
}

# Test-ErTrustedItem: '' for a plain folder or file with a trusted owner
# that no one else may write; otherwise what fails.
function Test-ErTrustedItem {
    param($Item)
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "$($Item.FullName) is a junction, link or other reparse point" }
    $sddl = $Item.GetAccessControl('Owner, Access').GetSecurityDescriptorSddlForm('Owner, Access')
    $owner = Get-ErOwnerSid $sddl
    if ((Get-ErTrustedSids) -notcontains $owner) { return "$($Item.FullName) is owned by $owner" }
    $writers = Get-ErWriters $sddl ($Item -is [IO.DirectoryInfo])
    if ($writers.Count -gt 0) { return "$($Item.FullName) may be written by " + ($writers -join ', ') }
    return ''
}

# The accounts trusted with what the reader imports and hardening keeps:
# SYSTEM, Administrators and TrustedInstaller.
function Get-ErTrustedSids {
    return @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
}

# Get-ErWriters: who besides the trusted accounts may write, from an access
# list in SDDL, so that callback and object entries count too. Deny entries
# are ignored (they only take rights away); inherit-only entries count on
# folders, where new files inherit them. CREATOR OWNER's entries are not
# counted: they give the account that makes a file rights on it, and that
# file is judged by its own access list. Returns the SIDs that may write, or
# 'unreadable'.
function Get-ErWriters {
    param([string]$Sddl, [bool]$Folder)
    # WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete,
    # WriteDAC, WriteOwner, GenericAll, GenericWrite.
    $rights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $trusted = Get-ErTrustedSids
    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    } catch {
        return , @('unreadable')
    }
    $out = @()
    if ($null -eq $sd.DiscretionaryAcl) { return , @('everyone (no access list)') }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $type = [string]$ace.AceType
        if ($type -like 'AccessDenied*' -or $type -like 'System*') { continue }
        if ($type -notlike 'AccessAllowed*') { $out += "an entry of type $type"; continue }
        # AceFlags is a byte enum, which Windows PowerShell's -band cannot
        # take as it is.
        if (-not $Folder -and ([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly)) { continue }
        $sid = [string]$ace.SecurityIdentifier
        if ($trusted -contains $sid -or $sid -eq 'S-1-3-0') { continue }
        if (([int64]$ace.AccessMask -band $rights) -ne 0) { $out += $sid }
    }
    return , $out
}

function Get-ErOwnerSid {
    param([string]$Sddl)
    try {
        return [string](New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)).Owner
    } catch {
        return ''
    }
}

# Reasons that hold for every value on the computer.
function Get-ErComputerReasons {
    param($Context)
    $r = @()
    if ($Context.GpRecordOff -or -not $Context.GpRecordRead) { $r += 'group_policy_record_off' }
    if ($Context.Mdm) { $r += 'mdm' }
    if ($Context.ConfigMgr) { $r += 'configmgr' }
    if ($Context.Dsc) { $r += 'dsc' }
    if ($Context.AzureMachineConfiguration) { $r += 'azure_machine_configuration' }
    if ($Context.OSConfig) { $r += 'osconfig' }
    if ($Context.Unreadable.all) { $r += 'unreadable' }
    return , $r
}

# Get-ErReasons: why the reader cannot tell who owns one value.
#   Kind      registry, security or audit
#   Defender  a Defender, attack surface reduction or firewall value
#   Product   antivirus or firewall: a value another such product would own
#   Tamper    a value Tamper Protection guards
function Get-ErReasons {
    param($Context, [string]$Kind, [switch]$Defender, [string]$Product = '', [switch]$Tamper)
    $all = Get-ErComputerReasons $Context
    $r = @($all | Where-Object { $_ -ne 'unreadable' })
    if ($Kind -eq 'registry' -and $Context.GpPreferences) { $r += 'group_policy_preferences' }
    if ($Defender -and $Context.DefenderForEndpoint) { $r += 'defender_for_endpoint' }
    if ($Product -eq 'firewall' -and -not $Context.Client) {
        if ($null -eq $Context.Wfp) { Read-ErFilteringPlatform $Context }
        if ($Context.Wfp.Providers.Count -gt 0) { $r += 'other_firewall' }
    }
    $u = $Context.Unreadable
    if ($u.all -or $u[$Kind] -or ($Product -and $u[$Product]) -or ($Defender -and $u.defender) -or ($Tamper -and $u.tamper)) { $r += 'unreadable' }
    return , $r
}

# Test-ErMdmWins: whether an MDM's setting of a Policy CSP policy wins over
# Group Policy's: enrolled, and MDMWinsOverGP set or unreadable; never for
# attack surface reduction rules, which it does not cover.
function Test-ErMdmWins {
    param($Context, [string]$Csp)
    return [bool]($Context.Mdm -and $Csp -and $Csp -ne 'Defender/AttackSurfaceReductionRules' -and
        ($Context.MdmWinsOverGp -or $Context.Unreadable.mdmWins))
}

# Get-ErProductOwner: another antivirus or firewall that is on, as the
# owner of the values such a product takes over, or $null.
function Get-ErProductOwner {
    param($Context, [string]$Product)
    if (-not $Product) { return $null }
    $names = @($Context.Products[$Product])
    if ($names.Count -eq 0) { return $null }
    return New-ErOwnerResult 'owner' 'security_product' (($names | Sort-Object) -join ', ') 'on' @()
}

# Resolve-ErRegistryOwner: who owns a registry value under HKLM.
#   -Csp      Area/Policy of the Policy CSP that sets the value, if any
#   -Defender the value belongs to Defender, attack surface reduction or
#             the firewall, which Defender for Endpoint's security settings
#             management may set
#   -Product  antivirus or firewall: another such product that is on owns it
#   -Tamper   Tamper Protection guards it
# Another antivirus or firewall comes first, then Group Policy (unless an
# MDM that wins over it sets the same policy), then Tamper Protection. A
# value under Policies that none of them explains, or that cannot be read,
# is cannot_tell.
function Resolve-ErRegistryOwner {
    param($Context, [string]$Path, [string]$Name, [string]$Csp = '', [switch]$Defender, [string]$Product = '', [switch]$Tamper)
    $byProduct = Get-ErProductOwner $Context $Product
    if ($byProduct) { return $byProduct }
    $gp = Find-ErGpRegistry $Context $Path $Name
    if ($gp -and -not (Test-ErMdmWins $Context $Csp)) {
        return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy $gp.Value @()
    }
    if ($Tamper -and $Context.TamperProtected) { return New-ErOwnerResult 'owner' 'tamper_protection' 'Tamper Protection' '' @() }
    $reasons = Get-ErReasons $Context 'registry' -Defender:$Defender -Product $Product -Tamper:$Tamper
    if ($reasons.Count -eq 0 -and (Test-ErPolicyPath $Path)) {
        $v = Get-ErRegistryValue $Path $Name
        if ($v.Error) {
            $reasons += 'unreadable'
            if ($Context.Notes -notcontains $v.Error) { $Context.Notes.Add($v.Error) }
        } elseif ($v.Exists) {
            $reasons += 'unexplained_policy'
        }
    }
    return New-ErUnownedResult $Context $reasons $Csp
}

# Resolve-ErSecurityOwner: who owns a security policy setting, by its
# name in a security template (MinimumPasswordLength, EnableGuestAccount).
function Resolve-ErSecurityOwner {
    param($Context, [string]$Setting)
    $csp = Get-ErSecurityCsp $Setting
    $gp = $Context.GpSecurity[$Setting.ToLowerInvariant()]
    if ($gp -and -not (Test-ErMdmWins $Context $csp)) {
        return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy $gp.Value @()
    }
    return New-ErUnownedResult $Context (Get-ErReasons $Context 'security') $csp
}

# Resolve-ErAuditOwner: who owns an audit subcategory, by its GUID. Where
# subcategories do not override categories, Group Policy's legacy audit
# category holds each of its subcategories.
function Resolve-ErAuditOwner {
    param($Context, [string]$Guid)
    $g = $Guid.Trim('{', '}').ToLowerInvariant()
    $sub = Get-ErAuditSubcategory $g
    $csp = $(if ($sub) { $sub.Csp } else { '' })
    $gp = $Context.GpAudit[$g]
    if ($gp -and -not (Test-ErMdmWins $Context $csp)) {
        return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy (ConvertTo-ErAuditSetting $gp.Value) @()
    }
    if (-not $Context.SubcategoriesOverride -and $Context.GpLegacyAudit.Count -gt 0) {
        if ($sub) {
            $l = $Context.GpLegacyAudit[$sub.Category]
            if ($l) {
                return New-ErOwnerResult 'owner' 'group_policy' $l.Policy (ConvertTo-ErAuditSetting ([int]$l.Success + 2 * [int]$l.Failure)) @()
            }
        } else {
            # A subcategory the reader does not know: any category may hold it.
            $policies = @($Context.GpLegacyAudit.Values | ForEach-Object { $_.Policy } | Sort-Object -Unique)
            return New-ErOwnerResult 'owner' 'group_policy' ($policies -join ', ') 'legacy categories' @()
        }
    }
    return New-ErUnownedResult $Context (Get-ErReasons $Context 'audit') $csp
}

function New-ErOwnerResult {
    param([string]$Result, [string]$Owner, [string]$Policy, [string]$Value, [string[]]$Reasons)
    return @{ Result = $Result; Owner = $Owner; Policy = $Policy; Value = $Value; Reasons = @($Reasons) }
}

# New-ErUnownedResult: cannot_tell with the reasons, and what the MDM set
# where it may hold the value; none without reasons.
function New-ErUnownedResult {
    param($Context, [string[]]$Reasons, [string]$Csp)
    if (@($Reasons).Count -eq 0) { return New-ErOwnerResult 'none' '' '' '' @() }
    $r = New-ErOwnerResult 'cannot_tell' '' '' '' $Reasons
    if ($Context.Mdm -and $Csp) { $r.Mdm = Read-ErMdmPolicy $Context $Csp }
    return $r
}

# Get-ErSecurityCsp: the Policy CSP's Area/Policy that sets a security
# setting, or ''. DeviceLock's password policies are the ones Windows 11
# 24H2 and Server 2025 (build 26100) list; the newer ClearTextPassword and
# AccountLockoutPolicy where Windows has them.
function Get-ErSecurityCsp {
    param([string]$Setting)
    $t = @{
        minimumpasswordlength  = 'DeviceLock/MinDevicePasswordLength'
        passwordcomplexity     = 'DeviceLock/MinDevicePasswordComplexCharacters'
        passwordhistorysize    = 'DeviceLock/DevicePasswordHistory'
        maximumpasswordage     = 'DeviceLock/DevicePasswordExpiration'
        minimumpasswordage     = 'DeviceLock/MinimumPasswordAge'
        cleartextpassword      = 'DeviceLock/ClearTextPassword'
        lockoutbadcount        = 'DeviceLock/AccountLockoutPolicy'
        lockoutduration        = 'DeviceLock/AccountLockoutPolicy'
        resetlockoutcount      = 'DeviceLock/AccountLockoutPolicy'
        enableguestaccount     = 'LocalPoliciesSecurityOptions/Accounts_EnableGuestAccountStatus'
        enableadminaccount     = 'LocalPoliciesSecurityOptions/Accounts_EnableAdministratorAccountStatus'
        lsaanonymousnamelookup = 'LocalPoliciesSecurityOptions/NetworkAccess_AllowAnonymousSIDOrNameTranslation'
    }
    $c = $t[$Setting.ToLowerInvariant()]
    if ($c) { return $c }
    return ''
}

# Get-ErAuditSubcategory: an audit subcategory's legacy category (as
# RSOP_AuditPolicy names it) and the Policy CSP's Audit policy that sets
# it, by the GUID's last digits; $null for a GUID the reader does not know.
function Get-ErAuditSubcategory {
    param([string]$Guid)
    if ($Guid.Trim('{', '}').ToLowerInvariant() -notmatch '^0cce92([0-9a-f]{2})-69ae-11d9-bed3-505054503030$') { return $null }
    $t = @{
        '10' = @('AuditSystemEvents', 'System_AuditSecurityStateChange')
        '11' = @('AuditSystemEvents', 'System_AuditSecuritySystemExtension')
        '12' = @('AuditSystemEvents', 'System_AuditSystemIntegrity')
        '13' = @('AuditSystemEvents', 'System_AuditIPsecDriver')
        '14' = @('AuditSystemEvents', 'System_AuditOtherSystemEvents')
        '15' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditLogon')
        '16' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditLogoff')
        '17' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditAccountLockout')
        '18' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditIPsecMainMode')
        '19' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditIPsecQuickMode')
        '1a' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditIPsecExtendedMode')
        '1b' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditSpecialLogon')
        '1c' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditOtherLogonLogoffEvents')
        '43' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditNetworkPolicyServer')
        '47' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditUserDeviceClaims')
        '49' = @('AuditLogonEvents', 'AccountLogonLogoff_AuditGroupMembership')
        '1d' = @('AuditObjectAccess', 'ObjectAccess_AuditFileSystem')
        '1e' = @('AuditObjectAccess', 'ObjectAccess_AuditRegistry')
        '1f' = @('AuditObjectAccess', 'ObjectAccess_AuditKernelObject')
        '20' = @('AuditObjectAccess', 'ObjectAccess_AuditSAM')
        '21' = @('AuditObjectAccess', 'ObjectAccess_AuditCertificationServices')
        '22' = @('AuditObjectAccess', 'ObjectAccess_AuditApplicationGenerated')
        '23' = @('AuditObjectAccess', 'ObjectAccess_AuditHandleManipulation')
        '24' = @('AuditObjectAccess', 'ObjectAccess_AuditFileShare')
        '25' = @('AuditObjectAccess', 'ObjectAccess_AuditFilteringPlatformPacketDrop')
        '26' = @('AuditObjectAccess', 'ObjectAccess_AuditFilteringPlatformConnection')
        '27' = @('AuditObjectAccess', 'ObjectAccess_AuditOtherObjectAccessEvents')
        '44' = @('AuditObjectAccess', 'ObjectAccess_AuditDetailedFileShare')
        '45' = @('AuditObjectAccess', 'ObjectAccess_AuditRemovableStorage')
        '46' = @('AuditObjectAccess', 'ObjectAccess_AuditCentralAccessPolicyStaging')
        '28' = @('AuditPrivilegeUse', 'PrivilegeUse_AuditSensitivePrivilegeUse')
        '29' = @('AuditPrivilegeUse', 'PrivilegeUse_AuditNonSensitivePrivilegeUse')
        '2a' = @('AuditPrivilegeUse', 'PrivilegeUse_AuditOtherPrivilegeUseEvents')
        '2b' = @('AuditProcessTracking', 'DetailedTracking_AuditProcessCreation')
        '2c' = @('AuditProcessTracking', 'DetailedTracking_AuditProcessTermination')
        '2d' = @('AuditProcessTracking', 'DetailedTracking_AuditDPAPIActivity')
        '2e' = @('AuditProcessTracking', 'DetailedTracking_AuditRPCEvents')
        '48' = @('AuditProcessTracking', 'DetailedTracking_AuditPNPActivity')
        '4a' = @('AuditProcessTracking', 'DetailedTracking_AuditTokenRightAdjusted')
        '2f' = @('AuditPolicyChange', 'PolicyChange_AuditPolicyChange')
        '30' = @('AuditPolicyChange', 'PolicyChange_AuditAuthenticationPolicyChange')
        '31' = @('AuditPolicyChange', 'PolicyChange_AuditAuthorizationPolicyChange')
        '32' = @('AuditPolicyChange', 'PolicyChange_AuditMPSSVCRuleLevelPolicyChange')
        '33' = @('AuditPolicyChange', 'PolicyChange_AuditFilteringPlatformPolicyChange')
        '34' = @('AuditPolicyChange', 'PolicyChange_AuditOtherPolicyChangeEvents')
        '35' = @('AuditAccountManage', 'AccountManagement_AuditUserAccountManagement')
        '36' = @('AuditAccountManage', 'AccountManagement_AuditComputerAccountManagement')
        '37' = @('AuditAccountManage', 'AccountManagement_AuditSecurityGroupManagement')
        '38' = @('AuditAccountManage', 'AccountManagement_AuditDistributionGroupManagement')
        '39' = @('AuditAccountManage', 'AccountManagement_AuditApplicationGroupManagement')
        '3a' = @('AuditAccountManage', 'AccountManagement_AuditOtherAccountManagementEvents')
        '3b' = @('AuditDSAccess', 'DSAccess_AuditDirectoryServiceAccess')
        '3c' = @('AuditDSAccess', 'DSAccess_AuditDirectoryServiceChanges')
        '3d' = @('AuditDSAccess', 'DSAccess_AuditDirectoryServiceReplication')
        '3e' = @('AuditDSAccess', 'DSAccess_AuditDetailedDirectoryServiceReplication')
        '3f' = @('AuditAccountLogon', 'AccountLogon_AuditCredentialValidation')
        '40' = @('AuditAccountLogon', 'AccountLogon_AuditKerberosServiceTicketOperations')
        '41' = @('AuditAccountLogon', 'AccountLogon_AuditOtherAccountLogonEvents')
        '42' = @('AuditAccountLogon', 'AccountLogon_AuditKerberosAuthenticationService')
    }
    $row = $t[$Matches[1]]
    if (-not $row) { return $null }
    return @{ Category = $row[0]; Csp = 'Audit/' + $row[1] }
}

# The value an MDM set for a Policy CSP policy (Area/Policy), from the
# Config node through the MDM Bridge WMI provider; the value in effect,
# from its Result node; and the provider Windows recorded as winning under
# PolicyManager. Shown with a cannot_tell result until the reader is proven
# on a real enrolled computer. Each class is read once.
function Read-ErMdmPolicy {
    param($Context, [string]$Csp)
    $area, $policy = $Csp.Split('/', 2)
    $out = @{ Csp = $Csp; Config = ''; Current = ''; Provider = '' }
    foreach ($node in @(@('Config', 'Config01'), @('Current', 'Result01'))) {
        $class = "MDM_Policy_$($node[1])_$($area)02"
        if (-not $Context.MdmCache.ContainsKey($class)) {
            try {
                $Context.MdmCache[$class] = @(Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName $class -ErrorAction Stop -OperationTimeoutSec 30)
            } catch {
                $Context.MdmCache[$class] = @()
            }
        }
        $i = @($Context.MdmCache[$class])
        if ($i.Count -gt 0 -and $null -ne $i[0].$policy) { $out[$node[0]] = Limit-ErText ([string]$i[0].$policy) 80 }
    }
    $w = Get-ErRegistryValue "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\$area" ($policy + '_WinningProvider')
    if ($w.Exists) { $out.Provider = Limit-ErText ([string]$w.Data) 80 }
    return $out
}

function Get-ErGpoName {
    param($Context, $Id)
    $n = $Context.Gpos[[string]$Id]
    if ($n) { return $n }
    if ("$Id" -eq 'LocalGPO') { return 'Local Group Policy' }
    return [string]$Id
}

# Get-ErRegistryKey: how a value is looked up: the key without its hive,
# and the value's name, in lower case.
function Get-ErRegistryKey {
    param([string]$Path, [string]$Name)
    $p = $Path -replace '^(HKLM|HKEY_LOCAL_MACHINE|MACHINE)(:)?\\', ''
    return ($p.TrimEnd('\') + '|' + $Name).ToLowerInvariant()
}

# Values under HKLM\SOFTWARE\Policies are what administrative templates
# write. Windows' own CurrentVersion\Policies keys (UAC's values among
# them) are present on every computer and are not counted.
function Test-ErPolicyPath {
    param([string]$Path)
    return ($Path -match '^HKLM\\SOFTWARE\\(WOW6432Node\\)?Policies\\')
}

# Open-ErRegistryKey: a key under HKLM (its path without the hive), opened
# to read, or $null where it does not exist; it throws where the key could
# not be read. .NET's OpenSubKey throws only for access denied and answers
# $null for any other failure, as for a key that does not exist; so a $null
# is checked a level at a time from the hive, and a key its parent lists
# that will not open is a read that failed.
function Open-ErRegistryKey {
    param([string]$Path)
    $hklm = [Microsoft.Win32.Registry]::LocalMachine
    $k = $hklm.OpenSubKey($Path, $false)
    if ($null -ne $k) { return $k }
    $parent = $hklm
    $at = 'HKLM'
    try {
        foreach ($part in @($Path.Split('\') | Where-Object { $_ })) {
            $at += '\' + $part
            if (@($parent.GetSubKeyNames()) -notcontains $part) { return $null }
            $next = $parent.OpenSubKey($part, $false)
            if ($null -eq $next) { throw "$at is listed by its parent but could not be opened." }
            if (-not [object]::ReferenceEquals($parent, $hklm)) { $parent.Close() }
            $parent = $next
        }
        # Every level opened, this time.
        $k = $parent
        $parent = $hklm
        return $k
    } finally {
        if (-not [object]::ReferenceEquals($parent, $hklm)) { $parent.Close() }
    }
}

# Get-ErService: a service by its name, or $null where it is not installed;
# Error where that could not be told. Get-Service by name answers
# NoServiceFoundForGivenName for a service it could not query as for one
# that is not installed, so that answer is checked against Windows' whole
# list of services, which fails as a read does. (The list leaves out a
# service whose status the caller may not query; LocalSystem may query
# every service unless one's access list shuts it out.)
function Get-ErService {
    param([string]$Name)
    try {
        return @{ Service = (Get-Service -Name $Name -ErrorAction Stop); Error = '' }
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoServiceFoundForGivenName*') { return @{ Service = $null; Error = $_.Exception.Message } }
    }
    try {
        $listed = @(Get-Service -ErrorAction Stop | Where-Object { $_.Name -eq $Name })
    } catch {
        return @{ Service = $null; Error = "Windows' list of services could not be read: $($_.Exception.Message)" }
    }
    if ($listed.Count -gt 0) { return @{ Service = $null; Error = "Windows lists the service $Name, but it could not be queried." } }
    return @{ Service = $null; Error = '' }
}

# Get-ErRegistryValue: a value under HKLM, without following anything: its
# existence, data and kind; or, where it could not be read, Error, which
# names it: such a value is neither absent nor present, and every caller
# makes it unknown or cannot_tell.
function Get-ErRegistryValue {
    param([string]$Path, [string]$Name)
    $sub = $Path -replace '^HKLM\\', ''
    $k = $null
    try {
        $k = Open-ErRegistryKey $sub
        if ($null -eq $k) { return @{ Exists = $false; Data = $null; Kind = ''; Error = '' } }
        if (@($k.GetValueNames()) -notcontains $Name) { return @{ Exists = $false; Data = $null; Kind = ''; Error = '' } }
        $kind = $k.GetValueKind($Name).ToString()
        $data = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($kind -eq 'DWord') { $data = [uint32]([int64]$data -band 0xffffffffL) }
        return @{ Exists = $true; Data = $data; Kind = $kind; Error = '' }
    } catch {
        $e = $_.Exception
        if ($e.InnerException) { $e = $e.InnerException }
        return @{ Exists = $false; Data = $null; Kind = ''; Error = "HKLM\$sub\$Name could not be read: $($e.Message)" }
    } finally {
        if ($k) { $k.Close() }
    }
}

# A registry policy's bytes as the text of its value.
function ConvertFrom-ErRegistryBytes {
    param($Type, [byte[]]$Bytes)
    if ($null -eq $Bytes) { return '' }
    switch ([int]$Type) {
        4 { if ($Bytes.Length -ge 4) { return [string][BitConverter]::ToUInt32($Bytes, 0) } }
        11 { if ($Bytes.Length -ge 8) { return [string][BitConverter]::ToUInt64($Bytes, 0) } }
        { $_ -in 1, 2, 7 } { return [Text.Encoding]::Unicode.GetString($Bytes).TrimEnd([char]0).Replace([char]0, ',') }
    }
    return [BitConverter]::ToString($Bytes)
}

function ConvertTo-ErAuditSetting {
    param([int]$Value)
    switch ($Value) {
        0 { return 'none' }
        1 { return 'success' }
        2 { return 'failure' }
        3 { return 'success_failure' }
    }
    return "$Value"
}

# Limit-ErText: text read from the computer as a result may carry it:
# control characters as spaces, format characters (bidirectional marks,
# zero-width spaces) and line or paragraph separators removed, trimmed, at
# most Max characters, never cutting a character in two. Anyone who reaches
# the computer may have written such text (a failed sign-in's user name
# comes from whoever tried it).
function Limit-ErText {
    param([string]$Text, [int]$Max = 300)
    if ($null -eq $Text) { return '' }
    $t = (($Text -replace '[\p{Cc}]+', ' ') -replace '[\p{Cf}\p{Zl}\p{Zp}]', '').Trim()
    if ($t.Length -gt $Max) {
        $cut = $Max - 3
        if ($cut -gt 0 -and [char]::IsHighSurrogate($t[$cut - 1])) { $cut-- }
        $t = $t.Substring(0, $cut).TrimEnd() + '...'
    }
    return $t
}

# Invoke-ErProgram: runs a program with arguments, at most Seconds long,
# and returns its exit code and standard output.
function Invoke-ErProgram {
    param([string]$Path, [string[]]$Arguments, [int]$Seconds = 60)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = (@($Arguments | ForEach-Object { ConvertTo-ErArgument $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
    } catch {
        return @{ ExitCode = -1; Output = ''; Error = $_.Exception.Message }
    }
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($Seconds * 1000)) {
        try { $p.Kill() } catch { $null = $_ }
        return @{ ExitCode = -2; Output = ''; Error = "did not finish in $Seconds seconds" }
    }
    $p.WaitForExit()
    return @{ ExitCode = $p.ExitCode; Output = $out.Result; Error = $err.Result }
}

# New-ErWorkFolder: a folder for what Windows' readers write (gpresult's
# report, secedit's export, netsh's filtering platform state) under
# %SystemRoot%\Temp, with a new name each run, created with access for
# SYSTEM and Administrators only, so that no one else can read or replace
# what is written there. The caller removes it.
function New-ErWorkFolder {
    param([string]$Prefix)
    $path = Join-Path (Join-Path $env:SystemRoot 'Temp') ($Prefix + [guid]::NewGuid().ToString('N'))
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    $null = [IO.Directory]::CreateDirectory($path, $sec)
    return $path
}

# ConvertTo-ErAscii: a result line in ASCII, characters outside it escaped
# as JSON allows inside strings, the only place they can be.
function ConvertTo-ErAscii {
    param([string]$Json)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Json.ToCharArray()) {
        if ([int]$ch -gt 126) { $null = $sb.AppendFormat('\u{0:x4}', [int]$ch) } else { $null = $sb.Append($ch) }
    }
    return $sb.ToString()
}

# An argument quoted as the C runtime reads it.
function ConvertTo-ErArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]' -and $Value.Length -gt 0) { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}
