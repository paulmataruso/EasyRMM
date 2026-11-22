# EasyRMM's reader of who owns a Windows setting (ADR-0054, "Policy
# ownership: one reader, built here"). This file defines functions and does
# nothing else. Windows hardening's script includes it; followed by
# query.ps1 it is a script of its own, which the agent is to carry and
# start for log collection, the registry editor and the event viewer
# (ADR-0060, ADR-0067, ADR-0068). Windows PowerShell 5.1, Full Language Mode, no
# Add-Type, no modules from the PowerShell Gallery; accounts, subcategories
# and fields by SID, GUID and XML name, never by translated names.
#
# For each registry value, security setting and audit subcategory it gives
# exactly one of three results (Resolve-ErRegistryOwner and the others):
#   owner        who holds the value, the policy's name, the owner's value
#   none         no owner holds it: only then may a feature change it
#   cannot_tell  an owner may hold it whose settings the reader cannot read
#                yet, with fixed reasons (internal/winpolicy's Reasons):
#     group_policy_record_off   Group Policy's record of what it applied
#                               (the resultant set of policy) is turned off
#                               or cannot be read
#     group_policy_preferences  Group Policy carries registry preference
#                               items, which can set any registry value
#     mdm                       enrolled in an MDM: the reader of the Policy
#                               CSP's Config node is not proven on a real
#                               enrolled computer yet
#     defender_for_endpoint     onboarded to Defender for Endpoint, whose
#                               security settings management may apply
#                               Intune's Defender, attack surface reduction
#                               and firewall policies
#     configmgr                 a Configuration Manager client
#     dsc                       PowerShell DSC correcting drift
#     azure_machine_configuration
#     osconfig                  an OSConfig scenario is active, whose settings
#                               are named, not given as registry values
#     unexplained_policy        a value under HKLM\SOFTWARE\Policies that
#                               none of the readers explains
#
# Owners it reads, once per run (Get-ErPolicyContext):
# * Group Policy, from the domain or the local Group Policy object: the
#   resultant set of policy in WMI (root\rsop\computer): registry-based
#   policy (RSOP_RegistryPolicySetting, the winning policy, precedence 1),
#   the security settings (RSOP_SecuritySetting*, RSOP_RegistryValue) and
#   legacy audit categories (RSOP_AuditPolicy); gpresult's XML for advanced
#   audit policy, which Group Policy applies through an extension of its own,
#   for the policies' names, and for registry preference items. Where
#   gpresult names that extension without its settings (seen on a domain
#   member of Windows Server 2025), the extension's own record: the
#   policies in its history and the merged copy it keeps in
#   %SystemRoot%\security\audit\audit.csv.
# * MDM: enrolment under HKLM\SOFTWARE\Microsoft\Enrollments; the Policy
#   CSP's Config node through the MDM Bridge WMI provider
#   (root\cimv2\mdm\dmmap, MDM_Policy_Config01_<Area>02), the value in
#   effect from its Result node (MDM_Policy_Result01_<Area>02), and the
#   provider Windows records as winning under PolicyManager\current\device;
#   MDMWinsOverGP.
# * Defender for Endpoint's onboarding; a Configuration Manager client;
#   DSC's Local Configuration Manager; Azure's machine configuration;
#   OSConfig's active scenarios, where its module is installed; Tamper
#   Protection.

# What the reader read; one per run.
function Get-ErPolicyContext {
    param([string]$WorkFolder)
    $c = @{
        Notes                     = New-Object 'System.Collections.Generic.List[string]'
        Gpos                      = @{}
        GpRegistry                = @{}
        GpSecurity                = @{}
        GpSecurityRegistry        = @{}
        GpAudit                   = @{}
        GpLegacyAudit             = @{}
        GpRecordOff               = $false
        GpRecordRead              = $false
        GpPreferences             = $false
        Mdm                       = $false
        MdmProviders              = @()
        MdmWinsOverGp             = $false
        DefenderForEndpoint       = $false
        ConfigMgr                 = $false
        Dsc                       = $false
        AzureMachineConfiguration = $false
        OSConfigScenarios         = @()
        TamperProtected           = $false
        EasyRmmValues             = @{}
    }

    # Group Policy's record turned off: the policy "Turn off Resultant Set
    # of Policy logging".
    $off = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'RSoPLogging'
    if ($off.Exists -and "$($off.Data)" -eq '0') { $c.GpRecordOff = $true }

    # With the record off, WMI keeps the last record written before it was
    # turned off (seen on a domain member), which may name policies no
    # longer applied; so neither it nor gpresult, which reports from it, is
    # read. The extensions' own history and the audit copy are kept.
    if (-not $c.GpRecordOff) {
        Read-ErRsop $c
        Read-ErGpresult $c $WorkFolder
    }

    Read-ErAuditCopy $c

    # Registry preference items: Group Policy Preferences' registry
    # extension keeps a history of the policies that carried them.
    $history = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{B087BE9D-ED37-454f-AF9C-04291E351182}'
    if (Test-Path -LiteralPath $history) {
        if (@(Get-ChildItem -LiteralPath $history -ErrorAction SilentlyContinue).Count -gt 0) { $c.GpPreferences = $true }
    }

    # Get-ErMdmProviders returns its list as one value; @() around it would
    # make a list of one list.
    $c.MdmProviders = Get-ErMdmProviders
    $c.Mdm = $c.MdmProviders.Count -gt 0
    $wins = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict' 'MDMWinsOverGP'
    if ($wins.Exists -and "$($wins.Data)" -eq '1') { $c.MdmWinsOverGp = $true }

    $atp = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' 'OnboardingState'
    if ($atp.Exists -and "$($atp.Data)" -eq '1') { $c.DefenderForEndpoint = $true }

    if (Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue) { $c.ConfigMgr = $true }

    # DSC corrects drift only in ApplyAndAutoCorrect, and only with a
    # configuration to apply.
    $dscFolder = Join-Path $env:SystemRoot 'System32\Configuration'
    $meta = Join-Path $dscFolder 'MetaConfig.mof'
    if ((Test-Path -LiteralPath $meta) -and (Test-Path -LiteralPath (Join-Path $dscFolder 'Current.mof'))) {
        $text = Get-Content -LiteralPath $meta -Raw -ErrorAction SilentlyContinue
        if ($text -match 'ConfigurationMode\s*=\s*"ApplyAndAutoCorrect"') { $c.Dsc = $true }
    }

    # Azure machine configuration: the Arc agent's service, or the guest
    # configuration extension on an Azure virtual machine.
    if ((Get-Service -Name 'GCArcService' -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath (Join-Path $env:SystemDrive 'Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows'))) {
        $c.AzureMachineConfiguration = $true
    }

    # OSConfig (Windows Server 2025). A baseline can only have been applied
    # through it where its module is installed, so the reader asks that
    # copy, which EasyRMM never installs, for its active scenarios. OSConfig
    # names its settings (AfdDisableAddressSharing) and gives no registry
    # value for them, so an active scenario makes every value cannot_tell
    # (osconfig) rather than naming OSConfig as one value's owner. Its
    # read-only scenario (SecuredCoreState) sets nothing.
    if (Get-Module -ListAvailable -Name 'Microsoft.OSConfig' -ErrorAction SilentlyContinue) {
        try {
            Import-Module -Name 'Microsoft.OSConfig' -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null
            $c.OSConfigScenarios = @(Get-OSConfigMetadata -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null |
                Where-Object { [string]$_.Status -eq 'Active' -and [string]$_.Name -ne 'SecuredCoreState' } |
                ForEach-Object { [string]$_.Name })
        } catch {
            $c.OSConfigScenarios = @('(unreadable)')
            $c.Notes.Add("OSConfig's module is installed but did not list its scenarios: $($_.Exception.Message)")
        }
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.IsTamperProtected) { $c.TamperProtected = $true }
    } catch {
        $c.Notes.Add('Microsoft Defender did not report its status.')
    }
    return $c
}

# Get-ErMdmProviders: the MDMs the computer is enrolled in. Windows keeps
# enrolments of its own under the same key on every computer (providers
# "Local Authority", "Deploy Authority", "Cloud Authority",
# "WMI_Bridge_SCCM_Server", and some without a provider, seen on Windows
# Server 2025); an MDM's enrolment is enrolled (EnrollmentState 1) and
# records the discovery service it was found through. Intune's provider is
# "MS DM Server". Uses cmdlets only, so that it runs in Constrained
# Language Mode too.
function Get-ErMdmProviders {
    $out = @()
    foreach ($e in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction SilentlyContinue
        if ($p -and $p.ProviderID -and "$($p.EnrollmentState)" -eq '1' -and $p.DiscoveryServiceFullURL) {
            $out += [string]$p.ProviderID
        }
    }
    return , $out
}

# Read-ErRsop: the resultant set of policy Group Policy recorded in WMI.
function Read-ErRsop {
    param($c)
    try {
        foreach ($g in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_GPO -ErrorAction Stop -OperationTimeoutSec 60)) {
            $c.Gpos[[string]$g.id] = [string]$g.name
        }
        foreach ($s in @(Get-CimInstance -Namespace 'root\rsop\computer' -ClassName RSOP_RegistryPolicySetting -Filter 'precedence = 1' -ErrorAction Stop -OperationTimeoutSec 60)) {
            if ($s.deleted -or [string]::IsNullOrEmpty([string]$s.valueName) -or ([string]$s.valueName).StartsWith('**')) { continue }
            $c.GpRegistry[(Get-ErRegistryKey ('HKLM\' + $s.registryKey) $s.valueName)] = @{
                Value  = ConvertFrom-ErRegistryBytes $s.valueType $s.value
                Policy = Get-ErGpoName $c $s.GPOID
            }
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

# Group Policy's own report: advanced audit policy (applied by an
# extension of its own, not as registry policy), the policies' names, and
# whether registry preference items are among what it applied.
function Read-ErGpresult {
    param($Context, [string]$WorkFolder)
    if (-not $WorkFolder) { return }
    $file = Join-Path $WorkFolder 'gpresult.xml'
    $exe = Join-Path $env:SystemRoot 'System32\gpresult.exe'
    $run = Invoke-ErProgram $exe @('/scope', 'computer', '/x', $file, '/f') 120
    if ($run.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file)) {
        $Context.Notes.Add("gpresult did not report (exit code $($run.ExitCode)).")
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
function Read-ErAuditCopy {
    param($Context)
    $history = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'
    $names = @()
    $k = $null
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($history, $false)
        if ($null -eq $k) { return }
        foreach ($s in @($k.GetSubKeyNames())) {
            $n = Get-ErRegistryValue ('HKLM\' + $history + '\' + $s) 'DisplayName'
            if ($n.Exists -and "$($n.Data)" -and $names -notcontains "$($n.Data)") { $names += "$($n.Data)" }
        }
    } catch {
        $Context.Notes.Add("The audit policy extension's history could not be read: $($_.Exception.Message)")
        return
    } finally {
        if ($k) { $k.Close() }
    }
    if ($names.Count -eq 0) { return }
    $file = Join-Path $env:SystemRoot 'security\audit\audit.csv'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
    try {
        $rows = @(Import-Csv -LiteralPath $file -ErrorAction Stop)
    } catch {
        $Context.Notes.Add("The audit policy extension's copy could not be read: $($_.Exception.Message)")
        return
    }
    $policy = ($names | Sort-Object) -join ', '
    foreach ($r in $rows) {
        $guid = ([string]$r.'Subcategory GUID').Trim().Trim('{', '}').ToLowerInvariant()
        $value = [string]$r.'Setting Value'
        if ($guid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $value -notmatch '^[0-3]$') { continue }
        if (-not $Context.GpAudit.ContainsKey($guid)) {
            $Context.GpAudit[$guid] = @{ Value = [int]$value; Policy = $policy }
        }
    }
}

# Reasons that hold for every value on the computer.
function Get-ErComputerReasons {
    param($Context)
    $r = @()
    if ($Context.GpRecordOff -or -not $Context.GpRecordRead) { $r += 'group_policy_record_off' }
    if ($Context.ConfigMgr) { $r += 'configmgr' }
    if ($Context.Dsc) { $r += 'dsc' }
    if ($Context.AzureMachineConfiguration) { $r += 'azure_machine_configuration' }
    if ($Context.OSConfigScenarios.Count -gt 0) { $r += 'osconfig' }
    return , $r
}

# Resolve-ErRegistryOwner: who owns a registry value under HKLM.
#   -Csp      Area/Policy of the Policy CSP that sets the value, if any
#   -Defender the value belongs to Defender, attack surface reduction or
#             the firewall, which Defender for Endpoint's security settings
#             management may set
function Resolve-ErRegistryOwner {
    param($Context, [string]$Path, [string]$Name, [string]$Csp = '', [switch]$Defender)
    $key = Get-ErRegistryKey $Path $Name
    foreach ($table in $Context.GpRegistry, $Context.GpSecurityRegistry) {
        $gp = $table[$key]
        if ($gp) { return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy $gp.Value @() }
    }
    $reasons = @()
    if ($Context.GpRecordOff -or -not $Context.GpRecordRead) { $reasons += 'group_policy_record_off' }
    if ($Context.GpPreferences) { $reasons += 'group_policy_preferences' }
    $mdm = $null
    if ($Context.Mdm -and $Csp) {
        $reasons += 'mdm'
        $mdm = Read-ErMdmPolicy $Csp
    }
    if ($Context.DefenderForEndpoint -and $Defender) { $reasons += 'defender_for_endpoint' }
    if ($Context.ConfigMgr) { $reasons += 'configmgr' }
    if ($Context.Dsc) { $reasons += 'dsc' }
    if ($Context.AzureMachineConfiguration) { $reasons += 'azure_machine_configuration' }
    if ($Context.OSConfigScenarios.Count -gt 0) { $reasons += 'osconfig' }
    if ($reasons.Count -eq 0 -and (Test-ErPolicyPath $Path) -and -not $Context.EasyRmmValues[$key]) {
        if ((Get-ErRegistryValue $Path $Name).Exists) { $reasons += 'unexplained_policy' }
    }
    if ($reasons.Count -gt 0) {
        $r = New-ErOwnerResult 'cannot_tell' '' '' '' $reasons
        if ($mdm) { $r.Mdm = $mdm }
        return $r
    }
    return New-ErOwnerResult 'none' '' '' '' @()
}

# Resolve-ErSecurityOwner: who owns a security policy setting, by its
# name in a security template (MinimumPasswordLength, EnableGuestAccount).
function Resolve-ErSecurityOwner {
    param($Context, [string]$Setting)
    $gp = $Context.GpSecurity[$Setting.ToLowerInvariant()]
    if ($gp) { return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy $gp.Value @() }
    $reasons = Get-ErComputerReasons $Context
    if ($reasons.Count -gt 0) { return New-ErOwnerResult 'cannot_tell' '' '' '' $reasons }
    return New-ErOwnerResult 'none' '' '' '' @()
}

# Resolve-ErAuditOwner: who owns an audit subcategory, by its GUID. Group
# Policy's legacy audit categories, where it sets any, hold the whole audit
# policy unless subcategories override categories.
function Resolve-ErAuditOwner {
    param($Context, [string]$Guid, [bool]$SubcategoriesOverride)
    $gp = $Context.GpAudit[$Guid.Trim('{', '}').ToLowerInvariant()]
    if ($gp) { return New-ErOwnerResult 'owner' 'group_policy' $gp.Policy (ConvertTo-ErAuditSetting $gp.Value) @() }
    if (-not $SubcategoriesOverride -and $Context.GpLegacyAudit.Count -gt 0) {
        $first = @($Context.GpLegacyAudit.Values)[0]
        return New-ErOwnerResult 'owner' 'group_policy' $first.Policy 'legacy categories' @()
    }
    $reasons = Get-ErComputerReasons $Context
    if ($reasons.Count -gt 0) { return New-ErOwnerResult 'cannot_tell' '' '' '' $reasons }
    return New-ErOwnerResult 'none' '' '' '' @()
}

function New-ErOwnerResult {
    param([string]$Result, [string]$Owner, [string]$Policy, [string]$Value, [string[]]$Reasons)
    return @{ Result = $Result; Owner = $Owner; Policy = $Policy; Value = $Value; Reasons = @($Reasons) }
}

# The value an MDM set for a Policy CSP policy (Area/Policy), from the
# Config node through the MDM Bridge WMI provider; the value in effect,
# from its Result node; and the provider Windows recorded as winning under
# PolicyManager. Shown with a cannot_tell result until the reader is proven
# on a real enrolled computer.
function Read-ErMdmPolicy {
    param([string]$Csp)
    $area, $policy = $Csp.Split('/', 2)
    $out = @{ Csp = $Csp; Config = ''; Current = ''; Provider = '' }
    foreach ($node in @(@('Config', 'Config01'), @('Current', 'Result01'))) {
        try {
            $i = @(Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName "MDM_Policy_$($node[1])_$($area)02" -ErrorAction Stop -OperationTimeoutSec 30)
            if ($i.Count -gt 0 -and $null -ne $i[0].$policy) { $out[$node[0]] = [string]$i[0].$policy }
        } catch {
            $out[$node[0]] = ''
        }
    }
    $w = Get-ErRegistryValue "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\$area" ($policy + '_WinningProvider')
    if ($w.Exists) { $out.Provider = [string]$w.Data }
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

# Get-ErRegistryValue: a value under HKLM, without following anything: its
# existence, data and kind.
function Get-ErRegistryValue {
    param([string]$Path, [string]$Name)
    $sub = $Path -replace '^HKLM\\', ''
    $k = $null
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, $false)
        if ($null -eq $k) { return @{ Exists = $false; Data = $null; Kind = '' } }
        if (@($k.GetValueNames()) -notcontains $Name) { return @{ Exists = $false; Data = $null; Kind = '' } }
        $kind = $k.GetValueKind($Name).ToString()
        $data = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($kind -eq 'DWord') { $data = [uint32]([int64]$data -band 0xffffffffL) }
        return @{ Exists = $true; Data = $data; Kind = $kind }
    } catch {
        return @{ Exists = $false; Data = $null; Kind = ''; Error = $_.Exception.Message }
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
# report, secedit's export) under %SystemRoot%\Temp, with a new name each
# run, created with access for SYSTEM and Administrators only, so that no
# one else can read or replace what is written there. The caller removes it.
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
