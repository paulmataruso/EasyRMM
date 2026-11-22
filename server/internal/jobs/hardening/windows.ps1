# EasyRMM hardening for Windows computers and servers (ADR-0054), run by the
# EasyRMM agent as LocalSystem with Windows PowerShell 5.1. This release has
# one mode, check: for each chosen module it reports whether the module's
# settings are in effect, who else owns each (Group Policy, Tamper
# Protection, another antivirus or firewall) or why that cannot be told (an
# MDM, OSConfig and the others of internal/winpolicy), and what apply would
# change on this computer. It changes nothing (see "What check writes").
#
# Arguments, which are never part of this script's text. The EasyRMM server
# accepts only the names and forms below, and this script checks them again:
#   check <modules> [option ...]
#   <modules>              all, or a comma-separated list of accounts,
#                          firewall, defender, asr, smb, smb-signing, ntlm,
#                          wdigest, lsa-protection, name-resolution,
#                          powershell, rdp, uac, autoplay, anonymous, winrm,
#                          printing, features, tls, audit, device-guard,
#                          bitlocker and laps
#   allow-tcp=LIST         ports or ranges (8080,9000-9100) the firewall would
#   allow-udp=LIST         allow besides those in use
#   asr-block=LIST         attack surface reduction rules (GUIDs) to block
#                          rather than audit
#   ports-checked, firewall-server, domain-controller,
#   defender-server-realtime, smartscreen-block, cloud-block-high,
#   lsa-uefi-lock, lsa-unaudited, lockout-exposed, uac-enable,
#   uac-builtin-admin, deny-user-elevation, winrm-basic-off, spooler-off
#                          the switches of ADR-0054's modules
#
# Output: progress lines, then as the last line of stdout
#   EASYRMM-HARDENING-RESULT-V1 {"version":1,"mode":"check",...}
# in ASCII (other characters escaped), kept under 64 KiB. The exit code is 0
# whenever the check ran, whatever it found; 2 for a usage error; 3 when not
# run by an administrator.
#
# What check writes. Nothing it reports on. It runs Windows' own readers that
# write to files (secedit /export, auditpol /backup, gpresult /x) into a
# folder it makes under %SystemRoot%\Temp that only SYSTEM and
# Administrators can reach, and removes it before it ends. Where the
# Hardening folder exists, it opens its lock file (creating it if missing),
# and, as ADR-0054 requires of every mode, it may set an access list there
# back to the protected one, or move a file that fails the folder check
# aside within the folder.
#
# The record, which apply and undo are to write (W2) and check reads:
#   %ProgramData%\EasyRMM\Hardening\               SYSTEM and Administrators
#   %ProgramData%\EasyRMM\Hardening\manifest.json  {"formatVersion":1,...}
#   %ProgramData%\EasyRMM\Hardening\easyrmm-hardening.ps1  the script's copy
#   %ProgramData%\EasyRMM\Hardening\lock           one writer at a time
# A module with an intent and no done mark was interrupted: check reports it
# as half_applied.
#
# Benchmarks: each setting's values come from Microsoft's security baseline
# for the computer's Windows, except where ADR-0054 differs for safety. The
# settings, with how each stands against its DISA STIG rule (meets, differs,
# not set), are in windows-settings.json, which the server puts into this
# script with the ownership reader (internal/winpolicy) and log collection's
# audit table. EasyRMM claims compliance with nothing.

$ErScriptArgs = @($args)

#EASYRMM-INCLUDE

# ---------------------------------------------------------------------------
# What Constrained Language Mode allows: arguments, the platform, and a
# result in which every module is not supported. Nothing above this point
# runs anything; below it, only cmdlets and operators until the language
# mode is known.

$ErResultTag = 'EASYRMM-HARDENING-RESULT-V1'
$ErAllModules = @('accounts', 'firewall', 'defender', 'asr', 'smb', 'smb-signing', 'ntlm', 'wdigest', 'lsa-protection',
    'name-resolution', 'powershell', 'rdp', 'uac', 'autoplay', 'anonymous', 'winrm', 'printing', 'features', 'tls',
    'audit', 'device-guard', 'bitlocker', 'laps')
# Each option and the module it belongs to; domain-controller belongs to
# every module.
$ErOptionModule = @{
    'allow-tcp' = 'firewall'; 'allow-udp' = 'firewall'; 'ports-checked' = 'firewall'; 'firewall-server' = 'firewall'
    'domain-controller' = ''; 'defender-server-realtime' = 'defender'; 'smartscreen-block' = 'defender'
    'cloud-block-high' = 'defender'; 'asr-block' = 'asr'; 'lsa-uefi-lock' = 'lsa-protection'
    'lsa-unaudited' = 'lsa-protection'; 'lockout-exposed' = 'accounts'; 'uac-enable' = 'uac'
    'uac-builtin-admin' = 'uac'; 'deny-user-elevation' = 'uac'; 'winrm-basic-off' = 'winrm'; 'spooler-off' = 'printing'
}
$ErListOptions = @('allow-tcp', 'allow-udp', 'asr-block')

function Read-ErArguments {
    param([string[]]$Arguments)
    $r = @{ Mode = ''; Modules = @(); Options = @{}; Error = '' }
    if ($Arguments.Count -lt 1) { $r.Error = 'no mode given.'; return $r }
    $r.Mode = $Arguments[0]
    if ($r.Mode -ne 'check') { $r.Error = "unknown mode: $($r.Mode) (this release has check only)."; return $r }
    if ($Arguments.Count -lt 2) { $r.Error = 'no modules given.'; return $r }
    $chosen = @()
    if ($Arguments[1] -eq 'all') {
        $chosen = $ErAllModules
    } else {
        foreach ($m in ($Arguments[1] -split ',')) {
            if ($ErAllModules -notcontains $m) { $r.Error = "unknown module: $m."; return $r }
            if ($chosen -notcontains $m) { $chosen += $m }
        }
    }
    # The script's own order, whatever the order given.
    $r.Modules = @($ErAllModules | Where-Object { $chosen -contains $_ })
    for ($i = 2; $i -lt $Arguments.Count; $i++) {
        $name, $value = $Arguments[$i] -split '=', 2
        if (-not $ErOptionModule.ContainsKey($name)) { $r.Error = "unknown option: $name."; return $r }
        $module = $ErOptionModule[$name]
        if ($module -and $r.Modules -notcontains $module) { $r.Error = "option $name needs module $module."; return $r }
        if ($ErListOptions -contains $name) {
            if ($null -eq $value -or $value -eq '') { $r.Error = "option $name needs a list."; return $r }
            $list = @($value -split ',')
            foreach ($item in $list) {
                if ($name -eq 'asr-block') {
                    if ($item -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $r.Error = "asr-block: $item is not a rule's GUID."; return $r }
                } elseif ($item -notmatch '^([1-9][0-9]{0,4})(-([1-9][0-9]{0,4}))?$' -or [int]$Matches[1] -gt 65535 -or ($Matches[3] -and ([int]$Matches[3] -gt 65535 -or [int]$Matches[3] -lt [int]$Matches[1]))) {
                    $r.Error = "${name}: $item is not a port or a range."; return $r
                }
            }
            $r.Options[$name] = $list
        } else {
            if ($null -ne $value) { $r.Error = "option $name takes no value."; return $r }
            $r.Options[$name] = $true
        }
    }
    return $r
}

# The computer: Windows' version, edition, installation type, role, joins
# and MDM enrolment, read with cmdlets only.
function Get-ErPlatform {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = 0
    $ubr = 0
    if ($cv) {
        $build = [int]$cv.CurrentBuildNumber
        if ($null -ne $cv.UBR) { $ubr = [int]$cv.UBR }
    }
    $display = ''
    if ($cv -and $cv.DisplayVersion) { $display = [string]$cv.DisplayVersion } elseif ($cv -and $cv.ReleaseId) { $display = [string]$cv.ReleaseId }
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $role = 'workstation'
    $domain = $false
    if ($cs) {
        switch ([int]$cs.DomainRole) {
            2 { $role = 'standalone_server' }
            3 { $role = 'member_server' }
            4 { $role = 'domain_controller' }
            5 { $role = 'domain_controller' }
        }
        $domain = [bool]$cs.PartOfDomain
    }
    $entra = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue).Count -gt 0
    $joined = 'none'
    if ($domain -and $entra) { $joined = 'domain_entra' } elseif ($domain) { $joined = 'domain' } elseif ($entra) { $joined = 'entra' }
    $mdm = (Get-ErMdmProviders).Count -gt 0
    $arch = "$env:PROCESSOR_ARCHITECTURE".ToLowerInvariant()
    if ($arch -eq 'x86' -and $env:PROCESSOR_ARCHITEW6432) { $arch = "$env:PROCESSOR_ARCHITEW6432".ToLowerInvariant() }
    $edition = ''
    $install = ''
    if ($cv) { $edition = [string]$cv.EditionID; $install = [string]$cv.InstallationType }
    return @{
        Build = $build; Ubr = $ubr; DisplayVersion = $display; Edition = $edition; InstallationType = $install
        Role = $role; Joined = $joined; Mdm = $mdm; Architecture = $arch
        Client = ($install -eq 'Client'); Core = ($install -eq 'Server Core')
    }
}

# Where apply and undo are to run (ADR-0054, "Platforms"): full on the
# versions listed, check_only on those out of service, Home editions,
# multi-session Windows and ARM64 for now, unsupported on builds this
# script does not know.
function Get-ErSupport {
    param($Platform)
    $b = $Platform.Build
    $e = $Platform.Edition
    $now = (Get-Date).ToUniversalTime()
    if ($Platform.Architecture -eq 'arm64') { return 'check_only' }
    if ($Platform.Client) {
        if ($e -like 'Core*' -or $e -eq 'ServerRdsh') { return 'check_only' }
        # LTSC (EnterpriseS) is serviced on dates of its own and is not in
        # ADR-0054's list: check only until tested.
        $enterprise = @('Enterprise', 'Education') -contains $e
        $pro = @('Professional', 'ProfessionalWorkstation', 'ProfessionalEducation') -contains $e
        if (-not ($enterprise -or $pro)) { return 'check_only' }
        switch ($b) {
            26200 { return 'full' }
            26100 {
                if ($enterprise -and $now -lt [datetime]'2027-10-13') { return 'full' }
                return 'check_only'
            }
        }
        if ($b -ge 10240 -and $b -lt 26100) { return 'check_only' }
        return 'unsupported'
    }
    switch ($b) {
        26100 { return 'full' }
        20348 { return 'full' }
        17763 { return 'full' }
        14393 {
            if ($now -lt [datetime]'2027-01-13') { return 'full' }
            return 'check_only'
        }
    }
    return 'unsupported'
}

function ConvertTo-ErPlatformJson {
    param($Platform, [string]$Support, [string]$LanguageMode, $Extra)
    $w = @{
        build = $Platform.Build; ubr = $Platform.Ubr; displayVersion = $Platform.DisplayVersion; edition = $Platform.Edition
        installationType = $Platform.InstallationType; role = $Platform.Role; joined = $Platform.Joined; mdm = $Platform.Mdm
        architecture = $Platform.Architecture; languageMode = $LanguageMode
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $w[$k] = $Extra[$k] } }
    return @{
        id = 'windows'; versionId = "10.0.$($Platform.Build).$($Platform.Ubr)"; family = 'windows'; container = 'none'
        support = $Support; windows = $w
    }
}

$ErArgs = Read-ErArguments $ErScriptArgs
$ErLanguageMode = [string]$ExecutionContext.SessionState.LanguageMode
if ($ErLanguageMode -ne 'FullLanguage') {
    # App Control for Business or AppLocker put PowerShell in this mode: the
    # script cannot read or set what it needs, and must not try to get
    # around the computer's own control.
    if ($ErArgs.Error) { Write-Error "windows.ps1: $($ErArgs.Error)"; exit 2 }
    $p = Get-ErPlatform
    $mods = @()
    foreach ($m in $ErArgs.Modules) {
        $mods += @{ module = $m; state = 'not_supported'; reason = "PowerShell runs in $ErLanguageMode mode here (App Control or AppLocker), in which this script cannot read what it checks." }
    }
    $line = @{ version = 1; mode = $ErArgs.Mode; platform = (ConvertTo-ErPlatformJson $p (Get-ErSupport $p) $ErLanguageMode $null); modules = $mods } | ConvertTo-Json -Depth 8 -Compress
    Write-Output "$ErResultTag $line"
    exit 0
}

# ---------------------------------------------------------------------------
# Full Language Mode from here on.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Say {
    param([string]$Text)
    [Console]::Out.WriteLine($Text)
}

if ($ErArgs.Error) {
    [Console]::Error.WriteLine("windows.ps1: $($ErArgs.Error)")
    [Console]::Error.WriteLine('Usage: windows.ps1 check <all|module,...> [allow-tcp=LIST] [allow-udp=LIST] [asr-block=LIST] [switch ...]')
    exit 2
}
$ErIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$ErIdentity).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
    [Console]::Error.WriteLine('windows.ps1: run this as LocalSystem or as an elevated administrator.')
    exit 3
}

$ErMode = $ErArgs.Mode
$ErOptions = $ErArgs.Options
$ErPlatform = Get-ErPlatform
$ErSupport = Get-ErSupport $ErPlatform
$ErSettings = @((ConvertFrom-Json $ErSettingsJson).settings)
$ErAudit = ConvertFrom-Json $ErAuditTableJson

function Test-ErOption {
    param([string]$Name)
    return [bool]$ErOptions[$Name]
}

# A short, printable form of any text for the result.
function Limit-ErText {
    param([string]$Text, [int]$Max = 300)
    if ($null -eq $Text) { return '' }
    $t = ($Text -replace '[\x00-\x1f\x7f]+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

# ---------------------------------------------------------------------------
# Access lists of the Hardening folder and its files (the work folder,
# under %SystemRoot%\Temp, is the reader's New-ErWorkFolder).

$ErProtectedFolder = 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$ErInheritedFile = 'D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)'

# ---------------------------------------------------------------------------
# The Hardening folder (ADR-0054, "Backups, undo and interruptions"), with
# PR #61's rule: the chain from ProgramData down is plain folders with a
# trusted owner; the folder and its files have a trusted owner, the files
# are plain with one link, and they are judged by who may write.

$ErTrusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete,
# WriteDAC, WriteOwner, GenericAll, GenericWrite.
$ErWriteRights = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

# Test-ErWriters: who besides SYSTEM, Administrators and TrustedInstaller
# may write, from the access list in SDDL, so that callback and object
# entries count too. Deny entries are ignored (they only take rights away);
# inherit-only entries count on folders, where new files inherit them.
# Returns the SIDs that may write, or 'unreadable'.
function Get-ErWriters {
    param([string]$Sddl, [bool]$Folder)
    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    } catch {
        return @('unreadable')
    }
    $out = @()
    if ($null -eq $sd.DiscretionaryAcl) { return @('everyone (no access list)') }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $type = [string]$ace.AceType
        if ($type -like 'AccessDenied*' -or $type -like 'System*') { continue }
        if ($type -notlike 'AccessAllowed*') { $out += "an entry of type $type"; continue }
        # AceFlags is a byte enum, which Windows PowerShell's -band cannot
        # take as it is.
        if (-not $Folder -and ([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly)) { continue }
        $sid = [string]$ace.SecurityIdentifier
        if ($ErTrusted -contains $sid) { continue }
        if (([int64]$ace.AccessMask -band $ErWriteRights) -ne 0) { $out += $sid }
    }
    return , $out
}

# The access part of an SDDL with its entries in a fixed order, to compare
# access lists that hold the same allow entries in another order.
function ConvertTo-ErSortedSddl {
    param([string]$Sddl)
    if ($Sddl -notmatch '^(D:[A-Z]*)((\([^()]*\))*)$') { return $Sddl }
    $head = $Matches[1]
    $entries = @([regex]::Matches($Matches[2], '\([^()]*\)') | ForEach-Object { $_.Value } | Sort-Object)
    return $head + ($entries -join '')
}

function Get-ErOwnerSid {
    param([string]$Sddl)
    try {
        return [string](New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)).Owner
    } catch {
        return ''
    }
}

# The number of names a file has (hard links), from fsutil, which prints
# one per line.
function Get-ErLinkCount {
    param([string]$Path)
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\fsutil.exe') @('hardlink', 'list', $Path) 30
    if ($run.ExitCode -ne 0) { return -1 }
    return @(($run.Output -split "`r?`n") | Where-Object { $_.Trim() -ne '' }).Count
}

# Test-ErEntry: one folder or file of the Hardening folder. Returns
# 'ok', 'reset' (set back to the protected access list), or a failure.
function Test-ErEntry {
    param([string]$Path, [bool]$Folder, [bool]$ChainOnly)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'is a junction, link or other reparse point' }
    if ($Folder -ne ($item -is [IO.DirectoryInfo])) { return 'is not a plain ' + $(if ($Folder) { 'folder' } else { 'file' }) }
    $sddl = $item.GetAccessControl('Owner, Access').GetSecurityDescriptorSddlForm('Owner, Access')
    $owner = Get-ErOwnerSid $sddl
    if ($ErTrusted -notcontains $owner) { return "is owned by $owner, not by SYSTEM, Administrators or TrustedInstaller" }
    if ($ChainOnly) { return 'ok' }
    if (-not $Folder) {
        $links = Get-ErLinkCount $Path
        if ($links -ne 1) { return "has $links names (hard links), not one" }
    }
    $writers = Get-ErWriters $sddl $Folder
    if ($writers.Count -gt 0) { return 'may be written by ' + ($writers -join ', ') }
    $want = $(if ($Folder) { $ErProtectedFolder } else { $ErInheritedFile })
    $acl = $item.GetAccessControl('Access')
    if ((ConvertTo-ErSortedSddl $acl.GetSecurityDescriptorSddlForm('Access')) -eq (ConvertTo-ErSortedSddl $want)) { return 'ok' }
    if ($Folder) {
        $acl.SetSecurityDescriptorSddlForm($ErProtectedFolder)
    } else {
        $acl.SetSecurityDescriptorSddlForm('D:AI')
    }
    $item.SetAccessControl($acl)
    return 'reset'
}

# Move-ErAside: a failing file is renamed within Hardening\, never read
# again, and kept for an administrator to review.
function Move-ErAside {
    param([string]$Path)
    $to = $Path + '.set-aside-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    [IO.File]::Move($Path, $to)
    return $to
}

function Get-ErSha256 {
    param([string]$Path)
    $s = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        $h = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($h.ComputeHash($s)) -replace '-', '').ToLowerInvariant()
    } finally {
        $s.Dispose()
    }
}

# Open-ErHardening: checks the folder, takes its lock file, reads the
# manifest. In check mode it creates nothing but the lock file, and only
# where the folder exists.
function Open-ErHardening {
    $r = @{ Folder = 'absent'; Refusal = ''; Warnings = @(); SetAside = @(); Lock = $null; Manifest = $null; CopySha256 = '' }
    $chain = @($env:ProgramData, (Join-Path $env:ProgramData 'EasyRMM'))
    $dir = Join-Path $chain[1] 'Hardening'
    foreach ($c in $chain) {
        if (-not (Test-Path -LiteralPath $c)) { return $r }
        $t = Test-ErEntry $c $true $true
        if ($t -ne 'ok') { $r.Refusal = "$c $t."; return $r }
    }
    if (-not (Test-Path -LiteralPath $dir)) { return $r }
    $t = Test-ErEntry $dir $true $false
    if ($t -eq 'reset') {
        $r.Warnings += "The access list of $dir was set back to SYSTEM and Administrators only."
    } elseif ($t -ne 'ok') {
        $r.Folder = 'refused'
        $r.Refusal = "$dir $t. It is never moved; an administrator must remove or repair it."
        return $r
    }
    $r.Folder = 'present'
    $files = @{ lock = Join-Path $dir 'lock'; manifest = Join-Path $dir 'manifest.json'; copy = Join-Path $dir 'easyrmm-hardening.ps1' }
    foreach ($name in 'lock', 'manifest', 'copy') {
        $f = $files[$name]
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $t = Test-ErEntry $f $false $false
        if ($t -eq 'reset') {
            $r.Warnings += "The access list of $f was set back."
        } elseif ($t -ne 'ok') {
            $to = Move-ErAside $f
            $r.SetAside += $to
            $r.Refusal = "$f $t; it was moved aside to $to."
            return $r
        }
    }
    # One run at a time: the lock file, opened without sharing; check
    # waits up to five minutes for another run to finish.
    $deadline = (Get-Date).AddMinutes(5)
    while ($null -eq $r.Lock) {
        try {
            $r.Lock = [IO.File]::Open($files.lock, 'OpenOrCreate', 'ReadWrite', 'None')
        } catch [System.IO.IOException] {
            if ((Get-Date) -gt $deadline) { $r.Refusal = 'Another hardening run held the lock file for five minutes.'; return $r }
            Start-Sleep -Seconds 2
        }
    }
    if (Test-Path -LiteralPath $files.manifest) {
        try {
            $m = ConvertFrom-Json ([IO.File]::ReadAllText($files.manifest))
        } catch {
            $m = $null
        }
        if ($null -eq $m -or $m.formatVersion -ne 1) {
            $to = Move-ErAside $files.manifest
            $r.SetAside += $to
            $r.Refusal = "The manifest is not one this script reads; it was moved aside to $to."
            return $r
        }
        $r.Manifest = $m
    }
    if (Test-Path -LiteralPath $files.copy) {
        $r.CopySha256 = Get-ErSha256 $files.copy
        $want = ''
        if ($r.Manifest -and $r.Manifest.copySha256) { $want = [string]$r.Manifest.copySha256 }
        if ($want -ne $r.CopySha256) {
            $to = Move-ErAside $files.copy
            $r.SetAside += $to
            $r.Warnings += "The script's copy differed from the manifest's hash and was moved aside to $to; undo on the computer itself and the harvest wait for the next apply."
        }
    }
    return $r
}

# A module the manifest shows begun and not finished.
function Test-ErHalfApplied {
    param($Manifest, [string]$Module)
    if ($null -eq $Manifest -or $null -eq $Manifest.modules) { return $false }
    $m = $Manifest.modules.$Module
    return ($null -ne $m -and $m.intent -and -not $m.done)
}

# ---------------------------------------------------------------------------
# What the modules read, each once.

$ErCache = @{}

# secedit's export of the security policy in effect: [System Access] and
# its other sections, by key.
function Get-ErSecurityPolicy {
    if ($ErCache.ContainsKey('secedit')) { return $ErCache.secedit }
    $file = Join-Path $ErWork 'secedit.inf'
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\secedit.exe') @('/export', '/cfg', $file, '/areas', 'SECURITYPOLICY', '/quiet') 120
    $p = @{}
    if ($run.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $p[$Matches[1]] = $Matches[2].Trim('"') }
        }
        Remove-Item -LiteralPath $file -Force
    } else {
        $p = $null
    }
    $ErCache.secedit = $p
    return $p
}

# auditpol's backup: each subcategory's setting by GUID (0 none, 1 success,
# 2 failure, 3 both).
function Get-ErAuditPolicy {
    if ($ErCache.ContainsKey('auditpol')) { return $ErCache.auditpol }
    $file = Join-Path $ErWork 'audit.csv'
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\auditpol.exe') @('/backup', "/file:$file") 60
    $a = $null
    if ($run.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
        $a = @{}
        foreach ($row in @(Import-Csv -LiteralPath $file)) {
            $g = [string]$row.'Subcategory GUID'
            if ($g -match '^\{[0-9A-Fa-f-]{36}\}$') { $a[$g.ToLowerInvariant()] = [int]$row.'Setting Value' }
        }
        Remove-Item -LiteralPath $file -Force
    }
    $ErCache.auditpol = $a
    return $a
}

# Windows' optional features (clients) or Server Manager's features
# (servers), by name: $true installed, $false not.
function Get-ErFeatures {
    if ($ErCache.ContainsKey('features')) { return $ErCache.features }
    $f = @{}
    if ($ErPlatform.Client) {
        foreach ($x in @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)) {
            $f[[string]$x.FeatureName] = @('Enabled', 'EnablePending') -contains [string]$x.State
        }
    } else {
        foreach ($x in @(Get-WindowsFeature -ErrorAction Stop)) {
            $f[[string]$x.Name] = @('Installed', 'InstallPending') -contains [string]$x.InstallState
        }
    }
    $ErCache.features = $f
    return $f
}

function Get-ErMpPreference {
    if (-not $ErCache.ContainsKey('mppref')) {
        try { $ErCache.mppref = Get-MpPreference -ErrorAction Stop } catch { $ErCache.mppref = $null }
    }
    return $ErCache.mppref
}

function Get-ErMpStatus {
    if (-not $ErCache.ContainsKey('mpstatus')) {
        try { $ErCache.mpstatus = Get-MpComputerStatus -ErrorAction Stop } catch { $ErCache.mpstatus = $null }
    }
    return $ErCache.mpstatus
}

# Security Center's antivirus and firewall products other than Microsoft's
# that are on (workstations only; Microsoft says it is not supported on
# servers).
function Get-ErSecurityProducts {
    param([string]$Class)
    $names = @()
    if (-not $ErPlatform.Client) { return , $names }
    try {
        foreach ($p in @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName $Class -ErrorAction Stop -OperationTimeoutSec 30)) {
            $on = (([int64]$p.productState -shr 12) -band 0xF) -eq 1
            $ms = ([string]$p.pathToSignedProductExe) -match '(?i)windows defender|windowsdefender:|%ProgramFiles%\\Windows Defender'
            if ($on -and -not $ms) { $names += Limit-ErText ([string]$p.displayName) 80 }
        }
    } catch {
        $null = $_
    }
    return , $names
}

function Get-ErService {
    param([string]$Name)
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# One setting's result. The owner is asked only when the value is not in
# place: a value as strict as EasyRMM's is in place whoever set it, and is
# listed under managed with its owner.

function New-ErSetting {
    param($Def, [string]$State, $Value, [string]$Want, [string]$Note = '')
    $s = @{ id = [string]$Def.id; state = $State }
    if ($null -ne $Value) { $s.value = Limit-ErText ([string]$Value) 120 }
    if ($Want) { $s.want = $Want }
    if ($Note) { $s.note = Limit-ErText $Note 300 }
    return $s
}

# Compare a value with what the setting wants.
function Test-ErWant {
    param($Def, $Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $false }
    $d = $Def.data
    switch ([string]$Def.want) {
        'eq' { return "$Value" -eq "$d" }
        'min' {
            if ($null -ne $Def.orEq -and "$Value" -eq "$($Def.orEq)") { return $true }
            return [int64]$Value -ge [int64]$d
        }
        'range' { return [int64]$Value -ge [int64]$d -and [int64]$Value -le [int64]$Def.max }
        'in' { return @($d | ForEach-Object { "$_" }) -contains "$Value" }
        'bits' { return ([int64]$Value -band [int64]$d) -eq [int64]$d }
    }
    return $false
}

function Get-ErWantText {
    param($Def)
    switch ([string]$Def.want) {
        'eq' { return "$($Def.data)" }
        'min' { return ">= $($Def.data)" }
        'range' { return "$($Def.data) to $($Def.max)" }
        'in' { return (@($Def.data) -join ' or ') }
        'bits' { return "bits $($Def.data)" }
    }
    return ''
}

# Finish a setting that is not in place: managed elsewhere when an owner
# holds it, check only when the reader cannot tell, not in place when no
# owner holds it (apply would change it).
function Complete-ErSetting {
    param($Setting, $Owner, $Module)
    if ($Setting.state -ne 'not_in_place' -and $Setting.state -ne 'in_place') { return $Setting }
    if ($null -eq $Owner) { return $Setting }
    if ($Owner.Result -eq 'owner') {
        $m = @{ id = $Setting.id; owner = $Owner.Owner; policy = Limit-ErText $Owner.Policy 120; value = Limit-ErText $Owner.Value 120 }
        # ContainsKey: a hashtable without the key answers .item with its
        # own Item property.
        if ($Setting.ContainsKey('item')) { $m.item = $Setting.item }
        if ($Setting.state -eq 'not_in_place') {
            $Setting.state = 'managed_elsewhere'
            $m.state = 'managed_elsewhere'
        } else {
            $m.state = 'in_place'
        }
        $Module.managed += $m
    } elseif ($Owner.Result -eq 'cannot_tell' -and $Setting.state -eq 'not_in_place') {
        $Setting.state = 'check_only'
        $Setting.reasons = @($Owner.Reasons)
        if ($Owner.Mdm) {
            $Setting.mdm = @{ csp = $Owner.Mdm.Csp; config = Limit-ErText $Owner.Mdm.Config 80; current = Limit-ErText $Owner.Mdm.Current 80; provider = Limit-ErText $Owner.Mdm.Provider 80 }
        }
    }
    return $Setting
}

function Test-ErApplies {
    param($Def)
    $o = $Def.only
    if ($null -eq $o) { return $true }
    if ($null -ne $o.client -and [bool]$o.client -ne $ErPlatform.Client) { return $false }
    if ($o.notRoles -and @($o.notRoles) -contains $ErPlatform.Role) { return $false }
    if ($o.minBuild -and $ErPlatform.Build -lt [int]$o.minBuild) { return $false }
    return $true
}

# A registry setting: the value in effect, compared; absent is in place
# where Windows' behaviour without it is EasyRMM's.
function Test-ErRegistrySetting {
    param($Def, $Module)
    $v = Get-ErRegistryValue $Def.path $Def.name
    if ($Def.cite -eq 'not_set') {
        $shown = $(if ($v.Exists) { $v.Data } else { 'not set' })
        return New-ErSetting $Def 'reported' $shown ''
    }
    $want = Get-ErWantText $Def
    if (-not $v.Exists) {
        if ($Def.absent -eq 'in_place') { return New-ErSetting $Def 'in_place' 'not set (Windows default)' $want }
        $s = New-ErSetting $Def 'not_in_place' 'not set' $want
    } elseif (Test-ErWant $Def $v.Data) {
        $s = New-ErSetting $Def 'in_place' $v.Data $want
    } else {
        $s = New-ErSetting $Def 'not_in_place' $v.Data $want
    }
    $owner = Resolve-ErRegistryOwner $ErPolicy $Def.path $Def.name ([string]$Def.csp)
    return Complete-ErSetting $s $owner $Module
}

function Test-ErSecuritySetting {
    param($Def, $Module)
    $p = Get-ErSecurityPolicy
    if ($null -eq $p) { return New-ErSetting $Def 'unknown' $null '' 'secedit did not export the security policy.' }
    $v = $p[[string]$Def.key]
    if ($Def.cite -eq 'not_set') { return New-ErSetting $Def 'reported' $(if ($null -eq $v) { 'not set' } else { $v }) '' }
    $want = Get-ErWantText $Def
    $state = $(if ($null -ne $v -and (Test-ErWant $Def $v)) { 'in_place' } else { 'not_in_place' })
    $s = New-ErSetting $Def $state $(if ($null -eq $v) { 'not set' } else { $v }) $want
    return Complete-ErSetting $s (Resolve-ErSecurityOwner $ErPolicy ([string]$Def.key)) $Module
}

# An effective value read by a module itself, compared by the caller.
function Test-ErValue {
    param($Def, $Module, $Value, [bool]$InPlace, [string]$Want, [switch]$Defender, [string]$Note = '')
    if ($Def.cite -eq 'not_set') { return New-ErSetting $Def 'reported' $Value '' $Note }
    $s = New-ErSetting $Def $(if ($InPlace) { 'in_place' } else { 'not_in_place' }) $Value $Want $Note
    $owner = $null
    if ($Def.path) {
        $owner = Resolve-ErRegistryOwner $ErPolicy $Def.path $Def.name ([string]$Def.csp) -Defender:$Defender
    }
    return Complete-ErSetting $s $owner $Module
}

# A setting's option: with it, the setting counts and wants optionData.
function Get-ErOptionDef {
    param($Def)
    if (-not $Def.option -or -not (Test-ErOption ([string]$Def.option))) { return $Def }
    $d = $Def.PSObject.Copy()
    $d | Add-Member -NotePropertyName cite -NotePropertyValue 'meets' -Force
    if ($null -ne $Def.optionData) {
        $d | Add-Member -NotePropertyName want -NotePropertyValue 'eq' -Force
        $d | Add-Member -NotePropertyName data -NotePropertyValue $Def.optionData -Force
    }
    return $d
}

# ---------------------------------------------------------------------------
# The kinds of setting other than registry and secedit.

function Test-ErSmbSetting {
    param($Def, $Module)
    $key = 'smb-' + $Def.side
    if (-not $ErCache.ContainsKey($key)) {
        if ($Def.side -eq 'server') { $ErCache[$key] = Get-SmbServerConfiguration -ErrorAction Stop }
        else { $ErCache[$key] = Get-SmbClientConfiguration -ErrorAction Stop }
    }
    $v = $ErCache[$key].($Def.property)
    return Test-ErValue $Def $Module $v ("$v" -eq "$($Def.data)") "$($Def.data)"
}

function Test-ErFeatureSetting {
    param($Def)
    $name = $(if ($ErPlatform.Client) { $Def.feature.client } else { $Def.feature.server })
    if (-not $name) { return New-ErSetting $Def 'not_applicable' $null '' }
    $f = Get-ErFeatures
    if (-not $f.ContainsKey($name)) {
        if ($Def.cite -eq 'not_set') { return New-ErSetting $Def 'reported' 'not offered by this Windows' '' }
        return New-ErSetting $Def 'in_place' 'not offered by this Windows' 'not installed'
    }
    $shown = $(if ($f[$name]) { "$name installed" } else { "$name not installed" })
    if ($Def.cite -eq 'not_set') { return New-ErSetting $Def 'reported' $shown '' }
    return New-ErSetting $Def $(if ($f[$name]) { 'not_in_place' } else { 'in_place' }) $shown 'not installed'
}

$ErFirewallDefaults = @{ Enabled = 'True'; DefaultInboundAction = 'Block'; LogBlocked = 'False' }

function Test-ErFirewallSetting {
    param($Def, $Module)
    if (-not $ErCache.ContainsKey('fw')) {
        $ErCache.fw = @{}
        foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) { $ErCache.fw[[string]$p.Name] = $p }
    }
    $p = $ErCache.fw[[string]$Def.profile]
    $v = [string]$p.($Def.property)
    if ($v -eq 'NotConfigured') { $v = $ErFirewallDefaults[[string]$Def.property] }
    $note = ''
    if ($Def.property -eq 'Enabled' -and $v -eq 'False' -and -not $ErPlatform.Client -and -not (Test-ErOption 'firewall-server')) {
        $note = 'A server profile that is off is reported and turned on only with firewall-server, in two steps.'
    }
    return Test-ErValue $Def $Module $v (Test-ErWant $Def $v) (Get-ErWantText $Def) -Defender -Note $note
}

function Test-ErDefenderSetting {
    param($Def, $Module)
    $d = $Def
    $pref = Get-ErMpPreference
    if ($null -eq $pref) { return New-ErSetting $d 'unknown' $null '' 'Microsoft Defender did not report its preferences.' }
    $v = $pref.($d.property)
    if ($v -is [bool]) { $v = [string]$v }
    $realtime = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring') -contains [string]$d.property
    if ($realtime -and -not $ErPlatform.Client -and "$v" -eq 'True' -and -not (Test-ErOption 'defender-server-realtime')) {
        return New-ErSetting $d 'reported' $v '' 'Off on this server: turned on only with defender-server-realtime.'
    }
    $s = Test-ErValue $d $Module $v (Test-ErWant $d $v) (Get-ErWantText $d) -Defender
    if ($s.state -eq 'not_in_place' -and $d.tamper -and $ErPolicy.TamperProtected) {
        $s.state = 'managed_elsewhere'
        $Module.managed += @{ id = $s.id; owner = 'tamper_protection'; policy = 'Tamper Protection'; value = $s.value; state = 'managed_elsewhere' }
    }
    # A local Set-MpPreference value that the policy value apply writes
    # would outrank: one that is not what apply wants. (Windows itself keeps
    # some local values, such as cloud protection's, at their defaults.)
    if ($d.path) {
        $local = Get-ErRegistryValue ($d.path -replace '\\Policies\\Microsoft\\', '\Microsoft\') $d.name
        if ($local.Exists) {
            $lv = $local.Data
            if (@('True', 'False') -contains [string]$d.data) { $lv = $(if ("$lv" -eq '1') { 'True' } else { 'False' }) }
            if (-not (Test-ErWant $d $lv)) { $s.note = "A local setting ($($local.Data)) that a policy value would outrank." }
        }
    }
    return $s
}

function Test-ErSmartScreen {
    param($Def, $Module)
    $d = $Def
    $v = Get-ErRegistryValue $d.path $d.name
    if ($d.name -eq 'EnableSmartScreen') {
        if ($v.Exists) { $shown = [string]$v.Data }
        else {
            $local = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
            $shown = $(if ($local.Exists -and "$($local.Data)" -eq 'Off') { '0' } else { '1' })
        }
        return Test-ErValue $d $Module $shown ($shown -eq '1') '1'
    }
    $shown = $(if ($v.Exists) { [string]$v.Data } else { 'Warn' })
    return Test-ErValue $d $Module $shown (Test-ErWant $d $shown) (Get-ErWantText $d)
}

function Test-ErAsrSetting {
    param($Def, $Module)
    $pref = Get-ErMpPreference
    if ($null -eq $pref) { return New-ErSetting $Def 'unknown' $null '' 'Microsoft Defender did not report its preferences.' }
    $ids = @($pref.AttackSurfaceReductionRules_Ids | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $actions = @($pref.AttackSurfaceReductionRules_Actions)
    $i = [array]::IndexOf($ids, [string]$Def.rule)
    $v = $(if ($i -ge 0 -and $i -lt $actions.Count) { [int]$actions[$i] } else { 5 })
    $names = @{ 0 = 'off'; 1 = 'block'; 2 = 'audit'; 5 = 'not configured'; 6 = 'warn' }
    $block = [bool]$Def.block
    if ($Def.rule -eq 'e6db77e5-3df2-4cf1-b95a-636979351e5b' -and $ErPolicy.ConfigMgr) { $block = $false }
    if ($ErOptions['asr-block'] -and @($ErOptions['asr-block']) -contains [string]$Def.rule) { $block = $true }
    $ok = $(if ($block) { $v -eq 1 } else { @(1, 2, 6) -contains $v })
    $want = $(if ($block) { 'block' } else { 'audit' })
    $path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $s = New-ErSetting $Def $(if ($ok) { 'in_place' } else { 'not_in_place' }) $names[$v] $want
    $owner = Resolve-ErRegistryOwner $ErPolicy $path ([string]$Def.rule) ([string]$Def.csp) -Defender
    return Complete-ErSetting $s $owner $Module
}

# WinRM: a policy value wins over the local configuration, which wins over
# Windows' default.
function Test-ErWinRmSetting {
    param($Def, $Module)
    $p = Get-ErRegistryValue $Def.path $Def.name
    if ($p.Exists) { $v = [string]$p.Data }
    else {
        $l = Get-ErRegistryValue $Def.localPath $Def.localName
        $v = $(if ($l.Exists) { [string]$l.Data } else { [string]$Def.default })
    }
    $note = ''
    if ($v -ne '0' -and $Def.localName -and -not (Test-ErOption 'winrm-basic-off')) {
        $note = 'On here: left and reported unless winrm-basic-off is given.'
    }
    return Test-ErValue $Def $Module $v ($v -eq "$($Def.data)") "$($Def.data)" -Note $note
}

function Test-ErSchannelSetting {
    param($Def, $Module)
    $e = Get-ErRegistryValue $Def.path 'Enabled'
    $dbd = Get-ErRegistryValue $Def.path 'DisabledByDefault'
    if ($e.Exists) {
        return Test-ErValue $Def $Module "Enabled=$($e.Data)" ("$($e.Data)" -eq '0') 'Enabled=0'
    }
    if ($dbd.Exists -and "$($dbd.Data)" -eq '1') {
        return Test-ErValue $Def $Module 'DisabledByDefault=1' $false 'Enabled=0' -Note 'Off unless a program asks for it by name.'
    }
    # Windows' defaults: SSL 2.0 and 3.0 off on every version the agent
    # supports; TLS 1.0 and 1.1 on before build 26100, and on 26100 and
    # later Microsoft's pages disagree, so the check does not guess.
    if ($Def.id -like 'tls-ssl*') { return New-ErSetting $Def 'in_place' 'not set (Windows default: off)' 'Enabled=0' }
    if ($ErPlatform.Build -lt 26100) { return Test-ErValue $Def $Module 'not set (Windows default: on)' $false 'Enabled=0' }
    return New-ErSetting $Def 'unknown' 'not set' 'Enabled=0' 'Microsoft''s pages disagree on whether this version turns it off by default.'
}

# ---------------------------------------------------------------------------
# Settings no kind covers, by ID.

function Test-ErCustomSetting {
    param($Def, $Module)
    switch ([string]$Def.id) {
        'lsa-protection-value' {
            $v = Get-ErRegistryValue $Def.path 'RunAsPPL'
            $boot = Get-ErRegistryValue $Def.path 'RunAsPPLBoot'
            $want = $(if (Test-ErOption 'lsa-uefi-lock') { @('1') } else { @('1', '2') })
            $shown = $(if ($v.Exists) { "RunAsPPL=$($v.Data)" } elseif ($boot.Exists) { "RunAsPPLBoot=$($boot.Data)" } else { 'not set' })
            $data = $(if ($v.Exists) { "$($v.Data)" } elseif ($boot.Exists) { "$($boot.Data)" } else { '' })
            return Test-ErValue $Def $Module $shown ($want -contains $data) ($want -join ' or ')
        }
        'lsa-protection-running' {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12; StartTime = $os.LastBootUpTime } -MaxEvents 1 -ErrorAction SilentlyContinue)
            if ($e.Count -gt 0) { return New-ErSetting $Def 'in_place' "level $($e[0].Properties[0].Value)" 'protected' }
            return New-ErSetting $Def 'not_in_place' 'not recorded since the last start' 'protected'
        }
        'powershell-script-block-logging' {
            $row = @($ErAudit.values | Where-Object { $_.id -eq 'script-block-logging' })[0]
            $v = Get-ErRegistryValue $row.path $row.name
            return New-ErSetting $Def 'reported' $(if ($v.Exists) { $v.Data } else { 'not set' }) '' 'Set by log collection''s Configure logging.'
        }
        'rdp-nla' { return Test-ErRdpSetting $Def $Module 'UserAuthenticationRequired' 'UserAuthentication' '1' }
        'rdp-encryption' { return Test-ErRdpSetting $Def $Module 'MinEncryptionLevel' 'MinEncryptionLevel' '3' }
        'uac-on' {
            $v = Get-ErRegistryValue $Def.path $Def.name
            $on = -not $v.Exists -or "$($v.Data)" -ne '0'
            if (-not $on -and -not (Test-ErOption 'uac-enable')) { return New-ErSetting $Def 'reported' '0' '' 'UAC is off: turned on only with uac-enable (a restart).' }
            return Test-ErValue $Def $Module $(if ($on) { '1' } else { '0' }) $on '1'
        }
        'printing-spooler' { return Test-ErSpooler $Def }
        'device-guard-vbs' { return Test-ErDeviceGuard $Def 'vbs' }
        'device-guard-hvci' { return Test-ErDeviceGuard $Def 2 }
        'device-guard-credential-guard' { return Test-ErDeviceGuard $Def 1 }
        'bitlocker-protected' { return Test-ErBitLocker $Def 'protected' }
        'bitlocker-preboot-pin' { return Test-ErBitLocker $Def 'pin' }
        'bitlocker-recovery-password' { return Test-ErBitLocker $Def 'recovery' }
        'laps-managed' { return Test-ErLaps $Def }
        'audit-subcategories' { return Test-ErAuditSubcategories $Def $Module }
        'audit-legacy-overridden' { return Test-ErAuditValue $Def $Module 'legacy-categories-overridden' }
        'audit-command-lines' { return Test-ErAuditValue $Def $Module 'process-command-lines' }
        'audit-log-sizes' { return Test-ErAuditLogs $Def $Module }
    }
    throw "no check for $($Def.id)"
}

function Test-ErRdpSetting {
    param($Def, $Module, [string]$WmiName, [string]$RegName, [string]$Want)
    $v = $null
    try {
        $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop -OperationTimeoutSec 30
        if ($ts) { $v = [string]$ts.$WmiName }
    } catch {
        $v = $null
    }
    if ($null -eq $v -or $v -eq '') {
        $r = Get-ErRegistryValue 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' $RegName
        $v = $(if ($r.Exists) { [string]$r.Data } else { 'not set' })
    }
    $ok = $(if ($WmiName -eq 'MinEncryptionLevel') { $v -match '^\d+$' -and [int]$v -ge [int]$Want } else { $v -eq $Want })
    return Test-ErValue $Def $Module $v $ok $(if ($WmiName -eq 'MinEncryptionLevel') { ">= $Want" } else { $Want })
}

function Test-ErSpooler {
    param($Def)
    $svc = Get-ErService 'Spooler'
    if ($null -eq $svc) { return New-ErSetting $Def 'in_place' 'not installed' 'stopped and disabled' }
    $shown = "$($svc.State), $($svc.StartMode)"
    $off = $svc.StartMode -eq 'Disabled' -and $svc.State -eq 'Stopped'
    $counted = $ErPlatform.Role -eq 'domain_controller' -or (Test-ErOption 'spooler-off')
    if (-not $off) {
        $why = @()
        if (@(Get-CimInstance -ClassName Win32_Printer -Filter 'Shared=TRUE' -ErrorAction SilentlyContinue).Count -gt 0) { $why += 'shares a printer' }
        $f = Get-ErFeatures
        if ($f['Print-Server']) { $why += 'has the Print Server role' }
        if ($f['RDS-RD-Server']) { $why += 'is a Remote Desktop session host' }
        if ($why.Count -gt 0) { return New-ErSetting $Def 'not_applicable' $shown '' ('Left: this server ' + ($why -join ', ') + '.') }
        if (-not $counted) { return New-ErSetting $Def 'reported' $shown '' 'Stopped on domain controllers, and on other servers only with spooler-off.' }
    }
    return New-ErSetting $Def $(if ($off) { 'in_place' } else { 'not_in_place' }) $shown 'stopped and disabled'
}

function Test-ErDeviceGuard {
    param($Def, $What)
    if (-not $ErCache.ContainsKey('dg')) {
        $ErCache.dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    }
    $dg = $ErCache.dg
    if ($null -eq $dg) { return New-ErSetting $Def 'unknown' $null '' 'Windows did not report Device Guard''s state.' }
    if ($What -eq 'vbs') {
        $v = [int]$dg.VirtualizationBasedSecurityStatus
        $names = @{ 0 = 'off'; 1 = 'on, not running'; 2 = 'running' }
        return New-ErSetting $Def $(if ($v -eq 2) { 'in_place' } else { 'not_in_place' }) $names[$v] 'running'
    }
    $running = @($dg.SecurityServicesRunning) -contains [uint32]$What
    return New-ErSetting $Def $(if ($running) { 'in_place' } else { 'not_in_place' }) $(if ($running) { 'running' } else { 'not running' }) 'running'
}

# BitLocker through its WMI provider, which is there whenever BitLocker
# is: the system volume's protection, and its key protectors by type (1
# TPM, 3 recovery password, 4 TPM and PIN, 6 TPM, PIN and startup key).
function Get-ErBitLocker {
    if (-not $ErCache.ContainsKey('bl')) {
        $ErCache.bl = $null
        try {
            $vol = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($env:SystemDrive)'" -ErrorAction Stop
            if ($vol) {
                $types = @()
                $ids = (Invoke-CimMethod -InputObject $vol -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 } -ErrorAction Stop).VolumeKeyProtectorID
                foreach ($id in @($ids)) {
                    $types += [int](Invoke-CimMethod -InputObject $vol -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $id } -ErrorAction Stop).KeyProtectorType
                }
                $status = (Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus -ErrorAction Stop).ProtectionStatus
                $ErCache.bl = @{ On = ([int]$status -eq 1); Types = $types }
            }
        } catch {
            $ErCache.bl = $null
        }
    }
    return $ErCache.bl
}

function Test-ErBitLocker {
    param($Def, [string]$What)
    $bl = Get-ErBitLocker
    switch ($What) {
        'protected' { return New-ErSetting $Def $(if ($bl.On) { 'in_place' } else { 'not_in_place' }) $(if ($bl.On) { 'on' } else { 'off' }) 'on' }
        'pin' {
            $pin = ($bl.Types -contains 4) -or ($bl.Types -contains 6)
            return New-ErSetting $Def $(if ($pin) { 'in_place' } else { 'not_in_place' }) ('protectors ' + (($bl.Types | Sort-Object -Unique) -join ',')) 'TPM and PIN'
        }
        'recovery' { return New-ErSetting $Def $(if ($bl.Types -contains 3) { 'in_place' } else { 'not_in_place' }) $(if ($bl.Types -contains 3) { 'yes' } else { 'no' }) 'yes' }
    }
}

# Windows LAPS, by its policy (from Group Policy or the LAPS CSP), or
# legacy Microsoft LAPS's.
function Test-ErLaps {
    param($Def)
    $dirs = @{ '1' = 'Entra ID'; '2' = 'Active Directory' }
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS') {
        $v = Get-ErRegistryValue $p 'BackupDirectory'
        if ($v.Exists -and $dirs["$($v.Data)"]) { return New-ErSetting $Def 'in_place' ('Windows LAPS to ' + $dirs["$($v.Data)"]) 'managed' }
    }
    $legacy = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    if ($legacy.Exists -and "$($legacy.Data)" -eq '1') { return New-ErSetting $Def 'in_place' 'legacy Microsoft LAPS' 'managed' }
    return New-ErSetting $Def 'not_in_place' 'not managed' 'managed'
}

# The audit table (ADR-0060): each subcategory by GUID, with its owner.
function Test-ErAuditSubcategories {
    param($Def, $Module)
    $a = Get-ErAuditPolicy
    if ($null -eq $a) { return , @(New-ErSetting $Def 'unknown' $null '' 'auditpol did not report the audit policy.') }
    $bits = @{ success = 1; failure = 2; success_failure = 3 }
    $override = Get-ErRegistryValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    $out = @()
    foreach ($row in @($ErAudit.subcategories)) {
        if ($row.set -eq 'left') { continue }
        if ($row.domainControllersOnly -and $ErPlatform.Role -ne 'domain_controller') { continue }
        $v = $a[[string]$row.guid]
        $want = $bits[[string]$row.set]
        $s = New-ErSetting $Def $(if ($null -ne $v -and ($v -band $want) -eq $want) { 'in_place' } else { 'not_in_place' }) (ConvertTo-ErAuditSetting ([int]$v)) $row.set
        $s.item = [string]$row.guid
        $owner = Resolve-ErAuditOwner $ErPolicy ([string]$row.guid) ($override.Exists -and "$($override.Data)" -eq '1')
        $out += Complete-ErSetting $s $owner $Module
    }
    return , $out
}

function Test-ErAuditValue {
    param($Def, $Module, [string]$Row)
    $r = @($ErAudit.values | Where-Object { $_.id -eq $Row })[0]
    $d = $Def.PSObject.Copy()
    $d | Add-Member -NotePropertyName path -NotePropertyValue $r.path -Force
    $d | Add-Member -NotePropertyName name -NotePropertyValue $r.name -Force
    $d | Add-Member -NotePropertyName want -NotePropertyValue 'eq' -Force
    $d | Add-Member -NotePropertyName data -NotePropertyValue $r.data -Force
    return Test-ErRegistrySetting $d $Module
}

function Test-ErAuditLogs {
    param($Def, $Module)
    $pwsh = Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
    $out = @()
    foreach ($row in @($ErAudit.logs)) {
        if ($row.onlyWith -eq 'pwsh' -and -not $pwsh) { continue }
        $log = Get-WinEvent -ListLog ([string]$row.channel) -ErrorAction SilentlyContinue
        $kb = $(if ($log) { [int64]($log.MaximumSizeInBytes / 1024) } else { $null })
        $s = New-ErSetting $Def $(if ($null -ne $kb -and $kb -ge [int64]$row.minKB) { 'in_place' } else { 'not_in_place' }) $(if ($null -ne $kb) { "$kb KB" } else { 'no such log' }) ">= $($row.minKB) KB"
        $s.item = [string]$row.channel
        $owner = $null
        if (@('Security', 'System', 'Application') -contains [string]$row.channel) {
            $owner = Resolve-ErRegistryOwner $ErPolicy "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$($row.channel)" 'MaxSize'
        }
        $out += Complete-ErSetting $s $owner $Module
    }
    return , $out
}

# ---------------------------------------------------------------------------
# Modules.

# Failed sign-ins from public addresses in the Security log, as far back
# as it reaches up to 7 days: an exposed computer gets no lockout unless
# lockout-exposed is given.
function Get-ErExposure {
    $since = (Get-Date).AddDays(-7)
    $accounts = @{}
    $addresses = @{}
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
        $ip = $data['IpAddress']
        if (-not $ip -or $ip -eq '-' -or $ip -match '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)') { continue }
        $accounts[$data['TargetUserName']] = $true
        $addresses[$ip] = $true
    }
    $first = @(Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue)
    $reach = $(if ($first.Count -gt 0 -and $first[0].TimeCreated -gt $since) { $first[0].TimeCreated.ToUniversalTime().ToString('o') } else { $since.ToUniversalTime().ToString('o') })
    return @{
        Exposed = $addresses.Count -gt 0
        Accounts = @($accounts.Keys | Select-Object -First 10 | ForEach-Object { Limit-ErText $_ 64 })
        Addresses = @($addresses.Keys | Select-Object -First 10)
        Since = $reach
    }
}

# What stops a whole module before its settings are read.
function Get-ErModuleGate {
    param([string]$Name, $Module)
    switch ($Name) {
        { $_ -eq 'defender' -or $_ -eq 'asr' } {
            $st = Get-ErMpStatus
            $av = Get-ErSecurityProducts 'AntiVirusProduct'
            if ($av.Count -gt 0) {
                foreach ($n in $av) { $Module.managed += @{ id = $Name; owner = 'security_product'; policy = $n; value = 'on'; state = 'managed_elsewhere' } }
                return @{ state = 'managed_elsewhere'; reason = 'Another antivirus is on: ' + ($av -join ', ') + '.' }
            }
            if ($null -eq $st) { return @{ state = 'not_applicable'; reason = 'Microsoft Defender Antivirus is not installed or not running.' } }
            $mode = [string]$st.AMRunningMode
            if ($mode -and $mode -ne 'Normal') {
                return @{ state = $(if ($ErPlatform.Client) { 'managed_elsewhere' } else { 'not_applicable' }); reason = "Microsoft Defender Antivirus runs in $mode, beside another antivirus." }
            }
            if ($Name -eq 'asr' -and $ErPlatform.Build -eq 14393 -and -not $ErPolicy.DefenderForEndpoint) {
                return @{ state = 'not_supported'; reason = 'Attack surface reduction rules on Server 2016 need onboarding with Defender for Endpoint''s unified solution.' }
            }
        }
        'firewall' {
            $fw = Get-ErSecurityProducts 'FirewallProduct'
            if ($fw.Count -gt 0) {
                foreach ($n in $fw) { $Module.managed += @{ id = $Name; owner = 'security_product'; policy = $n; value = 'on'; state = 'managed_elsewhere' } }
                return @{ state = 'managed_elsewhere'; reason = 'Another firewall is on: ' + ($fw -join ', ') + '.' }
            }
            $svc = Get-ErService 'MpsSvc'
            if ($null -eq $svc -or $svc.State -ne 'Running') { $Module.notes += 'The Windows Defender Firewall service is not running.' }
        }
        'uac' {
            if ($ErPlatform.Core) { return @{ state = 'not_applicable'; reason = 'Server Core has no UAC prompts.' } }
        }
        'bitlocker' {
            if ($null -eq (Get-ErBitLocker)) { return @{ state = 'not_applicable'; reason = 'BitLocker is not installed.' } }
        }
        'accounts' {
            $x = Get-ErExposure
            $Module.exposure = @{ exposed = $x.Exposed; accounts = $x.Accounts; addresses = $x.Addresses; since = $x.Since }
            if ($x.Exposed -and -not (Test-ErOption 'lockout-exposed')) {
                $Module.notes += 'Failed sign-ins from public addresses: apply sets no lockout here unless lockout-exposed is given.'
            }
        }
    }
    return $null
}

function Invoke-ErModule {
    param([string]$Name)
    $m = @{ module = $Name; settings = @(); managed = @(); notes = @() }
    $gate = Get-ErModuleGate $Name $m
    if ($gate) {
        $m.state = $gate.state
        $m.reason = $gate.reason
        return $m
    }
    foreach ($def in @($ErSettings | Where-Object { $_.module -eq $Name })) {
        if (-not (Test-ErApplies $def)) {
            $m.settings += New-ErSetting $def 'not_applicable' $null ''
            continue
        }
        $d = Get-ErOptionDef $def
        $r = switch ([string]$d.kind) {
            'registry' { Test-ErRegistrySetting $d $m }
            'secedit' { Test-ErSecuritySetting $d $m }
            'smb' { Test-ErSmbSetting $d $m }
            'feature' { Test-ErFeatureSetting $d }
            'firewall' { Test-ErFirewallSetting $d $m }
            'defender' { Test-ErDefenderSetting $d $m }
            'smartscreen' { Test-ErSmartScreen $d $m }
            'asr' { Test-ErAsrSetting $d $m }
            'winrm' { Test-ErWinRmSetting $d $m }
            'schannel' { Test-ErSchannelSetting $d $m }
            default { Test-ErCustomSetting $d $m }
        }
        foreach ($x in @($r)) { $m.settings += $x }
    }
    $counted = @($m.settings | Where-Object { @('reported', 'not_applicable') -notcontains $_.state })
    $in = @($counted | Where-Object { $_.state -eq 'in_place' }).Count
    $elsewhere = @($counted | Where-Object { $_.state -eq 'managed_elsewhere' }).Count
    if ($counted.Count -eq 0) {
        $m.state = 'not_applicable'
        $m.reason = 'None of its settings applies to this computer.'
    } elseif ($in -eq $counted.Count) {
        $m.state = 'in_place'
    } elseif ($elsewhere + $in -eq $counted.Count -and $elsewhere -gt 0) {
        $m.state = 'managed_elsewhere'
        $m.reason = 'Settings that are not in place are held by another owner.'
    } elseif ($in -gt 0 -or $elsewhere -gt 0) {
        $m.state = 'partly'
    } else {
        $m.state = 'not_in_place'
    }
    return $m
}

# ---------------------------------------------------------------------------
# The run.

function Write-ErResult {
    param($Platform, $Modules)
    $max = 60000
    $line = ConvertTo-ErAscii (@{ version = 1; mode = $ErMode; platform = $Platform; modules = $Modules } | ConvertTo-Json -Depth 12 -Compress)
    if ($line.Length -gt $max) {
        # Too long: settings in place are left out, then every setting.
        foreach ($m in $Modules) {
            if ($m.settings) {
                $m.settings = @($m.settings | Where-Object { $_.state -ne 'in_place' })
                $m.settingsOmitted = 'in_place'
            }
        }
        $line = ConvertTo-ErAscii (@{ version = 1; mode = $ErMode; platform = $Platform; modules = $Modules } | ConvertTo-Json -Depth 12 -Compress)
    }
    if ($line.Length -gt $max) {
        foreach ($m in $Modules) {
            $m.settings = @()
            $m.managed = @()
            $m.settingsOmitted = 'all'
        }
        $line = ConvertTo-ErAscii (@{ version = 1; mode = $ErMode; platform = $Platform; modules = $Modules } | ConvertTo-Json -Depth 12 -Compress)
    }
    Say "$ErResultTag $line"
}

function Get-ErPlatformExtra {
    param($Folder)
    $owners = @{
        groupPolicyRecord = $(if ($ErPolicy.GpRecordOff) { 'off' } elseif ($ErPolicy.GpRecordRead) { 'read' } else { 'unread' })
        groupPolicyPreferences = $ErPolicy.GpPreferences
        mdm = $ErPolicy.Mdm; mdmWinsOverGp = $ErPolicy.MdmWinsOverGp
        defenderForEndpoint = $ErPolicy.DefenderForEndpoint; configMgr = $ErPolicy.ConfigMgr; dsc = $ErPolicy.Dsc
        azureMachineConfiguration = $ErPolicy.AzureMachineConfiguration; tamperProtected = $ErPolicy.TamperProtected
        osConfig = @($ErPolicy.OSConfigScenarios | ForEach-Object { Limit-ErText $_ 128 } | Select-Object -First 20)
    }
    # What makes apply check only on this computer (ADR-0054, Platforms).
    $reasons = @() + (Get-ErComputerReasons $ErPolicy)
    if ($ErPolicy.GpPreferences) { $reasons += 'group_policy_preferences' }
    if ($ErPolicy.Mdm) { $reasons += 'mdm' }
    return @{
        owners = $owners
        checkOnlyReasons = $reasons
        notes = @($ErPolicy.Notes | ForEach-Object { Limit-ErText $_ 200 } | Select-Object -First 10)
        hardening = @{ folder = $Folder.Folder; copySha256 = $Folder.CopySha256; warnings = @($Folder.Warnings); setAside = @($Folder.SetAside) }
    }
}

Say "EasyRMM hardening ($ErMode) on Windows build $($ErPlatform.Build).$($ErPlatform.Ubr), $($ErPlatform.Role), support: $ErSupport"
$ErWork = New-ErWorkFolder 'easyrmm-hardening-'
$ErFolder = $null
try {
    try {
        $ErFolder = Open-ErHardening
    } catch {
        $ErFolder = @{ Folder = 'refused'; Refusal = 'The Hardening folder could not be checked: ' + $_.Exception.Message; Warnings = @(); SetAside = @(); Lock = $null; Manifest = $null; CopySha256 = '' }
    }
    $ErPolicy = Get-ErPolicyContext $ErWork
    $platformJson = ConvertTo-ErPlatformJson $ErPlatform $ErSupport $ErLanguageMode (Get-ErPlatformExtra $ErFolder)
    $modules = @()
    if ($ErFolder.Refusal) {
        Say "Refused: $($ErFolder.Refusal)"
        foreach ($name in $ErArgs.Modules) { $modules += @{ module = $name; state = 'not_supported'; reason = Limit-ErText $ErFolder.Refusal 300 } }
    } elseif ($ErSupport -eq 'unsupported') {
        foreach ($name in $ErArgs.Modules) { $modules += @{ module = $name; state = 'not_supported'; reason = "Windows build $($ErPlatform.Build) has not been tested with this script." } }
    } else {
        foreach ($name in $ErArgs.Modules) {
            Say "Checking $name"
            try {
                $m = Invoke-ErModule $name
            } catch {
                $m = @{ module = $name; state = 'failed'; reason = Limit-ErText ("The check stopped: " + $_.Exception.Message) 300 }
            }
            if (Test-ErHalfApplied $ErFolder.Manifest $name) {
                $m.state = 'half_applied'
                $m.reason = 'An apply or undo of this module began and did not finish.'
            }
            Say "  $($m.state)"
            $modules += $m
        }
    }
    Write-ErResult $platformJson $modules
} finally {
    if ($ErFolder -and $ErFolder.Lock) { $ErFolder.Lock.Dispose() }
    Remove-Item -LiteralPath $ErWork -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
