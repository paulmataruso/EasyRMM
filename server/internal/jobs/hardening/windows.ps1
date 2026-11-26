# EasyRMM hardening for Windows computers and servers (ADR-0054), run by the
# EasyRMM agent as LocalSystem with Windows PowerShell 5.1. This release has
# four modes. check: for each chosen module it reports whether the module's
# settings are in effect, who else owns each (Group Policy, Tamper
# Protection, another antivirus or firewall) or why that cannot be told (an
# MDM, OSConfig and the others of internal/winpolicy, whose reader this
# script includes), and what apply would change on this computer. It
# changes nothing (see "What check writes"). apply and undo (ADR-0054, W2)
# write and put back the registry settings, keeping each value's earlier
# state in the manifest; confirm ends the connectivity guard (see "Apply,
# undo and the guard").
#
# Arguments, which are never part of this script's text. The EasyRMM server
# accepts only the names and forms below, and this script checks them again:
#   check|apply|undo <modules> [option ...]
#   check|apply|undo --settings ID,ID [option ...]
#   confirm
#   --settings             setting ids from windows-settings.json instead of
#                          modules (ADR-0078): only those settings are read,
#                          changed or put back
#   guard-minutes=N        apply only: after a change, a task on the computer
#                          undoes it in N minutes (1 to 60) unless confirm
#                          ends it first; rolled-back marks that undo
#   <modules>              all, or a comma-separated list of accounts,
#                          firewall, defender, asr, smb, smb-signing, ntlm,
#                          wdigest, lsa-protection, name-resolution,
#                          powershell, rdp, uac, autoplay, anonymous, winrm,
#                          printing, features, tls, audit, device-guard,
#                          bitlocker, laps, session, removable, mobile-code,
#                          rights, time, app-control and office
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
# write to files (secedit /export, auditpol /backup, gpresult /x, netsh wfp
# show state) into a
# folder it makes under %SystemRoot%\Temp that only SYSTEM and
# Administrators can reach, and removes it before it ends. Where the
# Hardening folder exists, it opens its lock file (creating it if missing),
# and, as ADR-0054 requires of every mode, it may set an access list there
# back to the protected one, or move a file that fails the folder check
# aside within the folder.
#
# Apply, undo and the guard. Apply writes only registry settings in this
# release (the other kinds are reported as skipped, with why). Before a
# module changes it writes its intent and each value's earlier state to
# the manifest, writes each value, reads it back and puts it back when it
# is not as intended; undo puts back each value that is still as apply
# left it and leaves, and reports, any other. When apply changed something
# and guard-minutes was given, a scheduled task (SYSTEM, from the script's
# copy in the Hardening folder) undoes exactly those settings when its
# time comes. The server queues a confirm job after each such apply; the
# job can only run where the agent is reachable, and removes the task. An
# agent that is cut off therefore loses the change by itself.
#
# The record, which apply and undo write and check reads:
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
    'audit', 'device-guard', 'bitlocker', 'laps', 'session', 'removable', 'mobile-code', 'rights', 'time', 'app-control', 'office')
# Each option and the module it belongs to; domain-controller belongs to
# every module.
$ErOptionModule = @{
    'allow-tcp' = 'firewall'; 'allow-udp' = 'firewall'; 'ports-checked' = 'firewall'; 'firewall-server' = 'firewall'
    'domain-controller' = ''; 'defender-server-realtime' = 'defender'; 'smartscreen-block' = 'defender'
    'cloud-block-high' = 'defender'; 'asr-block' = 'asr'; 'lsa-uefi-lock' = 'lsa-protection'
    'lsa-unaudited' = 'lsa-protection'; 'lockout-exposed' = 'accounts'; 'uac-enable' = 'uac'
    'uac-builtin-admin' = 'uac'; 'deny-user-elevation' = 'uac'; 'winrm-basic-off' = 'winrm'; 'spooler-off' = 'printing'
    'guard-minutes' = ''; 'rolled-back' = ''
}
$ErListOptions = @('allow-tcp', 'allow-udp', 'asr-block')

function Read-ErArguments {
    param([string[]]$Arguments)
    $r = @{ Mode = ''; Modules = @(); Settings = @(); Options = @{}; Error = '' }
    if ($Arguments.Count -lt 1) { $r.Error = 'no mode given.'; return $r }
    $r.Mode = $Arguments[0]
    if (@('check', 'apply', 'undo', 'confirm') -notcontains $r.Mode) { $r.Error = "unknown mode: $($r.Mode)."; return $r }
    if ($r.Mode -eq 'confirm') {
        if ($Arguments.Count -gt 1) { $r.Error = 'confirm takes no arguments.' }
        return $r
    }
    if ($Arguments.Count -lt 2) { $r.Error = 'no modules given.'; return $r }
    $chosen = @()
    $next = 2
    if ($Arguments[1] -eq '--settings') {
        # Setting ids, checked against the settings file; the modules are
        # those the settings belong to.
        if ($Arguments.Count -lt 3 -or $Arguments[2] -eq '') { $r.Error = 'no setting ids given.'; return $r }
        $known = @((ConvertFrom-Json $ErSettingsJson).settings)
        $ids = @()
        foreach ($id in ($Arguments[2] -split ',')) {
            $def = @($known | Where-Object { $_.id -eq $id })
            if ($def.Count -ne 1) { $r.Error = "unknown setting: $id."; return $r }
            if ($ids -notcontains $id) { $ids += $id; $chosen += [string]$def[0].module }
        }
        # The settings file's order, whatever the order given.
        $r.Settings = @($known | Where-Object { $ids -contains $_.id } | ForEach-Object { [string]$_.id })
        $next = 3
    } elseif ($Arguments[1] -eq 'all') {
        $chosen = $ErAllModules
    } else {
        foreach ($m in ($Arguments[1] -split ',')) {
            if ($ErAllModules -notcontains $m) { $r.Error = "unknown module: $m."; return $r }
            if ($chosen -notcontains $m) { $chosen += $m }
        }
    }
    # The script's own order, whatever the order given.
    $r.Modules = @($ErAllModules | Where-Object { $chosen -contains $_ })
    for ($i = $next; $i -lt $Arguments.Count; $i++) {
        $name, $value = $Arguments[$i] -split '=', 2
        if (-not $ErOptionModule.ContainsKey($name)) { $r.Error = "unknown option: $name."; return $r }
        $module = $ErOptionModule[$name]
        if ($module -and $r.Modules -notcontains $module) { $r.Error = "option $name needs module $module."; return $r }
        if ($name -eq 'guard-minutes') {
            if ($r.Mode -ne 'apply') { $r.Error = 'guard-minutes is for apply.'; return $r }
            if ($value -notmatch '^[1-9][0-9]?$' -or [int]$value -gt 60) { $r.Error = 'guard-minutes is a number of minutes from 1 to 60.'; return $r }
            $r.Options[$name] = [int]$value
            continue
        }
        if ($name -eq 'rolled-back' -and $r.Mode -ne 'undo') { $r.Error = 'rolled-back is for undo.'; return $r }
        if ($r.Mode -eq 'undo' -and @('domain-controller', 'rolled-back') -notcontains $name) { $r.Error = 'undo takes no options but domain-controller.'; return $r }
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
# and MDM enrolment, read with cmdlets only. What cannot be read is
# unknown, never a guess: the role and join as 'unknown' and the MDM
# enrolment as $null, with why in Unread (the reader's own note says why
# the enrolments could not be read); Get-ErPlatformExtra makes such a
# computer check only.
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
    $unread = @()
    $role = 'unknown'
    $domain = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($null -eq $cs) { throw 'Windows listed no computer system.' }
        switch ([int]$cs.DomainRole) {
            0 { $role = 'workstation' }
            1 { $role = 'workstation' }
            2 { $role = 'standalone_server' }
            3 { $role = 'member_server' }
            4 { $role = 'domain_controller' }
            5 { $role = 'domain_controller' }
            default { $unread += "Windows reported a domain role this script does not know: $($cs.DomainRole)." }
        }
        $domain = [bool]$cs.PartOfDomain
    } catch {
        $unread += "Windows did not report the computer's role and domain: $($_.Exception.Message)"
    }
    $entra = $false
    $join = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    # Test-Path is true for a key that exists and cannot be read.
    if (Test-Path -LiteralPath $join) {
        $failed = $null
        $joins = @(Get-ChildItem -LiteralPath $join -ErrorAction SilentlyContinue -ErrorVariable failed)
        if ($failed) {
            $entra = $null
            $unread += "Whether the computer is joined to Entra ID could not be read: $($failed[0].Exception.Message)"
        } else {
            $entra = $joins.Count -gt 0
        }
    }
    $joined = 'unknown'
    if ($null -ne $domain -and $null -ne $entra) {
        $joined = 'none'
        if ($domain -and $entra) { $joined = 'domain_entra' } elseif ($domain) { $joined = 'domain' } elseif ($entra) { $joined = 'entra' }
    }
    $enrolments = Get-ErMdmProviders
    $mdm = $(if ($enrolments.Error) { $null } else { $enrolments.Providers.Count -gt 0 })
    $arch = "$env:PROCESSOR_ARCHITECTURE".ToLowerInvariant()
    if ($arch -eq 'x86' -and $env:PROCESSOR_ARCHITEW6432) { $arch = "$env:PROCESSOR_ARCHITEW6432".ToLowerInvariant() }
    $edition = ''
    $install = ''
    if ($cv) { $edition = [string]$cv.EditionID; $install = [string]$cv.InstallationType }
    return @{
        Build = $build; Ubr = $ubr; DisplayVersion = $display; Edition = $edition; InstallationType = $install
        Role = $role; Joined = $joined; Mdm = $mdm; Architecture = $arch
        Client = ($install -eq 'Client'); Core = ($install -eq 'Server Core'); Unread = $unread
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
    if ($ErArgs.Mode -eq 'confirm') {
        # The guard's end needs only cmdlets.
        Unregister-ScheduledTask -TaskName 'EasyRMM Hardening Rollback' -TaskPath '\EasyRMM\' -Confirm:$false -ErrorAction SilentlyContinue
        exit 0
    }
    $p = Get-ErPlatform
    $mods = @()
    foreach ($m in $ErArgs.Modules) {
        $mods += @{ module = $m; state = 'not_supported'; reason = "PowerShell runs in $ErLanguageMode mode here (App Control or AppLocker), in which this script cannot read what it checks." }
        if ($ErArgs.Mode -eq 'apply' -or $ErArgs.Mode -eq 'undo') { $mods[-1].outcome = 'refused'; $mods[-1].outcomeReason = $mods[-1].reason }
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
    [Console]::Error.WriteLine('Usage: windows.ps1 check|apply|undo <all|module,...|--settings id,...> [allow-tcp=LIST] [allow-udp=LIST] [asr-block=LIST] [guard-minutes=N] [switch ...]; windows.ps1 confirm')
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

# ---------------------------------------------------------------------------
# Access lists of the Hardening folder and its files (the work folder,
# under %SystemRoot%\Temp, is the reader's New-ErWorkFolder).

$ErProtectedFolder = 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$ErInheritedFile = 'D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)'

# ---------------------------------------------------------------------------
# The Hardening folder (ADR-0054, "Backups, undo and interruptions"), with
# PR #61's rule: the chain from ProgramData down is plain folders with a
# trusted owner; the folder and its files have a trusted owner, the files
# are plain with one link, and they are judged by who may write (the
# reader's Get-ErTrustedSids and Get-ErWriters).

# The access part of an SDDL with its entries in a fixed order, to compare
# access lists that hold the same allow entries in another order.
function ConvertTo-ErSortedSddl {
    param([string]$Sddl)
    if ($Sddl -notmatch '^(D:[A-Z]*)((\([^()]*\))*)$') { return $Sddl }
    $head = $Matches[1]
    $entries = @([regex]::Matches($Matches[2], '\([^()]*\)') | ForEach-Object { $_.Value } | Sort-Object)
    return $head + ($entries -join '')
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
    if ((Get-ErTrustedSids) -notcontains $owner) { return "is owned by $owner, not by SYSTEM, Administrators or TrustedInstaller" }
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
# 2 failure, 3 both); $null where auditpol failed or its backup is not in
# its form.
function Get-ErAuditPolicy {
    if ($ErCache.ContainsKey('auditpol')) { return $ErCache.auditpol }
    $file = Join-Path $ErWork 'audit.csv'
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\auditpol.exe') @('/backup', "/file:$file") 60
    $a = $null
    if ($run.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
        $a = ConvertFrom-ErAuditBackup $file
        Remove-Item -LiteralPath $file -Force
    }
    $ErCache.auditpol = $a
    return $a
}

# ConvertFrom-ErAuditBackup: auditpol's backup file as each subcategory's
# setting by GUID, in lower case with its braces; $null where it is not in
# auditpol's form, as Read-ErAuditCopy checks the audit policy extension's
# copy: no Subcategory GUID and Setting Value columns, a subcategory's row
# that cannot be read, or no subcategory at all. Rows without a GUID are
# auditpol's options.
function ConvertFrom-ErAuditBackup {
    param([string]$Path)
    try {
        $header = [string](Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop)
        $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return $null
    }
    if ($header -notmatch '(^|,)"?Subcategory GUID"?(,|$)' -or $header -notmatch '(^|,)"?Setting Value"?(,|$)') { return $null }
    $a = @{}
    foreach ($row in $rows) {
        $g = ([string]$row.'Subcategory GUID').Trim()
        if (-not $g) { continue }
        $v = ([string]$row.'Setting Value').Trim()
        if ($g -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$' -or $v -notmatch '^[0-3]$') { return $null }
        $a[$g.ToLowerInvariant()] = [int]$v
    }
    if ($a.Count -eq 0) { return $null }
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

# Get-ErMpStatus: Defender's status, or $null with the error where it was
# not reported.
function Get-ErMpStatus {
    if (-not $ErCache.ContainsKey('mpstatus')) {
        try {
            $ErCache.mpstatus = @{ Status = (Get-MpComputerStatus -ErrorAction Stop); Error = '' }
        } catch {
            $ErCache.mpstatus = @{ Status = $null; Error = $_.Exception.Message }
        }
    }
    return $ErCache.mpstatus
}

# Get-ErServiceState: a service's status and start type, telling a service
# that is not installed from one that could not be read (Get-ErService).
# Windows PowerShell gives an empty start type, not an error, where the
# service's configuration may not be queried.
function Get-ErServiceState {
    param([string]$Name)
    $r = Get-ErService $Name
    if ($r.Error) { return @{ Installed = $true; Read = $false; Error = $r.Error } }
    if ($null -eq $r.Service) { return @{ Installed = $false; Read = $true } }
    try {
        $status = [string]$r.Service.Status
        $start = [string]$r.Service.StartType
    } catch {
        return @{ Installed = $true; Read = $false; Error = $_.Exception.Message }
    }
    if (-not $status -or -not $start) { return @{ Installed = $true; Read = $false; Error = 'its status or start type could not be read' } }
    return @{ Installed = $true; Read = $true; Status = $status; StartType = $start }
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

# Get-ErUnread: where any of a setting's registry reads failed, the setting
# as unknown (or, for one that is only reported, reported without a
# value), with the error, which names the value; $null where all were
# read. A value that cannot be read is neither absent nor present.
function Get-ErUnread {
    param($Def, [object[]]$Reads)
    foreach ($r in $Reads) {
        if ($r.Error) { return New-ErSetting $Def $(if ($Def.cite -eq 'not_set') { 'reported' } else { 'unknown' }) $null '' $r.Error }
    }
    return $null
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
        'nonempty' { return "$Value".Trim() -ne '' }
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
        'nonempty' { return 'a text' }
    }
    return ''
}

# Finish a setting that is not in place: managed elsewhere when an owner
# holds it, check only when the reader cannot tell, not in place when no
# owner holds it (apply would change it). An owner that gives no value of
# its own (Tamper Protection) holds the value the setting has.
function Complete-ErSetting {
    param($Setting, $Owner, $Module)
    if ($Setting.state -ne 'not_in_place' -and $Setting.state -ne 'in_place') { return $Setting }
    if ($null -eq $Owner) { return $Setting }
    if ($Owner.Result -eq 'owner') {
        $value = $(if ($Owner.Value) { $Owner.Value } else { [string]$Setting.value })
        $m = @{ id = $Setting.id; owner = $Owner.Owner; policy = Limit-ErText $Owner.Policy 120; value = Limit-ErText $value 120 }
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

# Get-ErApplies: whether a setting applies to this computer: '' where it
# does, 'not_applicable' where it does not, and 'unknown' where that turns
# on the computer's role and Windows did not report it.
function Get-ErApplies {
    param($Def)
    $o = $Def.only
    if ($null -eq $o) { return '' }
    if ($null -ne $o.client -and [bool]$o.client -ne $ErPlatform.Client) { return 'not_applicable' }
    if ($o.minBuild -and $ErPlatform.Build -lt [int]$o.minBuild) { return 'not_applicable' }
    if ($o.notRoles) {
        if ($ErPlatform.Role -eq 'unknown') { return 'unknown' }
        if (@($o.notRoles) -contains $ErPlatform.Role) { return 'not_applicable' }
    }
    return ''
}

# The note of a setting that turns on whether the computer is a domain
# controller, where Windows did not report its role (Get-ErPlatform): such
# a setting is unknown, never taken as either.
function Get-ErRoleUnknownNote {
    return 'Windows did not report the computer''s role, and this turns on whether it is a domain controller.'
}

# A registry setting: the value in effect, compared; absent is in place
# where Windows' behaviour without it is EasyRMM's.
function Test-ErRegistrySetting {
    param($Def, $Module)
    $v = Get-ErRegistryValue $Def.path $Def.name
    $unread = Get-ErUnread $Def @($v)
    if ($unread) { return $unread }
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
    $owner = Resolve-ErRegistryOwner $ErPolicy $Def.path $Def.name ([string]$Def.csp) -Tamper:([bool]$Def.tamper)
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
# Product: antivirus or firewall, for a value another such product takes
# over (with -Defender).
function Test-ErValue {
    param($Def, $Module, $Value, [bool]$InPlace, [string]$Want, [switch]$Defender, [string]$Product = '', [string]$Note = '')
    if ($Def.cite -eq 'not_set') { return New-ErSetting $Def 'reported' $Value '' $Note }
    $s = New-ErSetting $Def $(if ($InPlace) { 'in_place' } else { 'not_in_place' }) $Value $Want $Note
    $owner = $null
    if ($Def.path) {
        $owner = Resolve-ErRegistryOwner $ErPolicy $Def.path $Def.name ([string]$Def.csp) -Defender:$Defender -Product $Product -Tamper:([bool]$Def.tamper)
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
    return Test-ErValue $Def $Module $v (Test-ErWant $Def $v) (Get-ErWantText $Def) -Defender -Product 'firewall' -Note $note
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
    $s = Test-ErValue $d $Module $v (Test-ErWant $d $v) (Get-ErWantText $d) -Defender -Product 'antivirus'
    # A local Set-MpPreference value that the policy value apply writes
    # would outrank: one that is not what apply wants. (Windows itself keeps
    # some local values, such as cloud protection's, at their defaults.)
    if ($d.path) {
        $local = Get-ErRegistryValue ($d.path -replace '\\Policies\\Microsoft\\', '\Microsoft\') $d.name
        if ($local.Error) {
            $s.note = $local.Error
        } elseif ($local.Exists) {
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
    $unread = Get-ErUnread $d @($v)
    if ($unread) { return $unread }
    if ($d.name -eq 'EnableSmartScreen') {
        if ($v.Exists) { $shown = [string]$v.Data }
        else {
            $local = Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
            $unread = Get-ErUnread $d @($local)
            if ($unread) { return $unread }
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
    $owner = Resolve-ErRegistryOwner $ErPolicy $path ([string]$Def.rule) ([string]$Def.csp) -Defender -Product 'antivirus'
    return Complete-ErSetting $s $owner $Module
}

# WinRM: a policy value wins over the local configuration, which wins over
# Windows' default.
function Test-ErWinRmSetting {
    param($Def, $Module)
    $p = Get-ErRegistryValue $Def.path $Def.name
    $unread = Get-ErUnread $Def @($p)
    if ($unread) { return $unread }
    if ($p.Exists) { $v = [string]$p.Data }
    else {
        $l = Get-ErRegistryValue $Def.localPath $Def.localName
        $unread = Get-ErUnread $Def @($l)
        if ($unread) { return $unread }
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
    $unread = Get-ErUnread $Def @($e, $dbd)
    if ($unread) { return $unread }
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
            $unread = Get-ErUnread $Def @($v, $boot)
            if ($unread) { return $unread }
            $want = $(if (Test-ErOption 'lsa-uefi-lock') { @('1') } else { @('1', '2') })
            $shown = $(if ($v.Exists) { "RunAsPPL=$($v.Data)" } elseif ($boot.Exists) { "RunAsPPLBoot=$($boot.Data)" } else { 'not set' })
            $data = $(if ($v.Exists) { "$($v.Data)" } elseif ($boot.Exists) { "$($boot.Data)" } else { '' })
            return Test-ErValue $Def $Module $shown ($want -contains $data) ($want -join ' or ')
        }
        'lsa-protection-running' { return Test-ErLsaRunning $Def }
        'powershell-script-block-logging' {
            $row = @($ErAudit.values | Where-Object { $_.id -eq 'script-block-logging' })[0]
            $v = Get-ErRegistryValue $row.path $row.name
            $unread = Get-ErUnread $Def @($v)
            if ($unread) { return $unread }
            return New-ErSetting $Def 'reported' $(if ($v.Exists) { $v.Data } else { 'not set' }) '' 'Set by log collection''s Configure logging.'
        }
        'rdp-nla' { return Test-ErRdpSetting $Def $Module 'UserAuthenticationRequired' 'UserAuthentication' '1' }
        'rdp-encryption' { return Test-ErRdpSetting $Def $Module 'MinEncryptionLevel' 'MinEncryptionLevel' '3' }
        'uac-on' {
            $v = Get-ErRegistryValue $Def.path $Def.name
            $unread = Get-ErUnread $Def @($v)
            if ($unread) { return $unread }
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
        'rights-local-admins' { return Test-ErLocalAdmins $Def }
        'rights-debug' { return Test-ErUserRight $Def }
        'rights-take-ownership' { return Test-ErUserRight $Def }
        'rights-load-driver' { return Test-ErUserRight $Def }
        'rights-act-as-os' { return Test-ErUserRight $Def }
        'rights-remote-logon' { return Test-ErUserRight $Def }
        'rights-security-log' { return Test-ErUserRight $Def }
        'rights-audit-generate' { return Test-ErUserRight $Def }
        'time-service-running' { return Test-ErTimeService $Def }
        'time-synchronized' { return Test-ErTimeSync $Def }
        'app-control-enforced' { return Test-ErAppControl $Def }
        'office-internet-macros' { return Test-ErOfficeMacros $Def }
        'audit-subcategories' { return Test-ErAuditSubcategories $Def $Module }
        'audit-legacy-overridden' { return Test-ErAuditValue $Def $Module 'legacy-categories-overridden' }
        'audit-command-lines' { return Test-ErAuditValue $Def $Module 'process-command-lines' }
        'audit-log-sizes' { return Test-ErAuditLogs $Def $Module }
    }
    throw "no check for $($Def.id)"
}

# ---------------------------------------------------------------------------
# ADR-0078, C3: user rights, local administrators, the time source,
# application control and Office. Each only reads.

# secedit's export of the user rights assignments: each right's holders, as
# SIDs (or names where Windows has no SID), without their asterisks; $null
# where secedit failed.
function Get-ErUserRights {
    if ($ErCache.ContainsKey('rights')) { return $ErCache.rights }
    $file = Join-Path $ErWork 'rights.inf'
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\secedit.exe') @('/export', '/cfg', $file, '/areas', 'USER_RIGHTS', '/quiet') 120
    $r = $null
    if ($run.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
        $r = @{}
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            if ($line -match '^\s*(Se[A-Za-z]+)\s*=\s*(.*?)\s*$') {
                $r[$Matches[1]] = @($Matches[2].Split(',') | ForEach-Object { $_.Trim().Trim('"').TrimStart('*') } | Where-Object { $_ -ne '' })
            }
        }
        Remove-Item -LiteralPath $file -Force
    }
    $ErCache.rights = $r
    return $r
}

# One right: in place where everyone who holds it is among the setting's
# data (SIDs); nobody holding it is in place.
function Test-ErUserRight {
    param($Def)
    $r = Get-ErUserRights
    if ($null -eq $r) { return New-ErSetting $Def 'unknown' $null '' 'secedit did not export the user rights assignments.' }
    $names = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-555' = 'Remote Desktop Users'; 'S-1-5-19' = 'LOCAL SERVICE'; 'S-1-5-20' = 'NETWORK SERVICE' }
    $allowed = @($Def.data | ForEach-Object { "$_" })
    $held = @()
    if ($r.ContainsKey([string]$Def.key)) { $held = @($r[[string]$Def.key]) }
    $others = @($held | Where-Object { $allowed -notcontains $_ })
    $want = $(if ($allowed.Count -eq 0) { 'no one' } else { 'only ' + ((@($allowed | ForEach-Object { if ($names[$_]) { $names[$_] } else { $_ } })) -join ', ') })
    $shown = $(if ($held.Count -eq 0) { 'no one' } elseif ($others.Count -eq 0) { 'only those' } else { "$($others.Count) other account(s)" })
    return New-ErSetting $Def $(if ($others.Count -eq 0) { 'in_place' } else { 'not_in_place' }) $shown $want
}

# The direct members of the local Administrators group, counted; no names
# leave the computer.
function Test-ErLocalAdmins {
    param($Def)
    $max = [int]$Def.data
    try {
        $name = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value
        $name = $name.Substring($name.LastIndexOf('\') + 1)
        $group = [ADSI]"WinNT://./$name,group"
        $count = @($group.psbase.Invoke('Members')).Count
    } catch {
        return New-ErSetting $Def 'unknown' $null '' "The Administrators group could not be read: $($_.Exception.Message)"
    }
    return New-ErSetting $Def $(if ($count -le $max) { 'in_place' } else { 'not_in_place' }) "$count members" "at most $max"
}

function Test-ErTimeService {
    param($Def)
    $svc = Get-ErServiceState 'W32Time'
    if (-not $svc.Read) { return New-ErSetting $Def 'unknown' $null '' "The Windows Time service could not be read: $($svc.Error)" }
    if (-not $svc.Installed) { return New-ErSetting $Def 'not_in_place' 'not installed' 'running' }
    $ok = $svc.Status -eq 'Running' -and $svc.StartType -ne 'Disabled'
    return New-ErSetting $Def $(if ($ok) { 'in_place' } else { 'not_in_place' }) "$($svc.Status), $($svc.StartType)" 'running'
}

# The last successful synchronization, from w32tm's status: the one line
# whose text is a date in the computer's own format, whatever the language
# of its label.
function Test-ErTimeSync {
    param($Def)
    $max = [int]$Def.data
    $want = "within $max hours"
    $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\w32tm.exe') @('/query', '/status') 30
    if ($run.ExitCode -ne 0) {
        $svc = Get-ErServiceState 'W32Time'
        if ($svc.Read -and $svc.Installed -and $svc.Status -ne 'Running') { return New-ErSetting $Def 'not_in_place' 'the Windows Time service is not running' $want }
        return New-ErSetting $Def 'unknown' $null '' (Limit-ErText "w32tm did not report its status (exit $($run.ExitCode)): $($run.Error) $($run.Output)" 300)
    }
    $when = $null
    foreach ($line in ([string]$run.Output -split "`r?`n")) {
        $i = $line.IndexOf(':')
        if ($i -lt 1) { continue }
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($line.Substring($i + 1).Trim(), [ref]$t)) { $when = $t; break }
    }
    if ($null -eq $when) { return New-ErSetting $Def 'not_in_place' 'no successful synchronization reported' $want }
    $hours = [int][math]::Floor(([datetime]::Now - $when).TotalHours)
    return New-ErSetting $Def $(if ($hours -le $max) { 'in_place' } else { 'not_in_place' }) "$([math]::Max($hours, 0)) hours ago" $want
}

# Application control: App Control for Business (Device Guard's code
# integrity enforcement status: 1 audit, 2 enforced) or AppLocker's
# executable rules enforcing, with its service running. Audit mode is not
# enforcing and says so.
function Test-ErAppControl {
    param($Def)
    $want = 'enforced'
    $dg = Get-ErDeviceGuard
    $wdac = $(if ($dg.State) { [int]$dg.State.CodeIntegrityPolicyEnforcementStatus } else { -1 })
    if ($wdac -eq 2) { return New-ErSetting $Def 'in_place' 'App Control for Business enforced' $want }
    $mode = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe' 'EnforcementMode'
    $svc = Get-ErServiceState 'AppIDSvc'
    $enforced = $mode.Exists -and "$($mode.Data)" -eq '1'
    if ($enforced -and $svc.Read -and $svc.Installed -and $svc.Status -eq 'Running') { return New-ErSetting $Def 'in_place' 'AppLocker enforced' $want }
    if ($mode.Error -or ($null -eq $dg.State -and $wdac -lt 0 -and -not $mode.Exists)) {
        $why = $(if ($mode.Error) { $mode.Error } else { $dg.Error })
        return New-ErSetting $Def 'unknown' $null '' (Limit-ErText "Application control could not be read: $why" 300)
    }
    if ($enforced) { return New-ErSetting $Def 'not_in_place' 'AppLocker rules set, its service is not running' $want }
    if ($wdac -eq 1 -or ($mode.Exists -and "$($mode.Data)" -eq '0')) {
        return New-ErSetting $Def 'not_in_place' 'audit mode' $want 'A policy only logs what it would block; it blocks nothing.'
    }
    return New-ErSetting $Def 'not_in_place' 'no policy' $want
}

# Office's block on macros in files from the internet, for each of Word,
# Excel and PowerPoint that is installed, from the machine policy; a policy
# set per user is not seen.
function Test-ErOfficeMacros {
    param($Def)
    $apps = @(
        @{ Exe = 'WINWORD.EXE'; Key = 'word' },
        @{ Exe = 'EXCEL.EXE'; Key = 'excel' },
        @{ Exe = 'POWERPNT.EXE'; Key = 'powerpoint' })
    $installed = 0
    $open = 0
    $reads = @()
    foreach ($a in $apps) {
        $found = $false
        foreach ($root in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths') {
            $p = Get-ErRegistryValue "$root\$($a.Exe)" ''
            $reads += $p
            if ($p.Exists) { $found = $true }
        }
        if (-not $found) { continue }
        $installed++
        $v = Get-ErRegistryValue "HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\$($a.Key)\security" 'BlockContentExecutionFromInternet'
        $reads += $v
        if (-not ($v.Exists -and "$($v.Data)" -eq '1')) { $open++ }
    }
    $unread = Get-ErUnread $Def $reads
    if ($unread) { return $unread }
    if ($installed -eq 0) { return New-ErSetting $Def 'not_applicable' $null '' }
    return New-ErSetting $Def $(if ($open -eq 0) { 'in_place' } else { 'not_in_place' }) "$open of $installed applications allow them" 'none allow them' 'Reads the machine policy only; a policy set per user is not seen.'
}

# Remote Desktop's setting in effect, from its WMI provider; from the
# listener's registry value where Windows has no such provider or listener.
# A read that fails otherwise is unknown.
function Test-ErRdpSetting {
    param($Def, $Module, [string]$WmiName, [string]$RegName, [string]$Want)
    $v = $null
    try {
        $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop -OperationTimeoutSec 30
        if ($ts) { $v = [string]$ts.$WmiName }
    } catch {
        # WBEM_E_INVALID_NAMESPACE, WBEM_E_INVALID_CLASS: no provider.
        if ($_.FullyQualifiedErrorId -notmatch '^HRESULT 0x8004(100e|1010),') {
            return New-ErSetting $Def 'unknown' $null '' "Remote Desktop's settings could not be read: $($_.Exception.Message)"
        }
    }
    if ($null -eq $v -or $v -eq '') {
        $r = Get-ErRegistryValue 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' $RegName
        $unread = Get-ErUnread $Def @($r)
        if ($unread) { return $unread }
        $v = $(if ($r.Exists) { [string]$r.Data } else { 'not set' })
    }
    $ok = $(if ($WmiName -eq 'MinEncryptionLevel') { $v -match '^\d+$' -and [int]$v -ge [int]$Want } else { $v -eq $Want })
    return Test-ErValue $Def $Module $v $ok $(if ($WmiName -eq 'MinEncryptionLevel') { ">= $Want" } else { $Want })
}

# LSASS started as a protected process: Wininit's event 12 since the last
# start. Not in place only where the System log was read and has none.
function Test-ErLsaRunning {
    param($Def)
    try {
        $since = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    } catch {
        return New-ErSetting $Def 'unknown' $null 'protected' "Windows did not report when it last started: $($_.Exception.Message)"
    }
    $e = Get-ErEvents @{ FilterHashtable = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12; StartTime = $since }; MaxEvents = 1 }
    if (-not $e.Read) { return New-ErSetting $Def 'unknown' $null 'protected' "The System log could not be read: $($e.Error)" }
    if ($e.Events.Count -gt 0) { return New-ErSetting $Def 'in_place' "level $($e.Events[0].Properties[0].Value)" 'protected' }
    return New-ErSetting $Def 'not_in_place' 'not recorded since the last start' 'protected'
}

# Get-ErEvents: Get-WinEvent with the arguments; Read is false, with the
# error, where the log could not be read, whether Get-WinEvent reports that
# as an error or stops. No matching events is no error.
function Get-ErEvents {
    param([hashtable]$Arguments)
    $failed = $null
    try {
        $events = @(Get-WinEvent @Arguments -ErrorAction SilentlyContinue -ErrorVariable failed)
    } catch {
        return @{ Read = $false; Error = $_.Exception.Message; Events = @() }
    }
    $failed = @($failed | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' })
    if ($failed.Count -gt 0) { return @{ Read = $false; Error = $failed[0].Exception.Message; Events = @() } }
    return @{ Read = $true; Error = ''; Events = $events }
}

function Test-ErSpooler {
    param($Def)
    $svc = Get-ErServiceState 'Spooler'
    if (-not $svc.Read) { return New-ErSetting $Def 'unknown' $null 'stopped and disabled' "The Print Spooler service could not be read: $($svc.Error)" }
    if (-not $svc.Installed) { return New-ErSetting $Def 'in_place' 'not installed' 'stopped and disabled' }
    $shown = "$($svc.Status), $($svc.StartType)"
    $off = $svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped'
    $counted = $ErPlatform.Role -eq 'domain_controller' -or (Test-ErOption 'spooler-off')
    if (-not $off) {
        $why = @()
        try {
            if (@(Get-CimInstance -ClassName Win32_Printer -Filter 'Shared=TRUE' -ErrorAction Stop).Count -gt 0) { $why += 'shares a printer' }
        } catch {
            return New-ErSetting $Def 'unknown' $shown 'stopped and disabled' "Whether this computer shares a printer could not be read: $($_.Exception.Message)"
        }
        $f = Get-ErFeatures
        if ($f['Print-Server']) { $why += 'has the Print Server role' }
        if ($f['RDS-RD-Server']) { $why += 'is a Remote Desktop session host' }
        if ($why.Count -gt 0) { return New-ErSetting $Def 'not_applicable' $shown '' ('Left: this server ' + ($why -join ', ') + '.') }
        if (-not $counted) {
            if ($ErPlatform.Role -eq 'unknown') { return New-ErSetting $Def 'unknown' $shown 'stopped and disabled' (Get-ErRoleUnknownNote) }
            return New-ErSetting $Def 'reported' $shown '' 'Stopped on domain controllers, and on other servers only with spooler-off.'
        }
    }
    return New-ErSetting $Def $(if ($off) { 'in_place' } else { 'not_in_place' }) $shown 'stopped and disabled'
}

# Device Guard's state, read once: State, or Error where it could not be read.
function Get-ErDeviceGuard {
    if (-not $ErCache.ContainsKey('dg')) {
        try {
            $ErCache.dg = @{ State = (Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop); Error = '' }
        } catch {
            $ErCache.dg = @{ State = $null; Error = "Device Guard's state could not be read: $($_.Exception.Message)" }
        }
    }
    return $ErCache.dg
}

function Test-ErDeviceGuard {
    param($Def, $What)
    $read = Get-ErDeviceGuard
    $dg = $read.State
    if ($null -eq $dg) { return New-ErSetting $Def 'unknown' $null '' $(if ($read.Error) { $read.Error } else { 'Windows did not report Device Guard''s state.' }) }
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
# Installed is false only where the provider's namespace or class is
# absent; Read is false, with Error, where anything else stopped the read
# (a method that does not return 0 among it).
function Get-ErBitLocker {
    if (-not $ErCache.ContainsKey('bl')) {
        $bl = @{ Installed = $true; Read = $false; Error = ''; On = $false; Types = @() }
        try {
            $vol = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($env:SystemDrive)'" -ErrorAction Stop)
            if ($vol.Count -ne 1) { throw "BitLocker listed $($vol.Count) volumes for $($env:SystemDrive)." }
            $r = Invoke-CimMethod -InputObject $vol[0] -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 } -ErrorAction Stop
            if ($r.ReturnValue -ne 0) { throw "GetKeyProtectors returned $($r.ReturnValue)." }
            foreach ($id in @($r.VolumeKeyProtectorID)) {
                $t = Invoke-CimMethod -InputObject $vol[0] -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $id } -ErrorAction Stop
                if ($t.ReturnValue -ne 0) { throw "GetKeyProtectorType returned $($t.ReturnValue)." }
                $bl.Types += [int]$t.KeyProtectorType
            }
            $p = Invoke-CimMethod -InputObject $vol[0] -MethodName GetProtectionStatus -ErrorAction Stop
            if ($p.ReturnValue -ne 0) { throw "GetProtectionStatus returned $($p.ReturnValue)." }
            $bl.On = [int]$p.ProtectionStatus -eq 1
            $bl.Read = $true
        } catch {
            # WBEM_E_INVALID_NAMESPACE, WBEM_E_INVALID_CLASS: no BitLocker.
            if ($_.FullyQualifiedErrorId -match '^HRESULT 0x8004(100e|1010),') {
                $bl.Installed = $false
                $bl.Read = $true
            } else {
                $bl.Error = $_.Exception.Message
            }
        }
        $ErCache.bl = $bl
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
    $reads = @()
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS') {
        $v = Get-ErRegistryValue $p 'BackupDirectory'
        if ($v.Exists -and $dirs["$($v.Data)"]) { return New-ErSetting $Def 'in_place' ('Windows LAPS to ' + $dirs["$($v.Data)"]) 'managed' }
        $reads += $v
    }
    $legacy = Get-ErRegistryValue 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    if ($legacy.Exists -and "$($legacy.Data)" -eq '1') { return New-ErSetting $Def 'in_place' 'legacy Microsoft LAPS' 'managed' }
    # Not managed only where every policy was read.
    $unread = Get-ErUnread $Def ($reads + $legacy)
    if ($unread) { return $unread }
    return New-ErSetting $Def 'not_in_place' 'not managed' 'managed'
}

# The audit table (ADR-0060): each subcategory by GUID, with its owner.
function Test-ErAuditSubcategories {
    param($Def, $Module)
    $a = Get-ErAuditPolicy
    if ($null -eq $a) { return , @(New-ErSetting $Def 'unknown' $null '' 'auditpol did not report the audit policy.') }
    $bits = @{ success = 1; failure = 2; success_failure = 3 }
    $out = @()
    foreach ($row in @($ErAudit.subcategories)) {
        if ($row.set -eq 'left') { continue }
        $unknown = ''
        if ($row.domainControllersOnly -and $ErPlatform.Role -ne 'domain_controller') {
            if ($ErPlatform.Role -ne 'unknown') { continue }
            $unknown = Get-ErRoleUnknownNote
        }
        $v = $a[[string]$row.guid]
        if (-not $unknown -and $null -eq $v) { $unknown = 'auditpol''s backup has no row for this subcategory.' }
        if ($unknown) {
            $s = New-ErSetting $Def 'unknown' $null $row.set $unknown
            $s.item = [string]$row.guid
            $out += $s
            continue
        }
        $want = $bits[[string]$row.set]
        $s = New-ErSetting $Def $(if (($v -band $want) -eq $want) { 'in_place' } else { 'not_in_place' }) (ConvertTo-ErAuditSetting ([int]$v)) $row.set
        $s.item = [string]$row.guid
        $owner = Resolve-ErAuditOwner $ErPolicy ([string]$row.guid)
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
        # A log Windows does not have is a real answer; a log that could
        # not be read is unknown.
        $failed = $null
        $log = $null
        try {
            $log = Get-WinEvent -ListLog ([string]$row.channel) -ErrorAction SilentlyContinue -ErrorVariable failed
            $failed = @($failed | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingLogsFound*' })
        } catch {
            $failed = @($_)
        }
        if ($failed.Count -gt 0) {
            $s = New-ErSetting $Def 'unknown' $null ">= $($row.minKB) KB" "The log could not be read: $($failed[0].Exception.Message)"
            $s.item = [string]$row.channel
            $out += $s
            continue
        }
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

# Get-ErExposure: failed sign-ins (event 4625) in the Security log, as far
# back as it reaches up to 7 days, and at most Limit of them, newest first
# (ADR-0054, Accounts): those from public addresses, and the accounts with
# 10 or more within 15 minutes, which the lockout would have locked. An
# exposed computer gets no lockout unless lockout-exposed is given. Since is
# how far back the log was read: 7 days, the log's oldest event, or the
# oldest event read where the scan stopped at Limit (Get-ErLogReach). Read
# is false, with the error, where the log could not be read.
function Get-ErExposure {
    param([int]$Limit = 5000)
    $now = Get-Date
    $since = $now.AddDays(-7)
    $read = Get-ErEvents @{ FilterHashtable = @{ LogName = 'Security'; Id = 4625; StartTime = $since }; MaxEvents = $Limit }
    if (-not $read.Read) { return @{ Read = $false; Error = $read.Error } }
    $events = $read.Events
    $accounts = @{}
    $addresses = @{}
    $times = @{}
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
        # Windows writes '-' where it has no name.
        $user = Limit-ErText $data['TargetUserName'] 64
        if ($user -eq '-') { $user = '' }
        if ($user) {
            if (-not $times.ContainsKey($user)) { $times[$user] = New-Object 'System.Collections.Generic.List[datetime]' }
            $times[$user].Add($e.TimeCreated)
        }
        $ip = ConvertTo-ErPublicAddress $data['IpAddress']
        if (-not $ip) { continue }
        $addresses[$ip] = $true
        if ($user) { $accounts[$user] = $true }
    }
    $bursts = @()
    foreach ($u in $times.Keys) {
        $t = @($times[$u] | Sort-Object)
        for ($i = 0; $i + 9 -lt $t.Count; $i++) {
            if (($t[$i + 9] - $t[$i]).TotalMinutes -le 15) { $bursts += $u; break }
        }
    }
    if ($events.Count -ge $Limit) {
        $reach = $events[$events.Count - 1].TimeCreated
    } else {
        $first = Get-ErEvents @{ LogName = 'Security'; MaxEvents = 1; Oldest = $true }
        if (-not $first.Read) { return @{ Read = $false; Error = $first.Error } }
        $reach = $(if ($first.Events.Count -gt 0 -and $first.Events[0].TimeCreated -gt $since) { $first.Events[0].TimeCreated } else { $since })
    }
    $r = Get-ErLogReach $reach $now
    return @{
        Read = $true
        Exposed = $addresses.Count -gt 0 -or $bursts.Count -gt 0
        Accounts = @($accounts.Keys | Sort-Object | Select-Object -First 10)
        Addresses = @($addresses.Keys | Sort-Object | Select-Object -First 10)
        Bursts = @($bursts | Sort-Object | Select-Object -First 10)
        Since = $r.Since
        SinceReason = $r.SinceReason
    }
}

# Get-ErLogReach: how far back the log was read, from the time of the
# oldest record read and the check's own. A record dated after the check
# was written while the computer's clock was wrong: its time says nothing
# of how far back the log goes, so Since is null, with why.
function Get-ErLogReach {
    param([datetime]$Reach, [datetime]$Now)
    if ($Reach.ToUniversalTime() -gt $Now.ToUniversalTime()) {
        return @{ Since = $null; SinceReason = 'The oldest record read is dated after this check: the computer''s clock was wrong when it was written.' }
    }
    return @{ Since = $Reach.ToUniversalTime().ToString('o'); SinceReason = '' }
}

# ConvertTo-ErPublicAddress: an address outside the private, loopback,
# link-local and shared ranges, as text (an IPv4 address mapped into IPv6
# as IPv4); '' for any other address or text.
function ConvertTo-ErPublicAddress {
    param([string]$Text)
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse("$Text".Trim(), [ref]$a)) { return '' }
    if ($a.IsIPv4MappedToIPv6) { $a = $a.MapToIPv4() }
    $b = $a.GetAddressBytes()
    if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $private = $b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224 -or
            ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)
        if ($private) { return '' }
        return $a.ToString()
    }
    if ([System.Net.IPAddress]::IsLoopback($a) -or $a.Equals([System.Net.IPAddress]::IPv6None) -or $a.IsIPv6LinkLocal -or
        $a.IsIPv6SiteLocal -or $a.IsIPv6Multicast -or ($b[0] -band 0xfe) -eq 0xfc) {
        return ''
    }
    $a.ScopeId = 0
    return $a.ToString()
}

# What stops a whole module before its settings are read. A state that
# cannot be read stops it as failed, with the reason: never as not
# applicable.
function Get-ErModuleGate {
    param([string]$Name, $Module)
    switch ($Name) {
        { $_ -eq 'defender' -or $_ -eq 'asr' } {
            $av = @($ErPolicy.Products.antivirus)
            if ($av.Count -gt 0) {
                foreach ($n in $av) { $Module.managed += @{ id = $Name; owner = 'security_product'; policy = $n; value = 'on'; state = 'managed_elsewhere' } }
                return @{ state = 'managed_elsewhere'; reason = 'Another antivirus is on: ' + ($av -join ', ') + '.' }
            }
            $mp = Get-ErMpStatus
            $st = $mp.Status
            if ($null -eq $st) {
                # Without its status, Defender's service tells absent or
                # turned off from a status that could not be read.
                $svc = Get-ErServiceState 'WinDefend'
                if ($svc.Read -and -not $svc.Installed) { return @{ state = 'not_applicable'; reason = 'Microsoft Defender Antivirus is not installed.' } }
                if ($svc.Read -and $svc.Status -ne 'Running') {
                    return @{ state = 'not_applicable'; reason = "Microsoft Defender Antivirus is not running (its service is $($svc.Status), $($svc.StartType))." }
                }
                return @{ state = 'failed'; reason = "Microsoft Defender Antivirus did not report its status: $($mp.Error)" }
            }
            $mode = [string]$st.AMRunningMode
            if ($mode -and $mode -ne 'Normal') {
                return @{ state = $(if ($ErPlatform.Client) { 'managed_elsewhere' } else { 'not_applicable' }); reason = "Microsoft Defender Antivirus runs in $mode, beside another antivirus." }
            }
            if ($Name -eq 'asr' -and $ErPlatform.Build -eq 14393 -and -not $ErPolicy.DefenderForEndpoint) {
                return @{ state = 'not_supported'; reason = 'Attack surface reduction rules on Server 2016 need onboarding with Defender for Endpoint''s unified solution.' }
            }
        }
        'firewall' {
            $fw = @($ErPolicy.Products.firewall)
            if ($fw.Count -gt 0) {
                foreach ($n in $fw) { $Module.managed += @{ id = $Name; owner = 'security_product'; policy = $n; value = 'on'; state = 'managed_elsewhere' } }
                return @{ state = 'managed_elsewhere'; reason = 'Another firewall is on: ' + ($fw -join ', ') + '.' }
            }
            $svc = Get-ErServiceState 'MpsSvc'
            if (-not $svc.Read) {
                $Module.notes += "The Windows Defender Firewall service could not be read: $($svc.Error)"
            } elseif (-not $svc.Installed -or $svc.Status -ne 'Running') {
                $Module.notes += 'The Windows Defender Firewall service is not running.'
            }
        }
        'uac' {
            if ($ErPlatform.Core) { return @{ state = 'not_applicable'; reason = 'Server Core has no UAC prompts.' } }
        }
        'bitlocker' {
            $bl = Get-ErBitLocker
            if (-not $bl.Installed) { return @{ state = 'not_applicable'; reason = 'BitLocker is not installed.' } }
            if (-not $bl.Read) { return @{ state = 'failed'; reason = "BitLocker's state could not be read: $($bl.Error)" } }
        }
        'accounts' {
            $x = Get-ErExposure
            if (-not $x.Read) {
                $Module.notes += "The Security log could not be read for failed sign-ins: $($x.Error)"
            } else {
                $Module.exposure = @{ exposed = $x.Exposed; accounts = $x.Accounts; addresses = $x.Addresses; bursts = $x.Bursts; since = $x.Since }
                if ($x.SinceReason) { $Module.exposure.sinceReason = $x.SinceReason }
                if ($x.Exposed -and -not (Test-ErOption 'lockout-exposed')) {
                    $Module.notes += 'Failed sign-ins from public addresses, or 10 or more for one account within 15 minutes: apply sets no lockout here unless lockout-exposed is given.'
                }
            }
        }
    }
    return $null
}

function Invoke-ErModule {
    param([string]$Name, [string[]]$Only = @())
    $m = @{ module = $Name; settings = @(); managed = @(); notes = @() }
    $gate = Get-ErModuleGate $Name $m
    if ($gate) {
        $m.state = $gate.state
        $m.reason = Limit-ErText $gate.reason 300
        return $m
    }
    foreach ($def in @($ErSettings | Where-Object { $_.module -eq $Name -and ($Only.Count -eq 0 -or $Only -contains $_.id) })) {
        $applies = Get-ErApplies $def
        if ($applies -eq 'not_applicable') {
            $m.settings += New-ErSetting $def 'not_applicable' $null ''
            continue
        }
        if ($applies -eq 'unknown') {
            $m.settings += New-ErSetting $def 'unknown' $null '' (Get-ErRoleUnknownNote)
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
    $unknown = @($counted | Where-Object { $_.state -eq 'unknown' }).Count
    if ($counted.Count -eq 0) {
        $m.state = 'not_applicable'
        $m.reason = 'None of its settings applies to this computer.'
    } elseif ($unknown -eq $counted.Count) {
        # Nothing read is nothing in place or not: the settings say why.
        $m.state = 'failed'
        $m.reason = 'None of its settings could be read.'
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
# Apply, undo and the guard (ADR-0054, W2). The record is the manifest:
#   modules.<name> = { intent, done, settings.<id> = { kind, path, name,
#     before = {exists, kind, data}, target, after = {exists, kind, data}, at } }
# Only registry settings are written in this release.

$ErReportOnly = @('audit', 'device-guard', 'bitlocker', 'laps', 'rights', 'time', 'app-control', 'office')
$ErTaskName = 'EasyRMM Hardening Rollback'
$ErTaskPath = '\EasyRMM\'

function Get-ErHardeningDir {
    return (Join-Path (Join-Path $env:ProgramData 'EasyRMM') 'Hardening')
}

# ConvertTo-ErPlain: a manifest read as JSON, as hashtables.
function ConvertTo-ErPlain {
    param($Object)
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-ErPlain $p.Value }
        return $h
    }
    return $Object
}

function New-ErManifest {
    return @{ formatVersion = 1; copySha256 = ''; modules = @{} }
}

# Where apply makes the Hardening folder: a plain folder for SYSTEM and
# Administrators only. The chain above it is checked by Open-ErHardening.
function New-ErHardeningFolder {
    $base = Join-Path $env:ProgramData 'EasyRMM'
    if (-not (Test-Path -LiteralPath $base)) { [void][IO.Directory]::CreateDirectory($base) }
    $dir = Join-Path $base 'Hardening'
    if (-not (Test-Path -LiteralPath $dir)) {
        $sec = New-Object Security.AccessControl.DirectorySecurity
        $sec.SetSecurityDescriptorSddlForm($ErProtectedFolder)
        [void][IO.Directory]::CreateDirectory($dir, $sec)
    }
}

# Save-ErManifest: written beside the old one and put in its place.
function Save-ErManifest {
    param($Manifest)
    $dest = Join-Path (Get-ErHardeningDir) 'manifest.json'
    $tmp = $dest + '.new'
    $json = $Manifest | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $dest) { [IO.File]::Replace($tmp, $dest, $null) } else { [IO.File]::Move($tmp, $dest) }
}

# Keep-ErCopy: the script's copy, for undo on the computer itself and the
# guard's task; its hash goes in the manifest.
function Save-ErCopy {
    param($Manifest)
    $copy = Join-Path (Get-ErHardeningDir) 'easyrmm-hardening.ps1'
    $self = $PSCommandPath
    if ($self -and ([IO.Path]::GetFullPath($self) -ne [IO.Path]::GetFullPath($copy))) {
        [IO.File]::Copy($self, $copy, $true)
    }
    if (Test-Path -LiteralPath $copy) { $Manifest.copySha256 = Get-ErSha256 $copy }
}

function ConvertTo-ErDwordValue {
    param($Value)
    return [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32][int64]$Value), 0)
}

function Set-ErRegistryData {
    param([string]$Path, [string]$Name, [string]$Kind, $Data)
    $sub = $Path -replace '^HKLM\\', ''
    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($sub)
    try {
        if ($Kind -eq 'DWord') {
            $k.SetValue($Name, (ConvertTo-ErDwordValue $Data), [Microsoft.Win32.RegistryValueKind]::DWord)
        } else {
            $k.SetValue($Name, [string]$Data, [Microsoft.Win32.RegistryValueKind]::String)
        }
    } finally {
        $k.Close()
    }
}

function Remove-ErRegistryData {
    param([string]$Path, [string]$Name)
    $sub = $Path -replace '^HKLM\\', ''
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, $true)
    if ($null -eq $k) { return }
    try {
        $k.DeleteValue($Name, $false)
    } finally {
        $k.Close()
    }
}

# A value as the manifest keeps it.
function ConvertTo-ErValueRecord {
    param($Read)
    if ($Read.Exists) { return @{ exists = $true; kind = [string]$Read.Kind; data = $Read.Data } }
    return @{ exists = $false; kind = ''; data = $null }
}

# The stores apply writes. A record (in the manifest, and as built from a
# setting) names one: registry (path, name), secedit (key: a value of the
# security policy's System Access) or smb (side, property: a value of the
# SMB server's or client's configuration). Reads return Exists, Data, Kind
# and Error as Get-ErRegistryValue does.
function Read-ErStore {
    param($Rec)
    switch ([string]$Rec.store) {
        'registry' { return Get-ErRegistryValue $Rec.path $Rec.name }
        'secedit' {
            $null = $ErCache.Remove('secedit')
            $p = Get-ErSecurityPolicy
            if ($null -eq $p) { return @{ Exists = $false; Data = $null; Kind = ''; Error = 'secedit did not export the security policy.' } }
            if ($p.ContainsKey([string]$Rec.key)) { return @{ Exists = $true; Data = $p[[string]$Rec.key]; Kind = 'Secedit'; Error = '' } }
            return @{ Exists = $false; Data = $null; Kind = ''; Error = '' }
        }
        'smb' {
            try {
                $null = $ErCache.Remove('smb-' + $Rec.side)
                $c = $(if ($Rec.side -eq 'server') { Get-SmbServerConfiguration -ErrorAction Stop } else { Get-SmbClientConfiguration -ErrorAction Stop })
                return @{ Exists = $true; Data = $c.($Rec.property); Kind = 'Smb'; Error = '' }
            } catch {
                return @{ Exists = $false; Data = $null; Kind = ''; Error = "SMB's configuration could not be read: $($_.Exception.Message)" }
            }
        }
    }
    return @{ Exists = $false; Data = $null; Kind = ''; Error = 'unknown store' }
}

function Set-ErSecurityValue {
    param([string]$Key, $Data)
    $inf = Join-Path $ErWork 'apply.inf'
    $db = Join-Path $ErWork 'apply.sdb'
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[System Access]', "$Key = $Data")
    [IO.File]::WriteAllText($inf, (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::Unicode)
    try {
        $run = Invoke-ErProgram (Join-Path $env:SystemRoot 'System32\secedit.exe') @('/configure', '/db', $db, '/cfg', $inf, '/areas', 'SECURITYPOLICY', '/quiet') 120
        if ($run.ExitCode -ne 0) { throw "secedit /configure exited with $($run.ExitCode)." }
    } finally {
        Remove-Item -LiteralPath $inf, $db -Force -ErrorAction SilentlyContinue
    }
}

function Set-ErSmbValue {
    param([string]$Side, [string]$Property, $Data)
    $a = @{ Force = $true }
    $a[$Property] = [bool]$Data
    if ($Side -eq 'server') { Set-SmbServerConfiguration @a } else { Set-SmbClientConfiguration @a }
}

# Write-ErStore: a value; Restore-ErStore: what the record held before.
function Write-ErStore {
    param($Rec, $Data, [string]$Kind = 'DWord')
    switch ([string]$Rec.store) {
        'registry' { Set-ErRegistryData $Rec.path $Rec.name $Kind $Data }
        'secedit' { Set-ErSecurityValue $Rec.key $Data }
        'smb' { Set-ErSmbValue $Rec.side $Rec.property $Data }
    }
}

function Restore-ErStore {
    param($Rec, $Before)
    if ([string]$Rec.store -eq 'registry' -and -not $Before.exists) { Remove-ErRegistryData $Rec.path $Rec.name; return }
    Write-ErStore $Rec $Before.data $Before.kind
}

# Whether a read value is the manifest's value record.
function Test-ErValueIs {
    param($Read, $Record)
    if (-not $Record.exists) { return (-not $Read.Exists) }
    return ($Read.Exists -and "$($Read.Data)" -eq "$($Record.data)")
}

# The record apply makes of a setting that is not in place, with what it
# would write: $null where this release writes nothing for it (the second
# value says why).
function Get-ErStoreRecord {
    param($Def)
    switch ([string]$Def.kind) {
        'registry' { return @{ store = 'registry'; path = [string]$Def.path; name = [string]$Def.name } }
        'winrm' { return @{ store = 'registry'; path = [string]$Def.path; name = [string]$Def.name } }
        'schannel' { return @{ store = 'registry'; path = [string]$Def.path; name = 'Enabled' } }
        'secedit' { return @{ store = 'secedit'; key = [string]$Def.key } }
        'smb' { return @{ store = 'smb'; side = [string]$Def.side; property = [string]$Def.property } }
    }
    return $null
}

# What apply writes for a setting, from what it holds now.
function Get-ErTarget {
    param($Def, $Current)
    $d = $Def.data
    if ([string]$Def.kind -eq 'schannel') { return 0 }
    switch ([string]$Def.want) {
        'eq' { return $d }
        'min' { return $d }
        'in' { return @($d)[0] }
        'range' { return $Def.max }
        'bits' {
            if ($Current.Exists) { return [uint32](([int64]$Current.Data) -bor ([int64]$d)) }
            return $d
        }
    }
    return $null
}

# Set-ErOutcome: a module's outcome and why.
function Set-ErOutcome {
    param($Module, [string]$Outcome, [string]$Reason = '')
    $Module.outcome = $Outcome
    if ($Reason) { $Module.outcomeReason = Limit-ErText $Reason 300 }
    return $Module
}

function Add-ErSettingOutcome {
    param($Module, [string]$Id, [string]$Outcome, [string]$Note = '', $Before = $null, [string]$At = '')
    foreach ($s in $Module.settings) {
        if ($s.id -eq $Id) {
            $s.outcome = $Outcome
            if ($Note) { $s.note = Limit-ErText $Note 300 }
            if ($null -ne $Before) { $s.before = Limit-ErText ([string]$Before) 120 }
            if ($At) { $s.changedAt = $At }
            return
        }
    }
}

# Invoke-ErApply: one module. Reads it, writes each setting that is not in
# place and that no other owner holds, reads each back, and reads the
# module again for its state. The ids written are added to $Changed.
function Invoke-ErApply {
    param([string]$Name, [string[]]$Only, $Manifest, [string]$Now, [System.Collections.ArrayList]$Changed)
    if ($ErReportOnly -contains $Name) {
        return Set-ErOutcome (Invoke-ErModule $Name $Only) 'skipped' 'This module only reports; it has nothing to apply.'
    }
    $had = $Manifest.modules[$Name]
    if ($had -and $had.intent -and -not $had.done) {
        return Set-ErOutcome (Invoke-ErModule $Name $Only) 'refused' 'An earlier apply or undo of this module did not finish; undo it first.'
    }
    $pre = Invoke-ErModule $Name $Only
    if (@($pre.settings).Count -eq 0) {
        return Set-ErOutcome $pre 'skipped' $(if ($pre.reason) { $pre.reason } else { 'Nothing to apply.' })
    }
    $plans = @()
    $skipped = 0
    $readFailed = 0
    $lockoutHeld = [bool]($pre.exposure -and $pre.exposure.exposed -and -not (Test-ErOption 'lockout-exposed'))
    foreach ($s in @($pre.settings)) {
        if ($s.state -eq 'in_place') { continue }
        $def = @($ErSettings | Where-Object { $_.id -eq $s.id })[0]
        if ($s.state -ne 'not_in_place') {
            if (@('reported', 'not_applicable') -notcontains $s.state) {
                $skipped++
                Add-ErSettingOutcome $pre $s.id 'skipped' "Left as it is: $($s.state)."
            }
            continue
        }
        $d = Get-ErOptionDef $def
        $rec = Get-ErStoreRecord $d
        if ($null -eq $rec) {
            $skipped++
            Add-ErSettingOutcome $pre $s.id 'skipped' "This release only checks settings of kind $($d.kind) (ADR-0054, W2): each needs its machine test before it is written."
            continue
        }
        if ($lockoutHeld -and [string]$d.id -like 'accounts-lockout-*') {
            $skipped++
            Add-ErSettingOutcome $pre $s.id 'skipped' 'Failed sign-ins from public addresses were seen: no lockout is set here without lockout-exposed.'
            continue
        }
        $cur = Read-ErStore $rec
        if ($cur.Error) {
            $readFailed++
            Add-ErSettingOutcome $pre $s.id 'failed' $cur.Error
            continue
        }
        if ($rec.store -eq 'registry' -and $cur.Exists -and @('DWord', 'String') -notcontains [string]$cur.Kind) {
            $skipped++
            Add-ErSettingOutcome $pre $s.id 'skipped' "The value holds a $($cur.Kind), which this release does not restore."
            continue
        }
        $target = Get-ErTarget $d $cur
        if ($null -eq $target) {
            $skipped++
            Add-ErSettingOutcome $pre $s.id 'skipped' 'What to write is not defined for this setting.'
            continue
        }
        $rec.kind = $rec.store
        $plans += @{ id = [string]$d.id; rec = $rec; cur = $cur; target = $target; vkind = $(if ($target -is [string]) { 'String' } else { 'DWord' }) }
    }
    $mod = $pre
    if ($plans.Count -gt 0) {
        # Intent first, with every earlier value, so that an interruption
        # leaves what undo needs.
        $entry = @{ intent = $Now; done = $null; settings = @{} }
        if ($had -and $had.settings) { foreach ($k in $had.settings.Keys) { $entry.settings[$k] = $had.settings[$k] } }
        foreach ($p in $plans) {
            $r = @{}
            foreach ($k in $p.rec.Keys) { $r[$k] = $p.rec[$k] }
            $r.before = ConvertTo-ErValueRecord $p.cur
            $r.target = $p.target
            $r.vkind = $p.vkind
            $r.after = $null
            $r.at = $null
            $entry.settings[$p.id] = $r
        }
        $Manifest.modules[$Name] = $entry
        Save-ErManifest $Manifest
        foreach ($p in $plans) {
            $rec = $entry.settings[$p.id]
            $note = ''
            try {
                Write-ErStore $rec $p.target $p.vkind
                $back = Read-ErStore $rec
                if ($back.Exists -and "$($back.Data)" -eq "$($p.target)") {
                    $rec.after = ConvertTo-ErValueRecord $back
                    $rec.at = $Now
                    [void]$Changed.Add($p.id)
                    continue
                }
                $note = 'Read back, the value was not as written; it was put back.'
            } catch {
                $note = 'Writing failed: ' + $_.Exception.Message
            }
            try { Restore-ErStore $rec $rec.before } catch { $note += ' It could not be put back: ' + $_.Exception.Message }
            $entry.settings.Remove($p.id)
            $p.failed = $note
        }
        $entry.done = $Now
        if ($entry.settings.Count -eq 0) { $Manifest.modules.Remove($Name) }
        Save-ErManifest $Manifest
        $null = $ErCache.Remove('smb-server'), $ErCache.Remove('smb-client')
        $mod = Invoke-ErModule $Name $Only
        foreach ($p in $plans) {
            if ($p.failed) {
                Add-ErSettingOutcome $mod $p.id 'failed' $p.failed
            } else {
                Add-ErSettingOutcome $mod $p.id 'applied' '' $(if ($p.cur.Exists) { $p.cur.Data } else { 'not set' }) $Now
            }
        }
        foreach ($s in @($pre.settings)) {
            if ($s.outcome -and -not ($plans | Where-Object { $_.id -eq $s.id })) { Add-ErSettingOutcome $mod $s.id $s.outcome $s.note }
        }
        # A change that waits for a restart (Schannel's protocols).
        if ($Name -eq 'tls' -and @($plans | Where-Object { -not $_.failed }).Count -gt 0) { $mod.restart = $true }
    } else {
        foreach ($s in @($pre.settings)) {
            if ($s.state -eq 'in_place' -and -not $s.outcome) { $s.outcome = 'unchanged' }
        }
    }
    $wrote = @($plans | Where-Object { -not $_.failed }).Count
    $failed = @($plans | Where-Object { $_.failed }).Count + $readFailed
    $mod.recorded = [bool]$Manifest.modules.ContainsKey($Name)
    $mod.done = @($plans | Where-Object { -not $_.failed } | ForEach-Object { $_.id } | Select-Object -First 50)
    if ($wrote -gt 0) {
        $why = ''
        if ($failed -gt 0) { $why = "$failed setting(s) failed and were put back." }
        return Set-ErOutcome $mod 'applied' $why
    }
    if ($failed -gt 0) { return Set-ErOutcome $mod 'failed' 'No setting could be written.' }
    if ($skipped -gt 0) { return Set-ErOutcome $mod 'skipped' "$skipped setting(s) were left as they are; each says why." }
    return Set-ErOutcome $mod 'unchanged' ''
}

# Get-ErLeave: whether undo leaves a value because an owner the reader
# cannot read may write it again (ADR-0054, Before anything changes), and
# a note where it restores one that an owner may set again.
#   Store   registry or secedit (or smb, which no owner but an MDM sets)
#   returns @{ Leave = $bool; Why = text }
function Get-ErLeave {
    param([string]$Store, [string]$Path)
    $r = @($ErCannotTell)
    # Group Policy's preference items set any registry value; an MDM, an
    # OSConfig scenario or a reader that failed may set any value no other
    # owner holds.
    if ($r -contains 'mdm' -or $r -contains 'osconfig' -or $r -contains 'unreadable') {
        return @{ Leave = $true; Why = 'An owner this script cannot read (' + (($r | Where-Object { @('mdm', 'osconfig', 'unreadable') -contains $_ }) -join ', ') + ') may write it.' }
    }
    if ($Store -eq 'registry' -and $r -contains 'group_policy_preferences') {
        return @{ Leave = $true; Why = 'A Group Policy preference item may set it.' }
    }
    # Group Policy with its record turned off: every value it can set, the
    # registry policy values and the security policy.
    if ($r -contains 'group_policy_record_off' -and ($Store -eq 'secedit' -or ($Store -eq 'registry' -and $Path -match '\\Policies\\'))) {
        return @{ Leave = $true; Why = 'Group Policy, whose record is turned off, may write it.' }
    }
    # DSC and Azure machine configuration: nothing is left; the owner may
    # set the value again. Configuration Manager's baselines too.
    $again = @($r | Where-Object { @('dsc', 'azure_machine_configuration', 'configmgr') -contains $_ })
    if ($again.Count -gt 0) { return @{ Leave = $false; Why = 'Restored; ' + ($again -join ', ') + ' may set it again.' } }
    return @{ Leave = $false; Why = '' }
}

# Invoke-ErUndo: one module, from the manifest.
function Invoke-ErUndo {
    param([string]$Name, [string[]]$Only, $Manifest, [string]$Now)
    $e = $Manifest.modules[$Name]
    $mod = Invoke-ErModule $Name $Only
    if (-not $e -or -not $e.settings -or $e.settings.Count -eq 0) {
        return Set-ErOutcome $mod 'nothing_to_undo' 'EasyRMM has no record of applying this module.'
    }
    $ids = @($e.settings.Keys | Where-Object { $Only.Count -eq 0 -or $Only -contains $_ } | Sort-Object)
    if ($ids.Count -eq 0) { return Set-ErOutcome $mod 'nothing_to_undo' 'EasyRMM has no record of applying these settings.' }
    $restored = @()
    $left = @()
    $failed = @()
    foreach ($id in $ids) {
        $rec = $e.settings[$id]
        if (-not $rec.store) { $rec.store = 'registry' }
        $note = ''
        $cur = Read-ErStore $rec
        if ($cur.Error) {
            $left += $id
            $note = 'Left: ' + $cur.Error
        } elseif ($cur.Exists -and "$($cur.Data)" -eq "$($rec.target)") {
            $lv = Get-ErLeave ([string]$rec.store) ([string]$rec.path)
            if ($lv.Leave) {
                $left += $id
                $note = 'Left: ' + $lv.Why
            } else {
                try {
                    Restore-ErStore $rec $rec.before
                    $back = Read-ErStore $rec
                    if (Test-ErValueIs $back $rec.before) {
                        $restored += $id
                        $e.settings.Remove($id)
                        Add-ErSettingOutcome $mod $id 'restored' $lv.Why $null $Now
                        continue
                    }
                    $failed += $id
                    $note = 'Read back, the value was not as it was before.'
                } catch {
                    $failed += $id
                    $note = 'Putting it back failed: ' + $_.Exception.Message
                }
            }
        } elseif (Test-ErValueIs $cur $rec.before) {
            # Still, or again, as it was: nothing to put back.
            $e.settings.Remove($id)
            Add-ErSettingOutcome $mod $id 'unchanged' 'Already as it was before EasyRMM changed it.'
            $restored += $id
            continue
        } else {
            $left += $id
            $note = 'Left: it was changed after EasyRMM set it.'
            $e.settings.Remove($id)
        }
        Add-ErSettingOutcome $mod $id $(if ($failed -contains $id) { 'failed' } else { 'left' }) $note
    }
    if ($e.settings.Count -eq 0) { $Manifest.modules.Remove($Name) }
    Save-ErManifest $Manifest
    $null = $ErCache.Remove('smb-server'), $ErCache.Remove('smb-client')
    $fresh = Invoke-ErModule $Name $Only
    foreach ($s in @($mod.settings)) { if ($s.outcome) { Add-ErSettingOutcome $fresh $s.id $s.outcome $s.note } }
    $mod = $fresh
    $mod.recorded = [bool]$Manifest.modules.ContainsKey($Name)
    $mod.done = @($restored | Select-Object -First 50)
    if ($failed.Count -gt 0 -and $restored.Count -eq 0) { return Set-ErOutcome $mod 'failed' "$($failed.Count) setting(s) could not be put back." }
    if ($left.Count -gt 0 -or $failed.Count -gt 0) { return Set-ErOutcome $mod 'partly_undone' "$($left.Count + $failed.Count) setting(s) were left; each says why." }
    return Set-ErOutcome $mod 'undone' ''
}

# The guard: a scheduled task that undoes what apply just changed.
function Register-ErRollback {
    param([int]$Minutes, [string[]]$Ids)
    $copy = Join-Path (Get-ErHardeningDir) 'easyrmm-hardening.ps1'
    $argText = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $copy + '" undo --settings ' + ($Ids -join ',') + ' rolled-back'
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $exe -Argument $argText
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($Minutes))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    [void](Register-ScheduledTask -TaskName $ErTaskName -TaskPath $ErTaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force)
}

function Unregister-ErRollback {
    $t = Get-ScheduledTask -TaskName $ErTaskName -TaskPath $ErTaskPath -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $ErTaskName -TaskPath $ErTaskPath -Confirm:$false
        return $true
    }
    return $false
}

# What a rolled-back undo leaves for the next check to report.
function Save-ErRollbackNote {
    param([string[]]$Ids, [string]$Now)
    $f = Join-Path (Get-ErHardeningDir) 'last-rollback.json'
    $json = @{ at = $Now; ids = @($Ids) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($f, $json, (New-Object Text.UTF8Encoding($false)))
}

function Get-ErRollbackWarning {
    $f = Join-Path (Get-ErHardeningDir) 'last-rollback.json'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    try {
        $n = ConvertFrom-Json ([IO.File]::ReadAllText($f))
        $ids = @($n.ids) -join ', '
        return "A change was undone by the guard at $($n.at), because the agent did not confirm it in time: $ids."
    } catch {
        return $null
    }
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
                $m.settings = @($m.settings | Where-Object { $_.state -ne 'in_place' -or $_.outcome })
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
        osConfig = @($ErPolicy.OSConfigScenarios)
    }
    # What makes apply check only on this computer (ADR-0054, Platforms),
    # the platform's own reads among it.
    $reasons = @() + (Get-ErComputerReasons $ErPolicy)
    if ($ErPolicy.GpPreferences) { $reasons += 'group_policy_preferences' }
    if (@($ErPlatform.Unread).Count -gt 0 -and $reasons -notcontains 'unreadable') { $reasons += 'unreadable' }
    return @{
        owners = $owners
        checkOnlyReasons = $reasons
        notes = @(@($ErPlatform.Unread) + @($ErPolicy.Notes) | ForEach-Object { Limit-ErText $_ 200 } | Select-Object -First 10)
        hardening = @{ folder = $Folder.Folder; copySha256 = $Folder.CopySha256; warnings = @($Folder.Warnings); setAside = @($Folder.SetAside) }
    }
}

# New-ErRefused: a module an apply or undo did not touch, as the check
# reports modules it cannot read; apply and undo name the refusal.
function New-ErRefused {
    param([string]$Name, [string]$Why)
    $m = @{ module = $Name; state = 'not_supported'; reason = Limit-ErText $Why 300 }
    if ($ErMode -eq 'apply' -or $ErMode -eq 'undo') { $m.outcome = 'refused'; $m.outcomeReason = Limit-ErText $Why 300 }
    return $m
}

# Disarm the guard: what the server's confirm job runs, where the agent
# is reachable.
function Invoke-ErConfirm {
    try {
        $was = Unregister-ErRollback
        Say $(if ($was) { 'The guard was ended: the change stands.' } else { 'No guard was armed.' })
    } catch {
        [Console]::Error.WriteLine('windows.ps1: the guard could not be ended: ' + $_.Exception.Message)
        exit 1
    }
}

Say "EasyRMM hardening ($ErMode) on Windows build $($ErPlatform.Build).$($ErPlatform.Ubr), $($ErPlatform.Role), support: $ErSupport"
if ($ErMode -eq 'confirm') {
    Invoke-ErConfirm
    exit 0
}
$ErWork = New-ErWorkFolder 'easyrmm-hardening-'
$ErFolder = $null
$ErNow = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
try {
    if ($ErMode -eq 'apply') {
        # The folder is made here and nowhere else; check never makes it.
        try { New-ErHardeningFolder } catch { $ErFolder = @{ Folder = 'refused'; Refusal = 'The Hardening folder could not be made: ' + $_.Exception.Message; Warnings = @(); SetAside = @(); Lock = $null; Manifest = $null; CopySha256 = '' } }
    }
    if (-not $ErFolder) {
        try {
            $ErFolder = Open-ErHardening
        } catch {
            $ErFolder = @{ Folder = 'refused'; Refusal = 'The Hardening folder could not be checked: ' + $_.Exception.Message; Warnings = @(); SetAside = @(); Lock = $null; Manifest = $null; CopySha256 = '' }
        }
    }
    $ErPolicy = Get-ErPolicyContext $ErWork
    $ErCannotTell = @(Get-ErComputerReasons $ErPolicy)
    if ($ErPolicy.GpPreferences) { $ErCannotTell += 'group_policy_preferences' }
    if (@($ErPlatform.Unread).Count -gt 0 -and $ErCannotTell -notcontains 'unreadable') { $ErCannotTell += 'unreadable' }
    $modules = @()
    $changed = New-Object System.Collections.ArrayList
    $refusal = ''
    if ($ErFolder.Refusal) {
        $refusal = $ErFolder.Refusal
    } elseif ($ErSupport -eq 'unsupported' -and $ErMode -ne 'undo') {
        $refusal = "Windows build $($ErPlatform.Build) has not been tested with this script."
    } elseif ($ErMode -eq 'apply' -and $ErSupport -ne 'full') {
        $refusal = 'This computer is check only (Windows, edition or architecture not yet tested for apply).'
    } elseif ($ErMode -eq 'apply' -and $ErCannotTell.Count -gt 0) {
        $refusal = 'An owner of this computer''s settings cannot be read yet (' + ($ErCannotTell -join ', ') + '), so apply is check only here.'
    } elseif ($ErMode -eq 'apply' -and $ErPlatform.Role -eq 'unknown') {
        $refusal = 'Windows did not report the computer''s role, which apply needs.'
    } elseif (@('apply', 'undo') -contains $ErMode -and $ErPlatform.Role -eq 'domain_controller' -and -not (Test-ErOption 'domain-controller')) {
        $refusal = 'This is a domain controller: some changes affect every computer that signs in to the domain; choose the domain-controller option.'
    }
    if ($refusal) {
        Say "Refused: $refusal"
        foreach ($name in $ErArgs.Modules) { $modules += New-ErRefused $name $refusal }
    } else {
        $manifest = $null
        if (@('apply', 'undo') -contains $ErMode) {
            $manifest = $(if ($ErFolder.Manifest) { ConvertTo-ErPlain $ErFolder.Manifest } else { New-ErManifest })
            if ($ErMode -eq 'apply') {
                Save-ErCopy $manifest
                # The copy's hash is in the manifest, which therefore exists.
                Save-ErManifest $manifest
                Remove-Item -LiteralPath (Join-Path (Get-ErHardeningDir) 'last-rollback.json') -Force -ErrorAction SilentlyContinue
            }
        }
        foreach ($name in $ErArgs.Modules) {
            Say "$($ErMode): $name"
            try {
                if ($ErMode -eq 'apply') {
                    $m = Invoke-ErApply $name $ErArgs.Settings $manifest $ErNow $changed
                } elseif ($ErMode -eq 'undo') {
                    $m = Invoke-ErUndo $name $ErArgs.Settings $manifest $ErNow
                } else {
                    $m = Invoke-ErModule $name $ErArgs.Settings
                }
            } catch {
                $m = @{ module = $name; state = 'failed'; reason = Limit-ErText ("The $ErMode stopped: " + $_.Exception.Message) 300 }
                if ($ErMode -ne 'check') { $m.outcome = 'failed'; $m.outcomeReason = $m.reason }
            }
            if ($ErMode -eq 'check' -and (Test-ErHalfApplied $ErFolder.Manifest $name)) {
                $m.state = 'half_applied'
                $m.reason = 'An apply or undo of this module began and did not finish.'
            }
            Say "  $($m.state)$(if ($m.outcome) { ', ' + $m.outcome })"
            $modules += $m
        }
        if ($ErMode -eq 'apply' -and $changed.Count -gt 0) {
            Save-ErManifest $manifest
            $minutes = $ErOptions['guard-minutes']
            if ($minutes) {
                try {
                    Register-ErRollback ([int]$minutes) @($changed)
                    Say "The guard is armed: these changes are undone in $minutes minutes unless confirmed."
                } catch {
                    # Without its guard a change that may cut access is
                    # put back at once.
                    $why = $_.Exception.Message
                    Say 'The guard could not be armed; undoing what this apply changed.'
                    foreach ($name in $ErArgs.Modules) { [void](Invoke-ErUndo $name @($changed) $manifest $ErNow) }
                    foreach ($m in $modules) { $m.outcome = 'failed'; $m.outcomeReason = Limit-ErText ('The guard could not be armed, so the change was undone: ' + $why) 300 }
                }
            }
        }
        if ($ErMode -eq 'undo') {
            if ($manifest.modules.Count -eq 0) {
                # The record is consumed; so is the copy.
                Remove-Item -LiteralPath (Join-Path (Get-ErHardeningDir) 'manifest.json') -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path (Get-ErHardeningDir) 'easyrmm-hardening.ps1') -Force -ErrorAction SilentlyContinue
            }
            if (Test-ErOption 'rolled-back') {
                if (Test-Path -LiteralPath (Get-ErHardeningDir)) { Save-ErRollbackNote @($ErArgs.Settings) $ErNow }
                try { [void](Unregister-ErRollback) } catch { Say "The guard's task could not be removed: $($_.Exception.Message)" }
            }
        }
    }
    $rolled = Get-ErRollbackWarning
    if ($rolled) { $ErFolder.Warnings = @($ErFolder.Warnings) + $rolled }
    # After the modules: some records are read only when a setting needs
    # them, and add their notes.
    $platformJson = ConvertTo-ErPlatformJson $ErPlatform $ErSupport $ErLanguageMode (Get-ErPlatformExtra $ErFolder)
    Write-ErResult $platformJson $modules
} finally {
    if ($ErFolder -and $ErFolder.Lock) { $ErFolder.Lock.Dispose() }
    Remove-Item -LiteralPath $ErWork -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
