# A harness for the apply and undo logic of windows.ps1 (ADR-0054, W2) that
# runs on any PowerShell 7: the script's functions and the few variables
# they need are taken from its syntax tree, the registry is a hashtable and
# the ownership reader finds no owner. It prints one line per step,
# "name: value". Run: pwsh -File this.ps1 -Script windows.ps1 -Settings windows-settings.json
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param([string]$Script, [string]$Settings)
$ErrorActionPreference = 'Stop'
$ErSettingsJson = [IO.File]::ReadAllText($Settings)
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
$names = @('ErAllModules', 'ErOptionModule', 'ErListOptions', 'ErReportOnly', 'ErTaskName', 'ErTaskPath', 'ErProtectedFolder', 'ErInheritedFile')
foreach ($st in $ast.EndBlock.Statements) {
    if ($st -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $st.Extent.Text
    } elseif ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $names -contains $st.Left.VariablePath.UserPath) {
        Invoke-Expression $st.Extent.Text
    }
}
$ErSettings = @((ConvertFrom-Json $ErSettingsJson).settings)
$ErPlatform = @{ Build = 26100; Ubr = 1; Role = 'member_server'; Client = $false; Core = $false; Edition = 'ServerStandard'; Unread = @() }
$ErOptions = @{}
$ErPolicy = @{ Products = @{ antivirus = @(); firewall = @() } }
$ErCannotTell = @()
$ErCache = @{}
$script:Reg = @{}
$script:Saved = ''
$script:Fail = @{}
$script:Lose = @{}

function Limit-ErText { param($Text, $Max) $t = [string]$Text; if ($t.Length -gt $Max) { return $t.Substring(0, $Max) } return $t }
function Get-ErRegistryValue {
    param([string]$Path, [string]$Name)
    $k = "$Path|$Name"
    if ($script:Reg.ContainsKey($k)) { return @{ Exists = $true; Data = $script:Reg[$k].Data; Kind = $script:Reg[$k].Kind; Error = '' } }
    return @{ Exists = $false; Data = $null; Kind = ''; Error = '' }
}
function Set-ErRegistryData {
    param([string]$Path, [string]$Name, [string]$Kind, $Data)
    if ($script:Fail.ContainsKey($Name)) { throw 'access denied' }
    if ($script:Lose.ContainsKey($Name)) { return }
    $script:Reg["$Path|$Name"] = @{ Data = $Data; Kind = $Kind }
}
function Remove-ErRegistryData { param([string]$Path, [string]$Name) $script:Reg.Remove("$Path|$Name") }
function Resolve-ErRegistryOwner { return $null }
function Resolve-ErSecurityOwner { return $null }
function Get-ErModuleGate { return $null }
function Save-ErManifest { param($Manifest) $script:Saved = ($Manifest | ConvertTo-Json -Depth 10) }
$script:Sec = @{ MinimumPasswordLength = '7'; LockoutBadCount = '0'; PasswordComplexity = '0' }
$script:Smb = @{ 'server|EnableSMB1Protocol' = $true; 'server|RequireSecuritySignature' = $false }
function Get-ErSecurityPolicy { return $script:Sec }
function Set-ErSecurityValue { param([string]$Key, $Data) $script:Sec[$Key] = [string]$Data }
function Get-SmbServerConfiguration { [CmdletBinding()] param() return [pscustomobject]@{ EnableSMB1Protocol = $script:Smb['server|EnableSMB1Protocol']; RequireSecuritySignature = $script:Smb['server|RequireSecuritySignature']; EnableSecuritySignature = $true } }
function Set-ErSmbValue { param([string]$Side, [string]$Property, $Data) $script:Smb["$Side|$Property"] = [bool]$Data }
function Get-ErExposure { return @{ Read = $true; Exposed = $false; Accounts = @(); Addresses = @(); Bursts = @(); Since = $null; SinceReason = 'none' } }
function Test-ErFeatureSetting { param($Def) return New-ErSetting $Def 'not_in_place' 'present' 'absent' }
function Show { param($Name, $Value) "${Name}: $Value" }
function Get-Reg { param($Name) $m = $script:Reg.Keys | Where-Object { $_ -like "*|$Name" }; if ($m) { return [string]$script:Reg[$m].Data } return 'absent' }
function Get-Setting { param($Module, $Id) return @($Module.settings | Where-Object { $_.id -eq $Id })[0] }

$now = '2026-11-26T10:00:00Z'
$changed = New-Object System.Collections.ArrayList

# 1. Apply autoplay on a computer that has NoAutorun = 0 already.
$script:Reg['HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun'] = @{ Data = [uint32]0; Kind = 'DWord' }
$man = New-ErManifest
$m = Invoke-ErApply 'autoplay' @() $man $now $changed
Show 'apply1 outcome' $m.outcome
Show 'apply1 state' $m.state
Show 'apply1 changed' ($changed -join ',')
Show 'apply1 NoAutorun' (Get-Reg 'NoAutorun')
Show 'apply1 NoDriveTypeAutoRun' (Get-Reg 'NoDriveTypeAutoRun')
Show 'apply1 setting outcome' (Get-Setting $m 'autoplay-autorun').outcome
Show 'apply1 before' (Get-Setting $m 'autoplay-autorun').before
Show 'apply1 recorded' $m.recorded
Show 'manifest done' ($man.modules['autoplay'].done -eq $now)

# 2. Apply again changes nothing.
$changed2 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'autoplay' @() $man $now $changed2
Show 'apply2 outcome' $m.outcome
Show 'apply2 changed' $changed2.Count

# 3. The manifest as it was saved, read back; undo returns the originals.
$man2 = ConvertTo-ErPlain (ConvertFrom-Json $script:Saved)
$m = Invoke-ErUndo 'autoplay' @() $man2 $now
Show 'undo1 outcome' $m.outcome
Show 'undo1 NoAutorun' (Get-Reg 'NoAutorun')
Show 'undo1 NoDriveTypeAutoRun' (Get-Reg 'NoDriveTypeAutoRun')
Show 'undo1 NoAutoplayfornonVolume' (Get-Reg 'NoAutoplayfornonVolume')
Show 'undo1 record left' $man2.modules.Count

# 4. Undo with nothing recorded.
$m = Invoke-ErUndo 'autoplay' @() $man2 $now
Show 'undo2 outcome' $m.outcome

# 5. A value changed after apply is left.
$man = New-ErManifest
$changed3 = New-Object System.Collections.ArrayList
[void](Invoke-ErApply 'autoplay' @() $man $now $changed3)
$script:Reg['HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun'] = @{ Data = [uint32]7; Kind = 'DWord' }
$m = Invoke-ErUndo 'autoplay' @() $man $now
Show 'undo3 outcome' $m.outcome
Show 'undo3 NoAutorun' (Get-Reg 'NoAutorun')
Show 'undo3 NoDriveTypeAutoRun' (Get-Reg 'NoDriveTypeAutoRun')
Show 'undo3 left' (Get-Setting $m 'autoplay-autorun').outcome

# 6. A write that fails is reported and the others go on.
$script:Reg.Clear()
$script:Fail['NoAutorun'] = $true
$man = New-ErManifest
$changed4 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'autoplay' @() $man $now $changed4
Show 'fail outcome' $m.outcome
Show 'fail setting' (Get-Setting $m 'autoplay-autorun').outcome
Show 'fail other' (Get-Setting $m 'autoplay-all-drives').outcome
Show 'fail changed' ($changed4 -join ',')
Show 'fail NoAutorun' (Get-Reg 'NoAutorun')
$script:Fail.Clear()

# 7. A value that reads back wrong is put back.
$script:Reg.Clear()
$script:Lose['NoAutorun'] = $true
$script:Lose['NoDriveTypeAutoRun'] = $true
$script:Lose['NoAutoplayfornonVolume'] = $true
$man = New-ErManifest
$changed5 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'autoplay' @() $man $now $changed5
Show 'readback outcome' $m.outcome
Show 'readback record' $man.modules.ContainsKey('autoplay')
$script:Lose.Clear()

# 8. One setting by id: only it is written and put back.
$script:Reg.Clear()
$man = New-ErManifest
$changed6 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'autoplay' @('autoplay-autorun') $man $now $changed6
Show 'one changed' ($changed6 -join ',')
Show 'one NoDriveTypeAutoRun' (Get-Reg 'NoDriveTypeAutoRun')
$m = Invoke-ErUndo 'autoplay' @('autoplay-autorun') $man $now
Show 'one undo' $m.outcome
Show 'one NoAutorun' (Get-Reg 'NoAutorun')

# 9. A setting of a kind apply does not write is skipped, with why.
$script:Reg.Clear()
$man = New-ErManifest
$changed7 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'features' @() $man $now $changed7
Show 'kind outcome' $m.outcome

# 10. A module that only reports.
$m = Invoke-ErApply 'bitlocker' @() (New-ErManifest) $now $changed7
Show 'report outcome' $m.outcome

# 11. A bit mask keeps the bits already set.
$script:Reg.Clear()
$script:Reg['HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec'] = @{ Data = [uint32]1; Kind = 'DWord' }
$man = New-ErManifest
$changed8 = New-Object System.Collections.ArrayList
[void](Invoke-ErApply 'ntlm' @('ntlm-client-session') $man $now $changed8)
Show 'bits value' (Get-Reg 'NTLMMinClientSec')

# 12. An owner the reader cannot read: undo leaves the value.
$script:Reg.Clear()
$man = New-ErManifest
$changed9 = New-Object System.Collections.ArrayList
[void](Invoke-ErApply 'autoplay' @() $man $now $changed9)
$ErCannotTell = @('mdm')
$m = Invoke-ErUndo 'autoplay' @() $man $now
Show 'cannot outcome' $m.outcome
Show 'cannot NoAutorun' (Get-Reg 'NoAutorun')

# 13. Security policy values: written through secedit, read back, put back.
$script:Reg.Clear(); $ErCannotTell = @()
$man = New-ErManifest
$c10 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'accounts' @('accounts-min-length', 'accounts-complexity', 'accounts-lockout-threshold') $man $now $c10
Show 'sec outcome' $m.outcome
Show 'sec changed' ($c10 -join ',')
Show 'sec length' $script:Sec['MinimumPasswordLength']
Show 'sec lockout' $script:Sec['LockoutBadCount']
$man2 = ConvertTo-ErPlain (ConvertFrom-Json (ConvertTo-Json $man -Depth 10))
$m = Invoke-ErUndo 'accounts' @() $man2 $now
Show 'sec undo' $m.outcome
Show 'sec length undone' $script:Sec['MinimumPasswordLength']
Show 'sec lockout undone' $script:Sec['LockoutBadCount']

# 14. SMB's configuration, and Schannel and WinRM as registry values.
$man = New-ErManifest
$c11 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'smb' @('smb-server-smb1') $man $now $c11
Show 'smb outcome' $m.outcome
Show 'smb value' $script:Smb['server|EnableSMB1Protocol']
$m = Invoke-ErUndo 'smb' @() $man $now
Show 'smb undo' $m.outcome
Show 'smb undone' $script:Smb['server|EnableSMB1Protocol']
$script:Reg.Clear()
$ErPlatform.Build = 20348
$man = New-ErManifest
$c12 = New-Object System.Collections.ArrayList
$m = Invoke-ErApply 'tls' @('tls-tls10-server') $man $now $c12
Show 'tls outcome' $m.outcome
Show 'tls restart' $m.restart
Show 'tls value' (Get-Reg 'Enabled')
$m = Invoke-ErUndo 'tls' @() $man $now
Show 'tls undone' (Get-Reg 'Enabled')

# 15. An owner may set it again: restored with a note; Group Policy preferences leave it.
$script:Reg.Clear()
$man = New-ErManifest
$c13 = New-Object System.Collections.ArrayList
[void](Invoke-ErApply 'autoplay' @('autoplay-autorun') $man $now $c13)
$ErCannotTell = @('dsc')
$m = Invoke-ErUndo 'autoplay' @() $man $now
Show 'dsc outcome' $m.outcome
Show 'dsc note' (Get-Setting $m 'autoplay-autorun').note
$man = New-ErManifest
[void](Invoke-ErApply 'autoplay' @('autoplay-autorun') $man $now $c13)
$ErCannotTell = @('group_policy_preferences')
$m = Invoke-ErUndo 'autoplay' @() $man $now
Show 'prefs outcome' $m.outcome
$ErCannotTell = @('group_policy_record_off')
$m = Invoke-ErUndo 'autoplay' @() $man $now
Show 'record-off policy key' $m.outcome
