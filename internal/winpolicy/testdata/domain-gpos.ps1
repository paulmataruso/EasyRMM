# The Group Policy objects the ownership reader's domain test expects
# (TestQueryDomainAsSystem, in query_windows_test.go). Run it on a test
# domain's controller as a Domain Admin or SYSTEM, then gpupdate
# /target:computer /force on the member. Never on a production domain: it
# links its policies at the domain's root. docs/development/machine-tests.md
# says how the domain is made and how the record-off scenario is run.
#
# The security and audit policies are written as the Group Policy
# Management Console writes them (GptTmpl.inf, audit.csv, and their
# extensions in gPCMachineExtensionNames), since the GroupPolicy module has
# no cmdlet for either.
#
#   EasyRMM-W1-Registry     administrative templates: LLMNR off, WinRM
#                           client Basic on, Defender PUA protection on
#   EasyRMM-W1-Security     minimum password length 8, lockout after 5,
#                           LmCompatibilityLevel 3; linked first, ahead of
#                           Default Domain Policy, so its values win
#   EasyRMM-W1-Audit        Credential Validation success and failure,
#                           Process Creation success
#   EasyRMM-W1-Preferences  registry preference items (one of them WDigest)
#   EasyRMM-W1-RSoPOff      turns Group Policy's record off; made, not linked

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory
$root = (Get-ADDomain).DistinguishedName
$policies = Join-Path $env:SystemRoot 'SYSVOL\domain\Policies'

function New-TestGpo {
    param([string]$Name, [bool]$Link)
    $g = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $g) { $g = New-GPO -Name $Name -Comment 'EasyRMM ownership reader test' }
    if ($Link -and -not ((Get-GPInheritance -Target $root).GpoLinks | Where-Object DisplayName -eq $Name)) {
        New-GPLink -Guid $g.Id -Target $root -LinkEnabled Yes | Out-Null
    }
    return $g
}

# Register a client-side extension and its tool on the policy, and raise
# the computer version in the directory and in GPT.INI so members apply it.
function Add-TestExtension {
    param($Gpo, [string]$Pair)
    $dn = "CN={$($Gpo.Id)},CN=Policies,CN=System,$root"
    $o = Get-ADObject -Identity $dn -Properties gPCMachineExtensionNames, versionNumber
    $pairs = @([regex]::Matches([string]$o.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object { $_.Value })
    $all = @($pairs + $Pair) | Sort-Object -Unique
    $version = [int]$o.versionNumber
    $next = ($version -band 0xFFFF0000) + (($version -band 0xFFFF) + 1)
    Set-ADObject -Identity $dn -Replace @{ gPCMachineExtensionNames = ($all -join ''); versionNumber = $next }
    $ini = Join-Path $policies "{$($Gpo.Id)}\GPT.INI"
    $text = [regex]::Replace([IO.File]::ReadAllText($ini), '(?m)^Version=\d+', "Version=$next")
    [IO.File]::WriteAllText($ini, $text, [Text.Encoding]::ASCII)
}

function Write-TestFile {
    param([string]$Folder, [string]$Name, [string]$Text, [Text.Encoding]$Encoding)
    $null = New-Item -ItemType Directory -Force -Path $Folder
    [IO.File]::WriteAllText((Join-Path $Folder $Name), (($Text -replace "`r?`n", "`r`n") + "`r`n"), $Encoding)
}

$g = New-TestGpo 'EasyRMM-W1-Registry' $true
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -Type DWord -Value 0 | Out-Null
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -ValueName 'AllowBasic' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Type DWord -Value 1 | Out-Null

$g = New-TestGpo 'EasyRMM-W1-Security' $true
Write-TestFile (Join-Path $policies "{$($g.Id)}\Machine\Microsoft\Windows NT\SecEdit") 'GptTmpl.inf' @'
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 8
LockoutBadCount = 5
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,3
[Version]
signature="$CHICAGO$"
Revision=1
'@ ([Text.Encoding]::Unicode)
Add-TestExtension $g '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
Set-GPLink -Guid $g.Id -Target $root -Order 1 | Out-Null

$g = New-TestGpo 'EasyRMM-W1-Audit' $true
Write-TestFile (Join-Path $policies "{$($g.Id)}\Machine\Microsoft\Windows NT\Audit") 'audit.csv' @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,,3
,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1
'@ ([Text.Encoding]::ASCII)
Add-TestExtension $g '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

$g = New-TestGpo 'EasyRMM-W1-Preferences' $true
Set-GPPrefRegistryValue -Guid $g.Id -Context Computer -Action Update -Key 'HKLM\SOFTWARE\EasyRMMTest' -ValueName 'PrefValue' -Type DWord -Value 1 | Out-Null
Set-GPPrefRegistryValue -Guid $g.Id -Context Computer -Action Update -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ValueName 'UseLogonCredential' -Type DWord -Value 0 | Out-Null

$g = New-TestGpo 'EasyRMM-W1-RSoPOff' $false
Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'RSoPLogging' -Type DWord -Value 0 | Out-Null

(Get-GPInheritance -Target $root).GpoLinks | Format-Table Order, DisplayName, Enabled -AutoSize | Out-String -Width 120
