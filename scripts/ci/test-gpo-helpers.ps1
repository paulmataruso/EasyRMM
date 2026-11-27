# Runs the Group Policy scripts' shared helper functions (server/internal/winmod/grouppolicy/src/lib.txt, as built into every
# script) on sample data, in the PowerShell that runs this file: no domain, no GroupPolicy module. Built for Windows
# PowerShell 5.1, where the bug that prompted it lives (@(<List[object]>) of hashtables throws "Argument types do not
# match"), and it also passes in PowerShell 7.
#
# It cannot run what needs a domain: Get-Context, Get-DirSearcher, Get-LinkTargets (the directory search; its list building,
# Build-LinkTargetList, is run), Get-StagingBase/Save-GpoBackup (Backup-GPO), Get-GpmDomain/Get-WmiFilterList (the GPMC COM
# object), Resolve-Trustee (SID lookups) and every script body. Commands the helpers call that live in the GroupPolicy module
# (Get-GPInheritance) are replaced by a stand-in that returns a sample object.
#
#   powershell -File scripts/ci/test-gpo-helpers.ps1
param([string]$Script = '')

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Script) { $Script = Join-Path $repo 'server/internal/winmod/grouppolicy/scripts/status.ps1' }
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)); helpers from $(Split-Path -Leaf $Script)"

$parsed = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
$defs = @($parsed.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })
if ($defs.Count -lt 20) { Write-Host "only $($defs.Count) functions found in $Script"; exit 1 }
. ([scriptblock]::Create((($defs | ForEach-Object { $_.Extent.Text }) -join "`n")))

# What the helpers read from the script's own scope.
$version = 1
$p = '{"id":"11111111-2222-3333-4444-555555555555","expectComputerVersion":3,"name":"x"}' | ConvertFrom-Json

$failed = 0
$ran = 0
function Check([string]$Name, $Got, $Want) {
    $script:ran++
    $g = ConvertTo-Json -InputObject $Got -Compress -Depth 8
    $w = ConvertTo-Json -InputObject $Want -Compress -Depth 8
    if ($g -ne $w) { Write-Host "FAIL $Name`n  got  $g`n  want $w"; $script:failed++ }
}
function Check-True([string]$Name, [bool]$Cond) { Check $Name $Cond $true }

# Stop-With ends the script in production; here it records what it was told and throws a marker.
$script:stop = $null
function Stop-With($code, $message) {
    $script:stop = @{ code = [string]$code; message = [string]$message }
    throw 'EASYRMM-TEST-STOP'
}
function Get-Stop([scriptblock]$Block) {
    $script:stop = $null
    try { & $Block } catch { if ($_.Exception.Message -ne 'EASYRMM-TEST-STOP') { throw } }
    return $script:stop
}

# --- plain text and property helpers
Check 'Join-Text' (Join-Text 'a' 'b') 'ab'
Check 'Format-Text' (Format-Text 'x {0} y {1}' 'A' 'B') 'x A y B'
Check 'Get-Prop present' (Get-Prop $p 'name') 'x'
Check 'Get-Prop absent' (Get-Prop $p 'nope') $null
Check 'Get-Prop null object' (Get-Prop $null 'name') $null
Check 'Get-Text absent' (Get-Text $p 'nope') ''
Check 'Get-Text present' (Get-Text $p 'name') 'x'
Check-True 'Test-Param present' (Test-Param 'name')
Check 'Test-Param absent' (Test-Param 'nope') $false
Check 'Get-UtcText' (Get-UtcText ([datetime]'2026-01-02T03:04:05Z')) '2026-01-02T03:04:05Z'
Check 'Get-UtcText null' (Get-UtcText $null) $null
Check 'Get-Sum' (Get-Sum 2 3) 5
Check 'Get-HexHash' (Get-HexHash ([byte[]](97, 98, 99))) 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
$xml = New-Object System.Xml.XmlDocument
$xml.LoadXml('<a><Name>n</Name><Other>o</Other></a>')
Check 'Get-XmlChild' (Get-XmlChild $xml.DocumentElement 'Name') 'n'
Check 'Get-XmlChild missing' (Get-XmlChild $xml.DocumentElement 'Nope') ''

# --- distinguished names and kinds
$c = @{ Server = 'dc1.example.test'; Domain = 'example.test'; DomainDn = 'DC=example,DC=test'; ControllersDn = 'OU=Domain Controllers,DC=example,DC=test'; Common = @{ Server = 'dc1.example.test'; Domain = 'example.test' } }
Check-True 'Test-UnderDn inside' (Test-UnderDn 'OU=a,DC=example,DC=test' 'DC=example,DC=test')
Check 'Test-UnderDn outside' (Test-UnderDn 'OU=a,DC=other,DC=test' 'DC=example,DC=test') $false
Check-True 'Test-UnderDn equal' (Test-UnderDn 'dc=EXAMPLE,dc=test' 'DC=example,DC=test')
Check 'Get-TargetKind domain' (Get-TargetKind 'DC=example,DC=test' $c) 'domain'
Check 'Get-TargetKind dc_ou' (Get-TargetKind 'OU=Domain Controllers,DC=example,DC=test' $c) 'dc_ou'
Check 'Get-TargetKind site' (Get-TargetKind 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=test' $c) 'site'
Check 'Get-TargetKind ou' (Get-TargetKind 'OU=Staff,DC=example,DC=test' $c) 'ou'
Check-True 'Test-SensitiveKind domain' (Test-SensitiveKind 'domain')
Check 'Test-SensitiveKind ou' (Test-SensitiveKind 'ou') $false
Check 'Assert-InDomain outside' (Get-Stop { Assert-InDomain 'OU=a,DC=other,DC=test' $c }).code 'not_found'
Check 'Assert-InDomain inside' (Get-Stop { Assert-InDomain 'OU=a,DC=example,DC=test' $c }) $null
Check 'Assert-InDomain site' (Get-Stop { Assert-InDomain 'CN=s,CN=Sites,CN=Configuration,DC=other,DC=test' $c }) $null

# --- default policies and versions
Check-True 'Test-DefaultPolicy' (Test-DefaultPolicy '31B2F340-016D-11D2-945F-00C04FB984F9')
Check 'Test-DefaultPolicy other' (Test-DefaultPolicy '11111111-2222-3333-4444-555555555555') $false
Check 'Assert-NotDefault' (Get-Stop { Assert-NotDefault '6ac1786c-016f-11d2-945f-00c04fb984f9' 'renamed' }).code 'protected_policy'
Check 'Assert-NotDefault ok' (Get-Stop { Assert-NotDefault '11111111-2222-3333-4444-555555555555' 'renamed' }) $null
$g = [pscustomobject]@{
    Id = [guid]'11111111-2222-3333-4444-555555555555'; DisplayName = 'Sample'; GpoStatus = 'AllSettingsEnabled'; Description = 'd'; Owner = 'EXAMPLE\Domain Admins'
    CreationTime = [datetime]'2026-01-02T03:04:05Z'; ModificationTime = [datetime]'2026-02-03T04:05:06Z'
    Computer = [pscustomobject]@{ DSVersion = 3; SysvolVersion = 3 }; User = [pscustomobject]@{ DSVersion = 0; SysvolVersion = 0 }
    WmiFilter = [pscustomobject]@{ Name = 'F' }
}
Check 'Get-Versions' (Get-Versions $g) ([ordered]@{ computer = [ordered]@{ directory = 3; sysvol = 3 }; user = [ordered]@{ directory = 0; sysvol = 0 } })
Check 'Assert-Versions equal' (Get-Stop { Assert-Versions $g }) $null
$g2 = [pscustomobject]@{ Computer = [pscustomobject]@{ DSVersion = 4; SysvolVersion = 4 }; User = [pscustomobject]@{ DSVersion = 0; SysvolVersion = 0 } }
Check 'Assert-Versions moved' (Get-Stop { Assert-Versions $g2 }).code 'changed_meanwhile'
$row = ConvertTo-GpoRow $g
Check 'ConvertTo-GpoRow name' $row.name 'Sample'
Check 'ConvertTo-GpoRow id' $row.id '11111111-2222-3333-4444-555555555555'
Check 'ConvertTo-GpoRow wmi' $row.wmiFilter 'F'
Check 'ConvertTo-GpoRow created' $row.created '2026-01-02T03:04:05Z'
Check 'ConvertTo-GpoRow default' $row.default $false
$g.WmiFilter = $null
Check 'ConvertTo-GpoRow no filter' (ConvertTo-GpoRow $g).wmiFilter ''

# --- the link-target list: the 5.1 failure was here
$ous = @(
    @{ dn = 'OU=B,DC=example,DC=test'; name = 'B' },
    @{ dn = 'OU=A,DC=example,DC=test'; name = 'A' },
    @{ dn = 'OU=Domain Controllers,DC=example,DC=test'; name = 'Domain Controllers' }
)
$sites = @('Site-B', 'Site-A')
$t = Build-LinkTargetList $c $ous $sites 'CN=Configuration,DC=example,DC=test'
Check 'targets count' $t.Count 6
Check 'targets is an array' ($t -is [object[]]) $true
Check 'targets order' @($t | ForEach-Object { $_.name }) @('example.test', 'A', 'B', 'Domain Controllers', 'Site-A', 'Site-B')
Check 'targets kinds' @($t | ForEach-Object { $_.kind }) @('domain', 'ou', 'ou', 'dc_ou', 'site', 'site')
Check 'site dn' $t[4].dn 'CN=Site-A,CN=Sites,CN=Configuration,DC=example,DC=test'
$wrapped = @($t)
Check 'targets survive @()' $wrapped.Count 6
$none = Build-LinkTargetList $c @() @() 'CN=Configuration,DC=example,DC=test'
Check 'domain only' @($none).Count 1
Check 'one OU, one site' @(Build-LinkTargetList $c @(@{ dn = 'OU=A,DC=example,DC=test'; name = 'A' }) @('S') 'CN=Configuration,DC=example,DC=test').Count 3
# The failing pattern itself, kept as a statement of what 5.1 does: ToArray() works wherever @() may not.
$lst = New-Object System.Collections.Generic.List[object]
$lst.Add(@{ a = 1 }); $lst.Add(@{ a = 2 })
Check 'List.ToArray' $lst.ToArray().Count 2

# --- the links of one container (Get-GPInheritance stand-in)
function Get-GPInheritance {
    param([string]$Target, [string]$Server, [string]$Domain)
    [pscustomobject]@{
        GpoInheritanceBlocked = $true
        GpoLinks = @(
            [pscustomobject]@{ GpoId = [guid]'AAAAAAAA-0000-0000-0000-000000000001'; DisplayName = 'One'; Enabled = $true; Enforced = $false; Order = 1 },
            [pscustomobject]@{ GpoId = [guid]'AAAAAAAA-0000-0000-0000-000000000002'; DisplayName = 'Two'; Enabled = $false; Enforced = $true; Order = 2 }
        )
    }
}
$info = Get-TargetLinks @{ dn = 'OU=A,DC=example,DC=test'; name = 'A'; kind = 'ou' } $c
Check 'links count' @($info.links).Count 2
Check 'links id' $info.links[0].gpoId 'aaaaaaaa-0000-0000-0000-000000000001'
Check 'links enforced' $info.links[1].enforced $true
Check 'links blocked' $info.blocked $true

# --- security filtering
$perm = { param($level, $sid, $denied) [pscustomobject]@{ Permission = $level; Denied = $denied; Trustee = [pscustomobject]@{ Sid = [pscustomobject]@{ Value = $sid } } } }
$perms = @((& $perm 'GpoApply' 'S-1-5-11' $false), (& $perm 'GpoEdit' 'S-1-5-21-1' $false))
Check 'applies to someone' (Test-AppliesToSomeone $perms 'S-1-5-21-1' $false) $true
Check 'applies, authenticated users removed' (Test-AppliesToSomeone $perms 'S-1-5-11' $false) $false
Check 'applies, keep read' (Test-AppliesToSomeone $perms 'S-1-5-11' $true) $true
Check 'applies, empty' (Test-AppliesToSomeone @() 'S-1-5-11' $false) $false

# --- results
$out = New-Object System.IO.StringWriter
$old = [Console]::Out
[Console]::SetOut($out)
try {
    Write-Changed 'did it' ([ordered]@{ a = 1 }) ([ordered]@{ a = 2 }) $g2 $null (Get-Versions $g2) (Get-Versions $g2)
} finally { [Console]::SetOut($old) }
$line = $out.ToString().Trim()
Check-True 'Write-Changed marker' $line.StartsWith('EASYRMM-WINMOD-RESULT-V1 ')
$res = $line.Substring('EASYRMM-WINMOD-RESULT-V1 '.Length) | ConvertFrom-Json
Check 'Write-Changed ok' $res.ok $true
Check 'Write-Changed summary' $res.data.summary 'did it'

# --- Stop-ForError: each real error type, made by the real engine
function Get-ErrorRecord([scriptblock]$Block) { try { & $Block } catch { return $_ } }
function Test-Binding { [CmdletBinding()] param([string]$Known) }
$binding = Get-ErrorRecord { Test-Binding -Known 'x' -PassThru }
Check 'binding error is not not_found' (Get-Stop { Stop-ForError $binding }).code 'command_failed'
Check-True 'binding error says what it is' ((Get-Stop { Stop-ForError $binding }).message -match 'ParameterBinding')
$notFound = Get-ErrorRecord { throw (New-Object System.ArgumentException('The GPO cannot be found.')) }
Check 'not found' (Get-Stop { Stop-ForError $notFound }).code 'not_found'
$conflict = Get-ErrorRecord { throw (New-Object System.InvalidOperationException('A GPO with that name already exists.')) }
Check 'conflict' (Get-Stop { Stop-ForError $conflict }).code 'conflict'
$denied = Get-ErrorRecord { throw (New-Object System.UnauthorizedAccessException('Access is denied.')) }
Check 'denied' (Get-Stop { Stop-ForError $denied }).code 'access_denied'
$other = Get-ErrorRecord { throw (New-Object System.ArgumentException('Argument types do not match')) }
Check 'other' (Get-Stop { Stop-ForError $other }).code 'command_failed'

if ($failed -gt 0) { Write-Host "$failed of $ran checks failed."; exit 1 }
Write-Host "$ran helper checks passed."
