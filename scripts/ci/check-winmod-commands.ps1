# The command-parameter check for the Windows management modules' scripts (ADR-0073, ADR-0083). It parses every .ps1 under
# server/internal/winmod and, for every command call, checks each named parameter against the command's own metadata
# (Get-Command) in the running PowerShell: a parameter the command does not have fails the check. It also bans @(<generic
# List>), which throws in Windows PowerShell 5.1. No domain is needed. Run it under Windows PowerShell 5.1 and PowerShell 7
# on a computer with the GroupPolicy and ActiveDirectory modules (RSAT):
#
#   powershell -File scripts/ci/check-winmod-commands.ps1 -RequireModules GroupPolicy,ActiveDirectory
#   pwsh       -File scripts/ci/check-winmod-commands.ps1 -RequireModules GroupPolicy,ActiveDirectory
#
# A command that cannot be resolved (its module is not installed here) is listed and not checked; -RequireModules makes a
# missing module a failure, so a runner that lost the tools cannot pass by checking nothing.
param([string]$Root = '', [string[]]$RequireModules = @(), [switch]$SkipSelfTest)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Root) { $Root = Join-Path $repo 'server/internal/winmod' }
. (Join-Path $PSScriptRoot 'winmod-ast/WinmodCommands.ps1')

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
$missing = @($RequireModules | Where-Object { -not (Test-WinmodModuleAvailable $_) })
if ($missing.Count -gt 0) { Write-Host "required module(s) not installed: $($missing -join ', ')"; exit 1 }
Import-WinmodCheckModules (@('GroupPolicy', 'ActiveDirectory', 'DnsServer', 'DhcpServer', 'ADCSAdministration', 'PrintManagement', 'Defender', 'BitLocker', 'SmbShare', 'NetSecurity', 'ScheduledTasks') + $RequireModules)
foreach ($m in $RequireModules) {
    if ($null -eq (Get-Command -Module $m -ErrorAction SilentlyContinue | Select-Object -First 1)) { Write-Host "required module $m loaded no commands"; exit 1 }
}

if (-not $SkipSelfTest) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('winmod-cmd-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $tmp
    try {
        $bad = Join-Path $tmp 'bad.ps1'
        Set-Content -LiteralPath $bad -Encoding UTF8 -Value @'
$q = @{ Path = 'x'; Nope = 1 }
Get-ChildItem -LiteralPath 'x' -NoSuchParameter
Get-Item @q
function Local-Fn([string]$Name) { $Name }
Local-Fn -Name 'a' -Other 'b'
$list = New-Object System.Collections.Generic.List[object]
$arr = @($list)
'@
        $unres = @{}
        $got = @(Test-WinmodCommandFile $bad $unres)
        foreach ($want in @('has no parameter -NoSuchParameter', 'has no parameter -Nope', 'Local-Fn has no parameter -Other', 'list: ')) {
            if (-not ($got | Where-Object { $_ -like "*$want*" })) { Write-Host "self-test: expected a finding with '$want', got: $($got -join ' | ')"; exit 1 }
        }
        if ($got.Count -ne 4) { Write-Host "self-test: expected 4 findings, got $($got.Count): $($got -join ' | ')"; exit 1 }
        $good = Join-Path $tmp 'good.ps1'
        Set-Content -LiteralPath $good -Encoding UTF8 -Value @'
$q = @{ LiteralPath = 'x' }
Get-Item @q
Get-ChildItem -LiteralPath 'x' -Dir -Force -ErrorAction SilentlyContinue
function Local-Fn([string]$Name) { $Name }
Local-Fn -Name 'a'
$list = New-Object System.Collections.Generic.List[object]
$arr = $list.ToArray()
$x = @($list | Select-Object -First 1)
'@
        $got = @(Test-WinmodCommandFile $good $unres)
        if ($got.Count -ne 0) { Write-Host "self-test: the good fixture was flagged: $($got -join ' | ')"; exit 1 }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    Write-Host 'command check self-test passed.'
}

$files = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' | Sort-Object FullName)
$unresolved = @{}
$findings = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) { foreach ($x in (Test-WinmodCommandFile $f.FullName $unresolved)) { $findings.Add($x) } }
foreach ($x in $findings) { Write-Host $x }
if ($unresolved.Count -gt 0) {
    Write-Host "not checked (no metadata here): $((($unresolved.Keys | Sort-Object) | ForEach-Object { "$_ x$($unresolved[$_])" }) -join ', ')"
}
if ($findings.Count -gt 0) { Write-Host "$($findings.Count) finding(s)."; exit 1 }
Write-Host "$($files.Count) scripts: every named parameter exists on its command ($($unresolved.Count) command name(s) not checked)."
