# The PowerShell AST check for the Windows management modules' catalogue scripts (ADR-0073, slice 9). It parses every
# .ps1 under server/internal/winmod and fails on what the ADRs ban: Invoke-Expression, parameters outside the stdin
# variable, strings built from a parameter, filters from a value, and ConvertTo-SecureString -AsPlainText outside the
# one pinned helper (ADR-0077). Then it runs its own self-test over the fixtures, so a check that stopped catching
# something fails here too.
#
#   pwsh scripts/ci/check-winmod-ast.ps1 [-Root <folder>] [-SkipSelfTest]
#
# The pinned helpers are in winmod-helper-pins.json: {"Function-Name": "<SHA-256 of its body>"}.
param([string]$Root = '', [switch]$SkipSelfTest)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Root) { $Root = Join-Path $repo 'server/internal/winmod' }
. (Join-Path $PSScriptRoot 'winmod-ast/WinmodAst.ps1')

$pins = @{}
$pinFile = Join-Path $PSScriptRoot 'winmod-helper-pins.json'
if (Test-Path -LiteralPath $pinFile) {
    $obj = Get-Content -LiteralPath $pinFile -Raw | ConvertFrom-Json
    foreach ($prop in $obj.PSObject.Properties) { $pins[$prop.Name] = [string]$prop.Value }
}

$findings = @(Test-WinmodTree -Root $Root -Pins $pins)
$count = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1').Count
foreach ($f in $findings) { Write-Host $f }
if ($findings.Count -gt 0) { exit 1 }
Write-Host "$count catalogue scripts pass the AST check ($($pins.Count) pinned helper(s))."

if (-not $SkipSelfTest) {
    $global:LASTEXITCODE = 0
    & (Join-Path $PSScriptRoot 'winmod-ast/self-test.ps1')
    if ($LASTEXITCODE -ne 0) { exit 1 }
}
