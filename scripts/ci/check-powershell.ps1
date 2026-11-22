# Checks the PowerShell scripts the agent runs (the Windows software and
# hardening scripts, and internal/winpolicy's reader): each parses, with
# Windows PowerShell 5.1 where it is installed (the agent runs them with
# it) and with the PowerShell running this, and PSScriptAnalyzer finds no
# error or warning under PSScriptAnalyzerSettings.psd1.
#
#   pwsh scripts/ci/check-powershell.ps1 [-Module <folder holding PSScriptAnalyzer>]
#
# Without -Module it downloads PSScriptAnalyzer 1.24.0 from the PowerShell
# Gallery and checks the package's SHA-256 before loading it.
param([string]$Module = '')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scripts = @(
    Get-ChildItem -Path (Join-Path $root 'server/internal/jobs') -Recurse -Filter '*.ps1'
    Get-ChildItem -Path (Join-Path $root 'internal/winpolicy') -Recurse -Filter '*.ps1'
) | Sort-Object FullName

if (-not $Module) {
    $version = '1.24.0'
    $sha256 = 'e86c97d44bb1bc8a1de35e753b85ea1d938f6f9f881639a181507e079bca4556'
    $work = Join-Path ([IO.Path]::GetTempPath()) ('psa-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $work
    $pkg = Join-Path $work 'psa.nupkg'
    Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/PSScriptAnalyzer/$version" -OutFile $pkg -UseBasicParsing
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $pkg).Hash.ToLowerInvariant()
    if ($got -ne $sha256) { throw "PSScriptAnalyzer $version has SHA-256 $got, not $sha256." }
    $Module = Join-Path $work 'PSScriptAnalyzer'
    Expand-Archive -LiteralPath $pkg -DestinationPath $Module
}
Import-Module (Join-Path $Module 'PSScriptAnalyzer.psd1')

$failed = $false
$desktop = ''
if ($env:SystemRoot) { $desktop = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
foreach ($s in $scripts) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) {
        Write-Host "$($s.FullName):$($e.Extent.StartLineNumber): $($e.Message)"
        $failed = $true
    }
    if ($desktop -and (Test-Path -LiteralPath $desktop)) {
        $parse = '$t = $null; $e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$t, [ref]$e); ' +
            'foreach ($x in $e) { [Console]::WriteLine(\"{0}: {1}\", $x.Extent.StartLineNumber, $x.Message) }; exit $e.Count'
        $out = & $desktop -NoLogo -NoProfile -NonInteractive -Command $parse $s.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Host "$($s.FullName) (Windows PowerShell 5.1): $out"
            $failed = $true
        }
    }
}

$settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
foreach ($s in $scripts) {
    foreach ($r in @(Invoke-ScriptAnalyzer -Path $s.FullName -Settings $settings)) {
        Write-Host "$($s.FullName):$($r.Line): $($r.RuleName): $($r.Message)"
        $failed = $true
    }
}
if ($failed) { exit 1 }
Write-Host "$($scripts.Count) PowerShell scripts parse and pass PSScriptAnalyzer."
