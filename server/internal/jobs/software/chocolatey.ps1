# EasyRMM software action through Chocolatey (ADR-0028), run by the EasyRMM
# agent as LocalSystem. Arguments: install, upgrade or uninstall; the
# Chocolatey package id; for install, an optional version. The EasyRMM server
# accepts only plain ids and versions, and they are never part of this
# script's text.
$ErrorActionPreference = 'Stop'
$action = $args[0]
$id = $args[1]
$version = if ($args.Count -gt 2) { $args[2] } else { '' }

# Where Chocolatey's installer put it, for the whole computer.
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root) { $root = Join-Path $env:ProgramData 'chocolatey' }
$choco = Join-Path $root 'bin\choco.exe'
if (-not (Test-Path -LiteralPath $choco -PathType Leaf)) {
    Write-Output 'Chocolatey is not installed on this computer.'
    exit 2
}
# Any user may create a chocolatey folder under ProgramData; run choco only
# if no one but administrators could have put it there or changed it.
foreach ($exe in @($choco, (Join-Path $root 'choco.exe'))) {
    if ((Test-Path -LiteralPath $exe) -and -not (Test-AdminOnly $exe $root)) {
        Write-Output "Chocolatey in $root can be changed by accounts other than administrators, so EasyRMM will not run it as LocalSystem. Reinstall Chocolatey, or let only SYSTEM and Administrators change that folder."
        exit 2
    }
}

switch ($action) {
    'install' {
        $argv = @('install', $id, '-y', '--no-progress')
        if ($version) { $argv += @('--version', $version) }
    }
    'upgrade' { $argv = @('upgrade', $id, '-y', '--no-progress', '--fail-on-not-installed') }
    'uninstall' { $argv = @('uninstall', $id, '-y', '--no-progress') }
    default {
        Write-Output "Unknown action: $action"
        exit 2
    }
}

Write-Output ('+ choco ' + ($argv -join ' '))
& $choco @argv
$code = $LASTEXITCODE
if ($code -eq 1641 -or $code -eq 3010) {
    Write-Output 'Restart the computer to finish.'
    exit 0
}
exit $code
