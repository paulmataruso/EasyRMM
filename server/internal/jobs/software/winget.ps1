# EasyRMM software action through winget (ADR-0028), run by the EasyRMM
# agent as LocalSystem. Arguments: install, upgrade or uninstall; the winget
# package id; for install, an optional version. The EasyRMM server accepts
# only plain ids and versions, and they are never part of this script's text.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$action = $args[0]
$id = $args[1]
$version = if ($args.Count -gt 2) { $args[2] } else { '' }

# winget is installed for each user, and LocalSystem has none of its own: run
# the newest copy in the App Installer package's folder.
$candidates = foreach ($dir in Get-ChildItem -Path (Join-Path $env:ProgramFiles 'WindowsApps') -Directory `
        -Filter 'Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe' -ErrorAction SilentlyContinue) {
    $exe = Join-Path $dir.FullName 'winget.exe'
    $v = $null
    if ((Test-Path -LiteralPath $exe) -and [version]::TryParse(($dir.Name -split '_')[1], [ref]$v)) {
        [pscustomobject]@{ Path = $exe; Version = $v }
    }
}
$winget = $candidates | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty Path
if (-not $winget) {
    # Elsewhere on the system's PATH, only if no one but administrators can
    # change it: WindowsApps is Windows' own, other folders may not be.
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        if (-not (Test-AdminOnly $cmd.Source (Split-Path -Parent $cmd.Source))) {
            Write-Output "$($cmd.Source) can be changed by accounts other than administrators, so EasyRMM will not run it as LocalSystem."
            exit 2
        }
        $winget = $cmd.Source
    }
}
if (-not $winget) {
    Write-Output 'winget is not installed on this computer. It comes with App Installer on Windows 10 (1809 and later), Windows 11 and Windows Server 2025.'
    exit 2
}

$common = @('--id', $id, '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')
switch ($action) {
    'install' {
        # Installed for the whole computer: LocalSystem's own profile is of no use.
        $argv = @('install') + $common + @('--silent', '--accept-package-agreements', '--scope', 'machine')
        if ($version) { $argv += @('--version', $version) }
    }
    'upgrade' { $argv = @('upgrade') + $common + @('--silent', '--accept-package-agreements') }
    'uninstall' { $argv = @('uninstall') + $common + @('--silent') }
    default {
        Write-Output "Unknown action: $action"
        exit 2
    }
}

Write-Output ('+ winget ' + ($argv -join ' '))
& $winget @argv
$code = $LASTEXITCODE
switch ($code) {
    0 { exit 0 }
    -1978335189 { Write-Output 'No newer version is available.'; exit 0 } # 0x8A15002B
    -1978335135 { Write-Output 'The package is already installed.'; exit 0 } # 0x8A150061
    -1978334967 { Write-Output 'Restart the computer to finish.'; exit 0 } # 0x8A150109
    default {
        Write-Output ('winget failed: exit code 0x{0:X8}.' -f $code)
        exit 1
    }
}
