# Hand test: software on Windows with winget and Chocolatey

CI checks the Windows software scripts against stand-ins for `winget.exe`
and Chocolatey ([software_windows_test.go](../../server/internal/jobs/software_windows_test.go)).
It never installs real software. Before a release, run this test by hand on a
real Windows computer with the EasyRMM agent. It installs Sublime Text 4 and
Notepad++, then removes them: first with the four scripts below from the
script library, then with **Install software**
([Installing, updating and removing software](../operations/software.md)).

You need:

* A Windows computer with the EasyRMM agent that you can install software on
  and remove it from. Use a test machine, not a customer's.
* For winget: Windows 11 or Windows Server 2025, with App Installer
  installed. Windows Server 2019 and 2022 do not include winget; test only
  Chocolatey there.
* Internet access from the computer to `cdn.winget.microsoft.com`,
  `community.chocolatey.org` and the publishers' download sites.

## 1. Add the scripts to the library

In **Scripts → New script**, add each script below with the shell
**PowerShell** and a timeout of 30 minutes, at the **Shared** level or the
test computer's organization.
Each script runs as LocalSystem, as every script does. The three test
scripts end by reading Windows' own list of installed programs and fail if
the result is not what the action should have left.

### Install Chocolatey

Installs Chocolatey for the whole computer with its
[official install script](https://chocolatey.org/install), unless it is
already there.

```powershell
# Installs Chocolatey for the whole computer with its official install
# script, unless it is already installed.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root) { $root = Join-Path $env:ProgramData 'chocolatey' }
$choco = Join-Path $root 'bin\choco.exe'
if (Test-Path -LiteralPath $choco -PathType Leaf) {
    Write-Output "Chocolatey $(& $choco --version) is already installed in $root."
    exit 0
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$installer = (New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
Invoke-Expression $installer
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root) { $root = Join-Path $env:ProgramData 'chocolatey' }
$choco = Join-Path $root 'bin\choco.exe'
if (-not (Test-Path -LiteralPath $choco -PathType Leaf)) {
    Write-Output "The install script ended, but $choco is not there."
    exit 1
}
Write-Output "Chocolatey $(& $choco --version) is installed in $root."
```

### Test: winget, Sublime Text and Notepad++

Argument: `install` (or none) or `uninstall`.

```powershell
# Hand test: installs or removes Sublime Text 4 and Notepad++ with winget,
# for the whole computer. Argument: install (the default) or uninstall.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$action = if ($args.Count -gt 0) { $args[0] } else { 'install' }
if ($action -ne 'install' -and $action -ne 'uninstall') {
    Write-Output "Unknown action: $action. Use install or uninstall."
    exit 2
}

# LocalSystem has no winget of its own: use the newest App Installer's.
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
    Write-Output 'winget is not installed on this computer.'
    exit 2
}
Write-Output "winget $(& $winget --version) from $winget"

$failed = 0
foreach ($id in 'SublimeHQ.SublimeText.4', 'Notepad++.Notepad++') {
    $argv = @($action, '--id', $id, '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity', '--silent')
    if ($action -eq 'install') { $argv += @('--accept-package-agreements', '--scope', 'machine') }
    Write-Output ''
    Write-Output ('+ winget ' + ($argv -join ' '))
    & $winget @argv
    $code = $LASTEXITCODE
    switch ($code) {
        0 { Write-Output "${id}: done." }
        -1978335135 { Write-Output "${id}: already installed." } # 0x8A150061
        -1978335189 { Write-Output "${id}: already installed; no newer version." } # 0x8A15002B
        -1978335212 { Write-Output "${id}: not installed." } # 0x8A150014
        -1978334967 { Write-Output "${id}: done; restart the computer to finish." } # 0x8A150109
        default {
            Write-Output ('{0}: winget failed with exit code 0x{1:X8}.' -f $id, $code)
            $failed++
        }
    }
}

# What Windows lists as installed now.
$programs = Get-ItemProperty -ErrorAction SilentlyContinue -Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Write-Output ''
foreach ($name in 'Sublime Text', 'Notepad++') {
    $found = @($programs | Where-Object { $_.DisplayName -like "$name*" })
    if ($found.Count -gt 0) {
        $found | ForEach-Object { Write-Output "Installed: $($_.DisplayName) $($_.DisplayVersion)" }
    } else {
        Write-Output "Not installed: $name"
    }
    if (($action -eq 'install') -ne ($found.Count -gt 0)) {
        Write-Output "  Expected $name to be $(if ($action -eq 'install') { 'installed' } else { 'gone' })."
        $failed++
    }
}
if ($failed) { exit 1 }
```

### Test: Chocolatey, Sublime Text and Notepad++

Argument: `install` (or none) or `uninstall`. Removing also removes
`notepadplusplus.install`, the package that `notepadplusplus` points at
and that installs Notepad++.

```powershell
# Hand test: installs or removes Sublime Text 4 and Notepad++ with
# Chocolatey. Argument: install (the default) or uninstall.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$action = if ($args.Count -gt 0) { $args[0] } else { 'install' }
if ($action -ne 'install' -and $action -ne 'uninstall') {
    Write-Output "Unknown action: $action. Use install or uninstall."
    exit 2
}
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root) { $root = Join-Path $env:ProgramData 'chocolatey' }
$choco = Join-Path $root 'bin\choco.exe'
if (-not (Test-Path -LiteralPath $choco -PathType Leaf)) {
    Write-Output 'Chocolatey is not installed on this computer. Run "Install Chocolatey" first.'
    exit 2
}
Write-Output "Chocolatey $(& $choco --version) in $root"

$failed = 0
$packages = @('sublimetext4', 'notepadplusplus')
if ($action -eq 'uninstall') {
    # notepadplusplus only points at notepadplusplus.install, which installs
    # Notepad++. Only what Chocolatey has: it fails on the others.
    $packages = @('sublimetext4', 'notepadplusplus', 'notepadplusplus.install' | Where-Object { Test-Path -LiteralPath (Join-Path $root "lib\$_") -PathType Container })
}
if ($packages.Count -eq 0) {
    Write-Output 'Chocolatey has neither package.'
} else {
    $argv = @($action) + $packages + @('-y', '--no-progress')
    Write-Output ''
    Write-Output ('+ choco ' + ($argv -join ' '))
    & $choco @argv
    $code = $LASTEXITCODE
    if ($code -eq 1641 -or $code -eq 3010) {
        Write-Output 'Done; restart the computer to finish.'
    } elseif ($code -ne 0) {
        Write-Output "choco failed with exit code $code."
        $failed++
    }
}

# What Windows lists as installed now.
$programs = Get-ItemProperty -ErrorAction SilentlyContinue -Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Write-Output ''
foreach ($name in 'Sublime Text', 'Notepad++') {
    $found = @($programs | Where-Object { $_.DisplayName -like "$name*" })
    if ($found.Count -gt 0) {
        $found | ForEach-Object { Write-Output "Installed: $($_.DisplayName) $($_.DisplayVersion)" }
    } else {
        Write-Output "Not installed: $name"
    }
    if (($action -eq 'install') -ne ($found.Count -gt 0)) {
        Write-Output "  Expected $name to be $(if ($action -eq 'install') { 'installed' } else { 'gone' })."
        $failed++
    }
}
if ($failed) { exit 1 }
```

### Report: Sublime Text and Notepad++

Lists what Windows, winget and Chocolatey each have. It changes nothing.

```powershell
# Lists Sublime Text and Notepad++ as Windows, winget and Chocolatey see
# them. Changes nothing.
$ProgressPreference = 'SilentlyContinue'
Write-Output 'Windows (Apps and features):'
$programs = Get-ItemProperty -ErrorAction SilentlyContinue -Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$found = @($programs | Where-Object { $_.DisplayName -like 'Sublime Text*' -or $_.DisplayName -like 'Notepad++*' })
if ($found.Count -eq 0) { Write-Output '  neither' }
$found | ForEach-Object { Write-Output "  $($_.DisplayName) $($_.DisplayVersion) in $($_.InstallLocation)" }

$candidates = foreach ($dir in Get-ChildItem -Path (Join-Path $env:ProgramFiles 'WindowsApps') -Directory `
        -Filter 'Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe' -ErrorAction SilentlyContinue) {
    $exe = Join-Path $dir.FullName 'winget.exe'
    $v = $null
    if ((Test-Path -LiteralPath $exe) -and [version]::TryParse(($dir.Name -split '_')[1], [ref]$v)) {
        [pscustomobject]@{ Path = $exe; Version = $v }
    }
}
$winget = $candidates | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty Path
Write-Output ''
if ($winget) {
    foreach ($id in 'SublimeHQ.SublimeText.4', 'Notepad++.Notepad++') {
        Write-Output "winget list --id $id --exact:"
        & $winget list --id $id --exact --accept-source-agreements --disable-interactivity
    }
} else {
    Write-Output 'winget: not installed.'
}

$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root) { $root = Join-Path $env:ProgramData 'chocolatey' }
$choco = Join-Path $root 'bin\choco.exe'
Write-Output ''
if (Test-Path -LiteralPath $choco -PathType Leaf) {
    Write-Output 'Chocolatey:'
    & $choco list --limit-output | Where-Object { $_ -match '^(sublimetext|notepadplusplus)' } | ForEach-Object { Write-Output "  $_" }
} else {
    Write-Output 'Chocolatey: not installed.'
}
exit 0
```

## 2. Run the scripts

Run each script on the test computer with **Run** on the script's page,
with the arguments shown, and check each job's result. Run *Report* after any step
whose output is unclear.

| # | Script, arguments | Expect |
|---|---|---|
| 1 | Test: winget, `install` | *Succeeded*; both listed as installed |
| 2 | Test: winget, `install` again | *Succeeded*; winget says they are already installed, or updates one |
| 3 | Test: winget, `uninstall` | *Succeeded*; neither installed |
| 4 | Test: winget, `uninstall` again | *Succeeded*; winget finds neither |
| 5 | Install Chocolatey | *Succeeded*; names Chocolatey's version |
| 6 | Install Chocolatey again | *Succeeded*; "already installed" |
| 7 | Test: Chocolatey, `install` | *Succeeded*; both listed as installed |
| 8 | Test: Chocolatey, `uninstall` | *Succeeded*; neither installed |
| 9 | Test: Chocolatey, `uninstall` again | *Succeeded*; "Chocolatey has neither package." |

## 3. Use Install software

On the test computer's **Software** tab, **Install software**, or from
**Jobs → Install software**. After each job, the Software tab should show
the change within a minute or so.

### winget

| # | Action, package, version | Expect |
|---|---|---|
| 1 | Install `Notepad++.Notepad++`, version `8.9.8` | *Succeeded*; the Software tab shows Notepad++ 8.9.8 |
| 2 | Update `Notepad++.Notepad++` | *Succeeded*; the Software tab shows a newer version |
| 3 | Update `Notepad++.Notepad++` again | *Succeeded*; "No newer version is available." |
| 4 | Install `SublimeHQ.SublimeText.4` | *Succeeded*; Sublime Text in the Software tab |
| 5 | Install `SublimeHQ.SublimeText.4` again | *Succeeded*; "The package is already installed." or "No newer version is available." |
| 6 | Uninstall `SublimeHQ.SublimeText.4` and `Notepad++.Notepad++`, one job each | *Succeeded*; both gone from the Software tab |
| 7 | Uninstall `Notepad++.Notepad++` again | *Succeeded*; "Notepad++.Notepad++ is not installed." |
| 8 | Update `Notepad++.Notepad++` | *Failed*, exit code 3; "is not installed, so it cannot be updated." |
| 9 | Install `EasyRMM.NotAPackage` | *Failed*, exit code 1; "The winget source has no package with the ID EasyRMM.NotAPackage." |

If a winget version is no longer in the `winget` source, use one that
`winget show --id Notepad++.Notepad++ --versions` lists.

### Chocolatey

Chocolatey must be installed (*Install Chocolatey* above).

| # | Action, package, version | Expect |
|---|---|---|
| 1 | Install `notepadplusplus`, version `8.9.8` | *Succeeded*; the Software tab shows Notepad++ 8.9.8 |
| 2 | Update `notepadplusplus` | *Succeeded*; the Software tab shows a newer version |
| 3 | Install `sublimetext4` | *Succeeded*; Sublime Text in the Software tab |
| 4 | Install `sublimetext4` again | *Succeeded*; Chocolatey says it is already installed |
| 5 | Uninstall `sublimetext4` | *Succeeded*; Sublime Text gone |
| 6 | Uninstall `notepadplusplus` | *Succeeded*; **Notepad++ stays**, because `notepadplusplus.install` installed it |
| 7 | Uninstall `notepadplusplus.install` | *Succeeded*; Notepad++ gone |
| 8 | Uninstall `notepadplusplus` again | *Succeeded*; "notepadplusplus is not installed." and no `choco` line |
| 9 | Update `sublimetext4` | *Failed*, exit code 3; "is not installed, so it cannot be updated." |
| 10 | Install `easyrmm-not-a-package` | *Failed*; Chocolatey says the package was not found |

If a Chocolatey version is no longer on the community repository, use one
that [its page](https://community.chocolatey.org/packages/notepadplusplus#versionhistory)
lists.

## Record the result

Note the Windows edition and version, the agent's version, and the winget
and Chocolatey versions the scripts print. Then tick *winget and Chocolatey
scripts* under "Run on real computers" in the [roadmap](../../ROADMAP.md),
or note any step that did not do what the table says.
