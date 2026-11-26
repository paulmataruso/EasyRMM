Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $old = Get-Policy $false
    $pol = New-WBPolicy
    $haveTarget = $false
    if ($null -ne $old) {
        foreach ($t in @(Get-WBBackupTarget -Policy $old -ErrorAction SilentlyContinue)) {
            Add-WBBackupTarget -Policy $pol -Target $t | Out-Null
            $haveTarget = $true
        }
    } else {
        $first = Get-Prop $p 'targetVolume'
        if ($null -ne $first) {
            $target = New-WBBackupTarget -VolumePath $first
            Add-WBBackupTarget -Policy $pol -Target $target | Out-Null
            $haveTarget = $true
        }
    }
    if (-not $haveTarget) { Stop-Result 'no_target' 'Name a target volume: this computer has no policy to keep a target from.' }
    $items = 0
    $vols = Get-Prop $p 'volumes'
    if ($null -ne $vols) {
        foreach ($v in @($vols -split '\|')) {
            $vol = Get-WBVolume -VolumePath $v
            Add-WBVolume -Policy $pol -Volume $vol | Out-Null
            $items++
        }
    }
    $files = Get-Prop $p 'files'
    $exclude = Get-Prop $p 'exclude'
    if ($null -ne $exclude -and $null -eq $files) { Stop-Result 'bad_exclude' 'Exclusions need an included folder.' }
    if ($null -ne $files) {
        $spec = New-WBFileSpec -FileSpec @($files -split '\|')
        Add-WBFileSpec -Policy $pol -FileSpec $spec | Out-Null
        $items++
        if ($null -ne $exclude) {
            $skip = New-WBFileSpec -FileSpec @($exclude -split '\|') -Exclude
            Add-WBFileSpec -Policy $pol -FileSpec $skip | Out-Null
        }
    }
    if ([bool](Get-Prop $p 'systemState')) { Add-WBSystemState -Policy $pol | Out-Null; $items++ }
    if ([bool](Get-Prop $p 'bareMetal')) { Add-WBBareMetalRecovery -Policy $pol | Out-Null; $items++ }
    if ($items -eq 0) { Stop-Result 'no_items' 'Choose at least one thing to back up.' }
    $times = @(([string](Get-Prop $p 'times')) -split ',' | ForEach-Object { [datetime]::ParseExact($_.Trim(), 'HH:mm', [Globalization.CultureInfo]::InvariantCulture) })
    Set-WBSchedule -Policy $pol -Schedule $times | Out-Null
    $keepFull = $false
    if ($null -ne $old) {
        $opt = Get-First $old @('VssBackupOptions', 'VssBackupOption')
        $keepFull = ([string]$opt -eq 'VssFullBackup')
    }
    if ($keepFull) { Set-WBVssBackupOption -Policy $pol -VssFullBackup | Out-Null } else { Set-WBVssBackupOption -Policy $pol -VssCopyBackup | Out-Null }
    Set-WBPolicy -Policy $pol -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Setting the backup policy failed: ' + $_.Exception.GetType().Name)
}
