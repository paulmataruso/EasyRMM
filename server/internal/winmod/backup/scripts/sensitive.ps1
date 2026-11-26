Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $pol = Get-Policy $false
    $data = [ordered]@{ targets = @(); include = @(); exclude = @() }
    if ($null -ne $pol) {
        $targets = @()
        foreach ($t in @(Get-WBBackupTarget -Policy $pol -ErrorAction SilentlyContinue)) {
            $net = [string](Get-Prop $t 'NetworkPath')
            $label = [string](Get-First $t @('Label', 'InlineLabel'))
            $path = if ($net -ne '') { $net } else { [string](Get-Prop $t 'Path') }
            if ($path -eq '') { $path = $label }
            $targets += [ordered]@{ path = $path; label = $label; kind = $(if ($net -ne '') { 'network' } else { 'local' }) }
        }
        $data.targets = @($targets)
        $inc = @()
        foreach ($v in @(Get-Prop $pol 'VolumesToBackup')) {
            if ($null -ne $v) { $inc += [string](Get-First $v @('MountPath', 'VolumeLabel', 'Label')) }
        }
        foreach ($f in @(Get-First $pol @('FilesSpecsToBackup', 'FileSpecsToBackup'))) {
            if ($null -ne $f) { $inc += [string](Get-First $f @('FileSpec', 'Path')) }
        }
        $data.include = @($inc)
        $exc = @()
        foreach ($f in @(Get-First $pol @('FilesSpecsToBackup', 'FileSpecsToBackup'))) {
            if ($null -ne $f -and [bool](Get-Prop $f 'IsExclude')) { $exc += [string](Get-Prop $f 'FileSpec') }
        }
        $data.exclude = @($exc)
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the backup targets failed: ' + $_.Exception.GetType().Name)
}
