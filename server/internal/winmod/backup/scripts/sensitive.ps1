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
            # A real server gives TargetType (Volume, Disk or Network), with the share in Path; it has no NetworkPath.
            if ($net -eq '' -and [string](Get-Prop $t 'TargetType') -eq 'Network') { $net = [string](Get-Prop $t 'Path') }
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
        # A file spec is FilePath (with a trailing backslash), FileName ('*' for all of it), IsRecursive and IsIncludeSpec
        # (found on a real server; there is no FileSpec, Path or IsExclude).
        $exc = @()
        foreach ($f in @(Get-First $pol @('FilesSpecsToBackup', 'FileSpecsToBackup'))) {
            if ($null -eq $f) { continue }
            $spec = ([string](Get-Prop $f 'FilePath')).TrimEnd('\')
            $leaf = [string](Get-Prop $f 'FileName')
            if ($leaf -ne '' -and $leaf -ne '*') { $spec = $spec + '\' + $leaf }
            if ($null -ne (Get-Prop $f 'IsIncludeSpec') -and -not [bool](Get-Prop $f 'IsIncludeSpec')) { $exc += $spec } else { $inc += $spec }
        }
        $data.include = @($inc)
        $data.exclude = @($exc)
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the backup targets failed: ' + $_.Exception.GetType().Name)
}
