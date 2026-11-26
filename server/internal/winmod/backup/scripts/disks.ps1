Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $out = @()
    foreach ($d in @(Get-WBDisk -ErrorAction SilentlyContinue)) {
        $num = Get-Number (Get-Prop $d 'DiskNumber')
        $vols = @()
        foreach ($v in @(Get-Prop $d 'Volumes')) {
            if ($null -ne $v) {
                $vols += [ordered]@{
                    label = [string](Get-First $v @('VolumeLabel', 'Label'))
                    sizeBytes = Get-Number (Get-Prop $v 'TotalSpace')
                    freeBytes = Get-Number (Get-Prop $v 'FreeSpace')
                }
            }
        }
        $out += [ordered]@{
            number = $num
            id = [string](Get-First $d @('DiskId', 'DiskIdentifier'))
            name = [string](Get-First $d @('DiskName', 'Name'))
            sizeBytes = Get-Number (Get-Prop $d 'TotalSpace')
            online = -not [bool](Get-Prop $d 'IsOffline')
            hasData = ($vols.Count -gt 0)
            volumes = @($vols)
        }
    }
    Write-Result $true ([ordered]@{ disks = @($out) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the disks failed: ' + $_.Exception.GetType().Name)
}
