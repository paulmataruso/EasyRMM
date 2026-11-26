Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $pol = Get-Policy $true
    if ($null -eq $pol) { Stop-Result 'no_policy' 'Set the items and schedule first.' }
    $number = [int](Get-Prop $p 'diskNumber')
    $disk = @(Get-WBDisk | Where-Object { [int](Get-Prop $_ 'DiskNumber') -eq $number }) | Select-Object -First 1
    if ($null -eq $disk) { Stop-Result 'disk_changed' 'That disk is no longer there. Read the disks again.' }
    $id = [string](Get-First $disk @('DiskId', 'DiskIdentifier'))
    if ($id -ne [string](Get-Prop $p 'diskId')) { Stop-Result 'disk_changed' 'The disk with that number is not the one that was chosen. Read the disks again.' }
    $target = New-WBBackupTarget -Disk $disk
    foreach ($t in @(Get-WBBackupTarget -Policy $pol -ErrorAction SilentlyContinue)) { Remove-WBBackupTarget -Policy $pol -Target $t | Out-Null }
    # A disk target asks whether it may be formatted; with no console the answer is -Force (found on a real server).
    Add-WBBackupTarget -Policy $pol -Target $target -Force | Out-Null
    Set-WBPolicy -Policy $pol -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Setting the disk target failed: ' + $_.Exception.GetType().Name)
}
