Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $pol = Get-Policy $true
    if ($null -eq $pol) { Stop-Result 'no_policy' 'There is no backup policy.' }
    if ([bool](Get-Prop $p 'enabled')) { Set-WBVssBackupOption -Policy $pol -VssFullBackup | Out-Null } else { Set-WBVssBackupOption -Policy $pol -VssCopyBackup | Out-Null }
    Set-WBPolicy -Policy $pol -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Setting the backup type failed: ' + $_.Exception.GetType().Name)
}
