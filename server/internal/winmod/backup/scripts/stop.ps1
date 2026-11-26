Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $job = Get-RunningJob
    if ($null -eq $job) { Stop-Result 'not_running' 'No backup is running.' }
    if ([string](Get-Prop $job 'JobType') -ne 'Backup') { Stop-Result 'not_a_backup' 'The running operation is not a backup.' }
    Stop-WBJob -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Stopping the backup failed: ' + $_.Exception.GetType().Name)
}
