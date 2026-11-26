Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $job = Get-RunningJob
    if ($null -eq $job) { Stop-Result 'not_running' 'No recovery is running.' }
    if ([string](Get-Prop $job 'JobType') -eq 'Backup') { Stop-Result 'not_a_recovery' 'The running operation is a backup.' }
    Stop-WBJob -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Stopping the recovery failed: ' + $_.Exception.GetType().Name)
}
