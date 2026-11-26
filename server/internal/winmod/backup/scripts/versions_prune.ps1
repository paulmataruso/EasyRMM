Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $sets = @(Get-WBBackupSet | Sort-Object { [datetime](Get-Prop $_ 'BackupTime') } -Descending)
    $keep = Get-Prop $p 'keep'
    $drop = 0
    if ($null -ne $keep) {
        if ($sets.Count -gt [int]$keep) { $drop = $sets.Count - [int]$keep }
    } elseif ($sets.Count -gt 1) {
        $drop = 1
    }
    if ($sets.Count -gt 0 -and $drop -ge $sets.Count) { Stop-Result 'would_leave_none' 'That would remove every backup version.' }
    if ($drop -ne [int](Get-Prop $p 'expect')) { Stop-Result 'changed' 'The versions changed since the preview. Preview again.' }
    if ($drop -eq 0) { Write-Result $true ([ordered]@{ removed = 0; remaining = $sets.Count }) $null $null; exit 0 }
    $pol = Get-Policy $false
    $tgt = $null
    if ($null -ne $pol) { $tgt = @(Get-WBBackupTarget -Policy $pol -ErrorAction SilentlyContinue) | Select-Object -First 1 }
    if ($null -ne $keep) {
        if ($null -ne $tgt) { Remove-WBBackupSet -BackupTarget $tgt -KeepVersions ([int]$keep) -Force | Out-Null } else { Remove-WBBackupSet -KeepVersions ([int]$keep) -Force | Out-Null }
    } else {
        if ($null -ne $tgt) { Remove-WBBackupSet -BackupTarget $tgt -DeleteOldest -Force | Out-Null } else { Remove-WBBackupSet -DeleteOldest -Force | Out-Null }
    }
    $left = @(Get-WBBackupSet).Count
    Write-Result $true ([ordered]@{ removed = $drop; remaining = $left }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Removing the backup versions failed: ' + $_.Exception.GetType().Name)
}
