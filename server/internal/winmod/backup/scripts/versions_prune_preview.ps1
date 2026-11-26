Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $sets = @(Get-WBBackupSet | Sort-Object { [datetime](Get-Prop $_ 'BackupTime') } -Descending)
    $keep = Get-Prop $p 'keep'
    $drop = @()
    if ($null -ne $keep) {
        $n = [int]$keep
        if ($sets.Count -gt $n) { $drop = @($sets | Select-Object -Skip $n) }
    } elseif ($sets.Count -gt 1) {
        $drop = @($sets | Select-Object -Last 1)
    }
    if ($sets.Count -gt 0 -and $drop.Count -ge $sets.Count) { Stop-Result 'would_leave_none' 'That would remove every backup version.' }
    $list = @($drop | ForEach-Object { [ordered]@{ id = [string](Get-First $_ @('VersionId', 'BackupSetId')); time = Get-Utc (Get-Prop $_ 'BackupTime') } })
    Write-Result $true ([ordered]@{ total = $sets.Count; sets = @($list) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the versions to remove failed: ' + $_.Exception.GetType().Name)
}
