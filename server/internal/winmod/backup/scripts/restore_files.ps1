Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    Assert-NotBusy
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $windir = [string]$os.WindowsDirectory
    $drive = [string]$os.SystemDirectory.Substring(0, 2)
    $source = [string](Get-Prop $p 'source')
    $target = Get-Prop $p 'targetPath'
    if ($null -eq $target) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $target = Join-Path (Join-Path $drive 'EasyRMM-Restore') $stamp
    }
    $full = [System.IO.Path]::GetFullPath([string]$target).TrimEnd('\')
    if (Test-PathUnder $full $windir) { Stop-Result 'bad_target' 'Files are not restored into the Windows folder.' }
    if (Test-PathUnder $source $full) { Stop-Result 'bad_target' 'Restore to a different folder than the one the files came from.' }
    $want = [string](Get-Prop $p 'version')
    $set = @(Get-WBBackupSet | Where-Object { [string](Get-First $_ @('VersionId', 'BackupSetId')) -eq $want }) | Select-Object -First 1
    if ($null -eq $set) { Stop-Result 'version_not_found' 'That backup version is no longer there. Read the versions again.' }
    New-Item -ItemType Directory -Path $full -Force | Out-Null
    if ([bool](Get-Prop $p 'recursive')) {
        Start-WBFileRecovery -BackupSet $set -SourcePath $source -TargetPath $full -Option CreateCopyIfExists -Recursive -Async -Force | Out-Null
    } else {
        Start-WBFileRecovery -BackupSet $set -SourcePath $source -TargetPath $full -Option CreateCopyIfExists -Async -Force | Out-Null
    }
    Write-Result $true ([ordered]@{ started = $true; targetPath = $full }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Starting the restore failed: ' + $_.Exception.GetType().Name)
}
