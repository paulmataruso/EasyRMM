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
    $source = [string](Get-Prop $p 'source')
    if (Test-PathUnder $source $windir) { Stop-Result 'bad_target' 'Files are not restored over the Windows folder.' }
    $want = [string](Get-Prop $p 'version')
    $set = @(Get-WBBackupSet | Where-Object { [string](Get-First $_ @('VersionId', 'BackupSetId')) -eq $want }) | Select-Object -First 1
    if ($null -eq $set) { Stop-Result 'version_not_found' 'That backup version is no longer there. Read the versions again.' }
    if ([bool](Get-Prop $p 'recursive')) {
        Start-WBFileRecovery -BackupSet $set -SourcePath $source -Option OverwriteIfExists -Recursive -Async -Force | Out-Null
    } else {
        Start-WBFileRecovery -BackupSet $set -SourcePath $source -Option OverwriteIfExists -Async -Force | Out-Null
    }
    Write-Result $true ([ordered]@{ started = $true; targetPath = $source }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Starting the restore failed: ' + $_.Exception.GetType().Name)
}
