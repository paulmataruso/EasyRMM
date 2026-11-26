Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Wsb
    $out = @()
    foreach ($s in @(Get-WBBackupSet -ErrorAction SilentlyContinue)) {
        $kinds = @()
        foreach ($k in @(Get-First $s @('Application', 'Applications'))) { if ($null -ne $k -and [string]$k -ne '') { $kinds += 'application' } }
        if ($null -ne (Get-Prop $s 'Volume')) { $kinds += 'volume' }
        $id = [string](Get-First $s @('VersionId', 'BackupSetId'))
        $out += [ordered]@{
            id = $id
            time = Get-Utc (Get-Prop $s 'BackupTime')
            sizeBytes = Get-Number (Get-First $s @('BackupSize', 'Size'))
            kinds = @($kinds | Select-Object -Unique)
        }
        if ($out.Count -ge 100) { break }
    }
    Write-Result $true ([ordered]@{ versions = @($out) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the backup versions failed: ' + $_.Exception.GetType().Name)
}
