Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Server
    if (Import-Wsb) { Write-Result $true ([ordered]@{ installed = $true; restartNeeded = $false; alreadyInstalled = $true }) $null $null; exit 0 }
    if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        Stop-Result 'unsupported' 'This computer cannot install Windows features with Install-WindowsFeature.'
    }
    $r = Install-WindowsFeature -Name Windows-Server-Backup
    $restart = ([string](Get-Prop $r 'RestartNeeded') -eq 'Yes')
    Write-Result $true ([ordered]@{ installed = [bool](Get-Prop $r 'Success'); restartNeeded = $restart; alreadyInstalled = $false }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Installing Windows Server Backup failed: ' + $_.Exception.GetType().Name)
}
