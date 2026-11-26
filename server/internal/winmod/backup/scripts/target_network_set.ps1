Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
#@library credential
try {
    Assert-Wsb
    Assert-NotBusy
    $pol = Get-Policy $true
    if ($null -eq $pol) { Stop-Result 'no_policy' 'Set the items and schedule first.' }
    $cred = New-EasyRmmCredential (Get-Prop $p 'user') (Get-Prop $p 'password')
    $target = New-WBBackupTarget -NetworkPath (Get-Prop $p 'unc') -Credential $cred
    foreach ($t in @(Get-WBBackupTarget -Policy $pol -ErrorAction SilentlyContinue)) { Remove-WBBackupTarget -Policy $pol -Target $t | Out-Null }
    Add-WBBackupTarget -Policy $pol -Target $target | Out-Null
    Set-WBPolicy -Policy $pol -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true; credentialSet = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Setting the share target failed: ' + $_.Exception.GetType().Name)
}
