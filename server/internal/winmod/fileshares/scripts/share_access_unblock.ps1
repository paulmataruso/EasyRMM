Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $name = [string]$p.name
    Assert-Unprotected $name
    $null = Get-ShareOrStop $name
    $sid = Resolve-AccountSid ([string]$p.account)
    Unblock-SmbShareAccess -Name $name -AccountName (Get-AccountName $sid) -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Unblocking access failed: ' + $_.Exception.GetType().Name)
}
