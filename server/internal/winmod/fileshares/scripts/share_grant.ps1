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
    $right = [string]$p.right
    $sid = Resolve-AccountSid ([string]$p.account)
    if (Test-WeakGrant $sid $right) { Stop-Result 'weakens_access' 'This would open the share to everyone; reading may be granted, writing may not.' }
    Grant-SmbShareAccess -Name $name -AccountName (Get-AccountName $sid) -AccessRight $right -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Granting access failed: ' + $_.Exception.GetType().Name)
}
