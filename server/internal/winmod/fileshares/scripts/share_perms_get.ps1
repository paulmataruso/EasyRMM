Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $name = [string]$p.name
    $null = Get-ShareOrStop $name
    $entries = @()
    foreach ($a in @(Get-SmbShareAccess -Name $name)) {
        $entries += [ordered]@{
            account = [string](Get-Prop $a 'AccountName')
            right = [string](Get-Prop $a 'AccessRight')
            type = [string](Get-Prop $a 'AccessControlType')
        }
    }
    Write-Result $true ([ordered]@{ name = $name; entries = @($entries) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the share permissions failed: ' + $_.Exception.GetType().Name)
}
