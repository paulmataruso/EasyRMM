Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    Assert-EnterpriseCa $ca
    Assert-TemplateCmdlets
    $name = [string]$p.name
    $published = Get-PublishedNames
    if ($null -eq $published -or -not ($published -contains $name)) { Stop-Result 'not_found' 'This CA does not publish that template.' }
    Remove-CATemplate -Name $name -Force
    Write-Result $true ([ordered]@{ name = $name; published = $false }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Unpublishing the template failed: ' + $_.Exception.GetType().Name)
}
