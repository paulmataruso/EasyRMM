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
    $all = Get-TemplateInfos
    if ($null -eq $all) { Stop-Result 'directory_unavailable' 'The certificate templates could not be read from the directory.' }
    $t = $all | Where-Object { $_.name -eq $name } | Select-Object -First 1
    if ($null -eq $t) { Stop-Result 'not_found' 'There is no such template in the directory.' }
    if ($t.published) { Stop-Result 'exists' 'This CA already publishes that template.' }
    Add-CATemplate -Name $name -Force
    Write-Result $true ([ordered]@{ name = $name; published = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Publishing the template failed: ' + $_.Exception.GetType().Name)
}
