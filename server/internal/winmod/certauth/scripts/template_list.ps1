Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    if (-not $ca.Enterprise) { Write-Result $true ([ordered]@{ standalone = $true; templates = @() }) $null $null; exit 0 }
    $all = Get-TemplateInfos
    if ($null -eq $all) { Stop-Result 'directory_unavailable' 'The certificate templates could not be read from the directory.' }
    Write-Result $true ([ordered]@{ standalone = $false; templates = @($all | Where-Object { $_.published }) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the templates failed: ' + $_.Exception.GetType().Name)
}
