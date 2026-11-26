Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $name = [string]$p.name
    Assert-Unprotected $name
    if ($null -ne (Get-SmbShare -Name $name -ErrorAction SilentlyContinue)) { Stop-Result 'exists' 'A share of this name already exists.' }
    $path = Assert-ShareablePath ([string]$p.path)
    $enum = [string](Get-Prop $p 'enumeration')
    if ($enum -eq '') { $enum = 'AccessBased' }
    $cache = [string](Get-Prop $p 'caching')
    if ($cache -eq '') { $cache = 'Manual' }
    $desc = [string](Get-Prop $p 'description')
    New-SmbShare -Name $name -Path $path -Description $desc -FolderEnumerationMode $enum -CachingMode $cache -ReadAccess 'BUILTIN\Administrators' | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Creating the share failed: ' + $_.Exception.GetType().Name)
}
