Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $id = [uint64]([string]$p.id)
    if ($null -eq (Get-SmbOpenFile -FileId $id -ErrorAction SilentlyContinue)) { Stop-Result 'not_found' 'That file is no longer open.' }
    Close-SmbOpenFile -FileId $id -Force | Out-Null
    Write-Result $true ([ordered]@{ done = $true }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Closing the file failed: ' + $_.Exception.GetType().Name)
}
