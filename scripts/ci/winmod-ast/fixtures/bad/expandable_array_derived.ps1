# expect: string-build
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$a = @($p.name)
Write-Output "x $a"
