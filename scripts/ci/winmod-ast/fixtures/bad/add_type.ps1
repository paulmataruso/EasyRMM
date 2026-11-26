# expect: add-type
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -TypeDefinition $p.code
