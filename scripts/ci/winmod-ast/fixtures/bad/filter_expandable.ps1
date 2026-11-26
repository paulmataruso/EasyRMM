# expect: filter
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$x = Get-Date
Get-ADUser -Filter "Name -eq '$x'"
