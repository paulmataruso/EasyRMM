# expect: defender-list
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
Set-MpPreference -ExclusionPath @('C:\Temp')
