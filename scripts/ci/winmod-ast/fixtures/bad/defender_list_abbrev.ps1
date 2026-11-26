# expect: defender-list
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
Set-MpPreference -Exclusion:$p.value
Set-MpPreference -AttackSurfaceReductionRules_Ids $p.id
