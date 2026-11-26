# expect: strict-mode
Set-StrictMode -Version Latest
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
