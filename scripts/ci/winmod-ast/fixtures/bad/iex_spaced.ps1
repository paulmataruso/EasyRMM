# expect: iex,command-param
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
InVoKe-ExPrEsSiOn    -Command   '1'
