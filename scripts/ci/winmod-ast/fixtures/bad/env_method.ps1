# expect: stdin
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
[Environment]::GetEnvironmentVariable('PATH')
