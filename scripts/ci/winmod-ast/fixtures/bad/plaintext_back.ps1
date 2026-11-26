# expect: plaintext
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$t = ConvertFrom-SecureString $s -AsPlainText
