# expect: plaintext
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$s = ConvertTo-SecureString $p.secret -AsPlainText -Force
