# expect: plaintext
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$t = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
