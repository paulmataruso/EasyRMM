Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Print
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -LiteralPath $key -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Result $true (Get-Hardening) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Restricting driver installation failed: ' + $_.Exception.GetType().Name)
}
