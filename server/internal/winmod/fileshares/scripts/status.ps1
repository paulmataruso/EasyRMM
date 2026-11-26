Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Stop-Result 'module_missing' 'The Server service is not installed on this computer.' }
    $data = [ordered]@{
        serviceState = ([string]$svc.Status).ToLowerInvariant()
        shareCount = 0; userShareCount = 0; sessionCount = 0; openFileCount = 0
        smb1Enabled = $null; signingRequired = $null; encryptionRequired = $null
    }
    if ($svc.Status -eq 'Running' -and (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)) {
        $shares = @(Get-SmbShare)
        $data.shareCount = $shares.Count
        $data.userShareCount = @($shares | Where-Object { -not (Test-ProtectedShare ([string]$_.Name)) -and -not $_.Special }).Count
        $data.sessionCount = @(Get-SmbSession -ErrorAction SilentlyContinue).Count
        $data.openFileCount = @(Get-SmbOpenFile -ErrorAction SilentlyContinue).Count
        $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($null -ne $cfg) {
            $data.smb1Enabled = [bool](Get-Prop $cfg 'EnableSMB1Protocol')
            $data.signingRequired = [bool](Get-Prop $cfg 'RequireSecuritySignature')
            $data.encryptionRequired = [bool](Get-Prop $cfg 'EncryptData')
        }
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the file server state failed: ' + $_.Exception.GetType().Name)
}
