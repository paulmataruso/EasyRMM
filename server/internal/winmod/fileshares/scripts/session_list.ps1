Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $all = @(Get-SmbSession -ErrorAction SilentlyContinue)
    $out = @()
    foreach ($s in @($all | Select-Object -First 200)) {
        $out += [ordered]@{
            id = [string](Get-Prop $s 'SessionId')
            user = [string](Get-Prop $s 'ClientUserName')
            client = [string](Get-Prop $s 'ClientComputerName')
            openFiles = [int64](Get-Number (Get-Prop $s 'NumOpens'))
            secondsActive = [int64](Get-Number (Get-Prop $s 'SecondsExists'))
            secondsIdle = [int64](Get-Number (Get-Prop $s 'SecondsIdle'))
        }
    }
    Write-Result $true ([ordered]@{ sessions = @($out); total = $all.Count }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the sessions failed: ' + $_.Exception.GetType().Name)
}
