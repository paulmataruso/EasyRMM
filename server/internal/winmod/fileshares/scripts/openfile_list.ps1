Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $share = [string](Get-Prop $p 'share')
    $all = @(Get-SmbOpenFile -ErrorAction SilentlyContinue)
    if ($share -ne '') {
        $sh = Get-ShareOrStop $share
        $root = [string](Get-Prop $sh 'Path')
        $keep = @()
        foreach ($f in $all) {
            if ($root -ne '' -and (Test-PathUnder ([string](Get-Prop $f 'Path')) $root)) { $keep += $f }
        }
        $all = @($keep)
    }
    $out = @()
    foreach ($f in @($all | Select-Object -First 200)) {
        $out += [ordered]@{
            id = [string](Get-Prop $f 'FileId')
            sessionId = [string](Get-Prop $f 'SessionId')
            path = [string](Get-Prop $f 'Path')
            user = [string](Get-Prop $f 'ClientUserName')
            client = [string](Get-Prop $f 'ClientComputerName')
            locks = [int64](Get-Number (Get-Prop $f 'Locks'))
        }
    }
    Write-Result $true ([ordered]@{ files = @($out); total = $all.Count }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the open files failed: ' + $_.Exception.GetType().Name)
}
