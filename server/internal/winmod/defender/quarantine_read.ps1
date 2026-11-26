Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 8))
}
function Get-Prop($o, $name) {
    if ($null -ne $o -and $o.PSObject.Properties.Name -contains $name) { return $o.$name }
    return $null
}
function Get-Flag($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v) { return $null }
    return [bool]$v
}
function Get-Days($o, $name) {
    $v = Get-Prop $o $name
    if ($null -eq $v -or [int64]$v -gt 100000) { return $null }
    return [int]$v
}

# MpCmdRun.exe -Restore -ListAll prints one block per item: a "ThreatName = <name>" line, then the "file:" lines of its resources.
function Get-QuarantineItems {
    $raw = & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Restore -ListAll 2>&1 | ForEach-Object { [string]$_ }
    $items = @()
    $cur = $null
    foreach ($line in $raw) {
        if ($line -match '^\s*ThreatName\s*=\s*(.+?)\s*$') {
            if ($null -ne $cur) { $items += , $cur }
            $cur = [ordered]@{ name = $Matches[1]; path = '' }
        } elseif ($null -ne $cur -and $line -match '^\s*(?:containerfile|file)\s*:\s*(.+?)\s*$' -and -not $cur.path) {
            $cur.path = ($Matches[1] -replace '^_', '')
        }
    }
    if ($null -ne $cur) { $items += , $cur }
    return $items
}

try {
    if (-not (Get-Module -ListAvailable -Name Defender)) {
        Write-Result $false $null 'module_missing' 'The Defender module is not installed on this computer.'
        exit 0
    }
    Import-Module Defender

    $items = @(Get-QuarantineItems)
    Write-Result $true ([ordered]@{ items = $items }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('The Defender action failed: ' + $_.Exception.GetType().Name)
}
