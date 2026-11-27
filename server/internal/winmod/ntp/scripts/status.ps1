Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($fn_ok, $fn_data, $fn_code, $fn_message) {
    $fn_r = [ordered]@{ ok = $fn_ok; version = $version; data = $fn_data; error = $null }
    if (-not $fn_ok) { $fn_r.error = [ordered]@{ code = $fn_code; message = $fn_message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $fn_r -Compress -Depth 8))
}
function Stop-With($fn_code, $fn_message) {
    Write-Result $false $null $fn_code $fn_message
    exit 0
}

try {
    $tz = Get-TimeZone
    $w32tm = $null
    try {
        $svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        $svcState = if ($null -ne $svc) { [string]$svc.Status } else { 'NotInstalled' }
    } catch {
        $svcState = 'Unknown'
    }

    $source = ''
    $lastSync = $null
    $lastSyncError = $null
    $peers = @()
    if ($svcState -eq 'Running') {
        try {
            $raw = & w32tm.exe /query /status /verbose 2>&1
            $text = ($raw | Out-String)
            foreach ($line in $raw) {
                $s = [string]$line
                if ($s -match '^\s*Source\s*:\s*(.+)') { $source = $Matches[1].Trim() }
                if ($s -match '^\s*Last Successful Sync Time\s*:\s*(.+)') {
                    $ts = $Matches[1].Trim()
                    try { $lastSync = ([datetime]::Parse($ts)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch {}
                }
            }
        } catch {
            $lastSyncError = [string]$_.Exception.Message
        }
        try {
            $peerRaw = & w32tm.exe /query /peers /verbose 2>&1
            $current = $null
            foreach ($line in $peerRaw) {
                $s = [string]$line
                if ($s -match '^\s*Peer\s*:\s*(.+)') {
                    if ($null -ne $current) { $peers += $current }
                    $current = [ordered]@{ name = $Matches[1].Trim(); state = ''; lastSync = $null; pollInterval = 0 }
                }
                if ($null -ne $current) {
                    if ($s -match '^\s*State\s*:\s*(.+)') { $current.state = $Matches[1].Trim() }
                    if ($s -match '^\s*Last Successful Sync Time\s*:\s*(.+)') {
                        $ts = $Matches[1].Trim()
                        try { $current.lastSync = ([datetime]::Parse($ts)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch {}
                    }
                    if ($s -match '^\s*PollInterval\s*:\s*(\d+)') { $current.pollInterval = [int]$Matches[1] }
                }
            }
            if ($null -ne $current) { $peers += $current }
        } catch {}
    }

    $reg = @{}
    try {
        $k = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
        if ($null -ne $k) {
            $reg['ntpServer'] = if ($null -ne $k.NtpServer) { [string]$k.NtpServer } else { '' }
            $reg['type'] = if ($null -ne $k.Type) { [string]$k.Type } else { '' }
        }
    } catch {}

    $now = [System.DateTimeOffset]::UtcNow
    $data = [ordered]@{
        timezone       = [ordered]@{
            id            = [string]$tz.Id
            displayName   = [string]$tz.DisplayName
            standardName  = [string]$tz.StandardName
            utcOffset     = [string]$tz.BaseUtcOffset.ToString()
            daylightName  = [string]$tz.DaylightName
            supportsDst   = [bool]$tz.SupportsDaylightSavingTime
            isDst         = [bool]$tz.IsDaylightSavingTime($now)
        }
        service        = [ordered]@{
            state         = $svcState
            source        = $source
            lastSync      = $lastSync
            lastSyncError = $lastSyncError
        }
        config         = $reg
        peers          = $peers
        systemTimeUtc  = $now.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
