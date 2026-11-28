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
    $server = [string]$p.server
    $type = 'NTP'
    if ($null -ne $p.PSObject.Properties['syncType']) { $type = [string]$p.syncType }

    $before = @{}
    try {
        $k = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
        if ($null -ne $k) {
            $before['ntpServer'] = if ($null -ne $k.NtpServer) { [string]$k.NtpServer } else { '' }
            $before['type'] = if ($null -ne $k.Type) { [string]$k.Type } else { '' }
        }
    } catch {}

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'NtpServer' -Value $server
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'Type' -Value $type
    & w32tm.exe /config /syncfromflags:manual /update 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-With 'command_failed' 'w32tm /config failed.' }

    $svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -ne 'Running') {
        Start-Service -Name w32time
    }
    & w32tm.exe /resync /nowait 2>&1 | Out-Null

    $after = @{}
    try {
        $k = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
        if ($null -ne $k) {
            $after['ntpServer'] = if ($null -ne $k.NtpServer) { [string]$k.NtpServer } else { '' }
            $after['type'] = if ($null -ne $k.Type) { [string]$k.Type } else { '' }
        }
    } catch {}

    $data = [ordered]@{
        summary = 'NTP server configured'
        server  = $server
        type    = $type
        before  = $before
        after   = $after
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
