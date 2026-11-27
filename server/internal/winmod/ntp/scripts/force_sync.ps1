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
    $svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Stop-With 'not_found' 'The Windows Time service is not installed.' }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name w32time
        Start-Sleep -Seconds 1
    }
    $raw = & w32tm.exe /resync /force 2>&1
    $text = ($raw | Out-String).Trim()
    $success = ($LASTEXITCODE -eq 0)
    if (-not $success) { Stop-With 'command_failed' ('w32tm /resync failed: ' + $text) }

    Start-Sleep -Seconds 2
    $source = ''
    $lastSync = $null
    try {
        $status = & w32tm.exe /query /status /verbose 2>&1
        foreach ($line in $status) {
            $s = [string]$line
            if ($s -match '^\s*Source\s*:\s*(.+)') { $source = $Matches[1].Trim() }
            if ($s -match '^\s*Last Successful Sync Time\s*:\s*(.+)') {
                $ts = $Matches[1].Trim()
                try { $lastSync = ([datetime]::Parse($ts)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch {}
            }
        }
    } catch {}

    $data = [ordered]@{
        summary  = 'Time resync completed'
        output   = $text
        source   = $source
        lastSync = $lastSync
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
