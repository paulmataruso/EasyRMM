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
    $tzId = [string]$p.timezoneId
    $available = @([System.TimeZoneInfo]::GetSystemTimeZones() | ForEach-Object { $_.Id })
    if ($available -notcontains $tzId) {
        Stop-With 'not_found' ('No such timezone: {0}. Use the Windows timezone ID, e.g. "Eastern Standard Time".' -f $tzId)
    }
    $before = Get-TimeZone
    Set-TimeZone -Id $tzId
    $after = Get-TimeZone
    $data = [ordered]@{
        summary = ('Timezone changed from {0} to {1}' -f $before.Id, $after.Id)
        before  = [ordered]@{ id = [string]$before.Id; displayName = [string]$before.DisplayName }
        after   = [ordered]@{ id = [string]$after.Id; displayName = [string]$after.DisplayName }
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
