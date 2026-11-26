Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    $events = @()
    $note = ''
    try {
        $found = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4868, 4870, 4872, 4880, 4881, 4886, 4887, 4888) } -MaxEvents 200 -ErrorAction Stop)
        foreach ($e in $found) {
            $msg = [string]$e.Message
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            $events += [ordered]@{ id = [int]$e.Id; time = Get-Utc $e.TimeCreated; message = $msg }
        }
    } catch {
        if ($_.Exception.Message -match 'No events') { $note = 'No certificate services events are in the Security log. Auditing may be off for this CA.' }
        else { throw }
    }
    if ($events.Count -eq 0 -and $note -eq '') { $note = 'No certificate services events are in the Security log. Auditing may be off for this CA.' }
    Write-Result $true ([ordered]@{ events = @($events); note = $note }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the certificate services events failed: ' + $_.Exception.GetType().Name)
}
