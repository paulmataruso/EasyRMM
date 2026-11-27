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
    # Trigger an immediate Windows LAPS password rotation by resetting the
    # expiration time in AD. The LAPS CSE will then pick it up on its next
    # processing cycle (GPUpdate or background refresh).
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property PartOfDomain -ErrorAction Stop
    if (-not $cs.PartOfDomain) { Stop-With 'not_applicable' 'LAPS password rotation requires a domain-joined computer.' }

    # Try Windows LAPS first (Reset-LapsPassword is available on 2022+)
    $resetDone = $false
    try {
        $cmd = Get-Command -Name Reset-LapsPassword -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            Reset-LapsPassword
            $resetDone = $true
        }
    } catch {
        Stop-With 'command_failed' ('Reset-LapsPassword failed: ' + $_.Exception.Message)
    }

    if (-not $resetDone) {
        # Fall back: set the AD expiration time to now, which makes the CSE rotate on its next cycle
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)$))"
            $result = $searcher.FindOne()
            if ($null -eq $result) { Stop-With 'not_found' 'Could not find this computer in the directory.' }
            $entry = $result.GetDirectoryEntry()
            $now = [datetime]::UtcNow.ToFileTimeUtc()
            # Try Windows LAPS attribute first
            try { $entry.Properties['msLAPS-PasswordExpirationTime'].Value = $now; $entry.CommitChanges(); $resetDone = $true } catch {}
            if (-not $resetDone) {
                # Try legacy LAPS attribute
                try { $entry.Properties['ms-Mcs-AdmPwdExpirationTime'].Value = $now; $entry.CommitChanges(); $resetDone = $true } catch {}
            }
            if (-not $resetDone) { Stop-With 'not_applicable' 'No LAPS attributes found on this computer object. LAPS may not be configured.' }
        } catch {
            Stop-With 'command_failed' ('Failed to reset LAPS expiration: ' + $_.Exception.Message)
        }
    }

    # Trigger a gpupdate to make the CSE process sooner
    try { & gpupdate.exe /target:computer /force 2>&1 | Out-Null } catch {}

    $data = [ordered]@{
        summary = 'LAPS password rotation triggered'
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
