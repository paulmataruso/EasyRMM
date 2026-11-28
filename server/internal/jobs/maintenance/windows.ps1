# EasyRMM maintenance action (feature 11, slice 3), run by the EasyRMM agent
# as LocalSystem. Arguments: restart, shutdown, service_start, service_stop or
# service_restart; for the service actions, the service's name. The EasyRMM
# server accepts only plain names, and they are never part of this script's
# text. A restart or shutdown starts one minute from now, so that the run can
# report before the computer goes down.
$ErrorActionPreference = 'Stop'
$action = $args[0]
$name = if ($args.Count -gt 1) { $args[1] } else { '' }
switch ($action) {
    'restart' {
        Write-Output 'Restarting in one minute.'
        & "$env:SystemRoot\System32\shutdown.exe" /r /t 60 /d p:4:1 /c 'EasyRMM scheduled restart'
        exit $LASTEXITCODE
    }
    'shutdown' {
        Write-Output 'Shutting down in one minute.'
        & "$env:SystemRoot\System32\shutdown.exe" /s /t 60 /d p:4:1 /c 'EasyRMM scheduled shutdown'
        exit $LASTEXITCODE
    }
    { $_ -in 'service_start', 'service_stop', 'service_restart' } {
        if (-not $name) { Write-Output 'Name the service.'; exit 2 }
        $svc = Get-Service -Name $name -ErrorAction Stop
        switch ($action) {
            'service_start' { if ($svc.Status -ne 'Running') { Start-Service -Name $name } }
            'service_stop' { if ($svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force } }
            'service_restart' { Restart-Service -Name $name -Force }
        }
        $svc.Refresh()
        Write-Output "$name is $($svc.Status)."
        if ($action -ne 'service_stop' -and $svc.Status -ne 'Running') { exit 1 }
        exit 0
    }
    default { Write-Output "Unknown action: $action"; exit 2 }
}
