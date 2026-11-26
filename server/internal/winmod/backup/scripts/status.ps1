Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Server
    $data = [ordered]@{
        installed = $false; configured = $false; running = $false
        nextRun = $null; lastSuccess = $null; lastFailure = $null; lastResultHR = $null
        lastSuccessAgeDays = $null; versionCount = $null; oldestVersion = $null; newestVersion = $null
        schedule = @(); systemState = $false; bareMetal = $false; volumeCount = 0; fileSpecCount = 0
        vssFull = $false; targets = @(); job = $null
    }
    if (-not (Import-Wsb)) { Write-Result $true $data $null $null; exit 0 }
    $data.installed = $true
    $pol = Get-Policy $false
    $sum = $null
    try { $sum = Get-WBSummary -ErrorAction Stop } catch { $sum = $null }
    if ($null -ne $sum) {
        $data.nextRun = Get-Utc (Get-Prop $sum 'NextBackupTime')
        $ok = Get-Prop $sum 'LastSuccessfulBackupTime'
        $data.lastSuccess = Get-Utc $ok
        $data.lastResultHR = Get-Number (Get-Prop $sum 'LastBackupResultHR')
        $last = Get-Prop $sum 'LastBackupTime'
        $failed = ($null -ne $data.lastResultHR) -and ($data.lastResultHR -ne 0)
        if ($failed -and $null -ne (Get-Utc $last)) { $data.lastFailure = Get-Utc $last }
        if ($null -ne $data.lastSuccess) {
            $data.lastSuccessAgeDays = [int][math]::Floor(((Get-Date).ToUniversalTime() - [datetime]$ok).TotalDays)
        }
        $data.versionCount = Get-Number (Get-Prop $sum 'NumberOfVersions')
    }
    $sets = @(Get-WBBackupSet -ErrorAction SilentlyContinue)
    if ($sets.Count -gt 0) {
        $times = @($sets | ForEach-Object { Get-Prop $_ 'BackupTime' } | Where-Object { $null -ne $_ } | Sort-Object)
        if ($times.Count -gt 0) {
            $data.oldestVersion = Get-Utc $times[0]
            $data.newestVersion = Get-Utc $times[$times.Count - 1]
        }
        if ($null -eq $data.versionCount) { $data.versionCount = $sets.Count }
    }
    $job = Get-RunningJob
    if ($null -ne $job) {
        $data.running = $true
        $data.job = Convert-Job $job
    }
    if ($null -ne $pol) {
        $data.configured = $true
        $data.schedule = @(@(Get-Prop $pol 'Schedule') | Where-Object { $null -ne $_ } | ForEach-Object { ([datetime]$_).ToString('HH:mm') })
        $data.systemState = [bool](Get-Prop $pol 'SystemState')
        $data.bareMetal = [bool](Get-First $pol @('BMR', 'BareMetalRecovery'))
        $data.volumeCount = @(@(Get-Prop $pol 'VolumesToBackup') | Where-Object { $null -ne $_ }).Count
        $data.fileSpecCount = @(@(Get-First $pol @('FilesSpecsToBackup', 'FileSpecsToBackup')) | Where-Object { $null -ne $_ }).Count
        $opt = Get-First $pol @('VssBackupOptions', 'VssBackupOption')
        $data.vssFull = ([string]$opt -eq 'VssFullBackup')
        $targets = @()
        foreach ($t in @(Get-WBBackupTarget -Policy $pol -ErrorAction SilentlyContinue)) {
            $net = Get-First $t @('NetworkPath', 'Path')
            $vol = Get-First $t @('WBVolume', 'TargetVolume')
            $disk = Get-First $t @('WBDisk', 'Disk')
            $kind = 'volume'
            $free = $null; $total = $null; $online = $true
            if ($null -ne $disk -and $null -eq $vol) { $kind = 'disk' }
            if ($null -ne (Get-Prop $t 'NetworkPath') -and [string](Get-Prop $t 'NetworkPath') -ne '') { $kind = 'network' }
            # What a real server reports is TargetType (Volume, Disk or Network), with the share in Path; there is no NetworkPath.
            switch ([string](Get-Prop $t 'TargetType')) { 'Network' { $kind = 'network' } 'Disk' { $kind = 'disk' } 'Volume' { $kind = 'volume' } }
            if ($kind -eq 'network') {
                $online = [bool](Test-Path -LiteralPath ([string]$net))
            } elseif ($null -ne $vol) {
                $free = Get-Number (Get-Prop $vol 'FreeSpace')
                $total = Get-Number (Get-Prop $vol 'TotalSpace')
            } elseif ($null -ne $disk) {
                $free = Get-Number (Get-Prop $disk 'FreeSpace')
                $total = Get-Number (Get-Prop $disk 'TotalSpace')
            }
            $targets += [ordered]@{ kind = $kind; freeBytes = $free; totalBytes = $total; online = $online }
        }
        $data.targets = @($targets)
    }
    Write-Result $true $data $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Reading the backup state failed: ' + $_.Exception.GetType().Name)
}
