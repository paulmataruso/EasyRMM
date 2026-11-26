function Write-Result($ok, $data, $code, $message) {
    $r = [ordered]@{ ok = $ok; version = $version; data = $data; error = $null }
    if (-not $ok) { $r.error = [ordered]@{ code = $code; message = $message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 8))
}
function Stop-Result($code, $message) {
    Write-Result $false $null $code $message
    exit 0
}
function Get-Prop($o, $name) {
    if ($null -ne $o -and $o.PSObject.Properties.Name -contains $name) { return $o.$name }
    return $null
}
function Get-First($o, $names) {
    foreach ($n in $names) {
        $v = Get-Prop $o $n
        if ($null -ne $v) { return $v }
    }
    return $null
}
function Get-Utc($d) {
    if ($null -eq $d) { return $null }
    try {
        $t = [datetime]$d
        if ($t.Year -lt 2000) { return $null }
        return $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { return $null }
}
function Get-Number($v) {
    if ($null -eq $v) { return $null }
    try { return [int64]$v } catch { return $null }
}
function Assert-Server {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ([int]$os.ProductType -eq 1) {
        Stop-Result 'not_offered' 'Windows Server Backup is not offered on a desktop.'
    }
}
function Import-Wsb {
    if (-not (Get-Module -ListAvailable -Name WindowsServerBackup)) { return $false }
    Import-Module WindowsServerBackup
    return $true
}
function Assert-Wsb {
    Assert-Server
    if (-not (Import-Wsb)) { Stop-Result 'module_missing' 'Windows Server Backup is not installed on this computer.' }
}
function Get-RunningJob {
    $j = Get-WBJob -ErrorAction SilentlyContinue
    if ($null -eq $j) { return $null }
    foreach ($x in @($j)) {
        $state = [string](Get-Prop $x 'JobState')
        if ($state -eq 'Running') { return $x }
    }
    return $null
}
function Assert-NotBusy {
    if ($null -ne (Get-RunningJob)) { Stop-Result 'busy' 'Windows Server Backup is running another operation.' }
}
function Get-Policy([bool]$Editable) {
    try {
        if ($Editable) { return (Get-WBPolicy -Editable -ErrorAction Stop) }
        return (Get-WBPolicy -ErrorAction Stop)
    } catch { return $null }
}
function Convert-Job($j) {
    if ($null -eq $j) { return $null }
    $pct = Get-Number (Get-First $j @('PercentComplete', 'Progress'))
    return [ordered]@{
        type        = [string](Get-Prop $j 'JobType')
        state       = [string](Get-Prop $j 'JobState')
        startTime   = Get-Utc (Get-Prop $j 'StartTime')
        endTime     = Get-Utc (Get-Prop $j 'EndTime')
        percent     = $pct
        hresult     = Get-Number (Get-Prop $j 'HResult')
        detailedHResult = Get-Number (Get-Prop $j 'DetailedHResult')
    }
}
function Test-PathUnder([string]$Child, [string]$Parent) {
    $c = $Child.TrimEnd('\')
    $q = $Parent.TrimEnd('\')
    return ($c.Equals($q, [System.StringComparison]::OrdinalIgnoreCase) -or $c.StartsWith($q + '\', [System.StringComparison]::OrdinalIgnoreCase))
}
