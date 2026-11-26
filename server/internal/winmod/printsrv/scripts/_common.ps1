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
    if ($null -ne $o -and $null -ne $o.PSObject.Properties[$name]) { return $o.$name }
    return $null
}
function Get-Number($v) {
    if ($null -eq $v) { return $null }
    try { return [int64]$v } catch { return $null }
}
function Get-Utc($d) {
    if ($null -eq $d) { return $null }
    try {
        $t = [datetime]$d
        if ($t.Year -lt 2000) { return $null }
        return $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { return $null }
}
function Get-AgeMinutes($d) {
    if ($null -eq $d) { return $null }
    try {
        $t = [datetime]$d
        if ($t.Year -lt 2000) { return $null }
        return [int64][math]::Max(0, [math]::Floor(((Get-Date) - $t).TotalMinutes))
    } catch { return $null }
}
function Assert-Print {
    if (-not (Get-Command -Name Get-Printer -ErrorAction SilentlyContinue)) {
        Stop-Result 'module_missing' 'The PrintManagement tools are not available on this computer.'
    }
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Stop-Result 'module_missing' 'The Print Spooler is not installed on this computer.' }
    if ($svc.Status -ne 'Running') { Stop-Result 'service_stopped' 'The Print Spooler is not running.' }
}
function Get-PrinterOrStop([string]$Name) {
    $x = Get-Printer -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $x) { Stop-Result 'not_found' 'There is no printer of this name.' }
    return $x
}
function Get-JobIds([string]$Text) {
    return @($Text.Split(',') | ForEach-Object { [int]$_ })
}
# Point and Print (MSRC CVE-2021-34527, KB5005652). The policy key and its values; reads only.
function Get-PnpValue([string]$Name) {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $v = Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $v) { return $null }
    return (Get-Number (Get-Prop $v $Name))
}
function Get-Hardening {
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $restrict = Get-PnpValue 'RestrictDriverInstallationToAdministrators'
    $noWarn = Get-PnpValue 'NoWarningNoElevationOnInstall'
    $upd = Get-PnpValue 'UpdatePromptSettings'
    # An absent restrict value is the default, which updated Windows sets to restricted; only a 0 weakens it.
    $weak = (($null -ne $restrict -and $restrict -ne 1) -or ($noWarn -eq 1) -or ($upd -eq 2))
    return [ordered]@{
        restrictDriverInstall = $restrict
        noWarningNoElevation = $noWarn
        updatePromptSettings = $upd
        weakened = [bool]$weak
        spoolerRunning = ($null -ne $svc -and $svc.Status -eq 'Running')
        domainController = ([int]$os.ProductType -eq 2)
    }
}
