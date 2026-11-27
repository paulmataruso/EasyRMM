# EasyRMM log measurement (ADR-0060, slice 1), for Windows PowerShell 5.1.
# Reads what the computer's event logs hold for the last -Days days and
# prints one JSON document: per source, per event ID and per audit
# subcategory, the events and the estimated bytes, in all and as the
# collector's default filters would keep them. It changes nothing.
#
# Bytes are an estimate of one raw event as the store would keep it, its
# fields as JSON without the rendered message: 300 bytes for the envelope
# (ID, time, provider, level, computer) plus the length of each field
# value. Output schema: easyrmm.logmeasure/1.
param(
    [int]$Days = 7,
    [int]$MaxEventsPerChannel = 2000000,
    [int]$MaxCodes = 300
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$envelopeBytes = 300
$start = (Get-Date).AddDays(-$Days)
# Keywords bit of "Audit Failure".
$auditFailure = [long]0x10000000000000

# Audit subcategory of each Security event ID in ADR-0060's table, the ones
# the collector leaves out included, so their volume is seen. 4625 is in
# the table under Account Lockout and under Logon; it is counted under Account Lockout.
$subcategoryIds = [ordered]@{
    'Account Logon: Credential Validation'              = @(4774, 4775, 4776, 4777)
    'Account Logon: Kerberos Authentication Service'    = @(4768, 4771, 4772)
    'Account Logon: Kerberos Service Ticket Operations' = @(4769, 4770, 4773)
    'Account Management: Computer Account Management'   = @(4741, 4742, 4743)
    'Account Management: Other Account Management Events' = @(4782, 4793)
    'Account Management: Security Group Management'     = @(4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4799)
    'Account Management: User Account Management'       = @(4720, 4721, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798)
    'Detailed Tracking: Plug and Play Events'           = @(6416)
    'Detailed Tracking: Process Creation'               = @(4688)
    'DS Access: Directory Service Access'               = @(4662)
    'DS Access: Directory Service Changes'              = @(5136, 5137, 5138, 5139, 5141)
    'Logon/Logoff: Account Lockout'                     = @(4625)
    'Logon/Logoff: Group Membership'                    = @(4627)
    'Logon/Logoff: Logon'                               = @(4624, 4648)
    'Logon/Logoff: Logoff'                              = @(4634, 4647)
    'Logon/Logoff: Other Logon/Logoff Events'           = @(4778, 4779, 4800, 4801)
    'Logon/Logoff: Special Logon'                       = @(4672, 4964)
    'Object Access: Detailed File Share'                = @(5145)
    'Object Access: File Share'                         = @(5140, 5142, 5143, 5144)
    'Object Access: Other Object Access Events'         = @(4698, 4699, 4700, 4701, 4702)
    'Object Access: Removable Storage'                  = @(4663)
    'Policy Change: Audit Policy Change'                = @(4719, 4906, 4907, 4912)
    'Policy Change: Authentication Policy Change'       = @(4706, 4707, 4713, 4716, 4739)
    'Policy Change: Authorization Policy Change'        = @(4703, 4704, 4705, 4670)
    'Policy Change: MPSSVC Rule-Level Policy Change'    = @(4946, 4947, 4948)
    'Privilege Use: Sensitive Privilege Use'            = @(4673, 4674)
    'System: Other System Events'                       = @(5024, 5025, 5030, 5034, 5035, 5037, 5058, 5059, 5061)
    'System: Security State Change'                     = @(4608, 4616)
    'System: Security System Extension'                 = @(4610, 4611, 4614, 4622, 4697)
    'System: System Integrity'                          = @(4612, 4615, 4618, 5038)
}
$subcategoryOf = @{}
foreach ($name in $subcategoryIds.Keys) {
    foreach ($id in $subcategoryIds[$name]) { $subcategoryOf[[int]$id] = $name }
}

function ConvertTo-IdSet {
    param([int[]]$Ids)
    $set = @{}
    foreach ($i in $Ids) { $set[$i] = $true }
    return $set
}

# Security events collected by default (the table's third column), and the
# ones of which only an audit failure is collected.
$securityIds = ConvertTo-IdSet @(1102, 4608, 4610, 4611, 4612, 4614, 4615, 4616, 4618, 4622, 4624, 4625, 4647, 4648,
    4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4704, 4705, 4706, 4707, 4713, 4716, 4719, 4720, 4721, 4722,
    4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4738, 4739, 4740, 4741,
    4742, 4743, 4754, 4755, 4756, 4757, 4758, 4765, 4766, 4767, 4778, 4779, 4780, 4781, 4782, 4793, 4794, 4800,
    4801, 4906, 4912, 4946, 4947, 4948, 4964, 5024, 5025, 5030, 5034, 5035, 5037, 5038, 5136, 5137, 5138, 5139,
    5141, 5142, 5143, 5144, 6416)
$securityFailureIds = ConvertTo-IdSet @(4662, 4768, 4769, 4771, 4776)
# Accounts whose sign-ins and special logons are left out.
$systemAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')

function Get-PropertyText {
    param($Event, [int]$Index)
    if ($Event.Properties.Count -le $Index) { return '' }
    $v = $Event.Properties[$Index].Value
    if ($null -eq $v) { return '' }
    return [string]$v
}

function Test-SystemAccount {
    param([string]$Name)
    if ($systemAccounts -contains $Name) { return $true }
    if ($Name -like 'DWM-*' -or $Name -like 'UMFD-*') { return $true }
    return $false
}

# 4624's TargetUserName is property 5 and its LogonType 8; 4672's
# SubjectUserName is property 1.
function Test-SecurityKept {
    param($Event)
    $id = [int]$Event.Id
    if ($securityFailureIds.ContainsKey($id)) {
        return (($Event.Keywords -band $auditFailure) -ne 0)
    }
    if (-not $securityIds.ContainsKey($id)) { return $false }
    if ($id -eq 4624) {
        $name = Get-PropertyText $Event 5
        $type = Get-PropertyText $Event 8
        if (Test-SystemAccount $name) { return $false }
        if ($type -eq '5') { return $false }
        if ($type -eq '3' -and $name.EndsWith('$')) { return $false }
        return $true
    }
    if ($id -eq 4672) {
        return -not (Test-SystemAccount (Get-PropertyText $Event 1))
    }
    return $true
}

function Test-LevelError {
    param($Event)
    # Level 1 is critical, 2 error.
    return ($null -ne $Event.Level -and $Event.Level -le 2)
}

$systemIds = ConvertTo-IdSet @(104, 1074, 6005, 6006, 6008, 7040, 7045)
$applicationIds = ConvertTo-IdSet @(1033, 1034, 11707, 11724)
$defenderIds = ConvertTo-IdSet @(1005, 1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 2001, 3002,
    5001, 5004, 5007, 5008, 5010, 5012, 5013)
$powershellIds = ConvertTo-IdSet @(4104)
$sysmonLeftOut = ConvertTo-IdSet @(3, 7, 10, 22)
$rdpSessionIds = ConvertTo-IdSet @(21, 23, 24, 25, 39, 40)
$wmiIds = ConvertTo-IdSet @(5861)

# One entry per source of ADR-0060. Each Keep takes (event, channel).
$sources = @(
    @{ Name = 'windows.security'; Channels = @('Security'); Subcategories = $true
        Keep = { param($e, $c) Test-SecurityKept $e } },
    @{ Name = 'windows.system'; Channels = @('System'); Subcategories = $false
        Keep = { param($e, $c) (Test-LevelError $e) -or $systemIds.ContainsKey([int]$e.Id) } },
    @{ Name = 'windows.application'; Channels = @('Application'); Subcategories = $false
        Keep = { param($e, $c) (Test-LevelError $e) -or $applicationIds.ContainsKey([int]$e.Id) } },
    @{ Name = 'windows.defender'; Channels = @('Microsoft-Windows-Windows Defender/Operational'); Subcategories = $false
        Keep = { param($e, $c) $defenderIds.ContainsKey([int]$e.Id) } },
    @{ Name = 'windows.powershell'; Subcategories = $false
        Channels = @('Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational')
        Keep = { param($e, $c) $powershellIds.ContainsKey([int]$e.Id) } },
    @{ Name = 'windows.sysmon'; Channels = @('Microsoft-Windows-Sysmon/Operational'); Subcategories = $false
        Keep = { param($e, $c) -not $sysmonLeftOut.ContainsKey([int]$e.Id) } },
    @{ Name = 'windows.rdp'; Subcategories = $false
        Channels = @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational')
        Keep = {
            param($e, $c)
            if ([int]$e.Id -eq 1149) { return ($c -like '*RemoteConnectionManager*') }
            return $rdpSessionIds.ContainsKey([int]$e.Id)
        } },
    @{ Name = 'windows.wmi'; Channels = @('Microsoft-Windows-WMI-Activity/Operational'); Subcategories = $false
        Keep = { param($e, $c) $wmiIds.ContainsKey([int]$e.Id) } }
)

function Add-Count {
    param($Table, [string]$Key, [long]$Bytes, [bool]$Kept)
    $row = $Table[$Key]
    if ($null -eq $row) {
        $row = @{ events = [long]0; bytes = [long]0; keptEvents = [long]0; keptBytes = [long]0 }
        $Table[$Key] = $row
    }
    $row.events++
    $row.bytes += $Bytes
    if ($Kept) {
        $row.keptEvents++
        $row.keptBytes += $Bytes
    }
}

function ConvertTo-Rows {
    param($Table, [string]$KeyName)
    $rows = @(foreach ($k in $Table.Keys) {
            $row = [ordered]@{}
            $row[$KeyName] = $k
            $row['events'] = $Table[$k].events
            $row['bytes'] = $Table[$k].bytes
            $row['filteredEvents'] = $Table[$k].keptEvents
            $row['filteredBytes'] = $Table[$k].keptBytes
            [pscustomobject]$row
        })
    return @($rows | Sort-Object -Property bytes -Descending)
}

$results = @()
foreach ($src in $sources) {
    $present = @()
    $notes = @()
    $codes = @{}
    $subs = @{}
    $total = @{ events = [long]0; bytes = [long]0; keptEvents = [long]0; keptBytes = [long]0 }
    $truncated = $false
    foreach ($channel in $src.Channels) {
        $log = $null
        try { $log = Get-WinEvent -ListLog $channel -ErrorAction Stop } catch { $log = $null }
        if ($null -eq $log) { continue }
        $present += $channel
        $events = $null
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $start } -MaxEvents $MaxEventsPerChannel -ErrorAction Stop
        } catch {
            # "No events were found" is an empty log, not a failure.
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                $notes += "${channel}: $($_.Exception.Message)"
            }
            continue
        }
        $n = 0
        foreach ($e in $events) {
            $n++
            $bytes = $envelopeBytes
            foreach ($p in $e.Properties) {
                if ($null -ne $p.Value) { $bytes += ([string]$p.Value).Length }
            }
            $kept = [bool](& $src.Keep $e $channel)
            Add-Count $codes ([string][int]$e.Id) $bytes $kept
            if ($src.Subcategories) {
                $sub = $subcategoryOf[[int]$e.Id]
                if ($null -eq $sub) { $sub = '(not in the audit table)' }
                Add-Count $subs $sub $bytes $kept
            }
            $total.events++
            $total.bytes += $bytes
            if ($kept) {
                $total.keptEvents++
                $total.keptBytes += $bytes
            }
        }
        if ($n -ge $MaxEventsPerChannel) {
            $truncated = $true
            $notes += "${channel}: stopped at $MaxEventsPerChannel events; the counts are of the newest."
        }
    }
    $allCodes = ConvertTo-Rows $codes 'code'
    $entry = [ordered]@{
        source         = $src.Name
        present        = ($present.Count -gt 0)
        channels       = @($present)
        truncated      = $truncated
        notes          = @($notes)
        events         = $total.events
        bytes          = $total.bytes
        filteredEvents = $total.keptEvents
        filteredBytes  = $total.keptBytes
        codes          = @($allCodes | Select-Object -First $MaxCodes)
        codesOmitted   = [Math]::Max(0, $allCodes.Count - $MaxCodes)
        subcategories  = @(ConvertTo-Rows $subs 'name')
    }
    $results += [pscustomobject]$entry
}

$report = [ordered]@{
    schema      = 'easyrmm.logmeasure/1'
    platform    = 'windows'
    hostname    = $env:COMPUTERNAME
    days        = $Days
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    bytesModel  = "$envelopeBytes bytes plus the length of each field value"
    sources     = @($results)
}
ConvertTo-Json -InputObject $report -Depth 6 -Compress
