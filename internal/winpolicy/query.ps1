
# ---------------------------------------------------------------------------
# The reader started on its own (ADR-0054, "Policy ownership"): the agent
# starts this file, after reader.ps1, as a child process for the registry
# editor and the event viewer (ADR-0067, ADR-0068), with Windows
# PowerShell 5.1 as LocalSystem:
#
#   powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script> <request file>
#
# The request file is JSON, at most 1000 values in all:
#
#   {"registry": [{"path": "HKLM\\SOFTWARE\\Policies\\...", "name": "...",
#                  "csp": "Area/Policy", "defender": false,
#                  "product": "antivirus", "tamper": false}],
#    "security": ["MinimumPasswordLength"],
#    "audit": ["0cce9215-69ae-11d9-bed3-505054503030"]}
#
# registry: values under HKLM, with the Policy CSP policy that sets the
# value, if any; whether it belongs to Defender, attack surface reduction
# or the firewall (defender); whether another antivirus or firewall that is
# on takes it over (product, antivirus or firewall); and whether Tamper
# Protection guards it (tamper). security: security policy settings by
# their names in a security template; audit: audit subcategories by GUID.
#
# It prints one line, EASYRMM-WINPOLICY-V1 and the answers as JSON, each
# list in the request's order:
#
#   {"registry": [answer], "security": [answer], "audit": [answer], "notes": ["..."]}
#   answer: {"result": "owner|none|cannot_tell", "owner": "...", "policy": "...",
#            "value": "...", "reasons": ["..."], "mdm": {...}}
#
# Exit codes: 0 answered; 2 the request could not be read; 3 the reader
# cannot run here (no administrator, or not Full Language Mode), which the
# caller shows as cannot tell.

$ErQueryArgs = @($args)
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { exit 3 }
$ErQueryIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$ErQueryIdentity).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
    [Console]::Error.WriteLine('The reader needs an administrator or LocalSystem.')
    exit 3
}

# Read-ErQuery: the request, checked; throws with what is wrong.
function Read-ErQuery {
    param([string[]]$Arguments)
    if ($Arguments.Count -ne 1) { throw 'Give the request file, and nothing else.' }
    $file = $Arguments[0]
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "The request file $file does not exist." }
    $q = [IO.File]::ReadAllText($file) | ConvertFrom-Json
    if ($null -eq $q -or $q -isnot [System.Management.Automation.PSCustomObject]) { throw 'The request is not a JSON object.' }
    foreach ($p in $q.PSObject.Properties) {
        if ($p.Name -notin 'registry', 'security', 'audit') { throw "The request has an unknown field: $($p.Name)." }
    }
    $out = @{ Registry = @(); Security = @(); Audit = @() }
    foreach ($r in @($q.registry | Where-Object { $null -ne $_ })) {
        if ($r -isnot [System.Management.Automation.PSCustomObject] -or
            [string]$r.path -notmatch '^HKLM\\[^\x00-\x1f]{1,250}$' -or $null -eq $r.name -or
            [string]$r.name -match '[\x00-\x1f]' -or ([string]$r.name).Length -gt 255 -or
            ($r.csp -and [string]$r.csp -notmatch '^[A-Za-z0-9_]{1,64}/[A-Za-z0-9_]{1,128}$') -or
            ($null -ne $r.defender -and $r.defender -isnot [bool]) -or ($null -ne $r.tamper -and $r.tamper -isnot [bool]) -or
            ($r.product -and @('antivirus', 'firewall') -cnotcontains [string]$r.product)) {
            throw 'A registry value needs a path under HKLM\, a name, and may name a csp (Area/Policy), defender and tamper (true or false), and product (antivirus or firewall).'
        }
        foreach ($p in $r.PSObject.Properties) {
            if ($p.Name -notin 'path', 'name', 'csp', 'defender', 'product', 'tamper') { throw "A registry value has an unknown field: $($p.Name)." }
        }
        $out.Registry += , @{ Path = [string]$r.path; Name = [string]$r.name; Csp = [string]$r.csp; Defender = [bool]$r.defender; Product = [string]$r.product; Tamper = [bool]$r.tamper }
    }
    foreach ($s in @($q.security | Where-Object { $null -ne $_ })) {
        if ($s -isnot [string] -or $s -notmatch '^[A-Za-z]{1,64}$') { throw 'A security setting is named as in a security template.' }
        $out.Security += $s
    }
    foreach ($a in @($q.audit | Where-Object { $null -ne $_ })) {
        if ($a -isnot [string] -or $a -notmatch '^\{?[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$') { throw 'An audit subcategory is given by its GUID.' }
        $out.Audit += $a.Trim('{', '}')
    }
    if ($out.Registry.Count + $out.Security.Count + $out.Audit.Count -gt 1000) { throw 'A request holds at most 1000 values.' }
    return $out
}

function ConvertTo-ErAnswer {
    param($Result)
    $a = [ordered]@{ result = $Result.Result; owner = $Result.Owner; policy = $Result.Policy; value = $Result.Value; reasons = @($Result.Reasons) }
    if ($Result.Mdm) {
        $a.mdm = [ordered]@{ csp = $Result.Mdm.Csp; config = $Result.Mdm.Config; current = $Result.Mdm.Current; provider = $Result.Mdm.Provider }
    }
    return $a
}

try {
    $ErQuery = Read-ErQuery $ErQueryArgs
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
$ErQueryWork = New-ErWorkFolder 'easyrmm-winpolicy-'
try {
    $context = Get-ErPolicyContext $ErQueryWork
    $answers = [ordered]@{ registry = @(); security = @(); audit = @(); notes = @() }
    foreach ($r in $ErQuery.Registry) {
        $answers.registry += , (ConvertTo-ErAnswer (Resolve-ErRegistryOwner $context $r.Path $r.Name $r.Csp -Defender:$r.Defender -Product $r.Product -Tamper:$r.Tamper))
    }
    foreach ($s in $ErQuery.Security) {
        $answers.security += , (ConvertTo-ErAnswer (Resolve-ErSecurityOwner $context $s))
    }
    foreach ($g in $ErQuery.Audit) {
        $answers.audit += , (ConvertTo-ErAnswer (Resolve-ErAuditOwner $context $g))
    }
    # After the answers: some records are read only when a value needs them.
    $answers.notes = @($context.Notes | ForEach-Object { Limit-ErText $_ 300 })
    Write-Output ('EASYRMM-WINPOLICY-V1 ' + (ConvertTo-ErAscii ($answers | ConvertTo-Json -Depth 6 -Compress)))
} finally {
    Remove-Item -LiteralPath $ErQueryWork -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
