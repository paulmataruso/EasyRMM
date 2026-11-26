# Runs the catalogue scripts against the stand-in ActiveDirectory module (ActiveDirectory/ActiveDirectory.psm1) and
# checks what they answer and what they ask the directory to change. It cannot show that the real cmdlets behave as the
# stand-in does: that is the real-controller step of ADR-0075 section 9. Usage: pwsh run.ps1 -Scripts <folder>
param([Parameter(Mandatory)][string]$Scripts)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PSModulePath = $here + [IO.Path]::PathSeparator + $env:PSModulePath
$log = Join-Path ([IO.Path]::GetTempPath()) ('fakead-' + [guid]::NewGuid().ToString('N') + '.log')
$env:FAKEAD_LOG = $log
$failures = 0
$secretSeen = 'Sup3r-Secret-Marker!'

function Invoke-Action([string]$Name, $Params, [hashtable]$Env = @{}) {
    Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
    foreach ($k in $Env.Keys) { Set-Item -Path ('Env:' + $k) -Value $Env[$k] }
    try {
        $json = ConvertTo-Json -InputObject $Params -Compress
        $file = $Name
        if ($Name -eq 'user_reset_password') { $file = 'user_reset' }
        $out = $json | pwsh -NoProfile -File (Join-Path $Scripts ($file + '.ps1')) 2>&1
    } finally {
        foreach ($k in $Env.Keys) { Remove-Item -Path ('Env:' + $k) -ErrorAction SilentlyContinue }
    }
    $text = ($out | Out-String)
    $last = ($out | Where-Object { "$_".StartsWith('EASYRMM-WINMOD-RESULT-V1 ') } | Select-Object -Last 1)
    $result = $null
    if ($last) { $result = ("$last").Substring('EASYRMM-WINMOD-RESULT-V1 '.Length) | ConvertFrom-Json }
    $calls = @()
    if (Test-Path -LiteralPath $log) { $calls = @(Get-Content -LiteralPath $log) }
    [pscustomobject]@{ Result = $result; Calls = $calls; Text = $text }
}
function Check([string]$What, [bool]$Ok, $Detail = '') {
    if ($Ok) { Write-Host "ok    $What" } else { Write-Host "FAIL  $What  $Detail"; $script:failures++ }
}
function Expect-Error([string]$What, $r, [string]$Code) {
    $got = 'no result'
    if ($r.Result) { $got = if ($r.Result.ok) { 'ok' } else { $r.Result.error.code } }
    Check $What ($got -eq $Code) ("want $Code, got $got; " + $r.Text)
}
$dom = 'S-1-5-21-1-2-3'
function Sid($rid) { return "$dom-$rid" }

# --- reads ---
$r = Invoke-Action 'status' @{}
Check 'status answers' ($r.Result.ok -and $r.Result.data.domain -eq 'corp.test' -and $r.Result.data.passwordPolicy.minLength -eq 7 -and $r.Result.data.forestRootSid -eq $dom) $r.Text
$r = Invoke-Action 'status' @{} @{ FAKEAD_READONLY = '1' }
Check 'status on a read-only controller says so' ($r.Result.ok -and $r.Result.data.readOnly -eq $true) $r.Text
$r = Invoke-Action 'ou_tree' @{}
Check 'ou_tree marks the Domain Controllers OU unwritable' ($r.Result.ok -and @($r.Result.data.items | Where-Object { $_.name -eq 'Domain Controllers' -and -not $_.writable }).Count -eq 1) $r.Text
$r = Invoke-Action 'user_list' @{ pageSize = 5 }
$byId = @{}; if ($r.Result.ok) { foreach ($i in $r.Result.data.items) { $byId[$i.sam] = $i } }
Check 'user_list pages and names the protection of each row' ($r.Result.ok -and $r.Result.data.items.Count -eq 5 -and $r.Result.data.next -eq 'dave') $r.Text
$r = Invoke-Action 'user_list' @{}
$byId = @{}; if ($r.Result.ok) { foreach ($i in $r.Result.data.items) { $byId[$i.sam] = $i } }
$want = @{ ann = 'none'; bob = 'none'; dave = 'protected'; admin2 = 'protected'; pgu = 'protected'; oldadmin = 'protected'; svc_backup = 'service'; neverexp = 'none'; 'gmsa1$' = 'protected'; 'comp1$' = 'protected'; protdel = 'none' }
foreach ($k in $want.Keys) { Check "protection of $k is $($want[$k])" ($byId[$k].protection -eq $want[$k]) ($byId[$k] | ConvertTo-Json -Compress) }
$r = Invoke-Action 'user_list' @{ state = 'disabled' }
Check 'user_list state disabled' ($r.Result.ok -and $r.Result.data.items.Count -eq 1 -and $r.Result.data.items[0].sam -eq 'bob') $r.Text
$r = Invoke-Action 'user_list' @{ match = 'AN' }
Check 'user_list match is a prefix compared in memory' ($r.Result.ok -and $r.Result.data.items.Count -eq 1 -and $r.Result.data.items[0].sam -eq 'ann') $r.Text
$r = Invoke-Action 'user_list' @{ match = "'; Remove-Item *; '" }
Check 'user_list takes a hostile match as text' ($r.Result.ok -and $r.Result.data.items.Count -eq 0) $r.Text
$r = Invoke-Action 'user_get' @{ id = (Sid 1104) }
Check 'user_get answers' ($r.Result.ok -and $r.Result.data.sam -eq 'ann' -and $r.Result.data.mail -eq '') $r.Text
$r = Invoke-Action 'group_list' @{}
Check 'group_list shows Domain Admins as protected and Sales as not' ($r.Result.ok -and (@($r.Result.data.items | Where-Object { $_.sam -eq 'Domain Admins' -and $_.protection -eq 'protected' }).Count -eq 1) -and (@($r.Result.data.items | Where-Object { $_.sam -eq 'Sales' -and $_.protection -eq 'none' }).Count -eq 1)) $r.Text
$r = Invoke-Action 'group_members' @{ id = (Sid 1300) }
Check 'group_members' ($r.Result.ok -and $r.Result.data.total -eq 1 -and $r.Result.data.items[0].kind -eq 'user') $r.Text

$r = Invoke-Action 'computer_list' @{}
Check 'computer_list marks the controller' ($r.Result.ok -and $r.Result.data.items.Count -eq 2 -and (@($r.Result.data.items | Where-Object { $_.sam -eq 'DC1$' -and $_.controller }).Count -eq 1)) $r.Text
$r = Invoke-Action 'privileged_members' @{}
Check 'privileged_members lists the groups with their members and tier' ($r.Result.ok -and (@($r.Result.data.groups | Where-Object { $_.name -eq 'Domain Admins' -and $_.tier -eq 1 -and $_.total -eq 2 }).Count -eq 1) -and $null -ne $r.Result.data.groups[0].changedAt) $r.Text
$r = Invoke-Action 'health_read' @{}
Check 'health_read counts the locked-out accounts' ($r.Result.ok -and $r.Result.data.lockedOutCount -eq 1) $r.Text
$r = Invoke-Action 'computer_disable' @{ id = (Sid 3001) }
Check 'computer_disable disables an ordinary computer' ($r.Result.ok -and $r.Calls.Count -eq 1) $r.Text
$r = Invoke-Action 'computer_disable' @{ id = (Sid 3002) }
Expect-Error 'a domain controller is never disabled' $r 'protected_target'
Check 'and nothing changed' ($r.Calls.Count -eq 0)

# --- the help desk ---
$r = Invoke-Action 'user_disable' @{ id = (Sid 1104) }
Check 'disable an ordinary user' ($r.Result.ok -and ($r.Calls -join '|') -like 'Disable-ADAccount ann*Server=dc1.corp.test*') ($r.Calls -join '|' + $r.Text)
$r = Invoke-Action 'user_unlock' @{ id = (Sid 1105) }
Check 'unlock' ($r.Result.ok -and $r.Calls.Count -eq 1) $r.Text
$r = Invoke-Action 'user_enable' @{ id = (Sid 1105) }
Check 'enable' ($r.Result.ok -and ($r.Calls -join '|') -like 'Enable-ADAccount bob*') $r.Text
foreach ($case in @(
    @('dave', 1106, 'nested in Domain Admins'), @('admin2', 1107, 'a Domain Admins member'), @('pgu', 1108, 'primary group Domain Admins'),
    @('oldadmin', 1109, 'adminCount 1'), @('gmsa1$', 1112, 'a gMSA'), @('comp1$', 1113, 'a computer'))) {
    foreach ($a in 'user_disable', 'user_unlock', 'user_enable', 'user_delete', 'user_set', 'user_move') {
        $p = @{ id = (Sid $case[1]) }
        if ($a -eq 'user_set') { $p['title'] = 'x' }
        if ($a -eq 'user_move') { $p['targetOu'] = 'OU=Staff,DC=corp,DC=test' }
        $r = Invoke-Action $a $p
        Expect-Error "$a refuses $($case[2])" $r 'protected_target'
        Check "$a on $($case[2]) changed nothing" ($r.Calls.Count -eq 0) ($r.Calls -join '|')
    }
}
foreach ($rid in 500, 502, 512) {
    $r = Invoke-Action 'user_disable' @{ id = (Sid $rid) }
    Check "RID $rid is refused (not found here, never changed)" ($r.Calls.Count -eq 0) ($r.Calls -join '|')
}
$r = Invoke-Action 'user_disable' @{ id = (Sid 1110) }
Expect-Error 'a service account needs the second confirmation' $r 'service_account_confirmation_required'
$r = Invoke-Action 'user_disable' @{ id = (Sid 1110); serviceConfirm = 'service-account:wrong' }
Expect-Error 'a wrong service-account confirmation does not do' $r 'service_account_confirmation_required'
$r = Invoke-Action 'user_disable' @{ id = (Sid 1110); serviceConfirm = 'service-account:svc_backup' }
Check 'a confirmed service account is disabled' ($r.Result.ok -and $r.Calls.Count -eq 1) $r.Text
$r = Invoke-Action 'user_disable' @{ id = (Sid 1104) } @{ FAKEAD_READONLY = '1' }
Expect-Error 'a read-only controller changes nothing' $r 'read_only_dc'
$r = Invoke-Action 'user_disable' @{ id = (Sid 1104) } @{ FAKEAD_FAIL = 'Disable-ADAccount:ADServerDownException' }
Expect-Error 'ADWS down is its own error' $r 'adws_unavailable'
$r = Invoke-Action 'user_disable' @{ id = (Sid 1104) } @{ FAKEAD_FAIL = 'Get-ADGroup:ADFakeFailureException' }
Expect-Error 'a privileged group that cannot be read refuses the request (fails closed)' $r 'command_failed'
Check 'and changes nothing' ($r.Calls.Count -eq 0)
$r = Invoke-Action 'user_enable' @{ id = (Sid 1105) } @{ FAKEAD_FAIL = 'Get-ADObject:ADFakeFailureException' }
Expect-Error 'a member that cannot be resolved refuses the request' $r 'command_failed'

# --- passwords ---
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen; unlock = $true }
Check 'reset: password, must-change, unlock' ($r.Result.ok -and $r.Result.data.mustChange -eq $true -and $r.Result.data.unlocked -eq $true -and $r.Calls.Count -eq 3) ($r.Calls -join '|' + $r.Text)
Check 'reset passes a SecureString of the right length' (($r.Calls -join '|') -like "*NewPassword=secure($($secretSeen.Length))*") ($r.Calls -join '|')
Check 'the password is not in the output or the call log' (-not ($r.Text.Contains($secretSeen)) -and -not (($r.Calls -join '|').Contains($secretSeen)))
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen; mustChange = $false }
Check 'reset without must-change makes two calls fewer' ($r.Result.ok -and $r.Result.data.mustChange -eq $false -and $r.Calls.Count -eq 1) ($r.Calls -join '|')
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1111); password = $secretSeen }
Expect-Error 'must-change on a never-expires account is a conflict' $r 'conflict'
Check 'and no password was set' ($r.Calls.Count -eq 0)
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen } @{ FAKEAD_FAIL = 'Set-ADAccountPassword:ADPasswordComplexityException' }
Expect-Error 'the domain refuses the password' $r 'password_policy'
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen } @{ FAKEAD_FAIL = 'Set-ADUser:ADFakeFailureException' }
Expect-Error 'a reset whose flag step fails is partial' $r 'partial'
Check 'and says the password was changed' ($r.Result.error.message -like '*password was changed*' -and -not $r.Text.Contains($secretSeen))
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen; credUser = 'CORP\admin'; credPassword = 'Admin-Marker-1!' }
Check 'the credential fallback passes a credential' ($r.Result.ok -and ($r.Calls -join '|') -like '*Credential=credential*') ($r.Calls -join '|' + $r.Text)
Check 'and shows neither password' (-not $r.Text.Contains('Admin-Marker-1!') -and -not $r.Text.Contains($secretSeen) -and -not (($r.Calls -join '|').Contains('Admin-Marker-1!')))
$r = Invoke-Action 'user_reset_password' @{ id = (Sid 1104); password = $secretSeen; credUser = 'CORP\admin' }
Expect-Error 'half a credential is refused' $r 'conflict'

# --- the rest of the changes ---
$r = Invoke-Action 'user_set' @{ id = (Sid 1104); title = 'Boss'; mail = '' }
Check 'user_set sets and clears' ($r.Result.ok -and ($r.Result.data.changed -join ',') -like '*title*' -and ($r.Calls -join '|') -like '*Clear=mail*' -and ($r.Calls -join '|') -like '*Title=Boss*') ($r.Calls -join '|' + $r.Text)
$r = Invoke-Action 'user_set' @{ id = (Sid 1104) }
Expect-Error 'user_set with nothing to set' $r 'nothing_to_change'
$r = Invoke-Action 'user_set' @{ id = (Sid 1104); title = "x'; New-Item canary_a; '" }
Check 'a hostile attribute value is a value' ($r.Result.ok -and -not (Test-Path canary_a)) $r.Text
$r = Invoke-Action 'user_move' @{ id = (Sid 1104); targetOu = 'OU=Domain Controllers,DC=corp,DC=test' }
Expect-Error 'nothing is moved into Domain Controllers' $r 'protected_target'
$r = Invoke-Action 'user_move' @{ id = (Sid 1104); targetOu = 'OU=Staff,DC=other,DC=test' }
Expect-Error 'nothing is moved to another domain' $r 'not_found'
$r = Invoke-Action 'user_move' @{ id = (Sid 1104); targetOu = 'OU=Staff,DC=corp,DC=test' }
Check 'move' ($r.Result.ok -and $r.Calls.Count -eq 1) $r.Text
$r = Invoke-Action 'user_create' @{ ou = 'OU=Domain Controllers,DC=corp,DC=test'; sam = 'x1'; name = 'X One'; password = $secretSeen }
Expect-Error 'nothing is created in Domain Controllers' $r 'protected_target'
$r = Invoke-Action 'user_create' @{ ou = 'OU=Staff,DC=corp,DC=test'; sam = 'x1'; name = 'X One'; password = $secretSeen }
Check 'create enabled with a password, must change by default' ($r.Result.ok -and ($r.Calls -join '|') -like "*AccountPassword=secure($($secretSeen.Length))*" -and ($r.Calls -join '|') -like '*ChangePasswordAtLogon=True*' -and ($r.Calls -join '|') -like '*Enabled=True*' -and -not $r.Text.Contains($secretSeen)) ($r.Calls -join '|' + $r.Text)
$r = Invoke-Action 'user_create' @{ ou = 'OU=Staff,DC=corp,DC=test'; sam = 'x1'; name = 'X One' }
Expect-Error 'create needs a password (the server generates one)' $r 'invalid'
$r = Invoke-Action 'user_delete' @{ id = (Sid 1104) }
Check 'delete' ($r.Result.ok -and ($r.Calls -join '|') -like 'Remove-ADUser ann*') $r.Text
$r = Invoke-Action 'user_delete' @{ id = (Sid 1114) }
Expect-Error 'an object protected from accidental deletion is not deleted' $r 'not_enabled'
Check 'and the flag is not touched' ($r.Calls.Count -eq 0)
$r = Invoke-Action 'group_create' @{ ou = 'OU=Staff,DC=corp,DC=test'; name = 'New Group'; scope = 'domain_local'; category = 'security' }
Check 'group_create maps scope and category' ($r.Result.ok -and ($r.Calls -join '|') -like '*GroupCategory=Security*GroupScope=DomainLocal*') ($r.Calls -join '|' + $r.Text)
$r = Invoke-Action 'group_add_member' @{ id = (Sid 1300); member = (Sid 1105) }
Check 'add a member to an ordinary group' ($r.Result.ok -and ($r.Calls -join '|') -like 'Add-ADGroupMember Sales*') $r.Text
$r = Invoke-Action 'group_remove_member' @{ id = (Sid 1300); member = (Sid 1104) }
Check 'remove a member' ($r.Result.ok) $r.Text
foreach ($g in @(@(512, 'Domain Admins'), @(1201, 'a group nested in Domain Admins'))) {
    foreach ($a in 'group_add_member', 'group_remove_member', 'group_delete') {
        $r = Invoke-Action $a @{ id = (Sid $g[0]); member = (Sid 1104) }
        Expect-Error "$a refuses $($g[1])" $r 'protected_target'
        Check "$a on $($g[1]) changed nothing" ($r.Calls.Count -eq 0)
    }
}
$r = Invoke-Action 'group_add_member' @{ id = 'S-1-5-32-544'; member = (Sid 1104) }
Check 'the built-in Administrators group is refused too' (($r.Result -and -not $r.Result.ok) -and $r.Calls.Count -eq 0) $r.Text
$r = Invoke-Action 'group_delete' @{ id = (Sid 1300) }
Check 'delete an ordinary group' ($r.Result.ok) $r.Text

Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host 'all checks passed'
