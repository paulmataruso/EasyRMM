# Proves the AST check catches what it claims to (ADR-0073, ADR-0077): every fixture under fixtures/bad names, on its
# first line, the rules it must trip ("# expect: iex,command-param"); every fixture under fixtures/good must pass;
# and the pinned-helper exemption holds only for the helper whose body matches its pin.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WinmodAst.ps1')
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$failed = $false
function Fail($m) { Write-Host "self-test: $m"; $script:failed = $true }

$helperBody = (Get-Content -LiteralPath (Join-Path $fixtures 'good/_helpers.ps1') -Raw)
$helperAst = [System.Management.Automation.Language.Parser]::ParseInput($helperBody, [ref]$null, [ref]$null)
$fn = $helperAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$pin = Get-WinmodTextHash $fn.Body.Extent.Text
$pins = @{ 'New-EasyRmmCredential' = $pin }

foreach ($f in Get-ChildItem -LiteralPath (Join-Path $fixtures 'good') -Filter '*.ps1') {
    $got = @(Test-WinmodScript -Path $f.FullName -Pins $pins)
    if ($got.Count -gt 0) { Fail "$($f.Name) should pass but: $($got -join '; ')" }
}
$bad = @(Get-ChildItem -LiteralPath (Join-Path $fixtures 'bad') -Filter '*.ps1')
foreach ($f in $bad) {
    $first = (Get-Content -LiteralPath $f.FullName -TotalCount 1)
    if ($first -notmatch '^# expect: (.+)$') { Fail "$($f.Name) has no '# expect:' line"; continue }
    $got = @(Test-WinmodScript -Path $f.FullName -Pins $pins)
    foreach ($rule in ($Matches[1] -split ',')) {
        if (-not ($got | Where-Object { $_ -match ": $([regex]::Escape($rule.Trim())): " })) { Fail "$($f.Name) should trip '$rule' but found: $($got -join '; ')" }
    }
}

# The same helper with one character changed no longer matches its pin, so the exemption goes and the construct fails.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('winmod-ast-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
try {
    $changed = Join-Path $tmp '_helpers.ps1'
    Set-Content -LiteralPath $changed -Value $helperBody.Replace('-Force', '-Force -ErrorAction Stop') -Encoding UTF8
    $got = @(Test-WinmodScript -Path $changed -Pins $pins)
    if (-not ($got | Where-Object { $_ -match ': pin: ' })) { Fail "a changed pinned helper was accepted: $($got -join '; ')" }
    if (-not ($got | Where-Object { $_ -match ': plaintext: ' })) { Fail "a changed pinned helper kept its exemption: $($got -join '; ')" }

    # A pin that names a function nobody defines, and a helper defined twice, are findings of the tree check.
    $good = Join-Path $tmp 'tree'
    $null = New-Item -ItemType Directory -Path $good
    Copy-Item (Join-Path $fixtures 'good/_helpers.ps1') (Join-Path $good '_helpers.ps1')
    Copy-Item (Join-Path $fixtures 'good/_helpers.ps1') (Join-Path $good '_helpers2.ps1')
    $got = @(Test-WinmodTree -Root $good -Pins $pins)
    if (-not ($got | Where-Object { $_ -match 'defined more than once' })) { Fail "a duplicate pinned helper was accepted: $($got -join '; ')" }
    $got = @(Test-WinmodTree -Root $good -Pins @{ 'Gone-Helper' = $pin })
    if (-not ($got | Where-Object { $_ -match 'Gone-Helper is not defined' })) { Fail "a stale pin was accepted: $($got -join '; ')" }

    # The helper's own file is not a script: the exemption never reaches a script that defines the same name.
    $sneaky = Join-Path $tmp 'sneaky.ps1'
    Set-Content -LiteralPath $sneaky -Value ("Set-StrictMode -Version Latest`n`$ErrorActionPreference = 'Stop'`n`$p = [Console]::In.ReadToEnd() | ConvertFrom-Json`n" + $helperBody) -Encoding UTF8
    $got = @(Test-WinmodScript -Path $sneaky -Pins $pins)
    if (-not ($got | Where-Object { $_ -match ': pin: ' })) { Fail "a pinned helper outside a library was accepted: $($got -join '; ')" }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}
if ($failed) { exit 1 }
Write-Host "AST check self-test passed: $($bad.Count) bad fixtures, the good ones, and the pin cases."
