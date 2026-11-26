Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json

# A catalogue script of the shape ADR-0073 requires, used by the hostile-value test: each value of $p.values is
# only ever a cmdlet or function argument, and the result says what happened to it. If a value were evaluated,
# the test's canary files would appear in the working folder. The agent puts agentproto.ParamsPrologue in front,
# so standard input and output are UTF-8 and the result line carries names as they are.

function Get-Echo([string]$Text) { return $Text }

function Get-Sha256([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

$items = @()
foreach ($v in @($p.values)) {
    $splat = @{ Text = $v }
    $o = Write-Output -InputObject $v
    $found = $false
    try { $found = Test-Path -LiteralPath $v -ErrorAction Stop } catch { $found = $false }
    $items += [ordered]@{
        value        = $v
        length       = $v.Length
        sha256       = Get-Sha256 $v
        viaFunction  = ((Get-Echo -Text $v) -ceq $v)
        viaSplat     = ((Get-Echo @splat) -ceq $v)
        viaOutput    = ($o -ceq $v)
        viaObject    = (([pscustomobject]@{ v = $v }).v -ceq $v)
        asPathExists = [bool]$found
    }
}
$r = [ordered]@{ ok = $true; version = 1; data = [ordered]@{ items = $items }; error = $null }
[Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 6))
