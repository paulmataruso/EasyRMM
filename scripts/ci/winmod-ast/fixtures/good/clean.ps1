Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json

function Write-Result($ok, $data) {
    $r = [ordered]@{ ok = $ok; version = 1; data = $data }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $r -Compress -Depth 6))
}
try {
    $name = [string]$p.name
    $rows = Get-ChildItem -LiteralPath "C:\" -Filter '*.txt' -ErrorAction SilentlyContinue
    Write-Result $true ([ordered]@{ name = $name; count = @($rows).Count; fixed = "no values here" })
} catch {
    Write-Result $false $null
}
