Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $from = [int](Get-Number (Get-Prop $p 'fromId'))
    $rows = @(Invoke-View (Get-DispositionRestriction ([string]$p.disposition) $from) (Get-RequestColumns))
    $page = @($rows | Select-Object -First 100)
    $next = $null
    if ($rows.Count -gt 100) { $next = [int64](Get-Number (Get-Prop $rows[100] 'RequestID')) }
    Write-Result $true ([ordered]@{ requests = @($page | ForEach-Object { Convert-RequestRow $_ }); total = $rows.Count; next = $next }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the requests failed: ' + $_.Exception.GetType().Name)
}
