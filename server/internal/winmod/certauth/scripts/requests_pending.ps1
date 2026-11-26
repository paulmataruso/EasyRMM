Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    $ca = Assert-Ca
    Assert-CaRunning
    $rows = @(Invoke-View (Get-DispositionRestriction 'pending' 0) (Get-RequestColumns))
    $out = @($rows | Select-Object -First 100 | ForEach-Object { Convert-RequestRow $_ })
    Write-Result $true ([ordered]@{ requests = @($out); total = $rows.Count; next = $null }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the pending requests failed: ' + $_.Exception.GetType().Name)
}
