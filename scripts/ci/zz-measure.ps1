$ErrorActionPreference = 'Continue'
function T([string]$Name, [string]$Cmd) {
    $t = @()
    for ($i = 0; $i -lt 5; $i++) { $t += (Measure-Command { & powershell.exe -NoProfile -NonInteractive -Command $Cmd 2>&1 | Out-Null }).TotalMilliseconds }
    $t = $t | Sort-Object
    Write-Host ("TIMING {0,-55} median {1,7:N0} ms  (min {2:N0}, max {3:N0})" -f $Name, $t[2], $t[0], $t[4])
}
Write-Host ("PSVersion " + $PSVersionTable.PSVersion + "; modules on the path: " + (@(Get-Module -ListAvailable).Count))
T 'powershell start-up only' '0'
T 'old: Get-Module -ListAvailable GroupPolicy + Import' 'if (-not (Get-Module -ListAvailable -Name GroupPolicy)) { exit 3 }; Import-Module GroupPolicy'
T 'new: Import-Module GroupPolicy + Get-Module' 'Import-Module -Name GroupPolicy -ErrorAction SilentlyContinue; if ($null -eq (Get-Module -Name GroupPolicy)) { exit 3 }'
T 'Import-Module ActiveDirectory' 'Import-Module ActiveDirectory'
T 'Get-Module -ListAvailable (all)' '$null = Get-Module -ListAvailable'
T 'GetComputerDomain (no domain: time to fail)' 'try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { }'
T 'DNS GetHostEntry of own name' '[System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()) | Out-Null'
T 'Import GroupPolicy + Get-GPO -All (no domain: time to fail)' 'Import-Module GroupPolicy; try { Get-GPO -All } catch { }'
