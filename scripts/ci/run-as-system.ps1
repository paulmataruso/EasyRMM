# Runs a program as LocalSystem, as the agent's service runs, through a
# scheduled task, prints what it printed and exits with its exit code
# (ADR-0064's tests on CI's Windows runners). For CI only: the task's
# command file and output are in the runner's temporary folder.
#
#   run-as-system.ps1 -Program C:\t\jobs.test.exe -Arguments '-test.v','-test.run=AsSystem' `
#       -WorkingDirectory C:\src\agent\jobs -Environment 'EASYRMM_TEST_SYSTEM=1'
#
# Arguments and environment values may not hold double quotes, percent signs,
# carets, ampersands, pipes or angle brackets: they go through cmd.exe.
param(
    [Parameter(Mandatory = $true)][string] $Program,
    [string[]] $Arguments = @(),
    [string] $WorkingDirectory = (Get-Location).Path,
    [string[]] $Environment = @(),
    [int] $TimeoutMinutes = 30
)
$ErrorActionPreference = 'Stop'

foreach ($s in @($Program, $WorkingDirectory) + $Arguments + $Environment) {
    if ($s -match '["%^&|<>]') { throw "cmd.exe would read ${s} its own way" }
}
$dir = Join-Path $env:RUNNER_TEMP ('system-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$output = Join-Path $dir 'output.txt'
$exitFile = Join-Path $dir 'exit-code.txt'
$commands = Join-Path $dir 'run.cmd'
$lines = @('@echo off', 'setlocal')
foreach ($e in $Environment) { $lines += "set `"$e`"" }
$lines += "cd /d `"$WorkingDirectory`""
$lines += "`"$Program`" " + (($Arguments | ForEach-Object { "`"$_`"" }) -join ' ') + " > `"$output`" 2>&1"
$lines += "echo %ERRORLEVEL%> `"$exitFile`""
Set-Content -Path $commands -Value $lines -Encoding Ascii

$name = 'EasyRMM test ' + [guid]::NewGuid().ToString('N')
$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument "/d /c `"$commands`""
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
try {
    Start-ScheduledTask -TaskName $name
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes + 1)
    $ended = $null
    while (-not (Test-Path $exitFile)) {
        if ((Get-Date) -gt $deadline) { throw "The task did not finish in $TimeoutMinutes minutes." }
        # 267009: running; 267011: not yet run.
        $info = Get-ScheduledTaskInfo -TaskName $name
        if ($info.LastTaskResult -notin 267009, 267011 -and (Get-ScheduledTask -TaskName $name).State -eq 'Ready') {
            if ($null -eq $ended) { $ended = Get-Date }
            elseif ((Get-Date) -gt $ended.AddSeconds(15)) { throw "The task ended ($($info.LastTaskResult)) without an exit code." }
        }
        Start-Sleep -Seconds 2
    }
}
finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    if (Test-Path $output) { Get-Content -Path $output -Encoding UTF8 | Write-Output }
}
$text = ''
for ($i = 0; $i -lt 10 -and $text -eq ''; $i++) {
    $text = "$(Get-Content -Path $exitFile -Raw)".Trim()
    if ($text -eq '') { Start-Sleep -Seconds 1 }
}
$code = [int]$text
Write-Output "Exit code as LocalSystem: $code"
exit $code
