# Removing EasyRMM's MeshAgent by hand (Windows)

When a Windows device is removed while its EasyRMM agent is offline,
EasyRMM's MeshAgent may be left on the computer (ADR-0071). EasyRMM does not
ask MeshCentral to uninstall it, because that request also deletes any other
MeshAgent's Diagnostic Agent. Run this on the computer, in an elevated
PowerShell. It removes only EasyRMM's own service, folder and registry keys,
each by its exact name; another MeshAgent (`Mesh Agent`, or a custom name),
its folder and its keys are not looked at.

```powershell
$ErrorActionPreference = 'Continue'
$name = 'EasyRMMMeshAgent'
$dir  = Join-Path $env:ProgramFiles 'EasyRMM\MeshAgent'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Null
}
# Only a process that runs our own program, by its full path.
$exe = Join-Path $dir 'meshagent.exe'
Get-CimInstance Win32_Process -Filter "Name='meshagent.exe'" |
    Where-Object { $_.ExecutablePath -ieq $exe } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
foreach ($k in "HKLM:\SOFTWARE\Open Source\$name",
               "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$name") {
    Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
}
```

The process filter lists `meshagent.exe` processes only to compare each one's
full path with ours; it ends none of another program's.
