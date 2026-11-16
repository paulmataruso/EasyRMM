# ADR-0020: The Windows agent

* Status: Accepted (2026-11-16).

## Context
EasyRMM is for MSPs, whose fleets are mostly Windows. Until now the agent
(ADR-0015, 0017, 0018) ran only on Linux: the console offered no way to
install anything on Windows, scripts were Bash, sh or Python, and
inventory came from Linux files. The agent is one Go program; this ADR
records how the same program runs on Windows and how Windows computers
install it.

## Decision

### One agent, built for Windows
* `easyrmm-agent.exe` is the same Go program cross-compiled for
  `windows/amd64` and `windows/arm64` (`CGO_ENABLED=0`). Go 1.27 needs
  Windows 10 or Windows Server 2016 and later, which is what the agent
  supports. The Docker image and `make build-agents` build both, next to
  the Linux builds; the server hands them out like any other
  (`easyrmm-agent-windows-<arch>.exe`).
* Platform code sits behind small seams, so the protocol, enrollment,
  signing, the run loop and jobs are shared:
  * `host.Paths` lays files out per platform: `%ProgramFiles%\EasyRMM\Agent\
    easyrmm-agent.exe`, `%ProgramFiles%\EasyRMM\MeshAgent\`, and the state
    in `%ProgramData%\EasyRMM\Agent` (logs in `logs\`).
  * `host.Services` installs, restarts and removes services: systemd units
    on Linux, the Windows service manager on Windows.
  * Inventory, metrics and script execution have a Linux and a Windows
    implementation of the same functions.

### Services
* The agent runs as the **EasyRMMAgent** service ("EasyRMM Agent") as
  LocalSystem, started automatically, with recovery set to restart it
  (three times, counter reset after a day, also after a non-crash exit).
  Started by the service manager, the program notices it and runs the
  agent until Windows stops it; it writes its log to `agent.log` (10 MiB,
  one previous file kept) because a service has no console or journal.
* MeshAgent runs as its own service, **EasyRMMMeshAgent**, from
  `%ProgramFiles%\EasyRMM\MeshAgent\meshagent.exe`. MeshAgent reads its
  service name from `meshServiceName` in its `.msh` settings, which the
  agent sets, so EasyRMM's MeshAgent does not collide with one a customer
  installed from another MeshCentral ("Mesh Agent"). MeshAgent on Windows
  only works as a service; an agent that was only enrolled (`enroll`, no
  service) goes without it.
* The state folder and the MeshAgent folder get an access list of their
  own, not inherited: full control for SYSTEM and Administrators, nothing
  for anyone else. This replaces the Unix file modes; the agent's private
  key is protected by it.
* Installing over a running agent replaces the program by renaming the old
  one aside; a program in use that cannot be removed is deleted at the next
  restart (`MoveFileEx`, delay until reboot). The service is restarted when
  the program changed.

### Installing: install.ps1
* The server serves `GET /api/agent/v1/install.ps1`, per address like
  `install.sh` (ADR-0016), ASCII with CRLF line ends. **Devices → Add
  devices** shows a PowerShell one-liner for Windows first and the curl
  command for Linux. The one-liner turns on TLS 1.2 (Windows PowerShell 5.1
  leaves it off on older systems), downloads the script and runs it with
  the token as a parameter. It runs in Windows PowerShell as administrator.
* The script checks for an administrator, Windows 10 or later and the
  processor (x64 or ARM64), downloads the build and `SHA256SUMS`, compares
  the SHA-256, and runs `easyrmm-agent.exe install`, passing the token in
  `EASYRMM_TOKEN` rather than on the command line. Failures throw rather
  than exit, so the administrator's window stays open with the message.
* **By IP address**, where the certificate comes from the server's own
  authority: curl's pin (SHA-256 of the SubjectPublicKeyInfo) cannot be
  computed in Windows PowerShell 5.1, which has no API for the encoded
  public key info. The server therefore publishes a second pin of the same
  key, `KeyPin`: the hex SHA-256 of the public key bit string, which is
  what .NET's `X509Certificate.GetPublicKey()` returns. The one-liner sets
  `ServicePointManager.ServerCertificateValidationCallback` to accept only
  a certificate with that key, downloads the script and removes the
  callback; the script does the same for its downloads, fetches `ca.pem`
  over that pinned connection and enrolls with `--ca-file`. The check runs
  as a PowerShell script block, which PowerShell 7 cannot run on .NET's
  connection threads, so a pinned install needs Windows PowerShell.

### Scripts
* Two more shells: **PowerShell** (Windows PowerShell 5.1,
  `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File`, the script saved as UTF-8 with a byte order mark so non-ASCII text
  survives) and **cmd** (a `.cmd` batch file in the OEM code page with CRLF
  line ends, run as `cmd.exe /D /E:ON /V:OFF /S /C`). A shell runs on one
  platform; the server refuses a job for a device of another platform, and
  lists only matching scripts for a device. cmd arguments cannot contain
  double quotes or line breaks, which cmd cannot pass safely.
* Scripts run as LocalSystem, with the service's environment minus the
  agent's own settings, and TEMP pointed at the run's folder. The script
  runs in a job object: a timeout or cancel ends the script and everything
  it started. Console output that is not UTF-8 is decoded from the OEM code
  page.

### Inventory and health
* Hardware comes from the SMBIOS table Windows keeps
  (`GetSystemFirmwareTable`), processors from
  `GetLogicalProcessorInformationEx`, disks from `\\.\PhysicalDriveN`
  (size, model, serial, bus and SSD or HDD), the network from
  `GetAdaptersAddresses`, and the Windows name, version and build from the
  registry, with Windows 11 named as such (its registry still says 10).
* Installed programs are the ones **Apps & features** lists: the
  Uninstall keys of the machine (64- and 32-bit views) and of each user,
  without system components, updates and entries without a name. They are
  stored with their **publisher**, a new column. Their package source is
  `windows`.
* Health: processor (`GetSystemTimes`), memory, page files (shown as
  **Page file** rather than swap), uptime, processes and the fixed drives.
  Windows has no load average; the console leaves it out for Windows
  devices.

## Consequences
* Windows is first in the console: the Add devices page, the script editor
  (PowerShell by default) and the agent downloads.
* Tests: unit tests of everything that can be checked off Windows (the
  SMBIOS and storage parsers, program filtering, the installer's text,
  PowerShell's parse of it, the key pin against .NET's computation), the
  Windows code compiled and vetted in CI, and Windows-only tests that run on
  a Windows CI runner (services' access lists, real inventory and metrics,
  PowerShell and cmd jobs, a timeout ending a script's children).
* The agent is not code-signed yet: SmartScreen does not apply to the
  PowerShell install, but some endpoint protection products may hold an
  unsigned program for review. Signing and an MSI package for Group Policy
  and Intune are the next steps.
