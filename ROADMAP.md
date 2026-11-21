# Roadmap

What is left before 1.0.0, and what comes after it. What works today, and
how it was verified, is in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Before 1.0.0

Release candidates run on real deployments with real computers. 1.0.0
follows when these have been run there, or fixed:

**Run on real computers**

* Install a Windows update through EasyRMM. The Windows test machines so
  far had nothing missing, so install jobs completed without installing
  anything. Then restarts with someone signed in, removing an update, and
  "Restart all that need it" on an organization and a site.
* RDP sessions against a Windows device ([ADR-0026](docs/architecture/adr/0026-rdp-sessions.md)).
* A physical security key and a platform passkey (Windows Hello, iCloud
  Keychain) ([ADR-0032](docs/architecture/adr/0032-webauthn-passkeys.md)).
  A password manager's passkey (Bitwarden) works on a real deployment, as
  the second factor and for sign-in without a password.
* Authentik on a real deployment (`setup.sh --with-authentik`,
  [ADR-0044](docs/architecture/adr/0044-authentik-when-chosen.md)).
* Patching alerts and monthly reports through a real mail server and webhook.
* The winget and Chocolatey software scripts on Windows
  ([ADR-0028](docs/architecture/adr/0028-software-deployment.md)), with the
  [hand test](docs/development/windows-software-hand-test.md).
* On Windows: the rollback of an agent update that crashes, a `cmd` script's
  time-out ending its child processes, ARM64, and removing a device from
  the console ([ADR-0050](docs/architecture/adr/0050-removing-a-device.md)):
  the uninstaller started outside the agent's service, and whether
  MeshCentral can uninstall the MeshAgent the agent runs as a service.
* Enrollment with approval and the EasyPatch agent's dnf install on more
  Linux distributions (Debian, Ubuntu, Rocky Linux, Fedora).
* Importing a standalone EasyPatch on a real server with a DNS move, and
  with a Windows agent. The import is tested only from 1.10.0 with a Linux
  agent; 1.4 to 1.9 are accepted but untested.

**Build**

* Operators sign the Windows agent with their own code signing
  certificate ([ADR-0049](docs/architecture/adr/0049-operators-sign-windows-agents.md)):
  they sign the server's builds with their own tools and upload them, and
  the server checks and hands out the signed builds.

## After 1.0.0

* **Packages for the EasyRMM agent**: an MSI for Windows (needs Windows CI
  runners) and DEB and RPM packages for Linux. Today computers install with
  the PowerShell or shell command.
* **Authenticode signing** of the Windows agents with a certificate of
  EasyRMM's own, so Windows names a publisher without the operator signing
  them ([CODE_SIGNING.md](CODE_SIGNING.md)). On hold.
* **Email and webhook notifications for device alerts.** Patching alerts
  have them; device alerts show in the console only.
* **Patching**: giving or taking a tag from many devices at once, forcing a
  restart outside the policy, and removing and holding an update in one
  step.
* **Hardening a Linux computer in one click.** A choice of hardening
  modules (all of them, or some) that the agent applies, with what each
  changes shown first: EasyRMM's own implementation, modelled on what
  [ultimate-sys-hardening](https://github.com/Kal1010101/ultimate-sys-hardening)
  does. An ADR comes first.
* **Collecting logs** from Windows and Linux computers: the security log,
  Microsoft Defender's and other antivirus logs, the system log, PowerShell,
  auth and audit logs. EasyRMM keeps them and forwards them (to a SIEM, for
  example). The agent sets up the logging they need when it is installed
  (audit policy, log sizes, PowerShell script-block logging, auditd
  rules), so nobody does it by hand. An ADR comes first: storage and
  retention, the agent's limits on CPU, bandwidth and disk, and forwarding.
* **Upgrading EasyRMM from the console.** Today an upgrade is
  [run on the server](docs/operations/upgrading.md). The console would
  offer a newer release, check its signatures, back up, upgrade, and roll
  back if it fails. EasyRMM runs in containers, so something on the host
  does the upgrade; an ADR decides what, without giving the server the
  Docker socket.
* **The agent's WebSocket channel** ([ADR-0009](docs/architecture/adr/0009-agent-protocol.md)),
  if long polling (jobs within a second or so) stops being enough.
* **macOS.** There is no EasyRMM agent for macOS. The EasyPatch agent's
  macOS build is experimental and not released; before it is:
  * enroll a real Mac and run scans, installs, restarts and a self-update end
    to end (CI only installs, scans and uninstalls it);
  * sign and notarize the `.pkg` with an Apple Developer ID;
  * warn signed-in users on screen before a restart, as the Windows tray does;
  * on Apple silicon, macOS updates can be installed only by a volume owner or
    an MDM, so the agent fails them with `macos_owner_required`; this will
    probably stay a documented limit.
