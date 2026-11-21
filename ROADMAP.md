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
* A Windows agent signed with an operator's certificate from a public
  certificate authority ([ADR-0049](docs/architecture/adr/0049-operators-sign-windows-agents.md)):
  uploaded, installed and updated to on real Windows computers, and what
  Windows and Defender show for it.
* Enrollment with approval and the EasyPatch agent's dnf install on more
  Linux distributions (Debian, Ubuntu, Rocky Linux, Fedora).
* Importing a standalone EasyPatch on a real server with a DNS move, and
  with a Windows agent. The import is tested only from 1.10.0 with a Linux
  agent; 1.4 to 1.9 are accepted but untested.

## After 1.0.0

How the next eight features work and the order they are built in is in
[the feature plan](docs/architecture/feature-plan.md); each gets its ADR
before its code.

* **Hardening a Linux computer in one click**
  ([ADR-0051](docs/architecture/adr/0051-hardening-linux-computers.md)):
  check, apply and undo 14 hardening modules (SSH, firewall, fail2ban,
  kernel parameters, audit rules and more), some or all of them, as a job,
  with what each changes shown first. EasyRMM's own implementation, after
  studying [ultimate-sys-hardening](https://github.com/Kal1010101/ultimate-sys-hardening);
  safe for computers nobody is logged in to.
* **Upgrading EasyRMM from the console.** Today an upgrade is
  [run on the server](docs/operations/upgrading.md). A small updater on
  the host (not the server, which never gets the Docker socket) checks a
  release's signatures, backs up, upgrades, and rolls back if the new
  release fails its checks; then the console offers new releases and
  shows the upgrade.
* **Email and webhook notifications for device alerts**, through one
  sender that patching alerts move to as well: rules per organization,
  site and tag, maintenance windows, and one notice for a site that goes
  offline instead of one per device.
* **Let's Encrypt certificates set up from the console, in one step.**
  Today the server gets and renews certificates by itself for the names
  given at install. The console would check each name before asking Let's
  Encrypt, saying what to fix; get the certificates without a restart;
  show their expiry and renewals; alert when a renewal fails; and take
  new names, including moving an IP-only install to a name, with DNS-01
  for servers that the internet cannot reach.
* **Packages for the EasyRMM agent**: DEB and RPM packages for Linux and an
  MSI for Windows (for Group Policy and Intune). Today computers install
  with the PowerShell or shell command.
* **The agent's WebSocket channel** ([ADR-0009](docs/architecture/adr/0009-agent-protocol.md)):
  a live connection, so jobs and changes reach a computer at once, chosen
  per device, site or organization: *Automatic* (recommended), *Live
  connection* or *Regular check-ins*.
* **Collecting logs** from Windows and Linux computers: the security log,
  Microsoft Defender's and other antivirus logs, the system log, PowerShell,
  auth and audit logs. EasyRMM keeps them and forwards them (to a SIEM, for
  example). The agent sets up the logging they need (audit policy, log
  sizes, PowerShell script-block logging, auditd rules), so nobody does it
  by hand.
* **Authenticode signing** of the Windows agents with a certificate of
  EasyRMM's own, so Windows names a publisher without the operator signing
  them ([CODE_SIGNING.md](CODE_SIGNING.md)). On hold.
* **Patching**: giving or taking a tag from many devices at once, forcing a
  restart outside the policy, and removing and holding an update in one
  step.
* **macOS.** There is no EasyRMM agent for macOS. The EasyPatch agent's
  macOS build is experimental and not released; before it is:
  * enroll a real Mac and run scans, installs, restarts and a self-update end
    to end (CI only installs, scans and uninstalls it);
  * sign and notarize the `.pkg` with an Apple Developer ID;
  * warn signed-in users on screen before a restart, as the Windows tray does;
  * on Apple silicon, macOS updates can be installed only by a volume owner or
    an MDM, so the agent fails them with `macos_owner_required`; this will
    probably stay a documented limit.
