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
* Security keys and passkeys with a physical key and a platform passkey
  ([ADR-0032](docs/architecture/adr/0032-webauthn-passkeys.md)).
* Authentik on a real deployment (`setup.sh --with-authentik`,
  [ADR-0044](docs/architecture/adr/0044-authentik-when-chosen.md)).
* Patching alerts and monthly reports through a real mail server and webhook.
* The winget and Chocolatey software scripts on Windows
  ([ADR-0028](docs/architecture/adr/0028-software-deployment.md)), with the
  [hand test](docs/development/windows-software-hand-test.md).
* On Windows: the rollback of an agent update that crashes, a `cmd` script's
  time-out ending its child processes, and ARM64.
* Enrollment with approval and the EasyPatch agent's dnf install on more
  Linux distributions (Debian, Ubuntu, Rocky Linux, Fedora).
* Importing a standalone EasyPatch on a real server with a DNS move, and
  with a Windows agent. The import is tested only from 1.10.0 with a Linux
  agent; 1.4 to 1.9 are accepted but untested.

**Fix in the patching engine**

* The endpoint list sorts agent versions as text, so 1.10.0 comes before
  1.9.0 (`EndpointEndpoints.ListAsync`). Sort them as versions.
* An agent request that sends `null` for a list (for example
  `"activeJobIds": null`) gets 500 instead of 400. EasyPatch agents always
  send lists; reject null lists in the agent request types, with tests.

## After 1.0.0

* **Packages for the EasyRMM agent**: an MSI for Windows (needs Windows CI
  runners) and DEB and RPM packages for Linux. Today computers install with
  the PowerShell or shell command.
* **Authenticode signing** of the Windows agents, so Windows names a
  publisher ([CODE_SIGNING.md](CODE_SIGNING.md)).
* **Email and webhook notifications for device alerts.** Patching alerts
  have them; device alerts show in the console only.
* **Patching**: giving or taking a tag from many devices at once, forcing a
  restart outside the policy, and removing and holding an update in one
  step.
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
