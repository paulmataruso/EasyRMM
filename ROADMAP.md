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

## Done

Built and merged, ahead of 1.0.0. How each was verified is in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

* **Hardening a Linux computer in one click**: apply and undo (H2, PR #91)
  ([ADR-0051](docs/architecture/adr/0051-hardening-linux-computers.md)).
* **Hardening Windows computers**: the checks (W1, PR #92)
  ([ADR-0054](docs/architecture/adr/0054-hardening-windows-computers-and-servers.md)).
* **The self-updater**, 4a (PR #70)
  ([ADR-0052](docs/architecture/adr/0052-the-host-updater.md)).
* **PowerShell 7** (PR #104)
  ([ADR-0064](docs/architecture/adr/0064-remote-powershell-management.md)).
* **The mailer and Microsoft 365 mail** (PR #82, PR #97)
  ([ADR-0053](docs/architecture/adr/0053-one-notification-sender.md)).
* **Disk health** (PR #86)
  ([ADR-0065](docs/architecture/adr/0065-hardware-health.md)).
* **The customer documentation record** (PR #95)
  ([ADR-0066](docs/architecture/adr/0066-customer-documentation-and-assets.md)).
* **Patching improvements** (PR #100, PR #102, PR #103, PR #112).
* **One device tree, device moves, agent logs, and cross-path recovery of
  MeshAgent and both agents** (PR #114, PR #115, PR #116, PR #117, PR #118,
  PR #119, PR #120)
  ([ADR-0069](docs/architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md)).

## Next up

* **Remote desktop: a single selected monitor is cut off.** When one monitor is
  chosen in the remote desktop viewer, about the bottom quarter of the screen
  (for example the Windows Start menu) is hidden. The viewer's scaling for the
  selected display needs fixing.
* **Patching tree: selection should scope the page.** Choosing a device in the
  Patching tree should open that device's patching page. Choosing a group, site
  or organization should open the Patching page scoped to it. Today every choice
  opens the full Patching page.

## In progress

* PR #122: reconnect remote access on a MeshAgent that will not stop.
* PR #121: Defender exclusions at install and an always-current hash list
  (ADR-0070). Every agent folder and process is excluded before anything
  else installs. Hashes are refreshed on every rebuild, change and
  self-update, including when MeshCentral updates MeshAgent.

## After 1.0.0

Planned, in this order. Each feature gets its ADR before its code; the
plans are [the feature plan](docs/architecture/feature-plan.md) and
[the MSP feature plan](docs/architecture/feature-plan-msp.md).

1. **Our MeshAgent fully isolated from any other MeshAgent install on the
   same machine.** EasyRMM only ever touches its own.
2. **A single Repair button** that works out what is down and uses
   whichever agent is still running to fix MeshAgent or the other agent.
3. **Saved RDP credentials per device**, for users who choose to save
   them. They are encrypted at rest, limited to users with permission,
   audited on every use, and a saved password is never shown back.
4. **Quick Assist: on-demand support sessions.**
   * **Links:** a technician generates a one-time link to send to a user, or a
     permanent link. Downloading and running it starts the EasyRMM agent, MeshAgent
     and the patching agent for that session only, with no install.
   * **Session:** the computer appears in a separate Quick Assist section of the
     navigation. The technician accepts its connection request in the console, and
     it stays in the list for the whole session.
   * **Keeping it:** with the user's agreement, the technician can install the
     agents permanently. The device then stays in Quick Assist or is moved to any
     organization, site or group.
5. **The agent's live channel** (WebSockets)
   ([ADR-0059](docs/architecture/adr/0059-the-agents-websocket-channel.md),
   [ADR-0009](docs/architecture/adr/0009-agent-protocol.md)): jobs and
   changes reach a computer at once, chosen per device, site or
   organization: *Automatic* (recommended), *Live connection* or *Regular
   check-ins*.
6. **A Windows Defender module**: management from the console (settings,
   scans, signatures, threats and quarantine, exclusions, attack surface
   reduction, Controlled Folder Access). Defender events can be used as
   alert rules, with default rules. Tamper Protection is shown, not
   changed.
7. **Active Directory**: detect domain controllers, manage users and
   groups, reset passwords, disable accounts. Extends AD health (feature 12
   of the MSP feature plan).
8. **Server role modules**, each one can be switched off: AD Certificate
   Services, DNS, DHCP, file sharing, print server.
9. **Windows Backup management.** Full on servers (Windows Server Backup).
   On desktops, only what Windows exposes: File History and the system
   image.
10. **Security frameworks and compliance:**
   * **Pick a framework, check every host against it.** Frameworks: CMMC
     Level 1 and 2, NIST SP 800-171, NIST SP 800-53, the NIST
     Cybersecurity Framework, HIPAA, GDPR, SOC 2 (TSC), and more later (for
     example PCI DSS, ISO 27001, Essential Eight, Cyber Essentials). The
     check covers every requirement that can be verified on the machine.
   * **One fix per gap,** applied only when the admin clicks apply. Risky
     fixes (account lockout, BitLocker, FIPS mode, AppLocker/WDAC, LDAP
     signing) show a warning and need typed agreement for each item.
   * **For CMMC, a full SSP, POA&M and evidence workflow** in the console,
     with OSCAL export and an SPRS score shown as a range until every
     requirement is assessed.
   * **Built on one control library** with check, apply, undo and a risk
     tier for each control. Each framework is a pack that maps its
     requirements onto that library, using authoritative public sources
     (NIST, HHS, DoD, DISA).
   * **CIS Benchmark profiles for Windows and Windows Server,** built from
     EasyRMM's own checks of the same settings and cross-referenced by CIS
     recommendation number. CIS's own text is not copied, and the profiles
     are not CIS-certified.

   * **Linux and network-device baselines** are in scope.
   * **Every check records its provenance and a licence classification.**
     Licensed content (such as CIS's own text) can only come in as
     separate optional packages.

   Requirements: [compliance engine](docs/architecture/requirements/2026-11-24-compliance-engine.md).
   The design (an ADR) comes before any build.
11. **The rest of the MSP feature plan's order:**
   * Windows hardening W2 (apply and undo) and W3 (the console)
   * the updater's console (4b): today an upgrade is
     [run on the server](docs/operations/upgrading.md)
   * Let's Encrypt from the console, in one step
     ([ADR-0055](docs/architecture/adr/0055-lets-encrypt-in-one-step.md))
   * packages for the agent: DEB and RPM, and an MSI for Group Policy and
     Intune ([ADR-0056](docs/architecture/adr/0056-packages-for-the-agent.md))
   * the registry editor ([ADR-0067](docs/architecture/adr/0067-remote-registry-editor.md))
   * the event viewer ([ADR-0068](docs/architecture/adr/0068-remote-event-viewer.md))
   * BitLocker and LUKS management, and the keystore
   * security posture
   * the asset record and warranty
   * scheduled tasks
   * the software catalog
   * automation
   * [ADR-0057](docs/architecture/adr/0057-rotating-the-job-key.md) (the job
     key) and [ADR-0058](docs/architecture/adr/0058-signed-settings-that-reach-the-agent.md)
     (signed settings)
   * log collection ([ADR-0060](docs/architecture/adr/0060-collecting-logs.md))
   * the new name ([ADR-0061](docs/architecture/adr/0061-moving-to-a-new-name.md))
   * Linux one-click hardening, last
12. **Authenticode signing** of the Windows agents with a certificate of
   EasyRMM's own ([CODE_SIGNING.md](CODE_SIGNING.md)). On hold.

Also after 1.0.0:

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

## Known issues

* The Logs tab orders entries from different agents out of time order.
* MeshAgent writes no log, so its side is not visible.
* Recovery diagnostics are not yet in the Logs tab.
* Two CI tests are flaky: the AIDE baseline in the Linux VM tests, and the
  Rocky Linux 8 container check-in.
