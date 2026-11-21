# ADR-0056: Packages for the agent: DEB, RPM and MSI

* Status: Proposed (2026-11-21). Not implemented.
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md)
  (tokens, enrollment, MeshAgent), [ADR-0024](0024-enrollment-approval.md)
  (approval tokens), [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0049](0049-operators-sign-windows-agents.md) (operators sign the
  Windows agent) and [ADR-0050](0050-removing-a-device.md) (removing a
  device).
* Part of [the feature plan](../feature-plan.md#6-packages-for-the-agent-deb-rpm-msi):
  feature 6.

## Context
MSPs onboard computers with the tools they already run: Intune, Group
Policy, Configuration Manager, another RMM during a migration, Ansible, a
golden image. Those tools install packages. EasyRMM offers commands only:
[`install.sh`](../../../server/internal/httpapi/agentapi/install.sh.tmpl)
and [`install.ps1`](../../../server/internal/httpapi/agentapi/install.ps1.tmpl)
download the server's build for the computer, check it against
`SHA256SUMS` and run `easyrmm-agent install` with the token in
`EASYRMM_TOKEN`.

What exists, and what it means here:

* **The agent installs itself.** `easyrmm-agent install`
  ([`main.go`](../../../agent/cmd/easyrmm-agent/main.go)) enrolls, copies
  its own executable to its place (`/usr/local/bin/easyrmm-agent`, or
  `%ProgramFiles%\EasyRMM\Agent\easyrmm-agent.exe`;
  [`host.go`](../../../agent/host/host.go)) and creates its service: a unit
  it writes to `/etc/systemd/system/`
  ([`service.go`](../../../agent/host/service.go)), or the `EasyRMMAgent`
  service with its recovery settings
  ([`system_windows.go`](../../../agent/host/system_windows.go)). Once
  enrolled it fetches MeshAgent from the server, signed with the job key,
  and runs it as a service of its own (ADR-0015,
  [`meshagent.go`](../../../agent/meshagent/meshagent.go)).
* **The agent replaces its own executable.** An update renames the running
  file aside and puts the server's build in its place
  ([`update.go`](../../../agent/update/update.go)). The server tells builds
  apart by SHA-256 (ADR-0027), and on Windows the build may be one the
  operator signed (ADR-0049). A package that owned that file would find it
  changed after every update, and would put its own back at its next
  upgrade or repair.
* **An agent cannot wait to be enrolled.** `run` without an enrollment or
  an approval request fails (`main.go`,
  [`approval.go`](../../../agent/cmd/easyrmm-agent/approval.go)), so the
  service exists only after enrollment. A package installed without a
  token, as for a golden image, would have nothing to start.
* **Uninstalling tells the server nothing.** `easyrmm-agent uninstall`
  leaves the device listed as offline. The only report an agent makes
  about leaving answers a removal the console asked for (ADR-0050), and it
  deletes the device ([`removal.go`](../../../server/internal/agents/removal.go)).
* **A release builds the agents twice.** The image compiles them
  ([`Dockerfile`](../../../docker/server/Dockerfile), `-buildvcs=false`);
  [`bundle.sh`](../../../scripts/release/bundle.sh) compiles them again
  for the release files, without that flag. Built both ways from one
  checkout, the two files differ: the second records the commit (`go
  version -m` shows it). The attested agents of a release are therefore
  not the builds the server hands out, and an operator who signs the
  release's file, as ADR-0049 allows, would have it refused, its
  Authenticode digest not being the server's build's. Found while writing
  this ADR by building both ways locally; not yet checked against a
  published release.
* **The patching engine already ships packages.** The EasyPatch agent's
  DEB and RPM are built in a pinned container with networking off, and
  checked to hold the published agent byte for byte
  ([`build-linux-packages.sh`](../../../easypatch/scripts/build-linux-packages.sh),
  [`linux-packages/`](../../../easypatch/agent/Installer/linux-packages/Dockerfile)).
  Its MSIs are built with WiX 5.0.2 on the Windows runner
  ([`Package.wxs`](../../../easypatch/agent/Installer/Package.wxs),
  [`build-installer.ps1`](../../../easypatch/agent/Installer/build-installer.ps1)),
  and a build check makes sure the token's property is hidden and no
  progress message carries it
  ([`build-msi-linux.sh`](../../../easypatch/scripts/build-msi-linux.sh)).
  Its agent removes its own package in a transient unit with `apt-get
  remove` and a lock timeout, or `rpm -e`, and on Windows with `msiexec
  /x`, finding the product by its fixed upgrade code
  ([`LinuxAgentUninstaller.cs`](../../../easypatch/agent/EasyPatch.Linux/Platform/LinuxAgentUninstaller.cs),
  [`WindowsAgentUninstaller.cs`](../../../easypatch/agent/EasyPatch.Agent/Platform/WindowsAgentUninstaller.cs)).
  All of that is reused. Where EasyRMM's agent differs, so does the
  design: EasyPatch's packages own the agent's executable and unit and are
  how it updates itself, each with a `.sig` from the release key that the
  agent checks ([CODE_SIGNING.md](../../../CODE_SIGNING.md)); its MSI keeps
  the token in a registry value until the agent reads it, and runs WiX's
  util extension's custom actions; its DEB and RPM carry no OpenPGP
  signature.
* **Deployment tools keep no secret.** Group Policy's software
  installation cannot pass properties, and what Group Policy deploys sits
  in SYSVOL, which every domain user can read. Intune shows command lines
  to its administrators and its agent's logs on the device record them.
  On Linux any user can read another process's command line (`ps`); on
  Windows administrators can, and process-creation auditing, Sysmon and
  endpoint protection record them. Approval tokens (ADR-0024) exist for
  this: a copy that leaks enrolls nothing until someone approves it.

## Options

### Where packages are built
1. **At release, the same for every server** (chosen).
2. **On the server, per organization or token, with the token inside.**
   Rejected:
   * The package becomes the secret. It is copied into downloads folders,
     mail, file shares, SYSVOL, Intune and backups, and revoking the token
     is the only way to stop it.
   * Nothing could sign it. The server must not hold an operator's code
     signing key (ADR-0049), so a per-token MSI would never carry an
     Authenticode signature. A key on the server for OpenPGP signatures on
     DEB and RPM would be a second key beside the job key, and a computer
     would have to trust it before its first install: trust on first use
     again.
   * It closes nothing ADR-0017 leaves open. Pinning the job key inside the
     package does not help: the package arrives over the same connection
     as the enrollment, the only channel outside it is the text a
     technician copies from the console, and F0's rotation would make a
     pinned key stale.
   * MSIs need Windows Installer tooling a Linux server lacks; ADR-0008
     rejected per-server installers for the same reason.
   * Computers would install files the release's attestation and
     checksums do not cover.
3. **Both.** Per-server packages would bring all of the above for nothing
   that a generic package and a file cannot do.

### How the token reaches a package
* **Inside the package**: rejected, above.
* **A command line.** Readable by every user on Linux, logged by `sudo`,
  shell history and process auditing. Not offered on Linux, as
  `install.sh` already avoids it. On Windows, `msiexec` properties are how
  deployment tools pass settings: offered, with the MSI keeping the token
  out of its own logs; administrators and process-creation logs still see
  the command line, and log collection (feature 3) is planned to redact
  `TOKEN=`.
* **The environment.** Only the same user and root can read a process's
  environment, and it passes through `sudo --preserve-env` and the package
  manager to the package's scripts. Offered on Linux.
* **A file**, readable by root (SYSTEM and Administrators on Windows)
  only, deleted once used. It is protected like the device key it is
  exchanged for, which is the stronger credential, and it is what
  configuration management, cloud-init and Group Policy Preferences
  deliver. Offered everywhere.
* **A transform (MST) per token for Group Policy**, as the feature plan
  proposed. Rejected: the server would need a writer for Windows
  Installer's compound files and transforms, built for this alone; a
  transform in a share is as readable as a file in it; and Group Policy
  Preferences deliver the same file every other path uses.
* **A file beside the MSI.** Rejected: one planted in a downloads folder
  would point the computer at someone else's server.
* **debconf.** Rejected: it keeps answers in its database.

Whatever the path, a token given to a deployment tool should be an
approval token, or a deployment token limited in uses and time.

### Who updates the agent
* **The server, through the agent's own update** (ADR-0027, ADR-0049)
  (chosen).
* **apt and dnf repositories on the EasyRMM server.** Rejected: the package
  manager updates every computer at its next timer, with none of the
  rollout's limit, probation, rollback, backoff or per-device status;
  Windows, containers and agents installed by command would still need the
  agent's own update, so there would be two; on Windows the server's build
  may be the operator's signed one, which no package carries; a repository
  needs an OpenPGP key that every computer trusts, held by the server or
  by the release; and every computer's package manager would contact the
  server on its own schedule and report errors when it is down, which the
  patching engine's scans would see.
* **The package as the vehicle of updates**, as EasyPatch's agent does.
  Rejected: builds are identified by their executable's SHA-256 and signed
  by operators as executables; a package would have to be rebuilt, and on
  Windows signed again, for every build the server hands out.

## Decision

### The server owns updates; the package owns its copy
* **A package carries its own copy of the agent** and never owns the
  agent's files. On its first install it runs `easyrmm-agent install
  --package <deb|rpm|msi>`, which does what `install` does today: enrolls,
  copies the agent to its place and creates the service.
* **Later package upgrades replace the package's copy only.** They never
  touch the running agent, its service or its enrollment, never move it to
  another server, and cannot get round the rollout or *Only signed builds*.
  An MSP that mirrors the packages in its own repository, pushes a newer
  one from Intune, or lets the patching engine approve it, changes nothing
  that runs.
* **`install --package` never replaces an installed agent.** On a
  computer where the agent is installed (by the command, or by an earlier
  package), it records which package now installed it and changes nothing
  else.
* **The package's copy hands over.** Asked to do anything on a computer
  where the agent is installed, the package's copy runs the installed
  agent with the same arguments, so the newest code does the work, also
  when the agent has updated itself past the package.
* **Versions.** `dpkg -l`, `rpm -q` and Programs and Features show the
  package's version, not the agent's after it has updated itself; the
  console shows the agent's.
* **The device records how its agent was installed**: the heartbeat's
  facts carry `installer` (`deb`, `rpm`, `msi`, or none for the command),
  stored with the device and shown on its page.

### The enrollment file
* **Where.** `/etc/easyrmm-agent/install.conf`, and
  `%ProgramData%\EasyRMM\Agent\install.conf` on Windows (the agent's state
  folder). One INI format for both, because Windows Installer writes INI
  files without a custom action:

  ```ini
  [enrollment]
  server=https://rmm.example.com
  token=ert_...
  ca=MIIC...
  ```

  `ca` is optional: the server's own certificate authority, base64 DER on
  one line, for a server on an IP address or with its internal authority.
* **Other inputs.** On Linux, `EASYRMM_SERVER`, `EASYRMM_TOKEN` and
  `EASYRMM_CA_FILE` (a PEM file, as `--ca-file`) in the environment win
  over the file. The MSI's properties are written into the file, so on
  Windows the file is the only input.
* **Only a file an administrator made is read.** On Linux a regular file,
  not a link, owned by root, with no permission for group or others, in a
  directory only root can change. On Windows a plain file, not a reparse
  point, owned by SYSTEM, Administrators or TrustedInstaller, in the state
  folder the agent protects first, as it does for its key (any user may
  create folders under ProgramData; the agent already moves aside one it
  did not make). Anything else is refused, and the agent says why.
* **Deleted once used.** Once the agent has enrolled, or saved its request
  for approval, it deletes the file: the token then lives only where it
  lives today (`pending.json` while waiting for approval) or nowhere. A
  file naming another server than the one the agent is enrolled with is
  reported and deleted too.
* **Without input the agent waits.** `install --package` without input
  installs the agent and its service, which looks for the file every 30
  seconds and enrolls when it appears. `easyrmm-agent status` says it
  waits and where the file goes. This is the golden image: the device key
  and MeshAgent's identity are made at enrollment, so clones of an image
  captured before it do not share them. Input from the environment that
  cannot be used at once is written to the file for the service.
* **Errors.** An answer that may change (no answer, a server error, a rate
  limit) is retried with the approval wait's backoff, 5 seconds to 5
  minutes. An answer that will not (`token_invalid`,
  `enrollment_rejected`, `key_in_use`, an address that is not HTTPS, a
  certificate that does not verify) is retried only when the file changes.
  `install --package` then exits with an error: the MSI fails and rolls
  back; the DEB's and RPM's scripts print it and finish, leaving the
  service waiting for a corrected file, because a failed `postinst` leaves
  the package half-configured and apt then tries, and fails, to configure
  it on every later run, the patching engine's included.

### DEB and RPM
The package `easyrmm-agent`, for `amd64` and `arm64` (`x86_64` and
`aarch64`):

| Path | Mode | What |
|---|---|---|
| `/usr/libexec/easyrmm-agent/easyrmm-agent` | 0755 root | The package's copy: the release's build, byte for byte |
| `/usr/sbin/easyrmm-agent` | link | To the copy, which hands over to the installed agent. On Rocky Linux and AlmaLinux, `sudo`'s `secure_path` leaves out `/usr/local/bin` |
| `/etc/easyrmm-agent/` | 0700 root | Where `install.conf` goes; the package ships no file in it, so no configuration file prompts on upgrade |
| `/usr/share/doc/easyrmm-agent/` | | The licence (FSL-1.1-ALv2); `%license` in the RPM |

* **Scripts.** The first install (DEB `postinst configure` without a
  previous version; RPM `%post` with `$1` = 1) runs `easyrmm-agent install
  --package`. A removal (`prerm remove`; `%preun` with `$1` = 0) runs
  `easyrmm-agent uninstall --package`. A purge removes `/etc/easyrmm-agent`.
  Upgrades run nothing. Every script exits 0 whatever the agent says, and
  shows what it says. Without systemd (a container), the install says to
  use `easyrmm-agent enroll` and `run`.
* **The agent's files stay the agent's**, exactly as for every Linux
  agent: `/usr/local/bin/easyrmm-agent`, its unit in
  `/etc/systemd/system/`, `/var/lib/easyrmm-agent/` and MeshAgent's
  files, written by `install` and removed by `uninstall`. Debian's and
  Fedora's packaging rules keep packages out of `/usr/local`; the package
  ships nothing there, but its script runs the program that writes there.
  This is deliberate: one layout means one update, uninstall and removal
  path for every Linux agent, and a computer can move between the command
  and the package without a second agent. Moving every Linux agent
  elsewhere would be its own change, with a migration of installed units.
* **Built** in a pinned container with networking off, as EasyPatch's: DEB
  with xz and `--root-owner-group`; RPM with a gzip payload and SHA-256
  file digests, readable by Enterprise Linux 8's rpm 4.14. No dependencies:
  the agent is a static Go program.
* **Versions**: `1.2.3`, and `1.2.3~rc.1` for a release candidate, in
  both formats (the tilde sorts the candidate first); RPM release 1.
* **Distributions**: ADR-0051's: Debian 12 and 13; Ubuntu 22.04, 24.04 and
  26.04; Rocky Linux and AlmaLinux 8, 9 and 10, which stand for RHEL
  (not tested itself); current Fedora. Elsewhere with dpkg, or rpm 4.14 and
  later, and systemd, it installs, unsupported until tested. Linux `arm`
  and `386` keep the install command only.

### MSI
* **Tooling.** WiX 5.0.2, the version EasyPatch's MSIs pin, so that the
  repository has one MSI toolchain, built with `dotnet build` on CI's
  `windows-2025` runner with ICE validation; an ICE error fails the build.
  Rejected: wixl from msitools, which builds from a subset of WiX's
  elements and cannot validate; WiX under Wine, which EasyPatch's
  `build-msi-linux.sh` uses for builds on Linux and which cannot validate
  either.
* **Packages**: x64 and ARM64, per machine, Windows Installer 5.0, a fixed
  upgrade code, major upgrades that allow the same version (a release
  replaces its candidate, whose MSI version has no room for `-rc`),
  downgrades refused. No dialogs: `/qn` and the deployment tools need
  none. No repair or modify entry in Programs and Features: there is
  nothing of the agent's for a repair to restore. Launch conditions: an
  administrator; Windows 10 or Server 2016 and later; and the processor
  the MSI is for, so that the x64 MSI does not put an emulated agent on
  ARM64 Windows.
* **Files**: `%ProgramFiles%\EasyRMM\Package\easyrmm-agent.exe`, the
  release's build byte for byte, and nothing else. The service is the
  agent's, created by `install` with its recovery settings as today; the
  MSI's service tables are not used, because the service runs the agent's
  own copy, which the MSI must not own.
* **Properties**: `SERVERURL` (HTTPS), `TOKEN` and `CACERT` (base64 DER),
  all secure; `TOKEN` hidden; `SERVERURL` and `TOKEN` together or not at
  all. When given, the MSI creates the state folder with access for SYSTEM
  and Administrators only (the SDDL the agent and EasyPatch's MSI use) and
  writes them to `install.conf` through its INI table. The progress
  template of that step leaves the value out, as EasyPatch's MSI does for
  its registry step, and the build checks both, as EasyPatch's does. The
  token is never in the registry, and no custom action has it on its
  command line.
* **Three custom actions**, each running the package's copy with fixed
  arguments, deferred, as LocalSystem; no script, no DLL, no WiX extension
  action:
  1. `install --package msi`, on the first install, after the file is
     written; its failure fails the install.
  2. Its rollback, `uninstall --package msi`, so that a failed or
     cancelled install leaves no agent.
  3. `uninstall --package msi` on removal, not during an upgrade's
     removal of the version it replaces; its failure never stops the
     removal.

  The agent's code is needed to enroll and to report, so custom actions
  cannot be avoided; these are the agent itself.
* **Deploying it**:
  * *Intune*: as a line-of-business app with the properties, or a Win32
    app. Detection by the MSI's product code is enough, since the agent's
    updates are not Intune's; a detection that must show the agent runs
    checks the `EasyRMMAgent` service.
  * *Group Policy*: the MSI assigned to computers, without properties,
    and `install.conf` delivered to `%ProgramData%\EasyRMM\Agent\` by Group
    Policy Preferences (*Files*, applied once). The order does not matter:
    the agent waits for the file. Use an approval token: SYSVOL is readable
    by every domain user.
  * *Another RMM, Configuration Manager, a script*: `msiexec /i … /qn
    SERVERURL=… TOKEN=…`.

### Signing
* **DEB and RPM carry no OpenPGP signature.** apt and dnf do not check a
  local package file's signature by default, and there is no repository,
  where signatures are checked. They rest on the server's HTTPS, on
  `SHA256SUMS` and on the release's attestation (`gh attestation verify`).
  CODE_SIGNING.md says so.
* **Release MSIs carry no Authenticode signature**: there is no project
  certificate, and signing through a vendor is on hold.
* **Operators sign the MSI, as they sign the agent (ADR-0049).** A
  PowerShell script, published with each release and on **Settings →
  Agent updates**, puts the operator's signed build into the MSI in place
  of the release's: it replaces the embedded cabinet with one holding the
  signed build, made with `makecab`, and updates the file's size and hash
  in the MSI's tables through the Windows Installer API, both part of
  Windows. It refuses a build without an Authenticode signature or for
  another architecture. The operator then signs the MSI with their own
  tools (`signtool`, `jsign`, `osslsigncode`) and deploys it with their own
  tool. EasyRMM never builds, reads or signs that MSI, and never holds the
  key.
* **Self-updates are unaffected.** The agent does not check Authenticode
  signatures: it updates on the server's signed instruction to the SHA-256
  it names (ADR-0027). No MSI is ever an update, so neither the MSI's
  signature nor what it carries changes how agents update. An operator's
  MSI installs the server's signed build, so the agent is current from its
  first heartbeat; the release's MSI installs the unsigned build, which
  updates to the signed one when the server has one, as ADR-0049's default
  does. EasyPatch's MSIs differ: they are its agent's updates, signed over
  their SHA-256, which is why ADR-0049 could not let operators sign them.
* **With *Only signed builds*** the console does not offer the release's
  MSI, whose agent WDAC and AppLocker would block, and links to the
  script instead.

### Built once, at release; served by the server
* **One build.** A release job builds each agent binary once; the image,
  the release files and the packages all take those files, and checks
  compare the SHA-256 of each across all of them (the agent inside each
  package included, as EasyPatch's builder checks its own). A build of the
  image from source still compiles its agents.
* **A reusable workflow builds the packages** for pull requests and `main`
  as well as for releases, without publishing, so that release steps are
  tested before a release; CI's images carry those packages. Nothing is
  signed, so these jobs need no secret and no release environment.
* **Published** with the release, in `SHA256SUMS`, attested and listed in
  the manifest: `easyrmm-agent_1.2.3_amd64.deb`,
  `easyrmm-agent-1.2.3-1.x86_64.rpm`, `easyrmm-agent-1.2.3-x64.msi` and
  their ARM64 versions.
* **Served by the server.** The image carries the packages of its own
  version beside the agents, root-owned and read-only, as the engine's
  image carries its agents' packages (ADR-0041). The server serves them at
  `/api/agent/v1/download/<file>`, lists them in `SHA256SUMS`, which the
  install scripts read by file name, and on **Add devices**
  (`/api/v1/agent-downloads`,
  [`enrollapi.go`](../../../server/internal/httpapi/enrollapi/enrollapi.go)).
  So a computer gets the server's own version, from the server it already
  has to reach. A server built from source without packages offers none.
  A package older than the server installs its own agent first, which the
  server then updates within its rollout setting.

### MeshAgent
No package contains or owns MeshAgent. After enrollment the agent fetches
it from the server, signed, and runs it as its own service, as today
(ADR-0015); `uninstall` removes it; package upgrades never touch it;
MeshCentral keeps updating it.

### Uninstalled
* **Removing a package removes the agent**: its script runs `uninstall
  --package`, which stops and removes the service and MeshAgent, tells the
  server, and deletes the agent's state and executable. `easyrmm-agent
  uninstall` reports the same way, whatever installed the agent; run by
  hand on an agent a package installed, it names the package manager's
  command and stops.
* **The report**: `POST /api/agent/v1/uninstalled`, signed with the device
  key like every agent request, naming the installer. It is best effort:
  sent before the key is deleted, given at most 10 seconds, never failing
  the removal.
* **The server** shows the device as *Uninstalled*, with when and how,
  instead of offline; no offline alert opens for it, and open ones
  resolve. The report is audited as `device.uninstalled`, recorded as the
  agent. **Remove device** on it deletes it at once, as **Remove anyway**
  does (ADR-0050), with its MeshCentral node and its EasyPatch agent. A
  device the console was removing is deleted on the report. A heartbeat
  from its key, as from a computer restored from a backup, makes it an
  ordinary device again. Feature 7's "no false offline alerts" is this
  report; whichever of the two is built first builds it.

### Removal from the console
For an agent a package installed, the uninstaller ADR-0050 starts (a
transient unit, or a detached process on Windows) checks the instruction,
keeps the device key and the instruction in memory, and removes the
package: `apt-get remove` with a 30-minute lock timeout, `rpm -e`, which
waits for rpm's lock, or `msiexec /x` with the product found by its
upgrade code, tried again every minute for 30 minutes while another
installation runs. The package's script runs `uninstall --package`, which
finds the saved instruction and so removes the agent without reporting
*Uninstalled*; the uninstaller then reports the removal with the key it
kept. If the package manager fails and the service still runs, it reports
the failure and the service stays, as ADR-0050 does when a service cannot
be removed. If the package is gone already, it uninstalls as for an agent
the command installed. The removal dialog warns that Intune, Group Policy
or configuration management may install the agent again.

### In the console
**Add devices** gains packages beside the install commands, rendered in
the browser from the token, as the commands are
([`AddDevicesPage.tsx`](../../../web/src/pages/devices/AddDevicesPage.tsx)):
for Windows, the MSI, its `msiexec` line (with `CACERT` for an address on
the server's own authority), `install.conf` to download, and the steps
for Intune and Group Policy; for Linux, the DEB and RPM, `install.conf`,
and `sudo --preserve-env=EASYRMM_SERVER,EASYRMM_TOKEN apt install ./…`
(or `dnf`). The deployment tools' steps recommend an approval token and
warn when a site's token has no use limit. Nothing new reaches the
server: the token is the one already shown, or shown again (ADR-0047).

## Testing
* **Unit**: the file's parsing and its checks of owner, mode and links on
  Linux, and of owner and reparse points on Windows (on CI's Windows
  runner); the environment's precedence; waiting, and a final refusal
  retried only when the file changes; `install --package` never replacing
  an installed agent; the hand-over; `uninstall --package` with and
  without a saved instruction; the report's time limit; each format's
  version. Coverage floors for the new packages.
* **PostgreSQL integration and HTTP API**: the report (signature, state,
  audit, alerts not opened and resolved, a removal confirmed, a heartbeat
  clearing it); the installer recorded; packages in the downloads and in
  `SHA256SUMS`.
* **Console**: Add devices' files and commands for each address, with the
  certificate authority where it applies; the warning for an unlimited
  site token; the device's installer and *Uninstalled*; the removal
  dialog's warning.
* **Builds**: each package holds the release's agent byte for byte;
  lintian and rpmlint, with any finding accepted listed with its reason;
  `shellcheck` on the scripts; ICE; the MSI's hidden property, progress
  template and platform (as `build-installer.ps1` checks EasyPatch's).
* **Whole machines** for DEB and RPM, with the harness of ADR-0051's first
  slice (`internal/vmtest` and `docs/development/machine-tests.md`, on
  that slice's branch, not on `main` yet): distributions' cloud images
  under QEMU with KVM and user networking, never a bridge, one job per
  image. Debian 12 and 13 and Ubuntu 22.04 and 24.04 for the DEB; Rocky
  Linux 8 and 9, AlmaLinux 9 and Fedora for the RPM, with SELinux
  enforcing as the images boot; Ubuntu 26.04 and the 10 releases as the
  harness gains them. The deployment runs on the host with host
  networking, as the bundle test brings it up, and the machine reaches it
  at QEMU's address for the host. On each:
  1. install with `install.conf`: enrolled, MeshAgent connected, the file
     gone, files and modes as above, and `dpkg -S` or `rpm -qf` showing
     that the package owns only its own;
  2. install with the environment, through `sudo --preserve-env` and apt
     or dnf;
  3. install without input: it waits; the file written later; it enrolls;
  4. a file others can read, or not owned by root: refused, with the
     reason;
  5. a refused token: the package installs and says why; a corrected file
     enrolls;
  6. an approval token: it waits, is approved through the API, enrolls;
  7. the agent updated by the server, then a newer package: the running
     agent's SHA-256 unchanged, the package's copy newer; after a restart
     the agent comes back;
  8. the package over an agent the install command installed: the same
     device and executable, the installer recorded;
  9. removal with apt or dnf: services, MeshAgent and files gone, the
     device *Uninstalled*; a purge;
  10. removal from the console: the package gone, the device deleted; and
      again while another process holds the package manager's lock, which
      it waits for.
* **arm64**: the same install, enrollment, upgrade and removal in systemd
  containers on GitHub's `ubuntu-24.04-arm` runner, with host networking,
  for Debian 13 and Rocky Linux 9, until the harness boots arm64 images.
* **The bundle test** enrolls one Linux agent from the DEB with
  `install.conf` as Add devices gives it; the EasyPatch agent is then
  installed and patches as today; `apt remove` leaves the device
  *Uninstalled*.
* **Windows**, on CI's `windows-2025` runner for x64 and GitHub's
  `windows-11-arm` runner for ARM64 (marked unverified if that runner is
  not available to the repository): ICE; a silent install with
  properties, with the file, and without input (it waits); the verbose log
  (`/l*v`), the registry and the state folder free of the token after
  enrollment; a refused token failing the install and rolling it back,
  leaving nothing; an upgrade and a repair leaving the agent alone;
  `msiexec /x` reporting *Uninstalled*; removal from the console; the
  operator's script with a certificate made for the run and `signtool`,
  as ADR-0049's test does: the MSI's signature verifies and the installed
  agent is the signed build. Steps that need a server run against the
  feature plan's Windows end-to-end harness; until it exists they are
  marked unverified.
* **Then the owner's real computers**: Windows through Intune or Group
  Policy; Ubuntu and Rocky Linux.

## Slices
Each merges on its own, with its documentation (the
[agents guide](../../deployment/agents.md), CODE_SIGNING.md,
IMPLEMENTATION_STATUS, ROADMAP, CHANGELOG, database.md for migrations).

1. **The enrollment file and an agent that waits**: `install.conf` and
   the environment, the checks, deletion, waiting, `install --package`,
   the hand-over. Verified by unit tests on Linux and Windows and by the
   bundle test, whose machine runs the agent as a package's script will
   (`install --package`, before any package exists) without input: it
   waits, and enrolls when the file appears.
2. ***Uninstalled* and the installer recorded**: the report, the server's
   state, alerts, the console, a local `uninstall` reporting. Verified by
   integration and console tests and by the bundle test.
3. **One build**: the release's agents built once, the checks across the
   image, the release files and the bundle. Verified on CI's image job and
   on the next release candidate.
4. **DEB**: the reusable workflow, the package, served by the server and
   released, Add devices, removal from the console through apt. Verified
   on the Debian and Ubuntu machines, the arm64 containers and the bundle
   test.
5. **RPM**: the same through rpm. Verified on the Rocky Linux, AlmaLinux
   and Fedora machines and the arm64 container.
6. **MSI**: x64 and ARM64, the properties, the file, the custom actions,
   Add devices with Intune and Group Policy, removal through `msiexec`,
   *Only signed builds* hiding it. Verified on the Windows runners.
7. **The operator's signed MSI**: the script and the guide. Verified on
   the Windows runner with a certificate made for the run.

## Consequences
* MSPs can install the agent with Intune, Group Policy, Configuration
  Manager, another RMM, configuration management or a golden image. The
  packages are the same for every server and never contain a token.
* The package manager and the agent never fight: package upgrades are
  inert for the running agent, which follows the server. The versions the
  package manager and Programs and Features show are the package's.
* Every packaged computer holds the agent twice, the package's copy and
  the agent's own.
* The agent's files stay in `/usr/local` and `/etc/systemd/system`, where
  distribution packaging rules keep packages out; the package itself
  ships nothing there.
* The MSI has three custom actions, all the agent itself. An unsigned MSI
  opened from a browser's download gets SmartScreen's warning; deployment
  tools do not show it.
* Under *Only signed builds*, Windows computers get an MSI only through
  the operator's script and signature.
* The image grows by six packages.
* **Not covered**:
  * apt and dnf repositories, and OpenPGP signatures on the packages.
  * An MSI signed by the project: code signing through a vendor is on
    hold.
  * Packages for macOS, and for Linux `arm` and `386`.
  * Images captured after enrollment: they carry the device key and
    MeshAgent's identity, and their clones are not detected.
  * SUSE and other distributions outside ADR-0051's list.
  * A proxy for the agent's connection.
