# ADR-0056: Packages for the agent: DEB, RPM and MSI

* Status: Proposed (2026-11-21). Not implemented.
* Revised after an independent review (2026-11-21), with the owner's
  decisions on tokens for deployment tools, *Uninstalled*, RPM signatures
  and EasyPatch's MSI check. Two questions remain for the owner
  ([Owner questions](#owner-questions)).
* Builds on: [ADR-0015](0015-enrollment-and-meshagent-delivery.md)
  (tokens, enrollment, MeshAgent), [ADR-0024](0024-enrollment-approval.md)
  (approval tokens), [ADR-0027](0027-agent-updates.md) (agent updates),
  [ADR-0049](0049-operators-sign-windows-agents.md) (operators sign the
  Windows agent), [ADR-0050](0050-removing-a-device.md) (removing a
  device), [ADR-0051](0051-hardening-linux-computers.md) (its machine
  harness), and ADR-0053 (one notification sender: *Uninstalled* and
  removals nobody asked for), proposed beside this one and not merged yet,
  so cited without a link.
* Refines: [ADR-0008](0008-unified-endpoint-installer.md), which chose
  MSI, DEB and RPM, the DEB and RPM built with nfpm. Here they are built
  with `dpkg-deb` and `rpmbuild`, as EasyPatch's are, and no package
  carries MeshAgent, as ADR-0015 already decided.
* Amends: [ADR-0027](0027-agent-updates.md): until a device has run the
  server's build once, the rollout mode does not hold it back (owner
  question 2).
* Part of [the feature plan](../feature-plan.md#6-packages-for-the-agent-deb-rpm-msi):
  feature 6. [Departures from the plan](#departures-from-the-plan) lists
  where this ADR differs from it.

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
  it writes to `/etc/systemd/system/` and starts with `systemctl enable
  --now` ([`service.go`](../../../agent/host/service.go)), or the
  `EasyRMMAgent` service with its recovery settings
  ([`system_windows.go`](../../../agent/host/system_windows.go)). It
  installs a service only where `/run/systemd/system` exists
  (`Available` in `service.go`, checked in `main.go`'s `enroll`). Once
  enrolled it fetches MeshAgent from the server, signed with the job key,
  and runs it as a service of its own (ADR-0015,
  [`meshagent.go`](../../../agent/meshagent/meshagent.go)).
* **The agent replaces its own executable.** An update renames the file it
  runs from, resolved through links (`Self` in
  [`update.go`](../../../agent/update/update.go)), aside and puts the
  server's build in its place. The server tells builds apart by SHA-256
  and moves an agent to its own build whichever is newer (ADR-0027); the
  rollout can also be *When asked* or *Off*. On Windows the build may be
  one the operator signed (ADR-0049). A package that owned that file
  would find it changed after every update, and would put its own back at
  its next upgrade or repair.
* **Older agents refuse what they do not know.** `install` and `uninstall`
  parse their options with `flag.ContinueOnError` (`main.go`), so an agent
  from before this feature answers `--package` with "flag provided but not
  defined" and an unknown command with "unknown command".
* **An agent cannot wait to be enrolled.** `run` without an enrollment or
  an approval request fails (`main.go`,
  [`approval.go`](../../../agent/cmd/easyrmm-agent/approval.go)), so the
  service exists only after enrollment. A package installed without a
  token, as for a golden image, would have nothing to start.
* **Uninstalling tells the server nothing.** `easyrmm-agent uninstall`
  leaves the device listed as offline. The only report an agent makes
  about leaving answers a removal the console asked for (ADR-0050), and the
  server deletes the device on it even when no removal is pending
  (`Removed` in [`removal.go`](../../../server/internal/agents/removal.go)
  records `removalCanceled`). ADR-0053 designs *Uninstalled* and changes
  that.
* **The ProgramData folder is not the administrators' alone.** Any user
  may create folders and files under `%ProgramData%`. The agent protects
  its state folder there by moving aside one it did not make and creating
  it anew with an access list for SYSTEM and Administrators only
  (`Protect` in `system_windows.go`), but only when it first saves state.
  EasyPatch's MSI keeps its enrollment token in a registry key it creates
  with such an access list
  ([`Package.wxs`](../../../easypatch/agent/Installer/Package.wxs)), where
  no user can create anything first.
* **A release builds the agents twice.** The image compiles them
  ([`Dockerfile`](../../../docker/server/Dockerfile)) with
  `-buildvcs=false`, from a build context without `.git`
  ([`.dockerignore`](../../../.dockerignore)), with its pinned Go;
  [`bundle.sh`](../../../scripts/release/bundle.sh) compiles them again
  for the release files with whatever Go is on the path. Built from a
  clone, `bundle.sh`'s files recorded the commit and so differed from the
  image's. PR #50 builds them with `-buildvcs=false` too: built from a
  clone, the release's agents are then byte for byte the image's. They
  remain two compilations, equal only while the two toolchains are.
* **The patching engine already ships packages.** The EasyPatch agent's
  DEB and RPM are built with `dpkg-deb` and `rpmbuild` in a pinned
  container with networking off, and checked to hold the published agent
  byte for byte
  ([`build-linux-packages.sh`](../../../easypatch/scripts/build-linux-packages.sh),
  [`linux-packages/`](../../../easypatch/agent/Installer/linux-packages/Dockerfile)).
  Its MSIs are built with WiX 5.0.2 on the Windows runner
  ([`build-agent.ps1`](../../../easypatch/scripts/build-agent.ps1) and
  [`build-installer.ps1`](../../../easypatch/agent/Installer/build-installer.ps1),
  which the release workflow runs). Only the build under Wine,
  [`build-msi-linux.sh`](../../../easypatch/scripts/build-msi-linux.sh),
  checks that the token's property is hidden and that no progress message
  carries it; `build-installer.ps1` checks the platform only. That is
  being fixed separately. Its agent removes its own package in a
  transient unit with `apt-get remove` and a lock timeout, or `rpm -e`,
  and on Windows with `msiexec /x`, finding the product by its fixed
  upgrade code
  ([`LinuxAgentUninstaller.cs`](../../../easypatch/agent/EasyPatch.Linux/Platform/LinuxAgentUninstaller.cs),
  [`WindowsAgentUninstaller.cs`](../../../easypatch/agent/EasyPatch.Agent/Platform/WindowsAgentUninstaller.cs)).
  All of that is reused. Where EasyRMM's agent differs, so does the
  design: EasyPatch's packages own the agent's executable and unit and are
  how it updates itself, each with a `.sig` from the release key that the
  agent checks ([CODE_SIGNING.md](../../../CODE_SIGNING.md)); its MSI runs
  WiX's util extension's custom actions; its DEB and RPM carry no OpenPGP
  signature.
* **Fedora now refuses unsigned packages.** Fedora 45 has the change
  *Enforcing signature checking by default*, which sets rpm's
  `%_pkgverify_level` from `digest` to `all`, RPM 6.0's own default:
  `rpm -i` and `dnf install ./…` refuse a package without a valid
  signature from an imported key
  (<https://fedoraproject.org/wiki/Changes/Enforcing_signature_checking_by_default>).
  Enterprise Linux 8 to 10 do not enforce it; dpkg checks no signature on
  a package file.
* **Deployment tools keep no secret.** Group Policy's software
  installation cannot pass properties, and what Group Policy deploys sits
  in SYSVOL, which every domain user can read. Intune shows command lines
  to its administrators and keeps them in its own logs on the device.
  On Linux any user can read another process's command line (`ps`); on
  Windows administrators can, and process-creation auditing, Sysmon and
  endpoint protection record them. Approval tokens (ADR-0024) exist for
  this: a copy that leaks enrolls nothing until someone approves it. Every
  token expires, after 1 to 90 days; a site token's use limit is optional
  ([`tokens.go`](../../../server/internal/agents/tokens.go)).

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
     RPMs would be a second key beside the job key, and a computer would
     have to trust it before its first install: trust on first use again.
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
  out of its own logs (except under the Debug policy, below);
  administrators, process-creation logs and the deployment tool still see
  the command line, and log collection (feature 3) is planned to redact
  `TOKEN=`.
* **The environment.** Only the same user and root can read a process's
  environment. Offered on Linux, with its limits stated in the guide:
  * typed as `export EASYRMM_TOKEN='…'`, as today's install command does
    (`linuxInstallCommand` in
    [`AddDevicesPage.tsx`](../../../web/src/pages/devices/AddDevicesPage.tsx)),
    the token lands in shell history, so the packages' commands read it
    with `read -rs` instead;
  * `sudo --preserve-env` passes it to the package manager, and from there
    every maintainer script and every apt or dnf hook in the transaction,
    and whatever they start, inherits it;
  * a sudoers rule that allows only some commands refuses
    `--preserve-env` unless it carries `SETENV`;
  * sudo-rs, which Ubuntu 26.04 runs as `sudo`, is untested.
* **A file**, readable by root (SYSTEM and Administrators on Windows)
  only, in a folder no one else can create first, deleted once used. It is
  protected like the device key it is exchanged for, which is the
  stronger credential, and it is what configuration management,
  cloud-init and Group Policy Preferences deliver. Offered everywhere.
* **A registry value**, as EasyPatch's MSI keeps its token in a key only
  SYSTEM and Administrators can reach. As safe as the file, but not chosen:
  Group Policy, images and Linux need the file anyway, and one input with
  one check is less to get wrong.
* **Hidden custom action data**, as the feature plan proposed. Rejected:
  the custom actions are the agent's own executable (below), which
  receives only a command line; reading custom action data needs a DLL
  or script action that would hand the token on to it, and Group Policy
  needs the file anyway.
* **A transform (MST) per token for Group Policy**, as the feature plan
  proposed. Rejected: the server would need a writer for Windows
  Installer's compound files and transforms, built for this alone; a
  transform in a share is as readable as a file in it; and Group Policy
  Preferences deliver the same file every other path uses.
* **A file beside the MSI.** Rejected: one planted in a downloads folder
  would point the computer at someone else's server.
* **debconf.** Rejected: it keeps answers in its database.

Whatever the path, a token given to a deployment tool must be an approval
token, or a site token limited in uses (every token expires). The console
shows the deployment tools' steps only for those ([In the
console](#in-the-console)).

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

### Old packages and new devices
* **Until a device has run the server's build once, the rollout mode does
  not hold it back** (chosen, owner question 2). A package kept for months
  in Intune, a mirrored repository or a golden image installs the agent
  of its release; the install command installs the server's build, so a
  new device from a package should end up the same.
* **A minimum agent version at enrollment.** Rejected: an old MSI in
  Intune would then fail on every computer, and roll back.
* **Nothing.** Rejected: with the rollout at *When asked* or *Off*, new
  devices would stay on an old agent nobody chose.

## Decision

### The server owns updates; the package owns its copy
* **A package carries its own copy of the agent** and never owns the
  agent's files. At every install or upgrade (DEB `postinst configure`,
  RPM `%post`, the MSI's first custom action) it runs `easyrmm-agent
  install --package <deb|rpm|msi>`. Where no agent is installed, that does
  what `install` does today: enrolls, copies the agent to its place and
  creates the service. Where one is installed, by the command or by an
  earlier package, it records which package now holds it and changes
  nothing else. Running it every time is what makes a reinstall after
  `apt remove` work: the package is then in dpkg's `config-files` state,
  and its `postinst` sees `configure` with the old version, as for an
  upgrade.
* **Later package upgrades replace the package's copy only.** They never
  touch the running agent, its service or its enrollment, never move it to
  another server, and cannot get round the rollout or *Only signed builds*.
  An MSP that mirrors the packages in its own repository, pushes a newer
  one from Intune, or lets the patching engine approve it, changes nothing
  that runs.
* **`install --package` never replaces an installed agent**, and records
  whether it installed the agent or adopted one already there, so that a
  rolled-back MSI undoes only what it did (`uninstall --package msi
  --rollback`, below).
* **The package's copy hands over, to an agent that says it can.** The
  copy knows itself by its resolved path
  (`/usr/libexec/easyrmm-agent/easyrmm-agent`,
  `%ProgramFiles%\EasyRMM\Package\easyrmm-agent.exe`). Asked to do anything
  on a computer where the agent is installed, it first runs `easyrmm-agent
  capabilities` from the agent's place, for 10 seconds at most. If the
  answer lists `package`, it runs the installed agent with the same
  arguments, so the code that runs the computer does the work, also after
  the server has updated it past the package. Otherwise (an agent from
  before this feature, which answers "unknown command", or one that does
  not start) the package's copy does the work itself. Which is newer does
  not matter: the server moves agents down as well as up, and *When asked*
  or *Off* leaves them where they are.
* **Paths are compared resolved.** A link at the agent's place pointing
  at the package's copy is no installed agent: the copy never hands over
  to itself, and `install` replaces such a link with the agent's own file.
* **The package's copy never runs as the agent.** `run` and `enroll` from
  it hand over, or, where no agent is installed, refuse and say that
  packages are not for containers without systemd. So the agent's
  self-update, which replaces the file it runs from, never rewrites a file
  the package owns.
* **Versions.** `dpkg -l`, `rpm -q` and Programs and Features show the
  package's version, not the agent's after it has updated itself; the
  console shows the agent's.
* **The device records how its agent was installed**: the heartbeat's
  facts carry `installer` (`deb`, `rpm`, `msi`, or none for the command),
  stored with the device and shown on its page.

### The enrollment file
* **Where.** `/etc/easyrmm-agent/install.conf` on Linux, in a folder the
  package ships (`/etc` is root's alone). On Windows
  `%ProgramFiles%\EasyRMM\Package\Enrollment\install.conf`, in a folder the
  MSI makes with an access list of its own (below). Not the agent's state
  folder under ProgramData: there a user can create the folder, the file
  or a hard link before the MSI writes, and Windows Installer's INI writer
  keeps an existing file's owner and access list; the agent's own
  protection of that folder comes later, once the token is on disk. Under
  Program Files users may read but create nothing.
* **One INI format for both**, because Windows Installer writes INI files
  without a custom action:

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
* **Only a file an administrator made, and only administrators can read,
  is read.** The file is opened first and checked on the open file, so
  that it cannot be swapped between the check and the read:
  * *Linux*: opened with `O_NOFOLLOW` and checked with `fstat`: a regular
    file with one link, owned by root, with no permission for group or
    others (an access list granting anyone else shows in the group bits);
    `/etc/easyrmm-agent` and `/etc` owned by root and writable by no one
    else.
  * *Windows*: opened without following reparse points and checked on the
    handle: a file, not a reparse point, with one link; owned by SYSTEM,
    Administrators or TrustedInstaller; an access list that grants nothing
    to anyone but SYSTEM and Administrators (a null access list, or an
    entry for `Users` inherited from Program Files, refuses it); every
    folder from `%ProgramFiles%\EasyRMM` down a plain folder with such an
    owner, in which no one else may create or change files.
  * The file is read once it has been unchanged for 5 seconds, so a file
    still being written, or not yet given its mode, is not taken.
  * Anything else is refused and left unread, and the agent says why in
    its log and in `easyrmm-agent status`; for a file others could read,
    it says to revoke the token. cloud-init's `write_files` makes files
    0644 unless told otherwise, and `tee` followed by `chmod` passes
    through 0644, so the guide's cloud-init, Ansible and shell snippets set
    mode 0600 from the start (`permissions: '0600'`, `mode: '0600'`,
    `install -m 0600`).
* **Deleted once used.** Once the agent has enrolled, or saved its request
  for approval, it deletes the file: the token then lives only where it
  lives today (`pending.json` while waiting for approval) or nowhere. An
  enrolled agent looks for the file when it starts and with each
  heartbeat: a file naming its own server, or holding no token (as a
  repair or an upgrade may leave), is deleted without a word; one naming
  another server is deleted and reported in its log and `status`.
  `uninstall` deletes it too.
* **Without input the agent waits.** `install --package` without input
  installs the agent and its service, which looks for the file every 30
  seconds and enrolls when it appears. `easyrmm-agent status` says it
  waits and where the file goes. This is the golden image: the device key
  and MeshAgent's identity are made at enrollment, so clones of an image
  captured before it do not share them. Input from the environment that
  cannot be used at once is written to the file for the service.
* **Errors.** An answer that may change is retried with the approval
  wait's backoff, 5 seconds to 5 minutes: no answer, a server error, a
  rate limit, or a certificate outside its validity period (Go's x509
  `Expired`, which covers not yet valid), as on a clone, a board without a
  real-time clock before its clock is set, or a server certificate just
  renewed, seen from a clock slightly behind. The agent's unit gains
  `After=time-sync.target` (`UnitContent` in `service.go`) for the same
  reason. An answer that will not change
  (`token_invalid`, `enrollment_rejected`, `key_in_use`, an address that
  is not HTTPS, a certificate from an unknown authority or for another
  name) is retried only when the file changes: its content, size, owner,
  mode or access list, or its modification or change time, so a `chmod`
  alone counts. `install --package` then exits with an error: the MSI
  fails and rolls back; the DEB's and RPM's scripts print it and finish,
  leaving the service waiting for a corrected file, because a failed
  `postinst` leaves the package half-configured and apt then tries, and
  fails, to configure it on every later run, the patching engine's
  included.

### Where there is no running systemd
`install --package` looks at what the computer has:

* **systemd running** (`/run/systemd/system`): the unit is written,
  enabled and started, unless Debian's `policy-rc.d` forbids starting
  services (it answers 101, as during image builds): then it is enabled
  only. `systemctl enable --now` does not ask `policy-rc.d`, so the agent
  does.
* **systemd installed but not running**: an image built offline
  (`virt-customize`, a chroot, `dnf --installroot`, mkosi). The agent is
  copied to its place, its unit written and enabled with `systemctl
  enable`, which works offline, and nothing is started or enrolled. At
  the image's first boot the service starts and waits for the file, or
  uses one the build left; each clone then enrolls with its own key.
  Input given during the build is written to the file, so the token is in
  the image: the guide says to use an approval token there.
* **No systemd**: a container. The package's files are unpacked, but no
  agent is installed: packages are not for containers without systemd.
  The script says so and points at the container guide, which runs the
  agent's own executable.

### DEB and RPM
The package `easyrmm-agent`, for `amd64` and `arm64` (`x86_64` and
`aarch64`):

| Path | Mode | What |
|---|---|---|
| `/usr/libexec/easyrmm-agent/easyrmm-agent` | 0755 root | The package's copy: the release's build, byte for byte |
| `/usr/sbin/easyrmm-agent` | link | To the copy, which hands over to the installed agent. On Rocky Linux and AlmaLinux, `sudo`'s `secure_path` leaves out `/usr/local/bin` |
| `/etc/easyrmm-agent/` | 0700 root | Where `install.conf` goes; the package ships no file in it, so no configuration file prompts on upgrade |
| `/usr/share/doc/easyrmm-agent/` | | The licence (FSL-1.1-ALv2); `%license` in the RPM |

* **Scripts.** Every DEB `postinst configure` and every RPM `%post` runs
  `easyrmm-agent install --package`, which installs the agent the first
  time and records the package on later runs. A removal (`prerm remove`;
  `%preun` with `$1` = 0) runs `easyrmm-agent uninstall --package`. A
  purge removes `/etc/easyrmm-agent`. Every script exits 0 whatever the
  agent says, and shows what it says: a failed `postinst` leaves the
  package half-configured, and a failed `prerm` blocks the removal. When
  the removal left the agent in place, the script says so and names the
  command that finishes it, `/usr/local/bin/easyrmm-agent uninstall`,
  which works once the package is gone ([Uninstalled](#uninstalled)).
* **The agent's files stay the agent's**, exactly as for every Linux
  agent: `/usr/local/bin/easyrmm-agent`, its unit in
  `/etc/systemd/system/`, `/var/lib/easyrmm-agent/` and MeshAgent's
  files, written by `install` and removed by `uninstall`. Debian Policy
  §9.1.2 forbids a package to place files in `/usr/local`, whether in its
  archive or from its maintainer scripts, and Fedora's packaging
  guidelines keep packages out of it too. This package ships nothing
  there, but its scripts run the program that writes there: a deliberate
  departure from both, which lintian and rpmlint cannot see. One layout
  means one update, uninstall and removal path for every Linux agent, and
  a computer can move between the command and the package without a
  second agent. Moving every Linux agent elsewhere would be its own
  change, with a migration of installed units.
* **Built** in a pinned container with networking off, as EasyPatch's:
  DEB with `dpkg-deb`, xz and `--root-owner-group`; RPM with `rpmbuild`, a
  gzip payload and SHA-256 file digests, readable by Enterprise Linux 8's
  rpm 4.14. Not nfpm, which ADR-0008 named: the repository keeps one way
  to build packages. No dependencies: the agent is a static Go program.
* **RPMs are signed; DEBs are not.** Each RPM gets an OpenPGP signature at
  release, made with `rpmsign` from the builder's pinned rpm, with a key
  of EasyRMM's releases: RSA, which Enterprise Linux 8's rpm 4.14 checks
  as well as Fedora's. Its private key is a secret of a protected GitHub
  environment, `release`, that admits only release tags, as
  `easypatch-release` holds EasyPatch's release key today
  ([`release.yml`](../../../.github/workflows/release.yml)); pull requests
  never reach it. Its public key, `RPM-GPG-KEY-easyrmm`, is published in
  the repository, with each release and by the server beside the
  packages, its fingerprint in CODE_SIGNING.md and the guide; the
  console's RPM steps import it first. Creating that key is the first
  owner question. DEBs stay unsigned: dpkg checks no signature on a
  package file.
* **Versions**: `1.2.3`, and `1.2.3~rc.1` for a release candidate, in
  both formats (the tilde sorts the candidate first); RPM release 1.
* **Distributions.** Supported where the machine tests run: Debian 12
  and 13, Ubuntu 22.04 and 24.04, Rocky Linux 8 and 9, AlmaLinux 9, and
  Fedora 45. ADR-0051's other releases (Ubuntu 26.04, AlmaLinux 8, Rocky
  Linux and AlmaLinux 10) and anything else with dpkg, or rpm 4.14 and
  later, and systemd install, unsupported until tested. Linux `arm` and
  `386` keep the install command only.

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
  none. `ARPNOREPAIR` and `ARPNOMODIFY` hide repair and change in Programs
  and Features; they do not stop a repair (`msiexec /f`, Intune's,
  Configuration Manager's), which the INI component below makes harmless.
  Launch conditions: an administrator; Windows 10 or Server 2016 and
  later; and the processor the MSI is for, so that the x64 MSI does not
  put an emulated agent on ARM64 Windows.
* **Files**: `%ProgramFiles%\EasyRMM\Package\easyrmm-agent.exe`, the
  release's build byte for byte, and the folder `Enrollment` beside it.
  The service is the agent's, created by `install` with its recovery
  settings as today; the MSI's service tables are not used, because the
  service runs the agent's own copy, which the MSI must not own.
* **The enrollment folder**, `%ProgramFiles%\EasyRMM\Package\Enrollment\`,
  is created by the MSI with `PermissionEx` (Windows Installer's
  `MsiLockPermissionsEx` table, no extension) and the descriptor
  `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, which EasyPatch's MSI
  gives its data folder: owned by Administrators, full control for SYSTEM
  and Administrators only, nothing inherited. No user can create the
  folder, a file in it or a link to one beforehand, so the file the MSI
  writes there is new and inherits only SYSTEM and Administrators.
* **Properties**: `SERVERURL` (HTTPS), `TOKEN` and `CACERT` (base64 DER),
  all secure; `TOKEN` hidden; `SERVERURL` and `TOKEN` together or not at
  all. When given, the MSI writes them to `install.conf` through its INI
  table, in a component of its own that is transitive and conditioned on
  `SERVERURL AND TOKEN`. A repair or an upgrade without them therefore
  writes nothing: nothing saves the properties, so without that condition
  a repair would write `server=` and `token=` empty. One with them, as an
  upgrade pushed with the first install's command line, writes a file the
  enrolled agent deletes without a word (above). The progress template of
  `WriteIniValues` leaves the value out, as EasyPatch's MSI does for its
  registry step.
* **Where the token goes.** The MSI writes it to no registry value and to
  no custom action's command line, and keeps it out of its log, except
  where the Windows Installer *Debug* policy is 7: then Windows Installer
  logs hidden properties too, as Microsoft documents for
  `MsiHiddenProperties`, and the guide says so. The deployment tool may
  keep the command line: Intune does, in its logs on the device; what
  else it keeps is checked on a real device.
* **Three custom actions**, each running the package's copy with fixed
  arguments, deferred, as LocalSystem; no script, no DLL, no WiX extension
  action:
  1. `install --package msi`, after `WriteIniValues`, on a first install
     and on each major upgrade's new product (`NOT Installed`), never on a
     repair; its failure fails the install.
  2. Its rollback, `uninstall --package msi --rollback`, sequenced before
     it. It undoes only what the first action recorded: an agent it
     installed is uninstalled; an agent it adopted keeps running, and the
     record of its installer is put back as it was.
  3. `uninstall --package msi` on removal (`REMOVE~="ALL" AND NOT
     UPGRADINGPRODUCTCODE`), not during an upgrade's removal of the
     version it replaces; its failure never stops the removal.

  The agent's code is needed to enroll and to report, so custom actions
  cannot be avoided; these are the agent itself.
* **The build checks**, in the Windows build path: `TOKEN` in
  `MsiHiddenProperties`, the `WriteIniValues` template without the value,
  and the platform. EasyPatch's MSIs get the same checks in that path
  (being fixed separately, above), so both MSIs are checked where releases
  are built.
* **Deploying it**:
  * *Intune*: as a line-of-business app with the properties, or a Win32
    app. Detection by the MSI's product code, or, where it must show that
    the agent runs, by the `EasyRMMAgent` service; never by the agent's
    version, which the server moves, down as well as up.
  * *Group Policy*: the MSI assigned to computers, without properties, and
    `install.conf` delivered by Group Policy Preferences (*Files*) to
    `%ProgramFiles%\EasyRMM\Package\Enrollment\`, from a share only Domain
    Computers can read, not SYSVOL, with item-level targeting: the MSI's
    `easyrmm-agent.exe` present, and the agent neither enrolled nor
    waiting (no `agent.json` and no `pending.json` in
    `%ProgramData%\EasyRMM\Agent\`). Not *Apply once*: the item delivers
    again at each refresh until the agent has used it. The targeting on
    the MSI's file keeps the order: Group Policy Preferences create a
    missing folder with the access it inherits from Program Files, where
    `Users` may read, and the agent would refuse that file.
  * *Another RMM, Configuration Manager, a script*: `msiexec /i … /qn
    SERVERURL=… TOKEN=…`.

### Signing
* **RPMs carry the release's OpenPGP signature; DEBs carry none** (above).
  Both also rest on the server's HTTPS, on `SHA256SUMS` and on the
  release's attestation (`gh attestation verify`). CODE_SIGNING.md says
  so.
* **Release MSIs carry no Authenticode signature**: there is no project
  certificate, and signing through a vendor is on hold.
* **Operators sign the MSI, as they sign the agent (ADR-0049).** A
  PowerShell script, published with each release and on **Settings →
  Agent updates**, puts the operator's signed build into the MSI in place
  of the release's. It replaces the embedded cabinet with one holding the
  signed build, made with `makecab`, and through the Windows Installer
  API, both part of Windows, updates the file's size and hash in the
  MSI's tables and gives the MSI a new product code and package code,
  keeping the upgrade code. So it installs over the release's MSI of the
  same version as a major upgrade, and the release's over it, instead of
  running a repair or failing with error 1638 (another version of this
  product is already installed).
* **It takes only the release's build plus a signature**, as ADR-0049's
  server does: the Authenticode digest of the signed build must equal that
  of the build in the release's MSI. The script computes both with a PE
  reader of its own, following the rules of
  [`authenticode`](../../../server/internal/agents/authenticode/authenticode.go)
  and tested against the same signed files. It refuses a build without an
  Authenticode signature or for another architecture. The guide takes the
  signed build from **Settings → Agent updates**, where the server has
  checked it already. The operator then signs the MSI with their own tools
  (`signtool`, `jsign`, `osslsigncode`) and deploys it with their own
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
* **With *Only signed builds*** the server withholds the release's MSIs
  from `/api/agent/v1/download/` and `SHA256SUMS`, as `Builds.List`
  withholds the release's builds that have no signed counterpart
  ([`builds.go`](../../../server/internal/agents/builds.go)): WDAC and
  AppLocker would block their agent. **Settings → Agent updates** keeps
  them for the operator's script, and **Add devices** links to it.

### Built once, at release; served by the server
* **One build.** A release job builds each agent binary once; the image,
  the release files and the packages all take those files, and checks
  compare the SHA-256 of each across all of them (the agent inside each
  package included, as EasyPatch's builder checks its own). A build of the
  image from source still compiles its agents.
* **A reusable workflow builds the packages** for pull requests and `main`
  as well as for releases, without publishing, so that release steps are
  tested before a release; CI's images carry those packages. Those builds
  are unsigned and need no secret. Only the release job, in the `release`
  environment, signs the RPMs, and checks each with `rpm -K` against the
  published key; the machine tests sign theirs with a key made for the
  run.
* **Published** with the release, in `SHA256SUMS`, attested and listed in
  the manifest: `easyrmm-agent_1.2.3_amd64.deb`,
  `easyrmm-agent-1.2.3-1.x86_64.rpm`, `easyrmm-agent-1.2.3-x64.msi`, their
  ARM64 versions, and `RPM-GPG-KEY-easyrmm`.
* **Served by the server.** The image carries the packages of its own
  version and the key beside the agents, root-owned and read-only, as the
  engine's image carries its agents' packages (ADR-0041). The server
  serves them at `/api/agent/v1/download/<file>`, lists them in
  `SHA256SUMS`, which the install scripts read by file name, and on **Add
  devices** (`/api/v1/agent-downloads`,
  [`enrollapi.go`](../../../server/internal/httpapi/enrollapi/enrollapi.go)).
  So a computer gets the server's own version, from the server it already
  has to reach. A server built from source without packages offers none.

### New devices start on the server's build
* **Until a device has run the server's build once, the rollout mode does
  not hold it back.** A device enrolled from an older package, whose agent
  is not the server's build, is updated at its first heartbeat whether the
  mode is *Automatically*, *When asked* or *Off*, within **Devices at
  once**; from then on the mode holds it as before. This amends ADR-0027
  (owner question 2).
* **A release candidate's MSI can replace its final release's.** The MSI
  version has no room for `-rc`, and same-version upgrades must be allowed
  for the final release to replace its candidate, so the reverse is
  allowed too. It changes only the package's copy, never the running
  agent; the guide says not to deploy candidates' MSIs through a
  deployment tool.

### MeshAgent
No package contains or owns MeshAgent. After enrollment the agent fetches
it from the server, signed, and runs it as its own service, as today
(ADR-0015); `uninstall` removes it; package upgrades never touch it;
MeshCentral keeps updating it.

### Uninstalled
* **Removing a package removes the agent**: its script runs `uninstall
  --package`, which stops and removes the service and MeshAgent, tells the
  server, and deletes the agent's state, its executable and
  `install.conf`. `easyrmm-agent uninstall` reports the same way, whatever
  installed the agent.
* **The report and what the server does are ADR-0053's**:
  `POST /api/agent/v1/uninstalled`, signed with the device key, best
  effort within 10 seconds, never failing the removal. The server marks
  the device *Uninstalled* and opens a critical notice, *agent removed
  without a request*, because a device key alone must not be able to
  silence a device; and a `/removed` report with no removal pending marks
  the device the same way instead of deleting it (ADR-0053 amending
  ADR-0050). This ADR adds the installer to the report, so that the notice
  says how the agent went (with the DEB, the RPM, the MSI, or by hand).
  Whichever of the two features is built first builds it, as ADR-0053
  designs it.
* **By hand, while a package holds the agent.** `easyrmm-agent uninstall`
  names the package manager's command and stops only while the package
  manager lists the package: `dpkg-query` showing it installed, `rpm -q`,
  or `MsiQueryProductState` for a product of the MSI's upgrade code. Once
  the package is gone, for example after a removal that could not remove
  the agent (the scripts and the MSI's third action never fail a
  removal), it uninstalls.

### Removal from the console
For an agent a package installed, the uninstaller ADR-0050 starts (a
transient unit, or a detached process on Windows) checks the instruction,
keeps the device key and the instruction in memory, and removes the
package:

* `apt-get purge` with a 30-minute lock timeout; not `remove`, which
  leaves the package in `config-files` state;
* `rpm -e`, started only when rpm's transaction lock (`%_rpmlock_path`)
  is free, tested without waiting every minute for 30 minutes, since rpm
  itself waits on that lock without limit;
* `msiexec /x` with the product found by its upgrade code, tried again
  every minute for 30 minutes while another installation runs.

The package's script runs `uninstall --package`, which finds the saved
instruction and so removes the agent without reporting *Uninstalled*; the
uninstaller then reports the removal with the key it kept. The scripts
always succeed, so the uninstaller judges by what is left, not by exit
codes: the agent's service gone means removed; still there, it reports
the failure, starts the service again, and the device stays, as ADR-0050
does when a service cannot be removed. If the package is gone already, it
uninstalls as for an agent the command installed. The removal dialog
warns that Intune, Group Policy or configuration management may install
the agent again.

### In the console
**Add devices** gains packages beside the install commands, rendered in
the browser from the token, as the commands are
([`AddDevicesPage.tsx`](../../../web/src/pages/devices/AddDevicesPage.tsx)).
Nothing new reaches the server: the token is the one already shown, or
shown again (ADR-0047).

* **For every token**: the MSI and its `msiexec` line (with `CACERT` for
  an address on the server's own authority); the DEB and RPM (the RPM key
  imported first, with its fingerprint), installed with the token read at
  a prompt, so that it is on no command line and in no shell history:

  ```sh
  read -rs EASYRMM_TOKEN    # paste the token; nothing is shown
  export EASYRMM_TOKEN EASYRMM_SERVER=https://rmm.example.com
  sudo --preserve-env=EASYRMM_SERVER,EASYRMM_TOKEN apt install ./easyrmm-agent_1.2.3_amd64.deb
  unset EASYRMM_TOKEN
  ```

  (or `dnf install`), in bash or zsh.
* **Only for an approval token, or a site token with a use limit** (every
  token has an expiry already): the steps for Intune and Group Policy, and
  `install.conf` to download. For any other token the page shows instead
  a link to creating one: those tools copy what they deploy into shares,
  Intune, downloads folders and backups.

## Departures from the plan
Feature 6 in [the feature plan](../feature-plan.md#6-packages-for-the-agent-deb-rpm-msi)
said what this ADR had to decide. Where it decides otherwise:

* **The MSI's token is stored until it is used.** The plan had it travel
  as hidden custom action data, never stored. Here the MSI writes it to
  `install.conf` in a folder only SYSTEM and Administrators can reach, and
  the agent deletes it once used, as it keeps `pending.json` meanwhile.
  The custom actions are the agent's executable, which receives only a
  command line, and Group Policy needs the file anyway.
* **Group Policy delivers a file, not a transform per token**, with
  Group Policy Preferences and item-level targeting.
* **Without input the agent waits for the file**, not for
  `easyrmm-agent enroll`; `easyrmm-agent install` with a token, by hand,
  still works through the hand-over.
* **Intune detects the package, not the agent's version**, which the
  server moves down as well as up (ADR-0027, ADR-0049).
* **Removal from the console runs `apt-get purge`**, not `dpkg -r`, and
  starts `rpm -e` only once rpm's lock is free. *Uninstalled* opens
  ADR-0053's critical notice; the plan had only the state.
* **Signing.** The plan left a signed MSI for later, through an MSI
  reader on the server. Here it is the last slice, and the operator's
  script does it on Windows, where the server reads no MSI. RPMs are
  signed, which Fedora 45 now requires; the plan left DEB and RPM to the
  attestation and checksums.
* **New devices start on the server's build** whatever the rollout mode,
  which the plan did not address (owner question 2).
* **Packages are not for containers without systemd**, and images built
  offline get an enabled service that is not started; the plan did not
  address either.
* **Order**: the enrollment file, the installer record and the one build
  come before the DEB, and the operator's signed MSI after the MSI.
* **Tests**: DEB and RPM on whole machines with the machine harness, not
  in systemd containers, which remain for arm64 until the harness boots
  arm64 images.

## Testing
* **Unit**:
  * the file's parsing, and its checks: on Linux `O_NOFOLLOW`, a regular
    file, one link, the owner, the mode and the directories; on Windows,
    on CI's Windows runner, reparse points, one link, the owner, the
    access list (an inherited `Users` entry, a null list) and the folders;
  * what counts as a change (a `chmod` alone), and the 5-second wait;
  * the environment's precedence;
  * waiting; errors that pass and final ones: a certificate outside its
    validity retried, one from an unknown authority or for another name
    final until the file changes;
  * `install --package` never replacing an installed agent, recording
    install or adopt; `--rollback` undoing only what was recorded;
  * the hand-over: to an agent listing `package`; not to one answering
    "unknown command" or not starting; never to itself through a link;
    `run` and `enroll` refused from the package's copy with no agent;
  * systemd running, installed but not running, absent; `policy-rc.d`
    answering 101; the unit's `After=time-sync.target`;
  * `uninstall --package` with and without a saved instruction;
    `uninstall` by hand refusing only while the package is listed (the
    package managers' queries replaced in tests); the report's time limit;
  * each format's version.

  Coverage floors for the new packages.
* **PostgreSQL integration and HTTP API**: the installer recorded, and
  carried in the report; a new device updated at its first heartbeat with
  the rollout *Off*, then held by it; the packages and the RPM key in the
  downloads and in `SHA256SUMS`; the release's MSIs withheld from both
  under *Only signed builds* and still on **Settings → Agent updates**. The
  *Uninstalled* state and its notice are ADR-0053's tests; here, a
  `/removed` report for a packaged device with no removal pending marks it
  *Uninstalled* and opens the notice instead of deleting it.
* **Console**: the packages' commands for each address, with the
  certificate authority where it applies and no token on a command line;
  the Intune and Group Policy steps and `install.conf` only for an
  approval token or a site token with a use limit, and the link otherwise;
  the device's installer; the removal dialog's warning.
* **Builds**: each package holds the release's agent byte for byte;
  lintian and rpmlint, with any finding accepted listed with its reason;
  `shellcheck` on the scripts; ICE; at release, each RPM's signature
  checked with `rpm -K` against the published key; in the Windows build
  path, for this MSI and EasyPatch's, the hidden property, the progress
  template and the platform.
* **Whole machines** for DEB and RPM, with the harness of ADR-0051's first
  slice (`internal/vmtest` and `docs/development/machine-tests.md`, on
  that slice's branch, not on `main` yet): distributions' cloud images
  under QEMU with KVM and user networking, never a bridge, one job per
  image. Debian 12 and 13 and Ubuntu 22.04 and 24.04 for the DEB; Rocky
  Linux 8 and 9, AlmaLinux 9 and Fedora 45 for the RPM, with SELinux
  enforcing as the images boot; Ubuntu 26.04, AlmaLinux 8 and the 10
  releases when the harness gains them, unsupported until then. The
  deployment runs on the host with host networking, as the bundle test
  brings it up, and the machine reaches it at QEMU's address for the
  host. On each:
  1. install with `install.conf`: enrolled, MeshAgent connected, the file
     gone, files and modes as above, and `dpkg -S` or `rpm -qf` showing
     that the package owns only its own;
  2. install with the environment, the token read with `read -rs`,
     through `sudo --preserve-env` and apt or dnf;
  3. install without input: it waits; the file written as the guide's
     cloud-init `write_files` writes it (mode 0600): it enrolls; and once
     more written with `tee`, then `chmod 0600`: refused at 0644, taken
     after the `chmod`;
  4. a file others can read, one not owned by root, a symbolic link and a
     second hard link: each refused, with the reason;
  5. a refused token: the package installs and says why; a corrected file
     enrolls;
  6. an approval token: it waits, is approved through the API, enrolls;
  7. the agent updated by the server, then a newer package. Three builds
     are made from the commit under test by the reusable workflow, with
     three versions in `-X main.Version` (`0.0.0-test.1`, `.2`, `.3`), so
     that their SHA-256s differ, and packaged. The package of `.1` is
     installed; the deployment, started with `.2` as its agents, updates
     the agent to it; the package of `.3` is installed over the first: the
     running agent still has `.2`'s SHA-256, the package's copy `.3`'s;
     after a restart the agent comes back on `.2`. On the RPM images,
     before and after the update: no SELinux denials (`ausearch -m AVC`),
     the agent's and MeshAgent's processes in the domains expected
     (`ps -eZ`), and `restorecon -nRv` over the agent's and the package's
     paths printing nothing;
  8. the package over an agent the install command installed: the same
     device and executable, the installer recorded;
  9. the package over an agent from before this feature (the last
     release's, from its GitHub release), and over an older one with it
     (`.1` under the package of `.3`): adopted, nothing replaced; then
     removed with apt or dnf: the first removed by the package's copy, the
     second through the hand-over;
  10. removal with apt or dnf: services, MeshAgent, the agent's files and
      `install.conf` gone, the device *Uninstalled* with ADR-0053's
      critical notice naming the package; a purge;
  11. after `apt remove`, the package installed again with a new
      `install.conf`: it enrolls;
  12. removal while the agent's own removal fails (a file in its state
      folder made immutable with `chattr +i`): the package is removed, the
      script says what is left and names the command; with the file freed,
      that command finishes, since the package is no longer listed;
  13. removal from the console: the package gone (not left as `rc`), the
      device deleted; again while another process holds the package
      manager's lock, which it waits for; and once more with the removal
      canceled in the console while it waits: the device marked
      *Uninstalled* with the notice, not deleted;
  14. an image built offline: the package installed into a copy of the
      image with `virt-customize`: nothing started or enrolled during the
      build; booted, the service runs and waits; `install.conf` dropped
      in; it enrolls. On Debian 13 also, with systemd running, a
      `policy-rc.d` answering 101: the service enabled, not started;
  15. on Fedora 45: `rpm -i` of the unsigned package refused; the signed
      package, its key imported, installs with `rpm -i` and, removed
      again, with `dnf install ./…`; on the other RPM images, `rpm -K`
      verifies it.
* **arm64**: the same install, enrollment, upgrade and removal in systemd
  containers on GitHub's `ubuntu-24.04-arm` runner, with host networking,
  for Debian 13 and Rocky Linux 9, until the harness boots arm64 images.
* **The bundle test** enrolls one Linux agent from the DEB with
  `install.conf` as Add devices gives it; the EasyPatch agent is then
  installed and patches as today; `apt remove` leaves the device
  *Uninstalled*, with the notice.
* **Windows**, on CI's `windows-2025` runner for x64 and GitHub's
  `windows-11-arm` runner for ARM64 (marked unverified if that runner is
  not available to the repository). These need no server, since an address
  nothing answers (a closed port on the runner itself) only makes the
  agent wait, and run in slice 6:
  1. ICE and the build checks;
  2. silent installs with properties (they install and wait), with the
     file, and without input (it waits);
  3. the verbose log (`/l*v`), the registry and both folders free of the
     token; then with the *Debug* policy at 7: the token in the log, as
     the guide warns;
  4. a standard user made for the run creates `%ProgramData%\EasyRMM\Agent\`,
     an `install.conf` in it and a hard link to that file, and tries to
     create `%ProgramFiles%\EasyRMM\Package\Enrollment\`, which Windows
     refuses; the MSI runs with `TOKEN`: that user can read the token
     nowhere, and the agent never reads their file;
  5. a repair (`msiexec /fa`) and an upgrade without properties while the
     agent waits: `install.conf` unchanged; an upgrade with the same
     properties: the same values written again;
  6. rollback: a build of the MSI made only for this test, with a
     deferred action after the first that always fails, on a computer
     without the agent (nothing left) and over an installed agent (still
     installed and running, its installer record unchanged); and an
     address whose certificate does not verify (a listener with a
     certificate made for the run), whose error is final: the install
     fails and rolls back, leaving nothing;
  7. `msiexec /x`: the service, MeshAgent's folder, the agent's files and
     `install.conf` gone;
  8. the operator's script with a certificate made for the run and
     `signtool`, as ADR-0049's test does: the MSI's signature verifies;
     the release's MSI installed, then the operator's over it: one product
     listed, the package's copy the signed build, the agent untouched; the
     script refuses an unsigned build and a signed build of another build.

  With a server, against the feature plan's Windows end-to-end harness,
  and marked unverified until it exists: enrollment through each path;
  `msiexec /fa`, and an upgrade with the first install's command line,
  after enrollment: still enrolled as the same device, `install.conf`
  deleted; `msiexec /x` reporting *Uninstalled*; removal from the console.
* **Then the owner's real computers**: Windows through Intune, recording
  where Intune keeps the command line, and through Group Policy with
  item-level targeting; Ubuntu and Rocky Linux.

## Slices
Each merges on its own, with its documentation (the
[agents guide](../../deployment/agents.md), CODE_SIGNING.md,
IMPLEMENTATION_STATUS, ROADMAP, CHANGELOG, database.md for migrations).

1. **The enrollment file and an agent that waits**: `install.conf` and
   the environment, the checks on both platforms, deletion, waiting, the
   errors and the unit's ordering, `install --package` with its record and
   `--rollback`, systemd running, offline or absent, `capabilities` and
   the hand-over, `uninstall` by hand. Verified by unit tests on Linux and
   Windows and by the bundle test, whose machine runs the agent as a
   package's script will (`install --package`, before any package exists)
   without input: it waits, and enrolls when the file appears.
2. **The installer recorded, and new devices on the server's build**: the
   fact, its field in the report, the first update outside the rollout
   mode. *Uninstalled* comes from ADR-0053's slice, which the plan's order
   puts first; if it has not landed, this slice builds it as ADR-0053
   designs it. Verified by integration and console tests and by the bundle
   test.
3. **One build**: the release's agents built once, the checks across the
   image, the release files and the bundle. Verified on CI's image job and
   on the next release candidate.
4. **DEB**: the reusable workflow, the package, served by the server and
   released, Add devices, removal from the console through apt. Verified
   on the Debian and Ubuntu machines, the arm64 containers and the bundle
   test.
5. **RPM**: the same through rpm, and its signature at release once the
   owner has decided on the key. Verified on the Rocky Linux, AlmaLinux
   and Fedora machines and the arm64 container.
6. **MSI**: x64 and ARM64, the properties, the enrollment folder, the
   custom actions, the build checks, Add devices with Intune and Group
   Policy, removal through `msiexec`, *Only signed builds* withholding it.
   Verified on the Windows runners, every check above that needs no
   server included.
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
* The agent's files stay in `/usr/local` and `/etc/systemd/system`, and
  the package's scripts run the program that writes there: a departure
  from Debian Policy §9.1.2 and Fedora's guidelines, stated here and in
  the guide.
* The MSI has three custom actions, all the agent itself. An unsigned MSI
  opened from a browser's download gets SmartScreen's warning; deployment
  tools do not show it.
* On Windows the token sits in a file only SYSTEM and Administrators can
  read until the agent has used it; under the *Debug* policy 7 it is also
  in Windows Installer's log, and the deployment tool may keep the command
  line.
* Deployment tools' steps need an approval token or a site token with a
  use limit; a technician with another token is sent to create one.
* Under *Only signed builds*, Windows computers get an MSI only through
  the operator's script and signature.
* The release holds an OpenPGP key for RPMs, if the owner agrees, which
  must be kept, and replaced with a new public key if it is ever lost.
* A new device from an old package updates at once, whatever the rollout
  mode, if the owner agrees.
* Packages are not for containers without systemd.
* The image grows by six packages and a key.
* **Not covered**:
  * apt and dnf repositories, and OpenPGP signatures on the DEBs.
  * An MSI signed by the project: code signing through a vendor is on
    hold.
  * Packages for macOS, and for Linux `arm` and `386`.
  * Images captured after enrollment: they carry the device key and
    MeshAgent's identity, and their clones are not detected.
  * SUSE and other distributions outside ADR-0051's list.
  * A proxy for the agent's connection.

## Owner questions
1. **A release key for RPMs.** Fedora 45 refuses unsigned packages.
   Proposed: an OpenPGP RSA key made for EasyRMM's releases, which signs
   RPMs only; its private key only in the protected `release` environment,
   never available to pull requests; its public key published in the
   repository, with each release and by the server. It costs nothing,
   unlike code signing through a vendor, which stays on hold; but it is a
   long-lived signing key the project must keep, and every computer that
   imports it trusts it for packages. Without it the RPM installs on
   Enterprise Linux but not on Fedora 45 and later, and the RPM slice
   lists Fedora as unsupported.
2. **New devices start on the server's build.** Proposed: until a device
   has run the server's build once, the rollout mode does not hold it
   back, so that an old MSI or package in a deployment tool never leaves
   new computers on an old agent while the rollout is *When asked* or
   *Off*. The alternative keeps ADR-0027 as it is, and such devices show
   as outdated until someone updates them.
