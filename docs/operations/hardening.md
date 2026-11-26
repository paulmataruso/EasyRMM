# Hardening Linux computers

EasyRMM checks how well the Linux computers it manages are hardened, in 14
areas called modules: SSH, the firewall, fail2ban, kernel parameters, audit
rules, file permissions, legacy services, kernel modules, sudo, time
synchronisation, shared memory, USB storage, SELinux or AppArmor, and file
integrity. A **check** changes nothing on the computer: it reports, module
by module, what is in place, what is missing, and what applying the module
would change. The design is in
[ADR-0051](../architecture/adr/0051-hardening-linux-computers.md).

Applying and undoing modules work through the API (ADR-0051's second
part; see [Applying and undoing](#applying-and-undoing)). The console starts
checks only, for now.

## Who can do what

| To | You need, on the device |
|---|---|
| See the findings, on the device's **Hardening** tab and in **Devices** | `device.view` (every role) |
| Run a check | `script.run`: Technicians and above, as for any script |
| Open the job a finding came from | `job.view` as well |
| Read the run's raw output | `job.view_sensitive` as well: Technicians and above ([Who sees output and arguments](scripts-and-jobs.md#who-sees-output-and-arguments)) |
| Apply or undo modules (through the API, for now) | `device.harden`: Site Administrators and above |

See [Roles and permissions](../security/rbac.md).

## Running a check

On a Linux device with the EasyRMM agent, open the **Hardening** tab and
choose **Run check…**:

* **Modules**: the ten recommended ones are chosen. The other four (shared
  memory, USB storage, SELinux or AppArmor, file integrity) are chosen one
  by one; their risk, beside each, is the risk of applying them. Checking
  them is as safe as checking the others.
* **Wait for the device**: how long the job waits for an offline device,
  24 hours unless changed.

**Run check** starts a job, like a script's (see
[Scripts and jobs](scripts-and-jobs.md)): it waits for the device, can be
stopped, and is listed on the **Jobs** page with the modules it checked.
EasyRMM sends its own script, with the modules as arguments; the agent runs
it as root, for at most 30 minutes. The tab says *Checking hardening* and
lists the run under **Checks** until it ends, then shows what it found.

Many devices at once: `POST /api/v1/jobs/hardening` with up to 500 devices,
`"mode": "check"`, the modules, `"options": {}` and `waitHours`. Every
device must be a Linux device with the agent, where you hold `script.run`,
or nothing runs and the reason names the device.

Each device's check is recorded in the audit log as *Hardening job*, with
the mode, the modules and the job.

## Reading the findings

The tab shows each module's latest finding, with how many of the modules
that apply here are in place. Each module has a state:

| State | Means |
|---|---|
| In place | Everything the module checks is in place |
| Partly in place | Some of it is; **Missing** lists the rest |
| Not in place | None of it is |
| Not applicable | The module does not apply to this computer, with the reason: no SSH server, say, or a container, where the kernel, its modules, audit, SELinux or AppArmor, `/dev/shm` and the clock belong to the host |
| Managed elsewhere | Something else manages it, so EasyRMM leaves it alone: a firewall of the computer's own, for example |
| Not supported on this version | EasyRMM has not tested this module with what the computer runs: sudo-rs, for now, which Ubuntu 25.10 and later use. The check reports what it found; nothing will be applied |
| Half applied | An apply or undo was interrupted |
| Failed | The module could not do its work, with the reason |

Under each module, **Missing** lists what is not in place, and **Apply would
change** what applying the module would do on this computer. The firewall
also lists the ports it would leave open, for TCP and UDP; the ports Docker
publishes (*Through Docker*), which reach their containers past the
firewall's rules; and services that are enabled but not running
(*Ports unknown*), whose ports it cannot see, and which the firewall would
cut off when they start.

A module checked by an earlier job than the latest one says so, with a link
to that job. Modules never checked are listed at the end.

**Last check** gives when the latest check ran, its job, the distribution
and release, how far EasyRMM's hardening supports it, and the container the
computer is, if it is one:

| Support | Means |
|---|---|
| Tested | Debian 12 and 13; Ubuntu 22.04, 24.04 and 26.04; Rocky Linux 8, 9 and 10; AlmaLinux 9 and 10; Fedora 45: the releases EasyRMM's machine tests apply and undo every module on |
| Check only | A release in its support that those tests do not cover (AlmaLinux 8; Red Hat Enterprise Linux 8, 9 and 10; Fedora 43 and 44), a newer release, or one out of its standard support (Debian 11, Ubuntu 20.04), which needs upgrading first. Checks report on it; nothing will be applied or undone |
| Not supported | Any other distribution or release. Checks report what they can |

**Checks** lists the device's latest hardening runs, with their status and,
for one that failed, why. **All hardening jobs** opens the **Jobs** page
with the device's hardening jobs.

`GET /api/v1/devices/{id}/hardening` returns the same findings.

## Across the fleet

**Devices** has a **Hardening** column on wide screens when the list has a
Linux device. It shows how many of a device's applicable modules are in
place (*9 of 10 in place*), or *Half applied* or *N failed* when a module
needs a closer look; hovering gives the count in each state. A Linux device
with the agent that was never checked shows *Not checked*.

The **Hardening** filter narrows the list:

| Filter | Lists |
|---|---|
| Needs attention | Devices with a module partly or not in place, half applied or failed |
| In place | Checked devices with none of those |
| Not checked | Linux devices with the agent that were never checked |

The filter is part of the page's address, so a link to `/devices?hardening=attention`
opens the list of devices to look at; the API takes the same parameter on
`GET /api/v1/devices`.

## Applying and undoing

The console starts checks only, for now. Apply and undo run through the
API: `POST /api/v1/jobs/hardening` with `"mode": "apply"` or `"undo"`, the
devices, the modules and `waitHours`, as for a check, and `device.harden` on
every device. Each is a job like a check's, recorded in the audit log as
*Hardening job* with its mode, modules and options. It ends by checking the
modules again, so the tab shows what they are now; each module's latest
finding also carries what the apply or undo did (`outcome`, `done`) and
whether EasyRMM's record of applying it is on the computer (`recorded`).

**Apply** changes only what the check found missing, and only to make it
stricter: a value already stricter than EasyRMM's stays. A second apply
changes nothing. It refuses what would lock you out or stop the computer
from starting, and says why: password sign-in off where no administrator
who may sign in has an SSH key, say, or USB storage off where a mounted filesystem is
on a USB disk, or `/etc/fstab` mounts one at boot without `nofail`. It
leaves alone a firewall the computer already has. A module
that fails part way is put back as it was, but for packages it installed
that cannot be removed (others need them, or the package manager fails):
the result names those and says why. Packages a module needs
(nftables, fail2ban, auditd, AIDE, chrony or systemd-timesyncd) come from
the computer's own repositories, without recommended packages; on Red Hat
Enterprise Linux 10, its rebuilds and Fedora, auditd comes with
audit-rules, which holds `auditctl` and `augenrules`; on Ubuntu
22.04, AIDE comes with mailutils, which its configuration package needs in
place of a mail server. An installation never removes a package: one that
would (a conflict) fails, and the module is put back. AIDE's first
database is built after the job ends, in `easyrmm-aide-init.service`; the
next check says whether it finished. fail2ban bans for an hour, longer for
repeat offenders, up to a day. A file apply changes that is a symbolic link
stays one, and where SELinux labels files, each keeps its label, through
apply and undo.

Apply's options:

| Option | Module | Does |
|---|---|---|
| `allowTcp`, `allowUdp` | firewall | Ports and ranges (`"8080"`, `"9000-9100"`) left open besides those in use |
| `trusted` | fail2ban | Addresses and ranges never banned, besides those fail2ban already trusts |
| `rootPasswordOff` | SSH | Turns root's password sign-in off even where root signed in with a password lately |
| `passwordOff` | SSH | Turns password sign-in off |
| `epel` | fail2ban | On Rocky Linux and AlmaLinux, adds the EPEL repository fail2ban comes from; refused on Red Hat Enterprise Linux, where EPEL is added by hand |

`passwordOff` is refused unless sshd has an `AuthorizedKeysCommand`, or
an administrator who may sign in has a key: root, where `PermitRootLogin`
lets root in with a key, or a member of `sudo`, `wheel` or `admin`, with a
login shell, an account that has not expired, and allowed by sshd's
`AllowUsers` and the like. The key is a line of their authorized keys file
that is one: a known type (Ed25519, RSA, ECDSA, or a security key's) with
its key, without a forced command (`command=`). Whether root signed in with
a password lately is read from what sshd itself wrote to the journal, and
from `auth.log` or `secure`. Anyone can write a line to those two files,
which can only keep root's password sign-in on.

**Undo** reverses what apply recorded. Before changing anything, each module
records on the computer, in `/var/lib/easyrmm-hardening/`, the files,
modes, kernel values, services, packages and rules it changes. Undo puts back
each one that is still as apply left it, leaves what someone changed since,
and says what it left and why. It removes the packages apply installed when
that removes nothing else, and only those still at the version apply
installed: one upgraded or installed again since stays. It removes them,
and never purges them, so what is the computer's stays: on Debian and
Ubuntu, their configuration files (dpkg's, and those `ucf` keeps, as
AIDE's), their logs (the audit trail in `/var/log/audit`, fail2ban's log)
and their data (fail2ban's ban database). dpkg then lists
such a package as `rc`, and the result names it with the command that
deletes what it left: `apt-get purge` and its name. On Red Hat Enterprise
Linux, its rebuilds and Fedora, the files a package did not ship (its
logs, its data) stay, and a configuration file changed since installation
is kept as `.rpmsave`. The rollback of a failed apply does the same. A
package an installation upgraded as a dependency stays upgraded.
A directory under `/etc` that was there before and that an installation
gave another mode or owner (on AlmaLinux 10, audit-rules makes
`/etc/audit` 0750) gets them back once that installation's packages are
gone, if they are still as it left them; so do files under `/etc` that
installing the packages made and that removing them leaves (audit-rules'
`audit.rules` files), only as made. Files that a program apply started made (AIDE's database, the audit rules'
backup) go only as they were made. Undo of the firewall alone is refused
while fail2ban, which bans with it, is applied: the result names fail2ban
(`undoWith`); undo both. It rebuilds the initramfs after taking out
usb-storage's file, and after taking out kernel-modules' or the kernel
module's file when a rebuild since apply (usb-storage's, or a kernel
update's) took that file in. A successful undo
removes the record, so a second one finds nothing to undo. Undo takes no
options. Without the agent, undo runs on the computer itself, as root:
`sh /var/lib/easyrmm-hardening/easyrmm-hardening.sh undo all`.

When the audit module installs auditd, it writes
`/var/lib/easyrmm/auditd-installed`, with the packages that installation
added. Undo removes auditd only while that file is there and no rules file
is left in `/etc/audit/rules.d/` but those its packages shipped, unchanged
(audit-rules' `audit.rules`, which it makes from its base rules when it is
installed, counts as shipped); the file goes with it. A rules file of anyone else's (log collection's among
them) keeps auditd installed and running, and the file stays, so that
whoever removes the last of those rules files can remove auditd. An auditd
that was installed before apply gets no such file and is never removed.

What each module's apply or undo did:

| Outcome | Means |
|---|---|
| Applied | It changed what **Done** lists |
| Unchanged | Everything was in place already |
| Refused | It changed nothing, and says why |
| Skipped | The module does not apply here, or something else manages it |
| Failed | It could not finish, and put back what it had changed, but for packages it names |
| Undone | Everything apply recorded is as it was before |
| Partly undone | **Done** lists what was put back, and what was left and why |
| Nothing to undo | EasyRMM has no record of applying the module on the computer |
| Not run | The job's time ran out before the module; the module's last finding stays. Run the apply or undo again for it |

Apply and undo run for at most an hour (a check, 30 minutes), and the
script works to that limit: it stops a step that would run past it, starts
no module with less than a minute left, and starts no package step without
the time it needs (five minutes to install, two to remove), failing the
module instead, which is put back. The modules after it are *Not run*. A
run canceled (**Stop job** or **Stop run**) stops the step it is in, and
the script releases the computer for the next run. A run canceled or out
of time in the middle of a module leaves it *Half applied*: applying
it again finishes it, and undo reverses it. Canceled while it installs
packages, the run first records those the installation had added, so undo
removes them too. A run that is killed outright, not canceled (the
agent's process killed, the computer losing power), cannot: undo then
says which installation was interrupted and leaves its packages, to
remove by hand if they are not wanted. Installing packages on a slow
computer takes a while, so apply fewer modules at a time there.

A package step cut short can leave the package database unusable, so that
every later one fails: dpkg *interrupted* on Debian and Ubuntu, and on Red
Hat Enterprise Linux 8 and its rebuilds an rpm database that answers
`DB_RUNRECOVERY`. Before each package step, apply and undo check for that.
While another process still uses the database (apt, unattended-upgrades,
dnf), they wait for it as apt waits for its lock, five minutes, and never
touch it; if it is still there, the module fails and names it. Otherwise
they recover the database: `dpkg --configure -a`, non-interactive, keeping
changed configuration files, for at most ten minutes; on RHEL 8, removing
the database's environment files, `/var/lib/rpm/__db.*`, which rpm makes
again (the database itself is in other files), then `rpm --rebuilddb`
(which a Docker container's filesystem may refuse; the finding then says
so, and the database rpm had is used).
`dpkg --configure -a` finishes every package dpkg left half installed, by
whichever run or person, running their maintainer scripts: the finding
names them. The module's finding records it
(`packageRecovery`: `recovered` or `failed`, with why, and `packages`, those
it configured), **Done** says so,
and the audit log records it as *Package database recovery*, by the
device's agent. A recovery that fails fails the module with its reason; an
undo that fails this way keeps its record, so it can be run again.
## Windows computers and servers

EasyRMM also checks Windows computers and servers, in 23 modules
([ADR-0054](../architecture/adr/0054-hardening-windows-computers-and-servers.md)).
This release checks only, through the API. The device's **Hardening** tab
and the dialog that starts a check are Linux's until the Windows console is
built (ADR-0054's W3); a checked Windows device's summary already shows in
**Devices**' column (when the list has a Linux device) and its *Needs
attention* and *In place* filters, and *Not checked* still lists Linux
devices only. Applying and undoing come with W2.

### Running a check

`POST /api/v1/jobs/hardening` with `"platform": "windows"`,
`"mode": "check"`, the modules, `"options"` and `waitHours`, for up to 500
Windows devices with the EasyRMM agent where you hold `script.run`. A
request names one platform's modules: a Windows module for a Linux device,
or a Linux one for a Windows device, refuses the request and names the
device. The modules, in the order they run:

`accounts`, `firewall`, `defender`, `asr` (attack surface reduction),
`smb`, `smb-signing`, `ntlm`, `wdigest`, `lsa-protection`,
`name-resolution`, `powershell`, `rdp`, `uac`, `autoplay`, `anonymous`,
`winrm`, `printing`, `features`, `tls`, four that only ever report:
`audit`, `device-guard`, `bitlocker`, `laps`; then (ADR-0078) `session`,
`removable`, `mobile-code`, which can change settings, and four that only
report: `rights`, `time`, `app-control`, `office`. On Linux, `lockout` only
reports.

The options change what a check compares with, as they will change what
apply does; each needs its module: `allowTcp` and `allowUdp` (ports and
ranges) and `portsChecked`, `firewallServer` (firewall); `defenderServerRealtime`,
`smartScreenBlock`, `cloudBlockHigh` (defender); `asrBlock` (the rules,
by GUID, that asr would block rather than audit, from the twelve it
audits); `lsaUefiLock`, `lsaUnaudited` (lsa-protection); `lockoutExposed`
(accounts); `uacEnable`, `uacBuiltinAdmin`, `denyUserElevation` (uac);
`winrmBasicOff` (winrm); `spoolerOff` (printing). `domainController`
belongs to no module: applying on a domain controller will need it, and a
check accepts it and reads the same with or without it.

The agent runs EasyRMM's script with Windows PowerShell 5.1 as
LocalSystem, for at most 30 minutes; a check of every module takes about
two minutes on a small server. The job keeps the script it sent and its
hash, as for any job. The script changes nothing it reports on. It runs
Windows' own readers (`secedit /export`, `auditpol /backup`,
`gpresult /x`) into a folder under `%SystemRoot%\Temp` that only SYSTEM
and Administrators can open, and removes it.

### What a check reports

`GET /api/v1/devices/{id}/hardening` returns, besides each module's state:

* **The platform**: build and update revision, edition, installation
  type (Server Core among them), role (workstation, member server,
  standalone server, domain controller), joined to a domain, to Entra ID,
  or neither, enrolled in an MDM, the architecture, PowerShell's language
  mode, and **support**: *full* where apply and undo are to run, *check
  only* where they will be refused, *unsupported* on a build the script
  has not been tested on (every module is then *not supported*).
* **Owners** the ownership reader found: Group Policy and whether its
  record of what it applied could be read, registry preference items, an
  MDM, Defender for Endpoint, a Configuration Manager client, DSC
  correcting drift, Azure machine configuration, OSConfig's active
  scenarios (Windows Server 2025, where its module is installed), Tamper
  Protection, another antivirus or firewall; and the reasons apply would
  be *check only* on this computer. OSConfig names its settings without
  their registry values, so while one of its scenarios is active every
  setting is *check only* with the reason `osconfig`. EasyRMM imports
  OSConfig's module only from Program Files or System32 and only where
  no one but SYSTEM, Administrators and TrustedInstaller can change it;
  a copy anywhere else, or one others can change, makes every setting
  *check only* (`osconfig`) as well. A value a Group Policy object deletes
  is *managed elsewhere*, with the value `deleted`.
* **Exposure** (the `accounts` module): whether the Security log, as far
  back as it reaches up to 7 days, shows failed sign-ins from public
  addresses or 10 or more for one account within 15 minutes; the accounts
  and addresses, and how far back the log was read (at most 5,000 failed
  sign-ins, newest first). Where the oldest record read is dated after
  the check, the computer's clock was wrong when it was written: `since`
  is then null and `sinceReason` says so. Apply will set no lockout on an
  exposed computer unless `lockoutExposed` is given.
* **Each setting**: its value, what EasyRMM wants, and its state: *in
  place*; *not in place* (apply would change it); *managed elsewhere*
  (another owner holds it, named under `managed` with its policy and
  value); *check only* (an owner EasyRMM cannot read yet may hold it, with
  the reasons); *reported* (EasyRMM never changes it, or only with an
  option); *not applicable*; or *unknown*, with why.
* **Related controls**: for each module, the NIST SP 800-53 Rev. 5,
  SP 800-171 Rev. 2 and Rev. 3 and ISO/IEC 27001:2022 controls that DISA's
  and NIST's published mappings relate its STIG rules to, and the sources
  (`controlSources`). These say what the settings relate to; EasyRMM
  claims compliance with nothing.

| Support | Windows |
|---|---|
| Full | Windows Server 2025, 2022 and 2019; Server 2016 until 13 January 2027; Windows 11 Pro, Enterprise and Education 25H2; 24H2 Enterprise and Education until 13 October 2027 |
| Check only | Windows 10; Windows 11 versions out of service for their edition; Home, LTSC and multi-session editions; ARM64 |
| Unsupported | Any other build, until tested |

Where PowerShell runs in Constrained Language Mode (App Control for
Business or AppLocker), the script reports the platform and every module
as *not supported* with the reason, and reads nothing else.

### The Hardening folder

Apply and undo will keep their record in `%ProgramData%\EasyRMM\Hardening`,
apart from the agent's own folder. Every run checks it first, as the agent
checks its own state folder: the folders above it must be plain folders
owned by SYSTEM, Administrators or TrustedInstaller; the folder and its
files must be owned by one of them, and only they may write. A folder that
fails is never moved: every module is *not supported*, and the reason
names the folder for an administrator to remove. A file that fails is
renamed within the folder (`.set-aside-` and the time) and the run
refused; an access list that lets no one else write but differs from the
protected one is set back, with a warning. These and the lock file, which
lets one run at a time in and which a check makes where the folder exists,
are the only changes a check makes. A check never creates the folder.

### Not verified yet

* The MDM reader is built against the registry and WMI layout Microsoft
  documents and has not run on a computer enrolled in Intune: on an
  enrolled computer every setting no other owner holds is *check only*,
  with the reason `mdm`, and the Policy CSP policy that may set it.
* Defender for Endpoint, a Configuration Manager client, Azure machine
  configuration and another vendor's antivirus or firewall are found by
  their services, Windows Security Center and (another firewall on a
  server) the filtering platform's providers, not yet on real computers;
  CI plants their signs on its runners.
* TLS 1.0 and 1.1 on build 26100 and later are *unknown* where no value
  is set: Microsoft's pages disagree on whether they are off by default.

## Troubleshooting

| What you see | What to check |
|---|---|
| No **Hardening** tab | The device is not Linux, or has no EasyRMM agent |
| No **Run check…** | You do not hold `script.run` on the device |
| A run *Failed*: "The script finished, but its output does not end with a result." | The script stopped before its last line: the run's output shows where (it needs `job.view_sensitive`) |
| A run *Timed out* | The check took more than 30 minutes, or an apply or undo more than an hour, which a computer under heavy load can. Run it again, or with fewer modules |
| A module *Failed*: "not enough of the job's time was left to …", and others *Not run* | The job's time ran out. Run the apply or undo again for those modules |
| An undo of the firewall *Refused*: "Undo fail2ban with it." | fail2ban is applied too, and bans with the firewall. Undo both |
| A module *Not applicable* in a container | The host owns what it hardens. Check the host |
| A module *Half applied* | An apply or undo was stopped part way. Apply the module again to finish it, or undo it |
| A module *Failed*: "dpkg was interrupted, and … still held its lock" | Another package manager was running. Let it finish, then run the apply or undo again |
| An undo *Partly undone* | Something changed since apply; **Done** says what was left and why. Put those back by hand if you need to |
| Every Windows module *Not supported*, naming `%ProgramData%\EasyRMM\Hardening` | Someone other than SYSTEM or Administrators owns it or may write to it, or it is a link. Remove it as an administrator; nothing in it was trusted |
| Every Windows module *Not supported*, naming Constrained Language Mode | App Control for Business or AppLocker restricts PowerShell on the computer. EasyRMM does not work around it |
| Windows settings *Check only*, reason `group_policy_record_off` | Group Policy's *Turn off Resultant Set of Policy logging* is set, or the record could not be read: EasyRMM cannot tell what Group Policy sets |
| Windows settings *Check only*, reason `unreadable` | A record EasyRMM needs could not be read (the platform's notes say which: the MDM enrolments, Group Policy's histories, the local policy file or its switch, a policy value, DSC's or OSConfig's record, Security Center, the filtering platform, Defender's status), or Windows did not report the computer's role or join (shown as *unknown*). Check the computer's health; EasyRMM does not guess the owner |
| A Windows setting *Unknown*, with an error in its note | The script could not read its value (an access list on a registry key, a key that will not open, a log or WMI provider that did not answer). A value that cannot be read is never taken as not set |
| A Windows setting *Unknown*: "Windows did not report the computer's role" | Windows' WMI provider did not say whether the computer is a domain controller, and the setting turns on it (those domain controllers are exempt from, audit subcategories set only on them, a running Print Spooler). Check WMI's health |
| A Windows module *Failed*: "None of its settings could be read." | Every setting the module counts is *unknown*: their notes give the errors |
| `defender` and `asr` *Failed*: "Microsoft Defender Antivirus did not report its status" | Defender's service runs, but `Get-MpComputerStatus` failed with the error shown. They are *not applicable* only where the service is not installed or not running |
| `bitlocker` *Failed*: "BitLocker's state could not be read" | BitLocker's WMI provider is there but its read failed with the error shown; *not applicable* means its provider is absent |
| Firewall settings *Check only*, reason `other_firewall` | On a server, another vendor's filtering platform provider filters inbound traffic (the notes name it): another firewall may manage the computer's firewall |
