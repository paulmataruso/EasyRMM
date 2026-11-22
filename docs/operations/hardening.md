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
| Tested | Debian 12 and 13; Ubuntu 22.04, 24.04 and 26.04; Rocky Linux, AlmaLinux and Red Hat Enterprise Linux 8, 9 and 10; Fedora 43, 44 and 45 |
| Check only | A newer release of those, not yet tested, or one out of its standard support (Debian 11, Ubuntu 20.04), which needs upgrading first. Checks report on it; nothing will be applied or undone |
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
from starting, and says why: password sign-in off where no account that may
sign in has an SSH key, say, or USB storage off where a mounted filesystem is
on a USB disk. It leaves alone a firewall the computer already has. A module
that fails part way is put back as it was, but for packages it installed
that cannot be removed (others need them, or the package manager fails):
the result names those and says why. Packages a module needs
(nftables, fail2ban, auditd, AIDE, chrony or systemd-timesyncd) come from
the computer's own repositories, without recommended packages. AIDE's first
database is built after the job ends, in `easyrmm-aide-init.service`; the
next check says whether it finished.

Apply's options:

| Option | Module | Does |
|---|---|---|
| `allowTcp`, `allowUdp` | firewall | Ports and ranges (`"8080"`, `"9000-9100"`) left open besides those in use |
| `trusted` | fail2ban | Addresses and ranges never banned, besides those fail2ban already trusts |
| `rootPasswordOff` | SSH | Turns root's password sign-in off even where root signed in with a password lately |
| `passwordOff` | SSH | Turns password sign-in off |
| `epel` | fail2ban | On Rocky Linux and AlmaLinux, adds the EPEL repository fail2ban comes from; refused on Red Hat Enterprise Linux, where EPEL is added by hand |

**Undo** reverses what apply recorded. Before changing anything, each module
records on the computer, in `/var/lib/easyrmm-hardening/`, the files,
modes, kernel values, services, packages and rules it changes. Undo puts back
each one that is still as apply left it, leaves what someone changed since,
and says what it left and why. It removes the packages apply installed when
that removes nothing else; a package an installation upgraded stays
upgraded. It rebuilds the initramfs after taking out usb-storage's file,
and after taking out kernel-modules' file when a rebuild since apply
(usb-storage's, or a kernel update's) took that file in. A successful undo
removes the record, so a second one finds nothing to undo. Undo takes no
options. Without the agent, undo runs on the computer itself, as root:
`sh /var/lib/easyrmm-hardening/easyrmm-hardening.sh undo all`.

When the audit module installs auditd, it writes
`/var/lib/easyrmm/auditd-installed`, with the packages that installation
added. Undo removes auditd only while that file is there and no rules file
is left in `/etc/audit/rules.d/` but those the package shipped, unchanged;
the file goes with it. A rules file of anyone else's (log collection's among
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

A job stopped, or out of its 30 minutes, in the middle of a module leaves it
*Half applied*: applying it again finishes it, and undo reverses it.
Installing packages on a slow computer takes a while, so apply fewer
modules at a time there.

## Troubleshooting

| What you see | What to check |
|---|---|
| No **Hardening** tab | The device is not Linux, or has no EasyRMM agent |
| No **Run check…** | You do not hold `script.run` on the device |
| A run *Failed*: "The script finished, but its output does not end with a result." | The script stopped before its last line: the run's output shows where (it needs `job.view_sensitive`) |
| A run *Timed out* | The check took more than 30 minutes, which a computer under heavy load can. Run it again, or check fewer modules |
| A module *Not applicable* in a container | The host owns what it hardens. Check the host |
| A module *Half applied* | An apply or undo was stopped part way. Apply the module again to finish it, or undo it |
| An undo *Partly undone* | Something changed since apply; **Done** says what was left and why. Put those back by hand if you need to |
