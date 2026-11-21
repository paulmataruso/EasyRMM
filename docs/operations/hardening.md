# Hardening Linux computers

EasyRMM checks how well the Linux computers it manages are hardened, in 14
areas called modules: SSH, the firewall, fail2ban, kernel parameters, audit
rules, file permissions, legacy services, kernel modules, sudo, time
synchronisation, shared memory, USB storage, SELinux or AppArmor, and file
integrity. A **check** changes nothing on the computer: it reports, module
by module, what is in place, what is missing, and what applying the module
would change. The design is in
[ADR-0051](../architecture/adr/0051-hardening-linux-computers.md).

Applying and undoing modules come next (ADR-0051's second part). Until
then, EasyRMM changes nothing on a computer for hardening; the findings tell
you what to change.

## Who can do what

| To | You need, on the device |
|---|---|
| See the findings, on the device's **Hardening** tab and in **Devices** | `device.view` (every role) |
| Run a check | `script.run`: Technicians and above, as for any script |
| Open the job a finding came from | `job.view` as well |
| Read the run's raw output | `job.view_sensitive` as well: Technicians and above ([Who sees output and arguments](scripts-and-jobs.md#who-sees-output-and-arguments)) |

See [Roles and permissions](../security/rbac.md). Applying and undoing will
need a permission of their own, `device.harden`, held by Site
Administrators and above.

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

## Troubleshooting

| What you see | What to check |
|---|---|
| No **Hardening** tab | The device is not Linux, or has no EasyRMM agent |
| No **Run check…** | You do not hold `script.run` on the device |
| A run *Failed*: "The script finished, but its output does not end with a result." | The script stopped before its last line: the run's output shows where (it needs `job.view_sensitive`) |
| A run *Timed out* | The check took more than 30 minutes, which a computer under heavy load can. Run it again, or check fewer modules |
| A module *Not applicable* in a container | The host owns what it hardens. Check the host |
