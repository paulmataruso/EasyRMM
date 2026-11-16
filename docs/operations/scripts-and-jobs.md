# Scripts and jobs

EasyRMM keeps a library of scripts and runs them on devices that have the
EasyRMM agent. Running a script on one or more devices is a **job**; each
device's part of it is a **run**, with its own status, exit code and output.
The design is in [ADR-0017](../architecture/adr/0017-scripts-and-jobs.md).

Scripts run on **Linux** devices for now, with Bash, POSIX `sh` or Python 3.
PowerShell and Windows devices come with the Windows agent.

## The library

Every script belongs to one level, chosen when it is added:

| Level | Runs on | Who can add and change it |
|---|---|---|
| Shared | Devices in every organization | Super Administrators |
| Organization | Devices in that organization and its sites | Organization Administrators of it (and Super Administrators) |
| Site | Devices in that site | Site Administrators of it and above |

Anyone with `script.view` sees the shared library and the scripts of the
organizations and sites their roles cover. Technicians and above
(`script.run`) can run them on the devices they support. See
[RBAC](../security/rbac.md) for the full role table.

A script has a name (unique within its level), an optional description, a
shell, a body of up to 64 KiB and a default timeout (1 second to 4 hours).
Windows line endings in the body are converted to Unix ones. Adding, changing
and deleting scripts is audited with the body's SHA-256.

## Running a script

From a script's page, **Run** asks for the devices; from a device's page,
**Run script** asks for the script. Both then take:

* **Arguments**, one per line, passed to the script exactly as typed, with
  no shell expansion: `$1`, `$2` and so on, or `sys.argv[1:]` in Python. At
  most 32, each up to 1 KiB. Arguments are stored with the job and shown to
  everyone who can see it; **never pass passwords or keys as arguments**.
* **Timeout**, the script's default unless changed for this job.
* **Wait for offline devices**, 1 hour to 7 days (24 hours by default). A
  device that does not come online in that time is marked *Expired*.

One job can target up to 500 devices. Every device must have the agent, be
covered by the script's level, and be one where the person running it holds
`script.run`; otherwise the job is refused and the reason names the device.

The job keeps its own copy of the script. Changing or deleting the script
afterwards does not change what a job runs, and a job's page shows the exact
script it ran. **Run again** on a job's page starts a new job with the
library's current version, after showing the devices and arguments again.

Each device's run is recorded in the audit log as *Ran script*, with the
script's hash and the number of arguments but not their values.

## What happens on the device

The agent checks for work continuously (a long poll), so an online device
starts a script within a second or two.

Before running anything, the agent verifies the job's Ed25519 signature
against the job key it pinned when it enrolled, and checks that the job is
for this device and has not expired. A job that fails these checks is
reported as failed and never runs.

The script then runs:

* as the agent's user, **root** on a standard install;
* with the chosen interpreter (`bash`, `sh` or `python3`), the first found
  in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`
  and `/bin`; a `#!` line is ignored;
* in a new, empty working directory under
  `/var/lib/easyrmm-agent/jobs/work/`, which is also `$HOME` and is removed
  afterwards;
* with a minimal environment: `PATH`, `HOME`, `LANG=C.UTF-8`,
  `EASYRMM_JOB_ID` and `EASYRMM_RUN_ID`. Nothing else from the agent's
  environment is passed on;
* with nothing on standard input (`/dev/null`);
* at most four at a time per device; further runs wait their turn.

When the timeout passes, or the run is stopped, the agent sends `SIGTERM` to
the script's whole process group, then `SIGKILL` 10 seconds later, so child
processes are stopped too. Processes that leave the group on purpose (for
example with `setsid`) are not followed.

Output is kept up to **256 KiB per stream**: the first and last 128 KiB of
standard output and of standard error, with a note in the middle saying how
much was left out. Output is sent when the script ends; it is not streamed
while it runs.

The agent records each run in `/var/lib/easyrmm-agent/jobs/journal/` until
the server has its result. If the agent restarts while a script runs, the
run is reported as failed ("The agent restarted while the script ran.")
rather than run a second time. Results the server could not take yet are
sent again later.

## Statuses

| Status | Meaning |
|---|---|
| Queued | Waiting for the device to pick it up |
| Delivered | The device has it and is about to start it. Not started within 2 minutes, it is delivered again |
| Running | Running on the device |
| Succeeded | Exited with code 0 |
| Failed | Exited with another code, was killed by a signal, or could not start (for example, the interpreter is not installed) |
| Timed out | Ran past its timeout and was stopped |
| Canceled | Stopped from the console, before or while it ran |
| Expired | The device did not pick it up before the wait ran out |
| No result | It started, but the device reported nothing by the timeout plus 5 minutes. A result that arrives later still replaces it |

**Stop job** cancels every run still open that you may cancel; **Stop run**
on a run's page cancels one. A run that has not started is canceled at once
and never runs. A running script is stopped the next time its device checks
in, within seconds when it is online. Whatever the script already changed
stays changed.

## Retention

Finished jobs, with their output, are removed after
`EASYRMM_JOB_RETENTION` (default `2160h`, 90 days; at least `24h`). Jobs
with runs still open are kept. The audit log keeps its own record of every
run for `EASYRMM_AUDIT_RETENTION`.

## Troubleshooting

| What you see | What to check |
|---|---|
| Runs stay *Queued* | The device is offline, or its agent is older than this feature. `sudo easyrmm-agent status` on the device, and `journalctl -u easyrmm-agent` |
| *Failed* with "The job's signature does not verify" | The device pinned another server's job key, for example after the server's database was replaced. Uninstall the agent and enroll it again |
| *Failed* with "… is not installed on this device." | Install the interpreter (`python3`, `bash`) or pick another shell |
| *No result* | The device went offline or the agent stopped during the run. The script may or may not have finished; check the device |
