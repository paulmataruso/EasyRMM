# Remote access: when it is down, and getting it back

A device's remote sessions need its **MeshAgent** connected to MeshCentral.
When the device's EasyRMM agent checks in but MeshAgent is not connected,
the console says why and offers a repair
([ADR-0069](../architecture/adr/0069-recovery-agent-logs-and-one-device-tree.md),
Part R, slice R1). The remote access alerts are in [Alerts](alerts.md#remote-access-policies).

## Why remote access is not connected

The EasyRMM agent reports MeshAgent's state with each heartbeat; the device
page and the alert say the first of these that applies:

| Reason | What it means |
|---|---|
| MeshAgent is not installed | Its program or settings are missing on the device |
| Installed but not running | Its service (a systemd unit or a Windows service), or the process the agent supervises, is not running |
| Settings for another server | The MeshCentral host in its settings (`meshagent.msh`) is not the one EasyRMM hands out for the device's site |
| Its node is in another site's group | MeshCentral lists the node the agent reported in another site's device group; EasyRMM does not link it |
| Running but not connected | Everything is as it should be on the device, and MeshCentral does not see it connected; the page says since when |
| Not known | The device runs an EasyRMM agent that does not report MeshAgent's state yet; updating the agent adds it |

The page also shows the host in the settings and the last error the agent
read (a failed start, restart or repair). The agent never sends a secret
with it; texts are cut at 300 characters.

## Reconnect remote access

The button is on the device page for those who hold `device.edit` on the
device, while the EasyRMM agent checks in. It starts a **repair** of
MeshAgent that the EasyRMM agent carries out, in two steps:

1. **Restart MeshAgent**: its service, or the child process the agent
   supervises.
2. **Put MeshAgent back**, if MeshCentral still does not see it connected
   2 minutes after the restart (or the restart failed): the agent stops
   MeshAgent, writes its program and settings again from the copies the
   server signs, and starts it. The node identity (`meshagent.db`) is not
   touched, so the node ID and keys stay. A download that fails leaves what
   is on the device alone.

The agent only does what its own code names for a step; the server's signed
instruction names a target and a step, never a command. It takes the
instruction with its next heartbeat (within a minute), and the page shows
each step and its outcome. One repair runs per device at a time, and a
repair that is not taken by the agent in 15 minutes, or runs longer than an
hour, ends as failed. Nothing is repaired on a device being removed.

Each request and each end is in the audit log (*Asked to reconnect remote access*,
*Repair ended*).

## Repair patching agent

On the same page, for those who hold `device.edit`, while the EasyRMM agent
checks in and the device's EasyPatch agent is linked to it, **Repair
patching agent** has the EasyRMM agent repair the EasyPatch agent **in
place, keeping its enrollment**, in two steps:

1. **Restart the EasyPatch agent's service** (the `EasyPatchAgent` Windows
   service, the `easypatch-agent` systemd unit).
2. **Reinstall its package of the same version**, if the EasyPatch agent
   has not checked in with the patching engine after the restart (the
   engine's view, read every 5 minutes, so the wait is 7 minutes): the
   agent downloads the package of the version installed from the engine,
   checks its size and SHA-256 against the signed instruction, and runs
   `msiexec /fa` on Windows or `apt-get install --reinstall` or `dnf
   reinstall` on Linux. It never runs the install that enrolls an agent
   (which refuses one that is enrolled and would make a new endpoint in
   the engine). The device must be enrolled already; a repair makes no
   enrollment. If the engine no longer offers that version, the repair
   says so and ends: update the EasyPatch agent instead.

Nothing is repaired for a device with no EasyPatch agent linked, in an
organization where patching is off, or being removed. Each request and each
end is audited, as for remote access.

## Automatic repairs

Unless an organization turns them off (**Repair agents automatically** in
the organization's *Edit*, with `org.manage`; on by default), EasyRMM starts
the repair itself when a condition has held for a while, as the server has
seen it:

| Condition | Seen for | Steps |
|---|---|---|
| The EasyRMM agent checks in, supervises MeshAgent here, MeshCentral has a group for the site, and MeshAgent is not connected | 10 minutes | Restart; reinstall after 20 more minutes |
| The EasyRMM agent checks in, the EasyPatch agent is linked, and the engine has not heard from it for 10 minutes | 30 minutes | Restart; reinstall after 30 more minutes |

* An **attempt** is one repair: the first step, then the second if the
  target is still broken after the wait. At most **one attempt** per target
  per device in **6 hours** and **3 in a rolling day**.
* The EasyPatch agent's check-in time comes from the engine every 5
  minutes, with one list call per engine organization. Nothing about the
  EasyPatch agents is judged while the engine does not answer, or for 15
  minutes after it does again; for MeshAgent, while EasyRMM's connection to
  MeshCentral is down or younger than 15 minutes. The clocks of the
  conditions start over meanwhile, so an outage never repairs every device.
* Never for a device being removed (its removal asked for, its EasyPatch
  agent being removed or opted out), for a target the device is not meant
  to have, or for an organization that turned automatic repairs off; a
  repair that runs when it is turned off stops without an alert.
* An attempt that ends with the target still broken raises one **Repair
  failed** warning on the device, with the last step's diagnostics, and its
  card lists the repairs tried. The alert resolves when the target is back,
  or by hand like any alert, and a later failed attempt updates it.
* The engine's own check-in interval is not read: an organization that
  sets it longer than 5 minutes is still waited on for 30 minutes before
  an attempt.

The EasyPatch agent repairing the EasyRMM agent, and repairs through
patching, are the next slice of the same ADR.

## The recovery copy

So that the EasyRMM agent can be put back when its program or service is
gone, a running agent keeps a copy of its own program in the `recovery`
folder of its state directory (`%ProgramData%\EasyRMM\Agent\recovery` on
Windows, `/var/lib/easyrmm-agent/recovery` on Linux), readable and writable
only by SYSTEM and Administrators (root on Linux), and checked with the rest
of that folder when the agent starts. It is written only after an update
has reached the server, never while a new build is on probation, from the
build that is running, and deleted first when the agent is removed.

`easyrmm-agent repair-install`, run as administrator or root, puts the
agent back in place on a machine that is enrolled: its program in the
program directory, its service registered as the installer registers it,
and started. The enrollment is not touched. Run from the recovery copy, it
needs no download.
