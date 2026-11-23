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

Automatic repairs, repairs of the EasyPatch agent, and repairs through
patching are later slices of the same ADR.
