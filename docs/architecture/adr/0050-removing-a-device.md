# ADR-0050: Removing a device

* Status: Accepted (2026-11-21). Not implemented yet.
* Refines: [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (the
  agents a device carries) and [ADR-0031](0031-easypatch-agent-install.md)
  (the EasyPatch agent EasyRMM installs).

## Context
The console cannot remove a device. A decommissioned computer stays in
the device list, its alerts and its patching state, and its agents stay on
it until someone runs `easyrmm-agent uninstall` there and uninstalls the
EasyPatch agent by hand. Even then the device stays listed as offline, and a
device MeshCentral still knows comes back as a discovered one.

A device is up to three things, each with its own agent:

* **EasyRMM's device**, with the EasyRMM agent. `easyrmm-agent uninstall`
  removes the agent, its service and state, and MeshAgent; it does not tell
  the server. It cannot run from inside the agent's own service: stopping
  the service stops it partway (Windows), or kills its control group
  (Linux).
* **MeshCentral's node**, with MeshAgent. While the node exists, EasyRMM's
  sync lists it. MeshCentral's `removedevices` deletes a node and
  disconnects its agent, but a MeshAgent still installed creates the node
  again when it reconnects to its device group; `uninstallagent` has a
  connected MeshAgent remove itself, and answers nothing.
* **The patching engine's endpoint**, with the EasyPatch agent. EasyRMM
  already removes those: `easypatch_removals` has the engine send the agent
  an uninstall job and revokes the endpoint if the agent has not gone after
  seven days ([ADR-0046](0046-what-one-product-retires.md)). The engine keeps
  the endpoint, revoked or decommissioned, for its history.

An agent whose device is gone gets `401 device_unknown` and keeps trying
for ever.

## Decision
* **Remove, then confirm.** **Remove device** on a device's page
  (`device.retire`, Site Administrator and up) asks the device to uninstall
  its agents. The device shows *Removing* until the EasyRMM agent confirms;
  EasyRMM then deletes it. Nothing about the device is deleted before that,
  so a removal that does not happen leaves a device someone can still see
  and remove by force. The request can be cancelled while nothing was
  confirmed.
* **The uninstall instruction is signed**, like an update instruction
  ([ADR-0027](0027-agent-updates.md)): a heartbeat answer carries it,
  signed with the job key, bound to the device, valid for minutes, under
  its own signature context. A job could not carry it: scripts stop with
  the agent.
* **The agent uninstalls from outside its service.** It copies itself to a
  temporary place and starts that copy detached, with `uninstall` and the
  instruction: as a transient systemd unit on Linux (as the EasyPatch agent
  does), as a process outside the service on Windows. The copy stops and
  removes the service and MeshAgent, then sends EasyRMM a signed report
  with the device key: removed, or what failed. Then it deletes the state
  and itself. A *removed* report is the confirmation; a failure shows on
  the device with **Remove anyway**.
* **The EasyPatch agent is removed when the device is deleted,** by the
  path that exists: the delete adds its endpoint to `easypatch_removals`,
  the engine sends the agent an uninstall job, and revokes the endpoint if
  the agent has not gone after the grace period. A cancelled removal
  leaves patching untouched.
* **MeshCentral's node is removed** when the device is deleted, after its
  MeshAgent was, so it does not come back as discovered.
* **Force removal.** When the device does not confirm, because it is off,
  gone or its uninstall failed, **Remove anyway** deletes it at once and
  removes its node. EasyRMM keeps the device's id, its agent's public key
  and its MeshAgent node for 90 days. If that EasyRMM agent comes back, its
  heartbeat is answered with the uninstall instruction instead of
  `device_unknown`; if that MeshAgent comes back, MeshCentral is told to
  uninstall it and remove its node again. Either way the computer cleans
  itself up. A device enrolled since then that reports the same MeshAgent
  node keeps it.
* **Devices only MeshCentral knows** (discovered, no EasyRMM agent) are
  removed the same way: MeshCentral uninstalls MeshAgent if it is
  connected, the node is removed, and it is kept for 90 days.
* **Endpoints only the patching engine has.** The patching overview's list
  of endpoints with no EasyRMM device gets **Remove**, through
  `easypatch_removals` as for a deleted device.
* **Audited**: the request, its cancellation, the confirmation, and a forced
  removal, each with the device's name and who asked.

## Consequences
* A decommissioned computer leaves the console with its agents removed, in
  one action, and a computer that was off cleans itself up when it comes
  back.
* Removing a device deletes its alerts, inventory, metrics and job history
  in EasyRMM (they cascade). The audit log keeps what happened. The
  patching engine keeps the endpoint's history, revoked.
* Agents older than this release cannot follow the instruction. Their
  devices are removed by force, and `easyrmm-agent uninstall` cleans them
  up locally. A MeshAgent they installed is still uninstalled through
  MeshCentral when it connects.
* A computer that stays off for more than 90 days after a forced removal
  keeps its agents; they get `device_unknown` from then on, and someone
  uninstalls them there.
* **Not covered**: bulk removal from the device list (later, on the same
  path), and removing an organization's or site's devices with it (sites
  with devices still cannot be deleted).
