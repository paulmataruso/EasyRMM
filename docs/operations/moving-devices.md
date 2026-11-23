# Moving devices

A device can be moved to another device group, another site, or another
organization. Until now a device's group was set when it enrolled and could
not be changed. The design is ADR-0069.

## How

* **Drag and drop.** Drag a device from the sidebar tree, or from the
  Devices list (every chosen row goes with it), onto a site or a device
  group in the tree. Dropped on an organization it opens *Move to…*, because
  an organization has several sites.
* **Move to…** In the tree, press Shift+F10 (or the context-menu key, or
  choose the row's **…** button) on a device; in the Devices list use the
  row's button, or choose devices and use *Move N devices to…*; on a
  device's page use *Move to…*. All open the same picker, so everything
  dragging does can be done with a keyboard and a screen reader.
* **API.** `POST /api/v1/devices/move` with `deviceIds` (up to 500), `siteId`
  and an optional `groupId`. It checks every device first and moves all or
  none; each device's move is audited (`device.move`, and `device.move_out`
  in the old organization's log when the organization changes).

## Who may

| Move | Needs |
|---|---|
| To another group of the device's site | `device.edit` on the device |
| To another site of its organization | `device.edit`, and `site.manage` on both sites |
| To another organization | `device.edit`, and `org.manage` on both organizations |

A person who cannot see the target site is told it does not exist.

## What follows a move

* **Remote access.** The device's MeshCentral node moves to the new site's
  device group (`changeDeviceMesh`) at the next device sync, and the
  device's EasyRMM agent, told by its next heartbeat, rewrites MeshAgent's
  settings and restarts it. Until the node has moved, the device keeps its
  remote-access link.
* **Patching.** The patching engine's reconcile moves the endpoint to the
  matching engine site. Moved to another organization, the endpoint is
  removed from the old engine organization and the agent re-enrolled in the
  new one if automatic installs are on and the agent is neither imported nor
  opted out; otherwise it stays unlinked, with its reason. Patch history
  stays with the old organization.
* **Policies and scripts** of the new site and organization apply from the
  move.

## Another organization's data stays with it

Before a move to another organization the server:

* cancels the device's queued job runs of the old organization (audited);
* refuses the move while a run is in progress: *try again when it finishes*;
* ends the device's open remote sessions;
* removes the device's alerts, open and resolved, because alerts belong to
  their device and have no organization of their own, and the new
  organization must not see the old one's;
* removes the device's agent logs and repair history, for the same reason.

A move to another site, in the same organization or not, also ends verbose
logging turned on for the device.

Job runs, patch history and audit records keep their organization and site,
so the old organization keeps its history and the new one does not see it.

### Every table that holds a device, organization or site

| Table | On a move |
|---|---|
| `devices` | moves (organization, site, group) |
| `agent_nonces`, `agent_updates`, `device_disk_health`, `device_disk_health_samples`, `device_hardening`, `device_hardening_checks`, `device_inventory`, `device_metric_samples`, `device_metrics`, `device_removals`, `device_software`, `enrollment_requests`, `retired_agent_nonces` | keyed by the device alone: the machine's own data, follows it |
| `remote_grants`, `alerts`, `agent_log_records`, `agent_log_days`, `agent_log_follow`, `agent_repairs` | removed with a move to another organization |
| `agent_conditions` | keyed by the device alone: how long a target has been down, follows it |
| `agent_log_verbose` | a device's row is removed with a move to another site; a group's belongs to the group |
| `job_runs`, `audit_log`, `retired_devices`, `mail_sends` | keep the organization and site they were written with |
| `alert_policies`, `contacts`, `device_groups`, `enrollment_tokens`, `mesh_sites`, `role_assignments`, `scripts`, `site_places`, `sites`, `easypatch_organizations`, `easypatch_sites` | owned by an organization or site, not by a device: untouched |
| `easypatch_devices`, `easypatch_install_restarts`, `easypatch_installs`, `easypatch_opt_outs`, `easypatch_removals` | the patching engine's links: follow through its reconcile |

An integration test fails when a table with a device, organization or site
column is added without a row here.

## Device groups

A site's menu in the tree offers *New group*; a group's offers *Rename* and
*Delete* (both need `site.manage`). Deleting a group leaves its devices in
the site, in no group.
