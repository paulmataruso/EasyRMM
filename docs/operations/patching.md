# Patching

EasyRMM patches devices through [EasyPatch](../integrations/easypatch.md):
EasyPatch keeps the update catalogue, each device's update state, the
policies and maintenance windows, and runs the scans and installs. EasyRMM
shows all of it in its own console, behind its own roles, so nobody needs
to sign in to EasyPatch for day-to-day patching. The design is in
[ADR-0030](../architecture/adr/0030-easypatch-connector.md).

## Setting it up

You need an EasyPatch server (1.9.0 or later) that the EasyRMM server can
reach over https, and a super administrator account in both.

1. **Create an API token in EasyPatch**: Settings → API tokens. Choose the
   EasyPatch organizations EasyRMM should patch, an expiry (up to a year),
   and the role:
   * **Operator** lets EasyRMM scan and install.
   * **Read only** lets EasyRMM show patch status, and nothing else.

   EasyPatch shows the token once; copy it.
2. **Connect EasyRMM**: Settings → EasyPatch. Enter EasyPatch's address
   (`https://patch.example.com`) and the token. If EasyPatch's certificate
   is signed by your own authority, paste that authority's certificate
   (PEM). EasyRMM checks the address and the token with EasyPatch before it
   saves anything; the token is stored encrypted and never shown again.
3. **Link organizations**: in the Organizations table, choose the EasyPatch
   organization each EasyRMM organization's devices are enrolled in. One
   EasyPatch organization serves one EasyRMM organization.
4. **Devices link themselves.** The EasyRMM agent asks the EasyPatch agent
   on the device who it is (`status --json`) and reports it with its
   inventory, at start and then hourly. Within a minute of that report
   EasyRMM checks with EasyPatch that the endpoint really is this device,
   and the device appears in **Patching**.

The status card shows the EasyPatch version, whether the token can act,
and two features that depend on the EasyPatch server:

* **Install later**: installs at a chosen time. Servers that do not list
  the `scheduled-installs` capability (stock EasyPatch 1.9.0) can only
  install now; EasyRMM does not offer a time there.
* **Who acted**: servers with the `on-behalf-of` capability record the
  EasyRMM user in their own audit log and on the job. Otherwise EasyPatch
  records the API token, and EasyRMM's audit log records the user.

EasyRMM checks the server every 10 minutes and records the last error.
Replacing the token for the same server: paste the new one and save.
Pointing EasyRMM at a different server forgets every organization and
device link, since they name the old server's ids.

## When a device is not linked

EasyRMM links a device only when everything agrees, and otherwise says why
(Settings → EasyPatch → Devices not linked, and the device's Patches tab):

| Reason | What to do |
|---|---|
| The EasyPatch agent is not enrolled and active | Enroll it, or check it on the device: `sudo /opt/easypatch/easypatch-agent status` on Linux, `& "$env:ProgramFiles\EasyPatch Agent\EasyPatch.Agent.exe" status` on Windows |
| The agent is enrolled with another server | The device belongs to another EasyPatch server; re-enroll it with this one |
| The organization is not linked | Link the device's EasyRMM organization in Settings → EasyPatch |
| EasyPatch has no such endpoint, or the token cannot see it | Add the endpoint's EasyPatch organization to the token |
| The endpoint belongs to another EasyPatch organization | The device is enrolled in the wrong EasyPatch organization, or the EasyRMM organization is linked to the wrong one |
| The endpoint is revoked or decommissioned in EasyPatch | Re-enroll the EasyPatch agent |
| The key fingerprint is not one of the endpoint's credentials | The endpoint id was copied from another machine, or its credential was revoked; re-enroll |
| Host names or serial numbers differ | The endpoint is another machine; re-enroll the EasyPatch agent on this one |
| Another device is already linked to the endpoint | Two EasyRMM devices claim one endpoint (a cloned disk, a reinstall). Retire the stale device in EasyRMM |

Refused devices are checked again every 15 minutes, and any device as soon
as its report changes; linked devices are checked again every six hours.

## Patching

**Patching** in the main menu lists the devices of linked organizations and
every device with an EasyPatch agent:

* **Status** is EasyPatch's compliance: up to date, updates missing,
  updates failed, restart needed, scan out of date, never scanned. Devices
  not patched from EasyRMM show why.
* **Missing** counts updates not yet installed (and how many are
  required), failed ones, and those that fix vulnerabilities exploited in
  the wild.
* Filters: organization, site, device group, status, name.

Choose devices to **Scan** them or **Install updates** (every update the
device's EasyPatch policy allows). The **Jobs** tab lists EasyPatch's jobs
for the devices you can see, refreshing every few seconds while any is
running; open one for its updates, events and progress, or to cancel it.

A device's **Patches** tab shows its status, the EasyPatch policy that
applies (when automatic installs run, scan interval, categories, delays),
updates to install, installed updates, the device's update history and its
jobs. Choose updates to install only those.

Scans and installs start when the device next checks in with EasyPatch
(every minute by default). Updates that need a restart finish at the next
restart: EasyRMM does not restart devices, EasyPatch's restart schedule (a
policy setting) may.

Policies, maintenance windows, rings and exclusions are edited in EasyPatch.

## Who can do what

| Permission | Allows | Built-in roles |
|---|---|---|
| `patch.view` (with `device.view`) | Patching, a device's Patches tab | Every role |
| `patch.manage` | Scan, install, cancel | Technician and above |
| `settings.manage` | Settings → EasyPatch | Super administrator |

Both are checked at the device's site before EasyPatch is called; a job is
shown only when its device is one you can see. With a Read only token,
nobody can act, whatever their role.

## Audit

| Action | Recorded |
|---|---|
| `patch.scan`, `patch.install` | One record per device that started, with the EasyPatch job id; installs record which updates and any scheduled time |
| `patch.cancel` | The job and its device |
| `easypatch.connection_update`, `easypatch.connection_delete` | The server, its version, whether the token changed and can act, and whether links were forgotten |
| `easypatch.organization_link`, `easypatch.organization_unlink` | Both organizations |

## Limits

* One EasyPatch server per EasyRMM installation.
* The device list reads at most 10,000 endpoints per EasyPatch organization
  and shows at most 5,000 devices; the job list shows the newest 200 jobs.
* The device list is cached for 30 seconds; a scan or install refreshes it.
* EasyRMM does not install the EasyPatch agent yet (planned, ADR-0031).
* The EasyPatch Linux agent needs systemd: it runs apt in transient
  systemd units. Containers without systemd enroll but cannot scan.
