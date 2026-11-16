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
5. **Devices without an EasyPatch agent** can get one from EasyRMM, one at
   a time, in bulk, or automatically for a whole organization: see
   [Installing the EasyPatch agent](#installing-the-easypatch-agent).

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

## Installing the EasyPatch agent

The EasyRMM agent can install the EasyPatch agent on Windows and Linux
devices (x64 and arm64) that have none, and enroll it in the EasyPatch
organization linked to the device's organization. The design is in
[ADR-0031](../architecture/adr/0031-easypatch-agent-install.md). It needs
an Operator token.

* **Chosen devices**: in **Patching**, choose devices marked *No EasyPatch
  agent* and **Install EasyPatch agent…**; or on a device's **Patches** tab,
  **Install EasyPatch agent…**. Needs `patch.manage`.
* **A whole organization**: Settings → EasyPatch → Organizations, **Install
  automatically** on a linked organization. Needs `settings.manage`. Every
  minute EasyRMM looks for devices in that organization with no EasyPatch
  agent, new ones included, and installs it. A failed automatic install is
  tried again an hour later, three times in all; after that, start it by
  hand.

What happens:

1. At its next check-in (within a minute) the device's EasyRMM agent gets a
   signed instruction, valid for 15 minutes. It carries EasyPatch's address,
   the CA certificate you gave EasyRMM (if any), the newest EasyPatch agent
   package for the device, and an enrollment token. EasyRMM creates that
   token in EasyPatch for this one install: single use, valid for an hour,
   for the linked EasyPatch organization and the EasyPatch site with the
   same name as the device's EasyRMM site (no site when none has that
   name). The token is never stored, and is revoked if the install fails.
2. The agent downloads the package from EasyPatch, checks its size and
   SHA-256 against EasyPatch's list, installs it (`msiexec` on Windows,
   `apt-get` or `dnf` on Linux) and enrolls it.
3. It reports the result with its next heartbeat. The EasyPatch agent shows
   up in the next inventory, and the device links itself as above.

**Patching** and the device's **Patches** tab show where each install is:
waiting for the device, installing, installed, or failed with the reason
(installer and enrollment exit codes are put into words). An install the
agent never acknowledges fails after three minutes; one it does not finish
reporting within 30 minutes fails then.

EasyRMM never installs a second EasyPatch agent: a device whose EasyRMM
agent reports one, in any state and enrolled with any server, is left
alone, and the agent checks again just before it installs. It never
re-enrolls (`--force`), upgrades or removes the EasyPatch agent either;
EasyPatch updates its own agent.

Requirements:

* An EasyRMM agent that reports the EasyPatch agent's install state (this
  release or later). An older one waits, with a note, until it updates.
* **Linux**: systemd, and apt-get or dnf. If EasyPatch's certificate comes
  from a private authority, add that authority to the device's certificate
  store first (`/usr/local/share/ca-certificates` and
  `update-ca-certificates`, or `/etc/pki/ca-trust/source/anchors` and
  `update-ca-trust`). The EasyPatch agent trusts that store only, and
  EasyRMM does not change it.
* **Windows**: nothing more; the MSI is given the CA certificate
  (`SERVERCACERT`).
* One install at a time per device, for at most 20 minutes. An EasyRMM
  agent update waits for it.

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
| `patch.manage` | Scan, install, cancel, install the EasyPatch agent | Technician and above |
| `settings.manage` | Settings → EasyPatch, including automatic installs of the EasyPatch agent | Super administrator |

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
| `patch.agent_install` | One record per device an EasyPatch agent install was requested for. Automatic installs are covered by the record of turning them on |
| `easypatch.organization_update` | **Install automatically** turned on or off, and for which organization |

EasyPatch records each enrollment token EasyRMM creates against the API
token, and against the EasyRMM user who asked for the install when the
server has the `on-behalf-of` capability.

## Limits

* One EasyPatch server per EasyRMM installation.
* The device list reads at most 10,000 endpoints per EasyPatch organization
  and shows at most 5,000 devices; the job list shows the newest 200 jobs.
* The device list is cached for 30 seconds; a scan or install refreshes it.
* The EasyPatch Linux agent needs systemd: it runs apt in transient
  systemd units. EasyRMM does not install it where there is none.
* EasyPatch sites are matched to EasyRMM sites by name only.
* EasyRMM does not connect to link-local addresses (`169.254.0.0/16`,
  `fe80::/10`) or cloud instance metadata addresses, even when the
  EasyPatch name resolves to one. EasyPatch on the same host or a private
  network is fine. Through an HTTPS proxy (`HTTPS_PROXY`), the check applies
  to the proxy's address.
