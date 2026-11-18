# Patching

EasyRMM patches devices through [EasyPatch](../integrations/easypatch.md):
EasyPatch keeps the update catalogue, each device's update state, the
policies and maintenance windows, and runs the scans and installs. EasyRMM
shows all of it in its own console, behind its own roles, so nobody needs
to sign in to EasyPatch for day-to-day patching. The design is in
[ADR-0030](../architecture/adr/0030-easypatch-connector.md).

## Setting it up

You need an EasyPatch server (1.9.0 or later) that the EasyRMM server can
reach over https, and a super administrator account in both. Any EasyPatch
server will do. To set one up, see EasyPatch's
[installation guide](../../easypatch/docs/installation.md), or
[EasyPatch on the same server as EasyRMM](../deployment/easypatch-cohost.md).

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

With the patching engine in EasyRMM's own deployment
(`EASYRMM_PATCHING=bundled`, see [Docker](../deployment/docker.md)), skip
steps 1 to 3: there is no token, and EasyRMM keeps the engine's
organizations itself (see
[Organizations in the bundled engine](#organizations-in-the-bundled-engine)).

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

### Organizations in the bundled engine

With the bundled engine, every EasyRMM organization and site has its own in
the engine, and EasyRMM keeps them the same
([ADR-0040](../architecture/adr/0040-one-set-of-organizations.md)):

* **Created** with EasyRMM's name and the organization's **time zone**
  (Organizations → edit; the engine's monthly reports use it), with
  automatic installs of the EasyPatch agent on. An engine organization
  with exactly the same name that nothing links yet is used instead of a
  new one.
* **Renamed** and given a new time zone when EasyRMM's changes. A name
  another engine organization already holds, in another case or archived,
  gets the first 8 characters of EasyRMM's id, as in `Acme (1a2b3c4d)`. It
  gets its plain name back when that is free.
* **Archived** when deleted in EasyRMM, renamed `… (deleted 2026-11-18
  1a2b3c4d)` so that the name can be used again. Endpoints stay in an
  archived organization. An agent EasyRMM did not remove itself keeps
  checking in until it is revoked in the engine.
* **Put back** when someone archives or deletes them in the engine's own
  console. Descriptions, notes and addresses entered there are kept.

This happens as soon as an organization or site changes, and the whole set
is compared every 5 minutes. If the engine is unavailable or refuses a
change, EasyRMM tries again every minute. Settings → EasyPatch shows when
the engine was last in step, what it could not do, and how many archives
and agent removals are waiting. Organizations are not linked by hand there.

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
   name; with the bundled engine, the site EasyRMM created for it). The token is never stored, and is revoked if the install fails.
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
re-enrolls (`--force`) or upgrades the EasyPatch agent either; EasyPatch
updates its own agent. It removes one only as described in
[Stopping patching for a device](#stopping-patching-for-a-device) and
[Devices that move or are deleted](#devices-that-move-or-are-deleted).

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

## Stopping patching for a device

On a device's **Patches** tab, **Stop patching…** (needs `patch.manage`):

* EasyRMM drops any install of the EasyPatch agent that is waiting, and
  never installs it on the device again, automatically or by hand.
* If EasyRMM linked the device's EasyPatch agent, it sends the agent an
  uninstall job, as below. An agent EasyRMM has not confirmed as one it
  manages (enrolled with another server, say) stays installed.
* It is refused while the agent is being installed. Wait for the install to
  finish, then stop patching.

**Allow patching again** on the same tab undoes it. A removal not sent yet
is cancelled. With automatic installs on, the agent is installed again
within a minute. Otherwise, install it by hand.

## Devices that move or are deleted

* **Deleted in EasyRMM:** the device's EasyPatch agent is uninstalled. The
  removal is cancelled if another EasyRMM device links or reports the same
  endpoint, as after two device records are merged.
* **Moved to another site** of its organization: with the bundled engine,
  its endpoint moves to that site.
* **Moved to another organization:** an endpoint cannot change
  organization in EasyPatch. EasyRMM has the old agent uninstall itself.
  When it is gone, automatic installs enroll it again in the new
  organization. The device's Patches tab says so in the meantime.

EasyRMM's console has no screen to move or retire a device yet; this covers
devices merged by EasyRMM and moves made through the API.

**How an agent is removed:** EasyRMM sends EasyPatch an `uninstall-agent`
job and checks every 5 minutes. A failed or expired job is sent again. The
agent is gone when EasyPatch no longer shows its endpoint as active. If it
is not gone within 7 days, or is too old to uninstall itself, EasyRMM
revokes the endpoint in EasyPatch, which stops serving it. Removal works
with a connected server too, with an Operator token.

## When a device is not linked

EasyRMM links a device only when everything agrees, and otherwise says why
(Settings → EasyPatch → Devices not linked, and the device's Patches tab):

| Reason | What to do |
|---|---|
| The EasyPatch agent is not enrolled and active | Enroll it, or check it on the device: `sudo /opt/easypatch/easypatch-agent status` on Linux, `& "$env:ProgramFiles\EasyPatch Agent\EasyPatch.Agent.exe" status` on Windows |
| The agent is enrolled with another server | The device belongs to another EasyPatch server; re-enroll it with this one |
| The organization is not linked | Link the device's EasyRMM organization in Settings → EasyPatch. With the bundled engine, EasyRMM is still creating it: Settings → EasyPatch says why if it cannot |
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
running. Open one for its updates, events and progress. A running job can
be cancelled. A job that failed, was cancelled or expired, or left some
updates uninstalled, can be run again with **Retry**; the new job opens in
its place. EasyPatch refuses a retry while the same job is already queued.

A device's **Patches** tab shows its status, the EasyPatch policy that
applies (when automatic installs run, scan interval, categories, delays),
updates to install, installed updates, the device's update history and its
jobs. Choose updates to install only those.

Scans and installs start when the device next checks in with EasyPatch
(every minute by default). Updates that need a restart finish at the next
restart.

### Restarts

**Restart…** appears on a device's Patches tab, and for chosen devices on
the Patching page, when EasyPatch reports that a restart is pending. EasyRMM
has one way to restart a device, chosen to be safe:

* The device restarts only if a restart is still pending when the job
  runs.
* Signed-in users see EasyPatch's five-minute countdown first.
* It happens now, or at a time up to 31 days ahead. A device that is
  offline then restarts if it comes back within two hours; otherwise
  EasyPatch drops the restart.
* **Servers restart only when you tick them**, by name, one by one or all
  at once. EasyPatch before 1.10.0 cannot say which devices are servers, so
  every device then needs a tick.
* EasyPatch runs one job at a time on a device, so a restart never starts
  in the middle of an install.

The dialog lists the devices that will not restart and why: no restart is
pending, the EasyPatch agent is too old to restart the computer, or the
device is not linked. Prompts, deadlines, messages to users and restart
schedules are set in EasyPatch.

### Changing things in EasyPatch

Policies, maintenance windows, rings, exclusions and holds are edited in
EasyPatch. Where EasyRMM shows them, it links to the page that edits them,
in the same tab, so the browser's Back button returns:

| In EasyRMM | Link | Opens in EasyPatch |
|---|---|---|
| A device's **In EasyPatch** row | Open in EasyPatch | The device's endpoint page, on the tab matching the view (updates, installed, history, jobs) |
| A device's policy card | Change in EasyPatch | The endpoint's policy tab |
| A device's updates to install | Exclude in EasyPatch | The endpoint's updates tab, where updates are excluded |
| An update's title | (the title) | The update's page: vulnerabilities, other devices missing it, hold |
| A job | Open in EasyPatch | The job's page |
| A restart of one device | More restart options in EasyPatch | The endpoint's page |

These links go through `/go/to-easypatch` on EasyRMM, which finds the
device's EasyPatch endpoint from EasyRMM's own links and redirects. A
device that is not linked opens EasyPatch's endpoint list searched by its
name; one you may not see opens the list. EasyPatch asks you to sign in
with its own account and checks its own permissions.

### Switching to EasyPatch

**EasyRMM | EasyPatch** under the logo (at the top of the menu on a phone)
switches to EasyPatch's console, in the same tab, on the page of what you
were looking at:

| In EasyRMM | Opens in EasyPatch |
|---|---|
| A device (its Patches tab: to install, installed, history, jobs) | Its endpoint page, on the matching tab; its overview from the device's other tabs |
| An organization, or one of its sites | The organization |
| A patch job open on the Patching page | The job |
| Patching, the device list | The endpoint list, or the job list from the Jobs tab |
| Anything else | EasyPatch's home |

It is shown once EasyPatch is set up, to super administrators and to
people with a role over a whole organization linked to EasyPatch. A role
over one site is not enough: EasyPatch has no sites to restrict to. When a
call to EasyPatch failed since its last good check (every ten minutes:
EasyPatch did not answer, or refused EasyRMM's token), a dot on
**EasyPatch** says so; the link still works, in case it has recovered.

EasyPatch's own switch, and its links into EasyRMM, open EasyRMM on the
matching page: an endpoint opens its device's Patches tab, an organization
the organization, a job the Patching job dialog. An endpoint or
organization EasyRMM does not link, or that you may not see, opens
Patching with a note saying so.

### Signing in to EasyPatch through EasyRMM

EasyRMM can be EasyPatch's sign-in provider: someone signed in to EasyRMM
opens EasyPatch without another password, and their EasyPatch role follows
their EasyRMM roles
([ADR-0036](../architecture/adr/0036-easyrmm-signs-in-to-easypatch.md)).

| EasyRMM | EasyPatch |
|---|---|
| Super administrator | SuperAdmin |
| `patch.configure` over a linked organization (organization administrator) | Admin of those organizations |
| Otherwise `patch.view` over a linked organization (technician, read-only) | ReadOnly in those organizations |
| A role over one site only, or over no linked organization | Cannot sign in this way |

EasyPatch gives one role per person, so someone who is Admin in one
organization and may only look in another is Admin in the first and not
listed in the second. They still see both in EasyRMM.

It needs a second factor in the EasyRMM session, even when
`EASYRMM_REQUIRE_MFA` is off: an authenticator code, a security key or
recovery code after the password, a passkey, or single sign-on from a
provider marked as enforcing MFA. People signed in before this version
sign in once more first.

To set it up, as a super administrator:

1. Connect EasyPatch (above). Settings → EasyPatch → **Sign-in** says
   whether this EasyPatch can sign people in through EasyRMM: it must list
   the `easyrmm-sign-in` capability.
2. Choose **Set up sign-in**. EasyRMM shows the issuer, a client ID and a
   client secret. The secret is shown once.
3. In EasyPatch, add a single sign-on provider of the kind EasyRMM and enter
   the three.

EasyPatch's server must reach EasyRMM's public address over HTTPS.
**Replace secret…** stops the old secret at once; **Turn off** stops
EasyRMM signing anyone in to EasyPatch. If EasyPatch's public address
changes, turn sign-in off and set it up again: EasyRMM sends people back
only to the address it was set up with.

EasyPatch's side, the EasyRMM kind of provider, is not released yet: until
an EasyPatch lists `easyrmm-sign-in`, the Sign-in card says EasyPatch needs
an update, and EasyPatch asks for its own account when you switch.

Scripts in the library that install updates themselves (Windows Update,
`apt upgrade`, `dnf upgrade`…) work around all of this. The script library
warns about them; see
[Scripts and jobs](scripts-and-jobs.md#scripts-that-install-updates).

## Who can do what

| Permission | Allows | Built-in roles |
|---|---|---|
| `patch.view` (with `device.view`) | Patching, a device's Patches tab | Every role |
| `patch.manage` | Scan, install, restart, cancel, retry, install the EasyPatch agent, stop and allow patching for a device | Technician and above |
| `patch.configure` | Change EasyPatch's standing rules: makes someone an Admin in EasyPatch rather than ReadOnly when they sign in to EasyPatch through EasyRMM. Only organization-wide roles hold it | Organization administrator and above |
| `settings.manage` | Settings → EasyPatch, including automatic installs of the EasyPatch agent | Super administrator |

Both are checked at the device's site before EasyPatch is called; a job is
shown only when its device is one you can see. With a Read only token,
nobody can act, whatever their role.

## Audit

| Action | Recorded |
|---|---|
| `patch.scan`, `patch.install` | One record per device that started, with the EasyPatch job id; installs record which updates and any scheduled time |
| `patch.restart` | One record per device that was asked to restart, with the EasyPatch job id, the condition, any scheduled time and the servers you confirmed |
| `patch.cancel` | The job and its device |
| `patch.retry` | The job retried, the new job and the device |
| `easypatch.connection_update`, `easypatch.connection_delete` | The server, its version, whether the token changed and can act, and whether links were forgotten |
| `easypatch.organization_link`, `easypatch.organization_unlink` | Both organizations |
| `patch.agent_install` | One record per device an EasyPatch agent install was requested for. Automatic installs are covered by the record of turning them on |
| `easypatch.organization_update` | **Install automatically** turned on or off, and for which organization |
| `patch.stop`, `patch.allow` | Patching stopped or allowed again for a device, by whom |
| `easypatch.organization_create`, `easypatch.organization_adopt`, `easypatch.site_create`, `easypatch.site_adopt` | The bundled engine's organization or site EasyRMM created, or the existing one it took, for which EasyRMM organization or site |
| `easypatch.organization_archive`, `easypatch.site_archive` | An engine organization or site archived because it was deleted in EasyRMM |
| `easypatch.agent_uninstall`, `easypatch.endpoint_revoke`, `easypatch.agent_remove` | An uninstall job sent, an endpoint revoked, and a removal finished, each with the device's host name and why |
| `idp.authorize` | A sign-in to EasyPatch through EasyRMM: the role and how many organizations it gave, or why it was refused (no second factor, no access, not signed in) |
| `idp.client_create`, `idp.client_rotate`, `idp.client_delete` | Sign-in through EasyRMM set up, its secret replaced, or turned off |

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
* With a connected server, EasyPatch sites are matched to EasyRMM sites by
  name only.
* Each minute, EasyRMM moves at most 200 endpoints to their device's site
  and handles at most 100 agent removals; the rest wait for the next
  minute.
* EasyRMM does not connect to link-local addresses (`169.254.0.0/16`,
  `fe80::/10`) or cloud instance metadata addresses, even when the
  EasyPatch name resolves to one. EasyPatch on the same host or a private
  network is fine. Through an HTTPS proxy (`HTTPS_PROXY`), the check applies
  to the proxy's address.
