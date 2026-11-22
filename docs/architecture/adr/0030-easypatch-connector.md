# ADR-0030: EasyPatch connector

* Status: Partly superseded by [ADR-0046](0046-what-one-product-retires.md)
  (2026-11-19). Accepted 2026-11-16. Removed in one-product R2: the
  connection to a separately run EasyPatch server with an API token, its CA
  certificate, read-only tokens, and organizations linked by hand. EasyRMM
  calls the patching engine in its own deployment with statements
  ([ADR-0038](0038-statements-to-the-patching-engine.md)) and links every
  organization itself ([ADR-0040](0040-one-set-of-organizations.md)). What
  stands: devices linked by what their EasyPatch agent reports, verified
  against the engine, and patch views and actions behind EasyRMM's roles.
  Amended 2026-11-22 ("Patch all, restart after an install, Update all
  now").
* Builds on: ADR-0010 (EasyPatch integration through a service API), ADR-0018
  (inventory).
* Refines: `docs/integrations/easypatch.md` (since replaced by [the patching engine](../patching-engine.md)),
  written against EasyPatch 1.7.1.

## Context
Patching belongs to EasyPatch (ADR-0010): its catalogue, per-device update
state, policies, maintenance windows and jobs. Administrators should manage it
from the EasyRMM console without signing in to EasyPatch. When the
integration was designed, EasyPatch had no credential for a service caller,
so the plan called for new asymmetric integration credentials, external ids,
delta sync and webhooks.

EasyPatch 1.9.0 has **API tokens**: bearer tokens stored as hashes, read-only
or operator (Admin), limited to chosen organizations, expiring within a year,
revocable, recorded in its audit log as `token:<name>`. Every route the
console needs accepts them: endpoints and their updates, installed updates and
history, effective policy, scans, installs, jobs with per-update progress,
cancellation. Two things are missing: an install cannot be scheduled through
the API (jobs have a `not_before` time that only restarts set), and the API
does not say which features a server has.

## Decision
* **One EasyPatch server per EasyRMM installation**, set in **Settings →
  EasyPatch** by a super administrator: its https URL, an EasyPatch API token
  (sealed with the server key like every integration secret, never shown
  again), and the certificate of a private CA when EasyPatch uses one.
  Saving checks the server (`/api/v1/server-info`: version, public URL) and
  what the token may do: an Operator token (role `Admin` in EasyPatch's API)
  can scan and install, a Read only token only shows. The API tokens replace the integration credentials
  planned in ADR-0010.
* **Organizations are linked by hand**, one EasyRMM organization to one
  EasyPatch organization. Only devices of linked organizations are patched
  from EasyRMM; the token should be limited to those organizations.
* **Devices are linked by what the device says, never by host name alone.**
  With its inventory, the EasyRMM agent reports what the local EasyPatch
  agent says about itself (`easypatch-agent status --json` on Linux,
  `EasyPatch.Agent.exe status --json` on Windows): its server, endpoint id,
  key fingerprint, enrollment status and version. The server links the device
  to that endpoint only when all of these hold:
  * the agent's server is the configured one;
  * EasyPatch has the endpoint, it is active, and it belongs to the EasyPatch
    organization linked to the device's organization;
  * one of the endpoint's active credentials has the reported key fingerprint;
  * host names match, and serial numbers match when both are known;
  * no other device is linked to the endpoint.

  Otherwise the device says why it is not linked, and nothing is merged.
  Links are checked again every six hours, refused devices every 15 minutes,
  and any device as soon as its report changes or its organization is linked
  or unlinked. When EasyPatch cannot answer, what was known stays.
* **EasyRMM does not copy patch data.** Views read EasyPatch when they open
  (the fleet list is cached for 30 seconds), so EasyPatch stays the single
  source of truth and nothing goes stale in two places.
* **Access is EasyRMM's**: `patch.view` at the device's site to see,
  `patch.manage` to act, checked before EasyPatch is called. A job is shown
  only when its endpoint is linked to a device the caller can see.
* **Actions**: scan; install every eligible update; install chosen updates
  (one device); cancel a job. Each is audited in EasyRMM (`patch.scan`,
  `patch.install`, `patch.cancel`) with the EasyPatch job ids. EasyPatch
  records the token, and with the changes below, the EasyRMM user too.
  **Install later** (a date and time up to 31 days ahead) is offered only
  when EasyPatch lists the `scheduled-installs` capability. A server without
  it would ignore the time and install at once.
* **Console**: **Patching** in the main menu (devices with compliance,
  missing and failed updates, pending restarts and last scan, filtered by
  organization, site, group and compliance, with bulk scan and install; and
  EasyPatch jobs with their progress), a **Patches** tab on each device
  (summary, effective maintenance window, missing updates, installed updates,
  history, jobs), and **Settings → EasyPatch**.
* **EasyPatch changes** (EasyPatch repository, branch `easyrmm-integration`,
  backward compatible):
  * `capabilities` in `/api/v1/server-info`;
  * an optional `scheduledAt` on install requests, single and bulk;
  * `X-EasyPatch-On-Behalf-Of` from API tokens, recorded in its audit log and
    on jobs;
  * update exclusions by API tokens (they failed with 401).

  EasyRMM works with a stock EasyPatch 1.9.0, without scheduling.

## Consequences
* Installing the EasyPatch agent from EasyRMM comes next (ADR-0031). Until
  then devices are linked when the EasyPatch agent is installed some other
  way.
* Policies, maintenance windows, rings, holds and exclusions are still
  edited in EasyPatch; devices show their effective window.
* No webhooks: views read EasyPatch, and running jobs are polled while
  someone watches them.
* A slow or unreachable EasyPatch makes the patch views fail with a clear
  error (the device list still shows, without EasyPatch's columns); nothing
  else in EasyRMM depends on it.

## Patch all, restart after an install, Update all now (amended 2026-11-22)

The owner asked, on 2026-11-22, in these words:

> Also on the Patching main screen, when you select an org, can you please
> put a patch all button and schuidale restart all button

> Also when a user selects a device under patching, and hits install
> updates, please give them an options to restart right after the updates
> are done(or as the updates need it)

> Also can we get a side wide update button. I would like a button that will
> do an immemdate windows update(as in install ALL updates, and restart if
> needed)

("side wide" is site-wide.) What follows was decided in review.

### Patch all and Schedule restart all
* With an organization chosen, the Patching overview shows **Patch all…**
  and **Schedule restart all…**, to those who hold `patch.manage` in it. A
  **site** filter beside the organization narrows both to one site, and adds
  Update all now. The organization's page has Patch all; the site's, Update
  all now.
* **"All" is resolved by the server, when the request runs**, never from a
  list the console sends: every device of the organization (or the site)
  that has a linked EasyPatch agent, whose patching is not stopped, and that
  the caller holds `patch.manage` for at its site. The dialog shows the same
  resolution beforehand (`GET /api/v1/patching/scope`): how many devices, by
  platform, and how many are left out and why (not permitted, patching
  stopped, no agent, agent not linked, platform). Devices the caller cannot
  see are not counted at all, so a site's technician learns nothing of other
  sites. A device enrolled between the dialog and the request is included;
  the result gives the counts as sent.
* **No silent truncation.** An install of what each policy allows goes to the
  engine in batches of at most 1,000 (its bulk limit), whatever the size of
  the organization. A batch the engine refuses, or does not answer, is
  reported device by device (refused: not sent; no answer: not known, see
  Jobs), and the next batch still goes. Requests that read every device
  first have a limit and refuse above it, saying so: every available update
  and a restart after the install reach at most 1,000 devices, a restart
  that need not be pending at most 100 (as for chosen devices).
* **Schedule restart all** reuses the restart dialog: only if a restart is
  pending by default, at a time by default. Servers restart only when ticked
  by name; for chosen devices an unticked server stops the request, as
  before, while a Patch all leaves it out and says so.
* **Audit**: each device's event as for chosen devices, with the scope and a
  request id, and one `patch.install_all` or `patch.restart_all` event for
  the organization or site, with the counts, what was left out and why, the
  platforms, each batch, and the restart choice.

### Restart after an install
* The install dialog, wherever it opens, offers **Don't restart** (the
  default), **Restart if the updates need it** and **Restart when done** (at
  most 100 devices, as any restart that need not be pending), then the
  restart modes (a countdown by default). Servers restart only when ticked
  by name; an unticked server installs and is not restarted. The dialog runs
  the restart plan first (`POST /api/v1/patching/restart/plan` with
  `afterInstall`), which reads each device from the engine.
* **The engine has no restart after an install.** Its install request takes
  a mode, updates, force and a time; its restart is a separate job. Asking
  for both at once is not safe: the engine runs one job at a time per
  endpoint, but a restart can be leased while an install waits, and could
  run first. So **EasyRMM starts the restart itself when the install ends**,
  per device:
  * the choice is kept in `easypatch_install_restarts` (migration 00038), so
    a restart of EasyRMM's server neither loses it nor repeats it;
  * every minute EasyRMM reads each install it waits for. **Completed**
    (partly failed too: the engine completes an install that installed
    anything) asks the engine for one restart, with the choice's mode;
    "only if the updates need it" restarts when the install reported that
    its updates need one, or the endpoint has a restart pending, and the
    agent checks again before it restarts;
  * **Failed, cancelled or expired installs never restart**, whatever the
    choice: a failed install has nothing to finish, and restarting a
    computer for it would only interrupt its user;
  * an install that **waits for a restart** to go on gets one restart then
    (only if pending), and the last when it has finished;
  * asking is claimed in the database first, so one of EasyRMM's servers
    asks. A claim a stopped server left behind is settled, once it is two
    minutes old, from the engine's restart jobs for the endpoint since then
    (one already recorded for another install does not count): found, it is
    adopted; not found, the restart is asked for again;
  * the device is read again when the restart is asked for: a server not
    ticked by name, an agent that cannot restart, patching stopped, or the
    endpoint changed, and it is not restarted, with the reason recorded;
  * EasyRMM gives up on an install that has not ended in 40 days (the engine
    expires one waiting for a restart after 30);
  * the restart is asked for on behalf of the person who asked for the
    install, and audited as `patch.restart` by EasyRMM's patching component,
    naming that person and the install job.
* The install job's detail shows the choice and what became of it; the
  restart's detail links back to the install.

### Update all now
* **Update all now…**, on the overview with a site chosen and on the site's
  page, opens the install dialog for that site with its presets: now, every available update, restart if the updates need it
  with a countdown. One confirmation sends it; every preset can be changed.
* **Every available update** is each update the engine reports missing or
  failed on the device, but not those excluded on it (counted, with the
  devices, and linked), held, or application updates the policy does not
  approve. Updates still in the policy's rollout delay are included, and
  counted. Drivers are included. **Feature upgrades are left out** unless
  ticked: they are large, change the operating system's version and
  restart more than once, so they are a choice of their own. The dialog
  reads every device first (`POST /api/v1/patching/install/plan`) and says
  what "all" includes. Each device's updates install as chosen updates.
* **Windows first**: Windows devices are included; Linux devices only when
  ticked, with their count.
* The audit names the site or organization, the scope, the presets and the
  counts.

