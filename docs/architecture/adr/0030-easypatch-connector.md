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
