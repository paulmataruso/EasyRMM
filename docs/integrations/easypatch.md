# EasyPatch integration

Status: **implemented** (Phase 8). The connector (ADR-0030): settings,
organization and device links, patch views and actions. Installing the
EasyPatch agent from EasyRMM (ADR-0031): on chosen devices or automatically
per organization. Operating both:
[docs/operations/patching.md](../operations/patching.md).

This document first listed the EasyPatch changes the integration would need,
written against EasyPatch 1.7.1 (ADR-0010). EasyPatch 1.9.0 changed that
picture; what was built, and what is still wanted, is below.

## Responsibilities

| Concern | Owner |
|---|---|
| Organizations, sites, users, RBAC, general hardware/software inventory | EasyRMM |
| Patch catalogue, per-device update state, patch policy, maintenance windows, rings, patch jobs, patch-related restarts | EasyPatch |
| Installing and enrolling the EasyPatch agent on endpoints that have none | EasyRMM agent, with a package from the customer's EasyPatch server and a single-use enrollment token (ADR-0031) |
| Updating the EasyPatch agent | EasyPatch |

EasyRMM never writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
and has no Windows Update or system-wide apt/dnf upgrade of its own (its
software actions install, update or remove one named package, ADR-0028).

Scripts can still do what EasyRMM does not. Once EasyPatch is set up, the
script library warns about scripts that patch the system themselves, naming
each line (see [Scripts and jobs](../operations/scripts-and-jobs.md#scripts-that-install-updates)).
It warns; it refuses nothing.

EasyRMM has no restart action of its own, so nothing it starts can restart a
device in the middle of an EasyPatch job. A restart action added later
should first check the device's running EasyPatch jobs.

## Topology

EasyPatch keeps its own deployment and hostname (e.g. `patch.example.com`),
on a separate host or a separate IP, because its Caddy binds host ports 80 and
443. EasyRMM reaches it over HTTPS only.

## EasyPatch changes

**Not needed any more.** EasyPatch 1.9.0's API tokens (bearer tokens,
Read only or Operator, limited to organizations, expiring, revocable,
audited as `token:<name>`) replace the planned integration credentials, and
every route the console needs accepts them. Devices are linked by what the
EasyPatch agent reports about itself, checked against the endpoint's
credential fingerprints, rather than by external ids.

**Proposed to EasyPatch** on the branch `easyrmm-integration` of the
EasyPatch repository, not merged there (backward compatible; EasyRMM works
with a stock 1.9.0 without them, and turns each on when the server lists its
capability in `/api/v1/server-info`):

1. `capabilities` in `/api/v1/server-info`.
2. `scheduled-installs`: an optional `scheduledAt` on
   `POST /endpoints/{id}/install-updates` and
   `POST /endpoints/bulk/install-updates`, up to 31 days ahead. A stock server
   ignores the field and installs at once, so EasyRMM never sends it there.
3. `on-behalf-of`: the `X-EasyPatch-On-Behalf-Of` header from API token
   callers, recorded in EasyPatch's audit log and on the job.
4. Update exclusions by API tokens (they failed with 401).

EasyRMM was run against a server built from that branch (2026-11-16). It
listed both capabilities. A scheduled install of one update on a Linux
device was held by EasyPatch until its time, delivered at the device's
first check-in after it, and installed. EasyPatch recorded the job as
requested by `token:<name> for <EasyRMM user>`.

**Still wanted, not built:**

1. **Token-bound enrolment** — a single-use enrolment token bound to an
   EasyRMM device, so an agent EasyRMM installs is linked at once. ADR-0031
   mints ordinary single-use tokens, and the device links itself through
   the usual checks after its next inventory.
2. **Delta sync and webhooks** — EasyRMM reads EasyPatch when someone looks
   and polls running jobs; webhooks would let it alert on compliance
   changes.
3. **Idempotency** — `Idempotency-Key` on job-creating requests. EasyPatch's
   duplicate-job check (`duplicate_job`) covers repeated clicks meanwhile.
4. **Co-hosting option** — bind-address/port overrides and forwarded-header
   trust settings in the production compose file.
5. **Licence permission** — EasyPatch is FSL-1.1-ALv2. EasyRMM does not
   redistribute EasyPatch binaries; the integration code in EasyRMM is
   AGPL and talks to EasyPatch only over its API. If the owner wants EasyRMM
   operators to be explicitly covered, publish an additional permission in
   the EasyPatch repository.

## Device correlation (never hostname-only)

1. The EasyRMM agent runs the local EasyPatch agent's `status --json` with
   its inventory and reports its server, endpoint id, key fingerprint,
   status and version over its authenticated channel.
2. The server links the device only when the agent is enrolled with the
   configured server, EasyPatch has the endpoint, active, in the EasyPatch
   organization linked to the device's organization, one of its active
   credentials has the reported fingerprint, host names match, serial
   numbers match when both are known, and no other device is linked to it.
3. Anything else is shown to administrators with the reason; nothing is
   merged automatically.
