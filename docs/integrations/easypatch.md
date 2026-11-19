# EasyPatch integration

Status: **implemented** (Phase 8). The connector (ADR-0030): settings,
organization and device links, patch views and actions. Installing the
EasyPatch agent from EasyRMM (ADR-0031): on chosen devices or automatically
per organization. Operating both:
[docs/operations/patching.md](../operations/patching.md).

EasyPatch is EasyRMM's patch management component. Its code is in
`easypatch/` of this repository ([monorepo.md](../development/monorepo.md)),
under its own licence ([LICENSING.md](../../LICENSING.md)). Since the
one-product plan, its server runs in every EasyRMM deployment as the
patching engine, on loopback, and EasyRMM's console is the only one: EasyRMM
calls the engine with a signed statement per request
([ADR-0038](../architecture/adr/0038-statements-to-the-patching-engine.md)).
The product switch and signing in to EasyPatch through EasyRMM were removed
([ADR-0046](../architecture/adr/0046-what-one-product-retires.md)). The
plans are in [the integration plan](../architecture/easypatch-integration-plan.md)
and [the one-product plan](../architecture/one-product-plan.md).

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

EasyRMM restarts devices only through EasyPatch: a restart job with one
fixed preset (only if a restart is pending, after EasyPatch's countdown,
servers confirmed by name). EasyPatch runs one job at a time on an endpoint,
so the restart never lands in the middle of an install. EasyRMM has no other
restart action.

## Topology

EasyPatch keeps its own deployment and hostname (e.g. `patch.example.com`).
It can run on another host, or on the same server as EasyRMM: EasyRMM's edge
then keeps ports 80 and 443 and passes EasyPatch's name through, still
encrypted, to EasyPatch's Caddy on loopback (ADR-0035,
[easypatch-cohost.md](../deployment/easypatch-cohost.md)). Either way
EasyRMM reaches it over HTTPS only; on the same server, over loopback.

## EasyPatch changes

**Not needed any more.** EasyPatch 1.9.0's API tokens (bearer tokens,
Read only or Operator, limited to organizations, expiring, revocable,
audited as `token:<name>`) replace the planned integration credentials, and
every route the console needs accepts them. Devices are linked by what the
EasyPatch agent reports about itself, checked against the endpoint's
credential fingerprints, rather than by external ids.

**Added to EasyPatch** in `easypatch/`, not in an EasyPatch release yet
(backward compatible; EasyRMM works with a stock 1.9.0 without them, and
turns each on when the server lists its capability in
`/api/v1/server-info`):

1. `capabilities` in `/api/v1/server-info`.
2. `scheduled-installs`: an optional `scheduledAt` on
   `POST /endpoints/{id}/install-updates` and
   `POST /endpoints/bulk/install-updates`, up to 31 days ahead. A stock server
   ignores the field and installs at once, so EasyRMM never sends it there.
3. `on-behalf-of`: the `X-EasyPatch-On-Behalf-Of` header from API token
   callers, recorded in EasyPatch's audit log and on the job.
4. Update exclusions by API tokens (they failed with 401).

They were written on an `easyrmm-integration` branch of EasyPatch before
EasyPatch came into this repository. EasyRMM was run against a server built
from that branch (2026-11-16). It listed both capabilities. A scheduled
install of one update on a Linux device was held by EasyPatch until its
time, delivered at the device's first check-in after it, and installed.
EasyPatch recorded the job as requested by
`token:<name> for <EasyRMM user>`.

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
5. **Licence permission** — resolved 2026-11-18: EasyRMM and EasyPatch are
   under one licence, FSL-1.1-ALv2, with one licensor
   ([ADR-0037](../architecture/adr/0037-one-licence.md)).

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
