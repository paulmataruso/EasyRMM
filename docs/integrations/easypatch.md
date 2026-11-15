# EasyPatch integration

Status: **designed, not implemented** (Phase 8). This document lists the
changes EasyPatch needs *before* the integration is built, as required by the
project rules. See ADR-0010 for the decision and the research report for the
analysis of EasyPatch v1.7.1.

## Responsibilities

| Concern | Owner |
|---|---|
| Organizations, sites, users, RBAC, general hardware/software inventory | EasyRMM |
| Patch catalogue, per-device update state, patch policy, maintenance windows, rings, patch jobs, patch-related restarts | EasyPatch |
| Installing and supervising the EasyPatch agent on endpoints | EasyRMM agent (download from the customer's EasyPatch server) |

EasyRMM never writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`,
never runs its own Windows Update or apt/dnf upgrade engine, and its script
library warns about scripts that would (PSWindowsUpdate, `usoclient`,
`apt upgrade`…). Reboots requested in EasyRMM check for active EasyPatch jobs
first.

## Topology

EasyPatch keeps its own deployment and hostname (e.g. `patch.example.com`),
on a separate host or a separate IP, because its Caddy binds host ports 80 and
443. EasyRMM reaches it over HTTPS only.

## Required EasyPatch changes

1. **Integration credentials** — a new authentication scheme for service
   callers. Preferred: an asymmetric credential (`i_…`) that reuses
   EasyPatch's existing request-signing format (ECDSA P-256 over method,
   target, timestamp, nonce, body hash). New table `integration_credentials`
   (name, public key, role cap, organization restrictions, allowed CIDRs,
   expiry, revocation, last use). Accepted by the Viewer/Operator policies,
   exempt from the interactive MFA state, rate-limited per credential,
   audited as `integration:<name>` with an informational
   `X-EasyPatch-On-Behalf-Of` header recorded in the audit log and in
   `jobs.requested_by`.
2. **External identifiers** — `external_source` and `external_id` on
   endpoints (unique among non-decommissioned), organizations and sites;
   exposed in DTOs; `GET /endpoints?externalId=`; `POST /endpoints/lookup`;
   `PUT/DELETE /endpoints/{id}/external-link` for adopting already-enrolled
   devices after fingerprint and SMBIOS checks.
3. **Token-bound enrolment** — `POST /enrollment-tokens` accepts
   `externalSource`/`externalId` (only with `maxUses=1`); enrolment copies the
   binding to the endpoint and prefers it when re-identifying a reinstall.
4. **Identity fields** — expose `smbiosUuid` and `enrollmentTokenId` in
   endpoint detail; document `easypatch-agent status --json` (`endpointId`,
   `credentialId`, `keyFingerprint`) as a stable, versioned contract.
5. **Delta sync** — `updatedSince` filters (and `externalId` in items) for
   endpoints, jobs and alerts.
6. **Integration webhooks** — events `job.created`, `job.progress`
   (throttled), `job.completed|failed|cancelled`, `endpoint.enrolled`,
   `endpoint.decommissioned`, `endpoint.compliance_changed`,
   `endpoint.reboot_pending`, signed with the existing `t=,v1=` HMAC scheme.
7. **Idempotency** — `Idempotency-Key` on job-creating requests.
8. **Co-hosting option** — bind-address/port overrides and forwarded-header
   trust settings in the production compose file.
9. **Licence permission** — EasyPatch is FSL-1.1-ALv2. EasyRMM does not
   redistribute EasyPatch binaries; the integration code in EasyRMM is
   AGPL and talks to EasyPatch only over its API. If the owner wants EasyRMM
   operators to be explicitly covered, publish an additional permission in
   the EasyPatch repository.

## Device correlation (never hostname-only)

1. EasyRMM mints a single-use EasyPatch enrolment token bound to its device id.
2. The EasyRMM agent installs the EasyPatch agent, enrols it with that token
   (passed on stdin, never on a command line), runs `status --json` and
   reports `endpointId` + `keyFingerprint` over its authenticated channel.
3. The server confirms the endpoint exists with that fingerprint and
   `externalId`, and cross-checks SMBIOS UUID and serial number.
4. Conflicts are surfaced to an administrator; nothing is merged
   automatically.
