# ADR-0045: Importing a standalone EasyPatch

* Status: Accepted (2026-11-19)
* Plan: [one product](../one-product-plan.md), phase S.
* Replaces: [ADR-0035](0035-cohosting-easypatch.md) (EasyPatch
  beside EasyRMM on one server) as the way an existing EasyPatch server
  joins EasyRMM. Builds on [ADR-0040](0040-one-set-of-organizations.md)
  (one set of organizations).

## Context
From phase S on, EasyRMM patches with the engine in its own deployment,
always (`EASYRMM_PATCHING` is no longer a setting). People who run a
standalone EasyPatch server, releases 1.4 to 1.10, need a way into it that
keeps their devices patching: their agents, enrollment, policies, history,
schedules and notification settings. Reinstalling an agent on every
device is the cost to avoid.

What holds the standalone server's state, and what moving it means:

* **The database.** Every release from 1.4 to 1.10 ran PostgreSQL 18.6
  and backs up with `pg_dump --format=custom --no-owner`
  (`scripts/backup.sh`, the same in every release). The engine is the same
  code with later migrations, so the same database, brought forward, is
  the engine's.
* **The Data Protection key ring** (`dpkeys.tar` in the backup). It
  encrypts webhook addresses, signing secrets, the SMTP password and
  second-factor secrets. Every release names the application `EasyPatch`
  and keeps unencrypted XML keys in a folder, as the engine does.
* **The agents' name.** Each agent connects to the server's
  `EASYPATCH_DOMAIN` on 443 and authenticates with its own credential,
  which is in the database. Since phase S0, EasyRMM's edge answers
  further names (`EASYRMM_PATCHING_AGENT_HOSTNAMES`) and forwards agent
  paths on them to the engine.
* **Accounts.** EasyRMM has its own accounts, roles and sign-in. The
  engine's console is not served in EasyRMM; people act through EasyRMM's
  statements (ADR-0038).
* **Names.** EasyPatch's organization and site names are unique exactly;
  EasyRMM's ignoring case. A server may have `Fabrikam` and `fabrikam`.

No EasyRMM release was ever published, so no deployment co-hosts an
EasyPatch server (ADR-0035) to be migrated from.

## Decision
**An import replaces a new deployment's engine database with the
standalone server's, and EasyRMM adopts its organizations.**
`deploy/scripts/import-easypatch.sh --backup DIR --hostname NAME`, run on
the EasyRMM server from `deploy/`, takes the folder `backup.sh` made.

1. **Refused unless safe.** The backup's checksums must match, the dump
   must be a custom-format dump, and `dpkeys.tar` must hold only
   `key-<id>.xml` files (it is unpacked as root). EasyRMM must accept its
   settings with the names added (`easyrmm-server migrate` with them).
   The engine must have no active endpoints: an import replaces its data,
   so it is for a deployment that does not yet patch, and two engines'
   endpoints are never merged.
2. **Restored aside, then prepared by the engine.** The dump is restored
   into `easypatch_import`, owned by the engine's owner role. The engine's
   new `prepare-import` command refuses a database with a migration the
   engine does not know (a newer EasyPatch) or none (not EasyPatch's),
   lets a pre-1.10 database with two addresses differing only in case pass
   the 1.10 schema (the later account gets `<id>@duplicate.invalid`),
   migrates, and disables the accounts: inactive, a password hash nothing
   matches, no second factor; sessions, API tokens, security keys and
   single sign-on providers are deleted. The accounts stay because the
   audit log and history name them. Nothing in the deployment changes
   before this step succeeds.
3. **Swapped, not overwritten.** With EasyRMM's server and the engine
   stopped, the engine's database is renamed
   `easypatch_before_import_<time>` and kept; the import takes its name.
   The backup's keys are added to the engine's key ring beside its own.
   The names go into `EASYRMM_PATCHING_AGENT_HOSTNAMES`.
4. **Adopted by EasyRMM.** `easyrmm-server import-easypatch`, with the
   server stopped so the reconciler does not act first, forgets every
   link to the replaced engine (device links, installs, removals, links of
   organizations and sites; opt-outs are EasyRMM's and stay) and places
   each active engine organization, in name order: it **joins** the
   EasyRMM organization with exactly its name; otherwise it becomes a
   **new** one with its name and time zone, unless EasyRMM has the name in
   another case, when it becomes `<name> (2)` (`(3)` …). Case collisions
   are named, never merged. Sites follow within their organization.
   Organizations install agents automatically, as every organization
   EasyRMM links does (ADR-0040). Archived organizations and sites stay in
   the engine only. The command is safe to run again: it finds what it
   made by name.
5. **Then nothing special.** The reconciler keeps the imported records as
   any other: EasyRMM's names and time zones lead, so the engine's
   `fabrikam` becomes `fabrikam (2)`, and an organization that joined
   EasyRMM's takes EasyRMM's time zone (the report says so, because
   maintenance windows follow it). An imported agent links to an EasyRMM
   device when the device's EasyRMM agent reports it with the old
   server's URL (phase S2); in another organization than its device, it is
   left alone and the reason shown.

## Deviations from a standalone server
* **Accounts do not come across.** People sign in to EasyRMM; EasyPatch's
  roles map to EasyRMM's only by being granted again.
* **Mail goes through EasyRMM's mail server.** The engine is given
  EasyRMM's settings (C5), which replace the imported ones.
* **Agent packages and the winget cache are not copied.** The engine's
  image carries packages signed with EasyPatch's release key (ADR-0041),
  the key released agents trust, so imported agents can update to the
  engine's version when automatic updates are on. The worker downloads
  winget again.
* **The old name serves agents only.** Its agent paths reach the engine;
  any other request (the old console, an old link) is sent to EasyRMM's
  Patching page. Deployment-code install scripts (`/downloads/install/`)
  are not served on it; new devices are installed through EasyRMM.
* **Agents must connect on 443**, and must trust the certificate EasyRMM
  presents for the old name. With ACME or a manual certificate that names
  it, they do. Agents of a lab server that used Caddy's internal CA, or a
  non-default port, are enrolled again.

## Consequences
* A standalone EasyPatch moves in with one script and a DNS change, and
  its devices keep their agents. The old server's data is kept twice until
  the administrator removes it: in the backup, and (on EasyRMM's side) the
  engine's database from before.
* An import is for a deployment whose engine patches nothing yet. Two
  standalone servers, or a server and a deployment already in use, cannot
  be merged; that would need endpoint and policy merging the engine does
  not have.
* `scripts/e2e/import.sh` (`make e2e-import`, in CI's bundle job) builds
  EasyPatch 1.10.0 from its release commit, gives it data through its own
  console API and a real Linux agent, backs it up as `backup.sh` does,
  imports it, and checks the agent checks in and scans through EasyRMM's
  edge on the old name and the old keys decrypt its webhook.
