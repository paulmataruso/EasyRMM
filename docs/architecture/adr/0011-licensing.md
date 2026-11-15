# ADR-0011: AGPL-3.0 for EasyRMM

* Status: Accepted (2026-11-15)

## Context
The project must use an OSI-approved licence. It bundles Apache-2.0
components (MeshAgent, and runs MeshCentral). The owner intends to maintain
and distribute it indefinitely; hosted closed forks are a realistic risk for
an RMM.

## Options
* MIT / Apache-2.0: maximum adoption, allows closed SaaS forks.
* **AGPL-3.0-or-later**: OSI-approved copyleft that also covers network use,
  so hosted modifications must be shared; compatible with including
  Apache-2.0 components.
* FSL (as EasyPatch): not OSI-approved — excluded by the requirements.

## Decision
AGPL-3.0-or-later for all EasyRMM code. Third-party components keep their
licences; notices are collected in `THIRD_PARTY_NOTICES.md` and shipped with
every package. Contributions are accepted under the Developer Certificate of
Origin.

## Consequences
Some organisations avoid AGPL dependencies; this does not affect operators
who run EasyRMM unmodified. Relicensing later requires agreement from all
contributors, so the decision should be revisited before external
contributions are accepted, if a different licence is preferred.
