# ADR-0037: One licence: FSL-1.1-ALv2 for all of EasyRMM

* Status: Accepted (2026-11-18), the owner's decision.
* Supersedes: [ADR-0011](0011-licensing.md) (AGPL-3.0 for EasyRMM).
* Resolves: the licence open item of [ADR-0013](0013-easypatch-design-system.md).
* Plan: [one product](../one-product-plan.md), phase L.

## Context
The repository held one project under two licences: EasyRMM's code under
AGPL-3.0-or-later, and EasyPatch's under FSL-1.1-ALv2, both owned by the same
person and company. They could only stay separate programs: the AGPL forbids
further restrictions, and the FSL's Competing Use clause is one, so code from
the two could not be combined into one program.

The owner then decided that EasyPatch is only part of EasyRMM from now on,
with one console. That means combining the code, so the licences had to
become one. The owner chose the FSL for both, with DHI Technical Services LLC
as the licensor of all of it.

## Decision
* The whole repository is under FSL-1.1-ALv2. `LICENSE.md` at the root is the
  licence text, "Copyright 2026 DHI Technical Services LLC"; there is no
  separate licence file under `easypatch/`.
* Contributions grant DHI Technical Services LLC a licence to use them under
  the FSL, the Apache License 2.0 or any other licence (`CONTRIBUTING.md`),
  as EasyPatch's terms already did.
* The licensor's intent, stated in `LICENSING.md` and the README: MSPs may run
  EasyRMM free of charge for their own and their clients' computers,
  including paid managed services; selling it, or offering it for others to
  run their own remote management or patching, is a Competing Use.
* Dependencies must be under permissive licences. CI checks Go modules (as
  before) and now the console's npm packages too.
* Wording: EasyRMM is "source-available", never "open source"; each version
  becomes Apache-2.0 two years after its release.

## Consequences
* EasyPatch's code and EasyRMM's can be combined: one console, one release.
* EasyRMM is no longer open source by the OSI definition. Copies of EasyRMM's
  code obtained under the AGPL between 2026-11-15 and 2026-11-18 keep that
  licence; `LICENSING.md` says so. No EasyRMM release had been published.
* Bundled third-party programs keep their own licences: MeshCentral and
  MeshAgent (Apache-2.0), and Authentik when it is chosen (MIT, its image
  pulled unmodified from its own registry and never redistributed, because
  the image also carries Enterprise code under a licence that forbids that).

## Alternatives considered
* **AGPL for both.** Open source, but gives up the protection against
  competitors hosting the product, which the owner wanted for EasyPatch.
* **Keep two licences and two programs.** Possible only without a merged
  console, which the owner decided to build.
