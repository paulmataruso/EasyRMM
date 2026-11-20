# Licensing

EasyRMM, including its patching engine and the EasyPatch agent
(`easypatch/`), is source-available under one licence: the **Functional
Source License, Version 1.1, ALv2 Future License**
([FSL-1.1-ALv2](LICENSE.md)). Copyright 2026 DHI Technical Services LLC,
the licensor. The decision is
[ADR-0037](docs/architecture/adr/0037-one-licence.md).

## What the licence allows

* You may use, copy, modify and redistribute EasyRMM for any purpose
  **except a Competing Use**: making it available to others in a commercial
  product or service that substitutes for EasyRMM or offers substantially
  similar functionality.
* The licensor's intent: MSPs and IT departments may run EasyRMM free of
  charge to manage, support and patch their own computers and the computers
  they manage for their clients, including as part of paid managed services.
  Selling EasyRMM, or offering it or a product built from it for others to
  run their own remote management or patch management, is not permitted.
* Each version becomes available under the Apache License 2.0 two years after
  it is released.
* For a commercial licence, contact DHI Technical Services LLC at
  [paulmataruso@dhitechnical.com](mailto:paulmataruso@dhitechnical.com).

EasyRMM is source-available, not open source: the Competing Use restriction
is not allowed by open-source definitions. Its code is public, and each
version becomes open source (Apache-2.0) two years after its release.

## Earlier licences

* EasyRMM's code outside `easypatch/` was published in this repository under
  the GNU Affero General Public License v3.0 or later from 2026-11-15 until
  the licence change of 2026-11-18. Copies obtained in that period remain
  available to their holders under that licence. Everything after the change
  is under FSL-1.1-ALv2 only. No EasyRMM release was published under the
  AGPL.
* The patching engine and the EasyPatch agent have always been under
  FSL-1.1-ALv2. EasyPatch's own releases, up to 1.10.0, are in its former
  repository, <https://github.com/paulmataruso/EasyPatch>.

## Contributing

Contributions are made on the terms in [CONTRIBUTING.md](CONTRIBUTING.md),
including a licence grant to DHI Technical Services LLC. They apply to the
whole repository, `easypatch/` included.

## Third-party software

Dependencies keep their own licences:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). CI holds every shipped
dependency to an allow-list of permissive licences (MIT, Apache-2.0, BSD,
ISC, MPL-2.0, and the PostgreSQL Licence for Npgsql): Go modules, the
console's npm packages and the engine's NuGet packages. The engine's
changelog also names each .NET dependency's licence when it is added
([easypatch/CHANGELOG.md](easypatch/CHANGELOG.md)).
