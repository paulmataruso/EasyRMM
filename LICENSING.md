# Licensing

This repository holds two products under two licences.

| Path | Product | Licence |
|---|---|---|
| Everything except `easypatch/` | EasyRMM | [GNU Affero General Public License v3.0 or later](LICENSE) |
| `easypatch/` | EasyPatch | [Functional Source License, Version 1.1, ALv2 Future License (FSL-1.1-ALv2)](easypatch/LICENSE.md), licensor DHI Technical Services LLC |

## How the two relate

* They are separate programs.
* EasyRMM talks to EasyPatch over EasyPatch's HTTP API and links to its
  console.
* Neither one links or includes the other's code.
* Each builds and releases on its own:
  * EasyRMM's tags are `easyrmm-v*`. Its images and bundle are built from the
    repository root.
  * EasyPatch's tags are `easypatch-v*`. Its images and packages are built from
    `easypatch/`.
* Being in one repository does not change either licence.

## Contributing

* Changes under `easypatch/` are made under EasyPatch's terms, including the
  licence grant to DHI Technical Services LLC
  ([easypatch/CONTRIBUTING.md](easypatch/CONTRIBUTING.md)).
* Changes anywhere else are made under EasyRMM's terms
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
* A pull request that touches both is covered by both, each for its part.

## Open item

EasyRMM's console uses a stylesheet and a logo construction derived from
EasyPatch's design system (ADR-0013). Before an EasyRMM release, the licensor
must give that grant in writing, and this file will record it. See the
[roadmap](ROADMAP.md).

## Third-party software

Dependencies keep their own licences:

* EasyRMM: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
* EasyPatch: there is no separate notices file. Its changelog names each
  dependency's licence when the dependency is added
  ([easypatch/CHANGELOG.md](easypatch/CHANGELOG.md)).
