# Third-party notices

EasyRMM is licensed under FSL-1.1-ALv2 (see `LICENSE.md`). It includes or
runs alongside the following third-party software, each under its own licence.
This file is shipped with every server image and endpoint package. A complete,
machine-generated inventory of library dependencies is produced by CI
(`licenses` job) and attached to each release.

## Components distributed with EasyRMM

| Component | Use | Licence | Source |
|---|---|---|---|
| MeshCentral | Remote access server (container image, unmodified) | Apache-2.0 | https://github.com/Ylianst/MeshCentral |
| MeshAgent | Remote access agent bundled in endpoint packages (unmodified binary) | Apache-2.0; bundles OpenSSL, libjpeg-turbo, Duktape and zlib under their own licences | https://github.com/Ylianst/MeshAgent |
| PostgreSQL | Database (container image) | PostgreSQL Licence | https://www.postgresql.org |

MeshCentral and MeshAgent are trademarks of their respective owners. EasyRMM
is not affiliated with or endorsed by the MeshCentral project.

## Development tooling vendored in the repository

| Component | Use | Licence | Source |
|---|---|---|---|
| Impeccable skill files (`.claude/skills/impeccable/`, `.claude/agents/impeccable-*`) | Design workflow for contributors using Claude Code; not shipped in any build | Apache-2.0 | https://github.com/pbakaus/impeccable |

## Go modules (server and agent)

| Module | Licence |
|---|---|
| github.com/jackc/pgx/v5 | MIT |
| github.com/pressly/goose/v3 | MIT |
| github.com/google/uuid | BSD-3-Clause |
| github.com/pquerna/otp | Apache-2.0 |
| github.com/coder/websocket | ISC |
| github.com/boombuler/barcode | MIT |
| golang.org/x/crypto, golang.org/x/net, golang.org/x/time, golang.org/x/sync, golang.org/x/text | BSD-3-Clause |

Frontend packages are listed in the generated inventory once the web
application is built.
