# Edge builds and the release manifest

What CI publishes for each build of `main`, and the manifest every release
and edge build carries: the interface between publishing
([releasing](../development/releasing.md)) and the updater
([ADR-0052](adr/0052-the-host-updater.md)). The ADR decides what is
published and how it is verified; this page fixes the details it leaves
open: names, fields, media types and the layout of the OCI artifact.

## Edge versions

As [ADR-0052](adr/0052-the-host-updater.md#channels-and-versions) decides,
`scripts/release/version.sh` computes them:

* **R** is the highest release among the tags reachable from the commit.
  Only `easyrmm-vX.Y.Z` and `easyrmm-vX.Y.Z-rc.N` (no leading zeros, N from
  1) are releases; other tags are ignored. A full release ranks above its
  release candidates.
* The version is `R.edge.<run>.<attempt>` when R is a release candidate
  (`v1.0.0-rc.4.edge.412.1`), else R with its patch raised,
  `-edge.<run>.<attempt>` (`v1.0.1-edge.415.1`).
* `<run>` and `<attempt>` are the CI run's number and attempt
  (`GITHUB_RUN_NUMBER`, `GITHUB_RUN_ATTEMPT`) as seen by its first job,
  **Edge version**. Re-running only the failed jobs keeps that job's
  result, so the version and the image built for it stay the same;
  re-running every job is a new attempt, a new image and a new version.
* With no release tag reachable there is no edge version, and CI fails
  (fetch the tags: `actions/checkout` with `fetch-depth: 0`).

Versions are written with the `v`, as the server reports them. The server
image's tag drops it, as release images do.

## What is published, and where

| Where | What |
|---|---|
| `ghcr.io/paulmataruso/easyrmm-server:<version without v>` | The server image CI built and tested, pushed unchanged: an OCI image index for `linux/amd64` and `linux/arm64`, with BuildKit's SBOM and provenance, and GitHub's build provenance attestation (stored under the tag `sha256-<index digest hex>`, ghcr.io having no referrers API). Also tagged `sha-<commit>` |
| `ghcr.io/paulmataruso/easyrmm-deploy:<version>` | The OCI artifact [below](#the-oci-artifact): the bundle, its manifest and the manifest's Sigstore bundle |
| `:edge` on both | The newest edge build that passed the edge test on `main`. It moves only to a higher version |

A release publishes on its GitHub release, as before: the bundle, the
manifest, `easyrmm-<version>-manifest.json.sigstore.json`, the agents and
`SHA256SUMS`.

Edge builds pair `main`'s server with the engine of R: the `easypatch`
section of R's release manifest, whose attestation (`release.yml` at R's
tag) CI verifies before using it. Until R's GitHub release exists (its
workflow still running, or failed), CI does not test against R's engine and
nothing is published.

## The OCI artifact

One OCI image manifest (OCI 1.1, pushed with `oras push`):

| Field | Value |
|---|---|
| `mediaType` | `application/vnd.oci.image.manifest.v1+json` |
| `artifactType` | `application/vnd.easyrmm.deploy.v1` |
| `config` | The empty descriptor (`application/vnd.oci.empty.v1+json`, `{}`) |
| `layers[0]` | The bundle, `application/vnd.easyrmm.deploy.bundle.v1.tar+gzip`, titled `easyrmm-<version>-deploy.tar.gz` |
| `layers[1]` | The manifest, `application/vnd.easyrmm.deploy.manifest.v1+json`, titled `easyrmm-<version>-manifest.json` |
| `layers[2]` | The manifest's Sigstore bundle, `application/vnd.dev.sigstore.bundle.v0.3+json`, titled `easyrmm-<version>-manifest.json.sigstore.json` |
| `annotations` | `org.opencontainers.image.version` (the version), `org.opencontainers.image.revision` (the commit), `org.opencontainers.image.source` (`https://github.com/paulmataruso/EasyRMM`) and `org.opencontainers.image.created` |

A layer's title is its `org.opencontainers.image.title` annotation, which
`oras pull` uses as the file name. Readers take each file by its media type
and refuse an artifact without exactly these three layers. Nothing in the
artifact is trusted before the manifest's attestation verifies; the
annotations are for people and for choosing which version `edge` names.

## The manifest

`easyrmm-<version>-manifest.json`, written by `scripts/release/manifest.sh`
for releases and edge builds alike:

```json
{
  "schemaVersion": 2,
  "version": "v1.0.1-edge.415.1",
  "commit": "<40 hex digits>",
  "bundle": {
    "file": "easyrmm-v1.0.1-edge.415.1-deploy.tar.gz",
    "sha256": "<64 hex digits>"
  },
  "easyrmm": {
    "version": "v1.0.1-edge.415.1",
    "image": "ghcr.io/paulmataruso/easyrmm-server:1.0.1-edge.415.1@sha256:<64 hex digits>"
  },
  "easypatch": {
    "version": "1.12.1",
    "image": "ghcr.io/paulmataruso/easypatch-server:1.12.1@sha256:<64 hex digits>",
    "agentPackages": [
      {"file": "EasyPatchAgent-1.12.1-x64.deb", "sha256": "<64 hex digits>"}
    ]
  },
  "postgres": {
    "major": 18,
    "image": "postgres:18.6-alpine3.24@sha256:<64 hex digits>"
  },
  "meshcentral": {
    "image": "ghcr.io/ylianst/meshcentral:1.3.1@sha256:<64 hex digits>"
  },
  "authentik": {
    "included": true,
    "version": "2026.8.5",
    "image": "ghcr.io/goauthentik/server:2026.8.5@sha256:<64 hex digits>"
  },
  "images": [
    "ghcr.io/goauthentik/server:2026.8.5@sha256:<64 hex digits>",
    "ghcr.io/paulmataruso/easypatch-server:1.12.1@sha256:<64 hex digits>",
    "ghcr.io/paulmataruso/easyrmm-server:1.0.1-edge.415.1@sha256:<64 hex digits>",
    "ghcr.io/ylianst/meshcentral:1.3.1@sha256:<64 hex digits>",
    "postgres:18.6-alpine3.24@sha256:<64 hex digits>"
  ]
}
```

| Field | Meaning |
|---|---|
| `schemaVersion` | `2`. Manifests of releases up to `v1.0.0-rc.4` have no such field and lack every field below except `commit`, `easyrmm` and `easypatch`; a reader that needs them refuses those |
| `version` | The EasyRMM version, with the `v`: the only version a reader trusts, once the attestation verifies |
| `commit` | The full commit the build is of; the attestation's source commit must equal it |
| `bundle` | The bundle's file name and SHA-256 |
| `easyrmm` | The version again, and the server image by tag and digest |
| `easypatch` | The patching engine: its version, its image by tag and digest, and the agent packages its image carries (for an edge build, R's list) |
| `postgres` | PostgreSQL's major version and image, the `postgres` service's |
| `meshcentral` | MeshCentral's image |
| `authentik` | Whether the bundle can run Authentik; when it can, its version and image. `{"included": false}` otherwise |
| `images` | Every image the bundle's `docker-compose.yml` names, in every profile, each once, sorted (byte order). In the unpacked bundle, with a `.env` that `setup.sh` made from its `.env.example`, `docker compose --profile '*' config --images \| sort -u` lists exactly these; `docker compose config --images` lists them less Authentik's unless `.env`'s `COMPOSE_PROFILES` names `authentik`. CI checks this for every build |

Every image is named by tag and digest. `bundle.sh` refuses a
`docker-compose.yml` that names one without a digest.

## The bundle

The same for a release and an edge build (`scripts/release/bundle.sh`,
[releasing](../development/releasing.md#what-a-release-contains)). Its
`deploy/.env.example` names the server by repository and by tag and digest:

```
EASYRMM_IMAGE=ghcr.io/paulmataruso/easyrmm-server
EASYRMM_VERSION=1.0.1-edge.415.1@sha256:<64 hex digits>
```

`setup.sh --upgrade` copies that `EASYRMM_VERSION` into `.env`, so an
upgraded deployment runs exactly the manifest's server image.

## The Sigstore bundle

`<manifest>.sigstore.json` is the Sigstore bundle (v0.3) of the GitHub
attestation of the manifest: SLSA build provenance
(`https://slsa.dev/provenance/v1`), signed with Sigstore's public-good
instance (the repository is public) by
`actions/attest-build-provenance`. Its statement's subjects name files by
SHA-256: for an edge build only the manifest; for a release every file of
the release, the manifest among them. Verifying needs this file and
Sigstore's trusted root, not GitHub's API:

| Certificate field | Edge build | Release |
|---|---|---|
| Issuer | `https://token.actions.githubusercontent.com` | the same |
| Source repository identifier | `1458774020` | the same |
| Subject alternative name and build config URI | `https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/main` | `https://github.com/paulmataruso/EasyRMM/.github/workflows/release.yml@refs/tags/easyrmm-<version>` |
| Source repository ref | `refs/heads/main` | `refs/tags/easyrmm-<version>` |
| Build trigger | `push` | `push` |
| Runner environment | `github-hosted` | `github-hosted` |
| Source repository digest | the manifest's `commit` | the manifest's `commit` |

By hand, with the GitHub CLI:

```bash
oras pull ghcr.io/paulmataruso/easyrmm-deploy:edge
m=$(ls easyrmm-*-manifest.json)
gh attestation verify "$m" --bundle "$m.sigstore.json" --repo paulmataruso/EasyRMM \
  --cert-identity https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/main \
  --source-ref refs/heads/main --source-digest "$(jq -r .commit "$m")" --deny-self-hosted-runners
sha256sum "$(jq -r .bundle.file "$m")"   # equals the manifest's bundle.sha256
```

## Retention

`.github/workflows/edge-retention.yml`, daily: from `easyrmm-deploy`, every
version older than 30 days that `edge` does not name; from
`easyrmm-server`, every edge image older than 30 days (all its tags edge
versions or `sha-<commit>`, none `edge`), with its platform and attestation
manifests and its `sha256-<digest>` attestations. Release images, and
whatever `edge` names, are never deleted.
