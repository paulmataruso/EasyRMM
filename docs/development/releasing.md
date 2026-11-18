# Releasing

Releases are cut by pushing a version tag. `.github/workflows/release.yml`
does the rest; nothing is published from a laptop. This page is about
EasyRMM's releases; EasyPatch's are released separately
([EasyPatch releases](#easypatch-releases)).

## Versions

Semantic versioning, tags `easyrmm-v1.2.3`. A pre-release adds a suffix,
`easyrmm-v1.2.3-rc.1`. The `easyrmm-` prefix keeps EasyRMM's tags apart from
EasyPatch's (`easypatch-v1.10.0`), which this repository also holds and
which `.github/workflows/easypatch-release.yml` releases.

| Tag | Image tags | GitHub release |
|---|---|---|
| `easyrmm-v1.2.3` | `1.2.3`, `1.2`, `latest` | Release, marked Latest |
| `easyrmm-v1.2.3-rc.1` | `1.2.3-rc.1` only | Pre-release |

EasyPatch's releases are never marked Latest, so the repository's latest
release is always EasyRMM's.

The server, the console and the agents carry the tag without its prefix as
their version, `v1.2.3` (`easyrmm-server version`, `easyrmm-agent version`).

## Cutting a release

1. On `main`, with CI green, move the changelog's `[Unreleased]` entries
   under a new heading `## [1.2.3] - YYYY-MM-DD`. The workflow refuses a tag
   without that section, and the section becomes the release notes.
2. Commit, then tag and push:

   ```bash
   git tag -s easyrmm-v1.2.3 -m "EasyRMM 1.2.3"
   git push origin easyrmm-v1.2.3
   ```

3. Watch the **Release** workflow. It:
   1. checks the tag's form and finds its changelog section;
   2. runs the backend, integration and frontend checks again on the tagged
      commit;
   3. builds the server image, checks it reports the version, and scans it
      with Trivy (high and critical fixable findings fail the release);
   4. pushes the image for amd64 and arm64 to
      `ghcr.io/paulmataruso/easyrmm-server`, with an SBOM, build provenance
      and a GitHub attestation;
   5. builds the release files with `scripts/release/bundle.sh`, attests
      them, and creates the GitHub release with the changelog's notes.

If any step fails, nothing after it runs. The image is pushed only after
every check passes, and the GitHub release is created only after the image
is pushed. To retry after fixing a problem in the workflow, delete the tag
and the draft release (if any), then tag again. Never move a published tag.

## What a release contains

| File | Contents |
|---|---|
| `easyrmm-v1.2.3-deploy.tar.gz` | In the repository's layout: `deploy/` (`docker-compose.yml`, `.env.example` pinned to this release's image, `scripts/setup.sh`), the PostgreSQL and MeshCentral start scripts the Compose file mounts from `docker/`, the deployment, agent, backup and upgrade guides, `LICENSE` and `CHANGELOG.md`. `bundle.sh` refuses to build a bundle that lacks a file the Compose file mounts |
| `easyrmm-agent-<os>-<arch>[.exe]` | The agents for Windows (amd64, arm64) and Linux (amd64, arm64, arm, 386). The server image carries the same agents and serves them to devices; these are for inspection and offline installs |
| `SHA256SUMS` | Checksums of the files above |

The files are reproducible. Given the same commit and Go version,
`scripts/release/bundle.sh easyrmm-v1.2.3 out/` builds the same bytes: archive entries
are sorted, owned by root and dated at the commit. Compare your build's
`SHA256SUMS` with the release's to check that a release matches its source.

## Verifying a release

```bash
sha256sum -c SHA256SUMS
gh attestation verify easyrmm-v1.2.3-deploy.tar.gz --repo paulmataruso/easyrmm
gh attestation verify oci://ghcr.io/paulmataruso/easyrmm-server:1.2.3 --repo paulmataruso/easyrmm
```

## EasyPatch releases

EasyPatch, in `easypatch/`, is built and released on its own:

* Its tags are `easypatch-v1.2.3`. The version must match `<Version>` in
  `easypatch/Directory.Build.props` and a section of
  `easypatch/CHANGELOG.md`.
* Pushing one runs `.github/workflows/easypatch-release.yml`. It runs
  EasyPatch's tests, builds and release-signs the agent packages, pushes the
  server and proxy images for x64 and ARM64 to GitHub Container Registry,
  and creates a GitHub release, never marked Latest.
* No EasyPatch release has been published from this repository yet.
  Releases up to 1.10.0, with their downloads, are in EasyPatch's
  [former repository](https://github.com/paulmataruso/EasyPatch/releases).
* Release signing:
  [easypatch/docs/security.md](../../easypatch/docs/security.md#agent-release-signing).

## Before the first public release

* Licence clearance for the EasyPatch-derived stylesheet and logo (ADR-0013).
* The workflow has not run on GitHub yet. Pushing workflow files needs a
  token with the `workflow` scope.
