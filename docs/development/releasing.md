# Releasing

Releases are cut by pushing a version tag. `.github/workflows/release.yml`
does the rest; nothing is published from a laptop.

## Versions

Semantic versioning, tags `v1.2.3`. A pre-release adds a suffix,
`v1.2.3-rc.1`.

| Tag | Image tags | GitHub release |
|---|---|---|
| `v1.2.3` | `1.2.3`, `1.2`, `latest` | Release |
| `v1.2.3-rc.1` | `1.2.3-rc.1` only | Pre-release |

The server, the console and the agents carry the tag as their version
(`easyrmm-server version`, `easyrmm-agent version`).

## Cutting a release

1. On `main`, with CI green, move the changelog's `[Unreleased]` entries
   under a new heading `## [1.2.3] - YYYY-MM-DD`. The workflow refuses a tag
   without that section, and the section becomes the release notes.
2. Commit, then tag and push:

   ```bash
   git tag -s v1.2.3 -m "EasyRMM 1.2.3"
   git push origin v1.2.3
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
| `easyrmm-v1.2.3-deploy.tar.gz` | `docker-compose.yml`, `.env.example` pinned to this release's image, `scripts/setup.sh`, the deployment and backup guides, `LICENSE`, `CHANGELOG.md` |
| `easyrmm-agent-<os>-<arch>[.exe]` | The agents for Windows (amd64, arm64) and Linux (amd64, arm64, arm, 386). The server image carries the same agents and serves them to devices; these are for inspection and offline installs |
| `SHA256SUMS` | Checksums of the files above |

The files are reproducible. Given the same commit and Go version,
`scripts/release/bundle.sh v1.2.3 out/` builds the same bytes: archive entries
are sorted, owned by root and dated at the commit. Compare your build's
`SHA256SUMS` with the release's to check that a release matches its source.

## Verifying a release

```bash
sha256sum -c SHA256SUMS
gh attestation verify easyrmm-v1.2.3-deploy.tar.gz --repo paulmataruso/easyrmm
gh attestation verify oci://ghcr.io/paulmataruso/easyrmm-server:1.2.3 --repo paulmataruso/easyrmm
```

## Before the first public release

* Licence clearance for the EasyPatch-derived stylesheet and logo (ADR-0013).
* The workflow has not run on GitHub yet. Pushing workflow files needs a
  token with the `workflow` scope.
