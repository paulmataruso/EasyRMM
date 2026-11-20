# Releasing

Releases are cut by pushing a version tag. `.github/workflows/release.yml`
does the rest; nothing is published from a laptop. Each EasyRMM release
carries the patching engine built from the same commit
([ADR-0043](../architecture/adr/0043-one-release.md)), and it is the only
release: the engine is not released on its own
([ADR-0046](../architecture/adr/0046-what-one-product-retires.md)).

## Versions

Semantic versioning, tags `easyrmm-v1.2.3`. A pre-release adds a suffix,
`easyrmm-v1.2.3-rc.1`. The `easyrmm-` prefix keeps EasyRMM's tags apart from
EasyPatch's old ones (`easypatch-v1.10.0`), which this repository also holds
and which nothing releases any more.

| Tag | EasyRMM's image tags | The engine's image tags | GitHub release |
|---|---|---|---|
| `easyrmm-v1.2.3` | `1.2.3`, `1.2`, `latest` | its version (`1.10.1`), `latest` | Release, marked Latest |
| `easyrmm-v1.2.3-rc.1` | `1.2.3-rc.1` only | its version only | Pre-release |

The server, the console and the agents carry the tag without its prefix as
their version, `v1.2.3` (`easyrmm-server version`, `easyrmm-agent version`).

### The patching engine's version

The engine keeps EasyPatch's own version line, because EasyPatch agents
choose updates by version: `<Version>` in `easypatch/Directory.Build.props`,
1.10.0 and up. A version is published once. A release whose engine version
was already published from another commit fails before anything is signed,
so **every EasyRMM release raises `<Version>`**, sets the same version in
`eptest.EngineVersion` (`server/internal/easypatch/eptest/eptest.go`; the
contract test fails until they match), and moves
`easypatch/CHANGELOG.md`'s `[Unreleased]` entries under `## [1.10.1] -
YYYY-MM-DD`. Running a failed release again for the same commit is allowed.

## One-time setup

Done once per repository, before the first release:

1. The `easypatch-release` environment, admitting only `easyrmm-v*` tags,
   with the release private key as its secret `EASYPATCH_RELEASE_KEY`:

   ```bash
   gh api -X PUT repos/paulmataruso/EasyRMM/environments/easypatch-release \
     -F 'deployment_branch_policy[protected_branches]=false' \
     -F 'deployment_branch_policy[custom_branch_policies]=true'
   gh api -X POST repos/paulmataruso/EasyRMM/environments/easypatch-release/deployment-branch-policies \
     -f name='easyrmm-v*' -f type=tag
   gh secret set EASYPATCH_RELEASE_KEY --env easypatch-release --repo paulmataruso/EasyRMM \
     < easypatch-release-key.pem
   ```

   The key must match `easypatch/keys/easypatch-release-key.pub.pem`
   (`openssl pkey -in easypatch-release-key.pem -pubout` prints it).
2. Write access for this repository's workflows to the engine's package.
   `ghcr.io/paulmataruso/easypatch-server` was created by EasyPatch's former
   repository, and a package admits only the workflows it lists. In the
   package's settings on GitHub (Your profile → Packages →
   easypatch-server → Package settings), under **Manage Actions access**,
   add the repository `paulmataruso/EasyRMM` with the role **Write**. There
   is no API for this. Without it the release fails when it first pushes the
   engine's image, before any tag anyone pulls.
3. Both packages public (Package settings → Danger Zone → Change
   visibility), so that a server pulls them without signing in. Both are
   public as of 2026-11-20.

## Cutting a release

1. On `main`, with CI green, move the changelog's `[Unreleased]` entries
   under a new heading `## [1.2.3] - YYYY-MM-DD`. The workflow refuses a tag
   without that section, and the section becomes the release notes. Raise
   the engine's version and move its changelog entries the same way
   ([above](#the-patching-engines-version)).
2. Commit, then tag and push:

   ```bash
   git tag -s easyrmm-v1.2.3 -m "EasyRMM 1.2.3"
   git push origin easyrmm-v1.2.3
   ```

3. Watch the **Release** workflow. It:
   1. checks the tag's form and finds its changelog section;
   2. checks the engine's version: its `easypatch/CHANGELOG.md` section, the
      release public key, and that no engine image of that version was
      published from another commit;
   3. runs every CI check again on the tagged commit: the backend,
      integration and frontend checks, and the engine's (its tests, package
      licences and vulnerable packages, an image built with test packages)
      and its agents' tests;
   4. builds the EasyPatch agent's Windows MSIs and Linux packages for x64
      and ARM64, signed with the release key (the `easypatch-release`
      environment's secret);
   5. builds EasyRMM's server image, checks it reports the version, scans it
      with Trivy (high and critical fixable findings fail the release) and
      pushes it for amd64 and arm64 to `ghcr.io/paulmataruso/easyrmm-server`,
      with an SBOM, build provenance and a GitHub attestation;
   6. builds the engine's image on each architecture carrying those
      packages, checks it carries them read-only and holds no secrets, scans
      it with Trivy the same way, and pushes it to
      `ghcr.io/paulmataruso/easypatch-server` with an SBOM, build
      provenance, the commit recorded, and a GitHub attestation;
   7. builds the release files with `scripts/release/bundle.sh`, with the
      engine pinned by digest, attests them, and creates the GitHub release
      with the changelog's notes and the engine's version.

If any step fails, nothing after it runs. No image is pushed until every
test has passed. The engine's images are pushed first under
per-architecture tags only (`1.10.1-amd64`, `1.10.1-arm64`), which nothing
pulls; EasyRMM's tags and then the engine's version and `latest` follow
only after both images passed their checks and scans, and the GitHub
release only after all of them. The agent packages are signed with the `easypatch-release`
environment's key, so that environment's deployment rule must admit
`easyrmm-v*` tags. To retry after fixing a problem in the workflow, delete
the tag and the draft release (if any), then tag again. Never move a
published tag.

## What a release contains

| File | Contents |
|---|---|
| `easyrmm-v1.2.3-deploy.tar.gz` | In the repository's layout (`scripts/release/deploy-tree.sh`): `deploy/` (`docker-compose.yml` with the patching engine pinned by digest, `.env.example` pinned to this release's image, `scripts/setup.sh`), the PostgreSQL and MeshCentral start scripts the Compose file mounts from `docker/`, the deployment, agent, backup and upgrade guides, `LICENSE` and `CHANGELOG.md`. `bundle.sh` refuses to build a bundle that lacks a file the Compose file mounts, or whose engine is not pinned |
| `easyrmm-v1.2.3-manifest.json` | The commit, EasyRMM's version and image digest, the engine's version and image digest, and the name and SHA-256 of each EasyPatch agent package the engine's image carries |
| `easyrmm-agent-<os>-<arch>[.exe]` | The agents for Windows (amd64, arm64) and Linux (amd64, arm64, arm, 386). The server image carries the same agents and serves them to devices; these are for inspection and offline installs |
| `SHA256SUMS` | Checksums of the files above |

The files are reproducible. Given the same commit, Go version and the image
pins from the release's manifest,

```bash
EASYRMM_IMAGE_PIN=<easyrmm.image> EASYPATCH_IMAGE_PIN=<easypatch.image> \
  EASYPATCH_PACKAGES=<the agent packages> scripts/release/bundle.sh easyrmm-v1.2.3 out/
```

builds the same bytes: archive entries are sorted, owned by root and dated at
the commit. Compare your build's `SHA256SUMS` with the release's to check
that a release matches its source.

## Verifying a release

```bash
sha256sum -c SHA256SUMS
gh attestation verify easyrmm-v1.2.3-deploy.tar.gz --repo paulmataruso/easyrmm
gh attestation verify oci://ghcr.io/paulmataruso/easyrmm-server:1.2.3 --repo paulmataruso/easyrmm
gh attestation verify oci://ghcr.io/paulmataruso/easypatch-server:1.10.1 --repo paulmataruso/easyrmm
```

## The patching engine's earlier releases

The engine is released only with EasyRMM (above). Before EasyPatch became
part of EasyRMM it was released on its own, up to 1.10.0:

* Those releases, with their downloads, stay in EasyPatch's
  [former repository](https://github.com/paulmataruso/EasyPatch/releases);
  their tags are in this repository as `easypatch-v1.10.0` and older. A
  server running one is imported
  ([Importing a standalone EasyPatch](../operations/import-easypatch.md)).
* The experimental macOS agent packages were published only with those
  releases. They are not in the engine's image, and an EasyRMM release does
  not build them: `easypatch/scripts/build-macos-packages.sh` builds and
  signs them by hand.
* How agent packages are signed and checked:
  [Agent release signing](../architecture/patching-engine.md#agent-release-signing)
  and [CODE_SIGNING.md](../../CODE_SIGNING.md).
