# Releasing

Releases are cut by pushing a version tag. `.github/workflows/release.yml`
does the rest; nothing is published from a laptop. Each EasyRMM release
carries the patching engine built from the same commit
([ADR-0043](../architecture/adr/0043-one-release.md)), and it is the only
release: the engine is not released on its own
([ADR-0046](../architecture/adr/0046-what-one-product-retires.md)).

## Versions

Semantic versioning, tags `easyrmm-v1.2.3`. A release candidate adds
`-rc.N`, `easyrmm-v1.2.3-rc.1`; no other suffix is a release, so that the
updater can sort every version (ADR-0052). Tag only commits on `main`: the
release workflow refuses any other tag. The `easyrmm-` prefix keeps EasyRMM's tags apart from
EasyPatch's old ones (`easypatch-v1.10.0`), which this repository also holds
and which nothing releases any more.

| Tag | EasyRMM's image tags | The engine's image tags | GitHub release |
|---|---|---|---|
| `easyrmm-v1.2.3` | `1.2.3`, `1.2`, `latest` | its version (`1.10.1`), `latest` | Release, marked Latest |
| `easyrmm-v1.2.3-rc.1` | `1.2.3-rc.1` only | its version only | Pre-release |

A release published out of order (`easyrmm-v1.1.5` after `easyrmm-v1.2.0`)
gets `1.1` only if no published `1.1.x` ranks above it, and neither
`latest` nor GitHub's Latest: those stay with the highest release
published (`scripts/release/release-tags.sh`).

The server, the console and the agents carry the tag without its prefix as
their version, `v1.2.3` (`easyrmm-server version`, `easyrmm-agent version`).

### The patching engine's version

The engine keeps EasyPatch's own version line, because EasyPatch agents
choose updates by version: `<Version>` in `easypatch/Directory.Build.props`,
1.10.0 and up. A version is published once. A release whose engine version
was already published from another commit fails before anything is signed,
so **every EasyRMM release raises `<Version>`**, sets the same version in
`eptest.EngineVersion` (`server/internal/easypatch/eptest/eptest.go`;
`TestEngineVersion` in `server/internal/easypatch` fails until they match),
and moves
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
4. The two rulesets in `.github/rulesets/` (ADR-0052: what the release
   workflow attests must come from `main` and from administrators' tags):
   - `main.json`: `main` changes only by pull request, with the **CI
     result** check from GitHub Actions passed; no force-push or deletion.
   - `release-tags.json`: only the repository's administrators create, move
     or delete `easyrmm-v*` tags.

   ```bash
   for f in .github/rulesets/main.json .github/rulesets/release-tags.json; do
     gh api -X POST repos/paulmataruso/EasyRMM/rulesets --input "$f"
   done
   gh api repos/paulmataruso/EasyRMM/rulesets --jq '.[] | "\(.id) \(.name) \(.enforcement)"'
   ```

   To change one later, edit its file here, then run `gh api -X PUT
   repos/paulmataruso/EasyRMM/rulesets/<id> --input <file>`. Nothing reads
   these files except that command.
5. After the first edge build is published ([below](#edge-builds)),
   `ghcr.io/paulmataruso/easyrmm-deploy` public, as in step 3: CI creates
   it private. In its settings, and in `easyrmm-server`'s, **Manage Actions
   access** must list `paulmataruso/EasyRMM` with the role **Admin** for
   the retention workflow to delete old versions; a package that this
   repository's workflow created has it already. Both only in the browser.

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
   5. builds EasyRMM's server image once, for amd64 and arm64; checks the
      amd64 one reports the version, scans both with Trivy (high and
      critical fixable findings fail the release) and checks both images'
      agents against `scripts/release/agents.sh`'s, in a job that may write
      nothing and reads no build cache; then another job, with no scanner,
      whose tools come from the tag's checkout before it downloads anything,
      takes that layout by the artifact ID and digest the first recorded
      and pushes it unchanged to `ghcr.io/paulmataruso/easyrmm-server`,
      with an SBOM, build provenance and a GitHub attestation;
   6. builds the engine's image on each architecture carrying those
      packages, checks it carries them read-only and holds no secrets, scans
      it with Trivy the same way, and pushes it to
      `ghcr.io/paulmataruso/easypatch-server` with an SBOM, build
      provenance, the commit recorded, and a GitHub attestation;
   7. builds the release files with `scripts/release/bundle.sh`, with the
      engine pinned by digest; checks the bundle against its manifest
      (`scripts/release/check-bundle.sh`) and the agents against the server
      image's (`scripts/release/check-agents.sh`: the same bytes, which
      ADR-0049's signed agents need); attests them, and creates the GitHub
      release with the changelog's notes, the engine's version, and the
      Sigstore bundle of the attestation beside the manifest.

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

A version's server image is pushed once. Re-running a release's failed
jobs is safe: run again, the push finds its own image and pushes nothing
(`1.2` and `latest` move only with a version's first push; if a run
stopped between its tags, set them by hand with `oras tag`). Re-running
all jobs, or tagging again, builds another image, which the push refuses
under a version that has one: once a version's server image is pushed, a
retry is the next version (`-rc.N+1`, or the next patch).

## Edge builds

Every build of `main` is also a version, published once every CI job
passed ([ADR-0052](../architecture/adr/0052-the-host-updater.md); names,
fields and layout in
[Edge builds and the release manifest](../architecture/edge-manifest.md)):

* **Its version** comes from the last release tag reachable,
  `scripts/release/version.sh edge <run> <attempt>`: `v1.0.0-rc.4.edge.412.1`
  after a release candidate, `v1.0.1-edge.415.1` after a release. CI's
  first job, **Edge version**, computes it for every run, pull requests
  included.
* **The server image is built once**, for amd64 and arm64, as that
  version (`docker-build.yml`). Both platforms are scanned and their agents
  checked against `scripts/release/agents.sh`'s; the smoke test and the
  end-to-end jobs run the amd64 image, each loading it by the digest the
  build recorded, and for `main` the publish job pushes it unchanged.
* **The engine is the last release's**, by digest, from that release's
  manifest once its attestation verifies. The contract and bundle tests
  run against it as well as against the engine built from the commit, and
  the edge bundle and manifest are built and checked as the updater will
  check them (`check-bundle.sh`, `check-agents.sh`). Until the last
  release's GitHub release exists, these jobs are skipped and nothing is
  published.
* **Publishing**, only for a push to `main` in this repository and after
  every other job, installs its tools from the commit before it downloads
  anything; takes the image and the bundle by the artifact IDs their jobs
  recorded, outside its workspace, and only as the layout of the tested
  digest and the files whose SHA-256s the edge bundle job gave; checks
  that the manifest names this version, commit and image; then pushes the server image (`easyrmm-server:<version
  without v>` and `sha-<commit>`) with a GitHub attestation, attests the
  manifest, and pushes `easyrmm-deploy:<version>`: the bundle, the
  manifest and the manifest's Sigstore bundle (`oras`). Then **Edge build
  verified** pulls it back by digest and verifies it as the updater will,
  and **Move edge** tags both `edge`, the server image first, only ever to
  a higher version. ADR-0052 also has that test upgrade the previous edge
  build to this one; that joins it with the updater.
* **A version is published once.** If the publish job fails because its
  version is published already with another image or bundle (the Docker
  job was run again on its own), re-run all jobs: a new attempt is a new
  version. Re-running only failed jobs is otherwise safe: what was
  published already is kept.
* **Retention**: `edge-retention.yml` deletes edge builds older than 30
  days, daily, never the server image a kept bundle names. Run it by hand
  (**Run workflow**) for a dry run listing exactly what it would delete.

Pull requests run everything up to publishing: the version, the image,
the tests against both engines, and the edge bundle and manifest, with
the image's digest as it would be pushed. Nothing is pushed or attested.

To check the newest edge build by hand, as the updater does (every
certificate field ADR-0052 names: the CLI checks the issuer, identity,
ref, commit and runner, `jq` the repository ID, build config and trigger):

```bash
oras pull ghcr.io/paulmataruso/easyrmm-deploy:edge
m=$(ls easyrmm-*-manifest.json)
workflow=https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/main
gh attestation verify "$m" --bundle "$m.sigstore.json" --repo paulmataruso/EasyRMM \
  --cert-identity "$workflow" --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --source-ref refs/heads/main --source-digest "$(jq -r .commit "$m")" --deny-self-hosted-runners \
  --format json |
  jq -e --arg workflow "$workflow" 'length > 0 and all(.[]; .verificationResult.signature.certificate |
    .sourceRepositoryIdentifier == "1458774020" and .buildConfigURI == $workflow and .buildTrigger == "push")'
scripts/release/check-bundle.sh . "$(jq -r .version "$m")"
```

## What a release contains

| File | Contents |
|---|---|
| `easyrmm-v1.2.3-deploy.tar.gz` | In the repository's layout (`scripts/release/deploy-tree.sh`): `deploy/` (`docker-compose.yml` with every image pinned by digest, `.env.example` pinned to this release's image by tag and digest, `scripts/setup.sh`), the PostgreSQL and MeshCentral start scripts the Compose file mounts from `docker/`, the deployment, agent, backup and upgrade guides, `LICENSE` and `CHANGELOG.md`. `bundle.sh` refuses to build a bundle that lacks a file the Compose file mounts, or whose engine is not pinned |
| `easyrmm-v1.2.3-manifest.json` | Schema version 2 ([fields](../architecture/edge-manifest.md#the-manifest)): the version and commit, the bundle's name and SHA-256, EasyRMM's and the engine's versions and images by digest, the EasyPatch agent packages the engine's image carries, PostgreSQL's major version and image, MeshCentral's image, whether Authentik is included and its image, and every image the bundle runs |
| `easyrmm-v1.2.3-manifest.json.sigstore.json` | The Sigstore bundle of the release's attestation, to verify the manifest without GitHub's API |
| `easyrmm-agent-<os>-<arch>[.exe]` | The agents for Windows (amd64, arm64) and Linux (amd64, arm64, arm, 386). The server image carries the same agents and serves them to devices; these are for inspection and offline installs |
| `SHA256SUMS` | Checksums of the files above but the Sigstore bundle, which is made after them |

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
workflow=https://github.com/paulmataruso/EasyRMM/.github/workflows/release.yml@refs/tags/easyrmm-v1.2.3
gh attestation verify easyrmm-v1.2.3-manifest.json --bundle easyrmm-v1.2.3-manifest.json.sigstore.json \
  --repo paulmataruso/EasyRMM --cert-identity "$workflow" --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --source-ref refs/tags/easyrmm-v1.2.3 --source-digest "$(jq -r .commit easyrmm-v1.2.3-manifest.json)" \
  --deny-self-hosted-runners --format json |
  jq -e --arg workflow "$workflow" 'length > 0 and all(.[]; .verificationResult.signature.certificate |
    .sourceRepositoryIdentifier == "1458774020" and .buildConfigURI == $workflow and .buildTrigger == "push")'
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
