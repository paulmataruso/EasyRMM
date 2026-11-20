# ADR-0043: One release

* Status: Accepted (2026-11-18)
* Plan: [one product](../one-product-plan.md), phase B8.
* Refines: [ADR-0041](0041-agent-packages-in-the-engine-image.md) (agent
  packages in the engine's image).

## Context
EasyRMM's deployment runs EasyPatch's engine beside EasyRMM's server, but the
two were released apart: EasyRMM by `easyrmm-v*` tags, the engine by
`easypatch-v*` tags, and the compose file named the engine's image by a tag in
`.env` (`dev` by default, built from a clone). A deployment could run any
engine with any EasyRMM, and an EasyRMM release did not say which engine it
was tested with.

EasyPatch agents choose updates by version, so one version must never be two
builds. Nothing stopped a second build of a published version from replacing
the first under the same tag.

## Decision
* **EasyRMM's release builds the engine.** `release.yml` calls
  `easypatch-release.yml` as a reusable workflow on the same commit. It runs
  EasyPatch's tests, signs the agent packages with the release key, and
  pushes the engine's server image (amd64 and arm64) carrying them. The
  index records the commit (`org.opencontainers.image.revision`).
* **The engine keeps its own version line**, `<Version>` in
  `easypatch/Directory.Build.props`, above 1.10.0. A version is published
  once: the workflow refuses a version whose image was published from
  another commit, or before images recorded their commit, before anything is
  signed. Running a release again for the same commit is allowed. Every
  EasyRMM release therefore raises the engine's version.
* **The bundle's compose file pins the engine by digest.** `bundle.sh`
  rewrites the engine's three image lines to
  `ghcr.io/<owner>/easypatch-server:<version>@sha256:<digest>` and drops the
  build from `../easypatch`, so a pinned engine is never built. Upgrading the
  bundle upgrades both programs together; `.env` cannot pair them wrongly.
* **A manifest** (`easyrmm-<version>-manifest.json`) records the commit, both
  images by digest, the engine's version, and the SHA-256 of each agent
  package the engine's image carries. The release notes name the engine's
  version.
* **One deployment tree.** `scripts/release/deploy-tree.sh` writes the files a
  release ships. `bundle.sh` packs it; the bundle test brings it up.
* **The bundle test** (`make e2e-bundle`, CI's *Bundle end to end*) runs on
  every change to EasyRMM or EasyPatch. It builds both images from the commit
  (the engine with Linux packages signed by a key made for the run), sets up
  that tree with `setup.sh --patching bundled` for an IP address, brings it
  up on host networking, and checks that only the edge listens beyond
  loopback. Then, with a Debian machine running systemd on the host's
  network:
  1. Playwright makes the first account on the first-run page, with a second
     factor, and a site;
  2. the machine runs the console's install command; EasyRMM installs the
     EasyPatch agent, which enrolls through EasyRMM's address with EasyRMM's
     authority ([ADR-0042](0042-agents-trust-easyrmms-authority.md)) and
     links;
  3. a scan finds the update a local package repository offers
     (`easyrmm-e2e-demo` 1.0.0 to 1.1.0), and installing it from EasyRMM
     changes the package on the machine;
  4. the engine refuses missing, malformed, forged, altered, expired and
     replayed statements (another path, method or query), a read-only role
     acting, and another organization's data; EasyRMM's edge never forwards
     its API.
* **EasyPatch can still be released alone** with an `easypatch-v*` tag until
  phase R folds its workflow into `release.yml`.

## Consequences
* The `easypatch-release` environment, whose key signs the agent packages,
  must admit `easyrmm-v*` tags.
* A release takes longer: the engine's tests, its Windows MSIs and its images
  are built in it.
* A clone still builds the engine from `easypatch/` (tag `dev`), so the
  compose file in the repository is not pinned; only release bundles are.
* The bundle test needs a privileged container (systemd as init), so it runs
  on CI's runners and on developer machines, never against shared hosts.
