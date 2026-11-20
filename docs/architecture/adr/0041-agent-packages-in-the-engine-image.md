# ADR-0041: Agent packages in the engine's image

* Status: Accepted (2026-11-18)
* Plan: the one-product plan (in the repository's history), phase B6.
* Refines: [ADR-0031](0031-easypatch-agent-install.md) (EasyRMM installs the
  EasyPatch agent from the packages the engine offers).

## Context
The patching engine offers the EasyPatch agent's packages
(`EasyPatchAgent-<version>-<arch>.<msi|deb|rpm|pkg>`) from one directory.
EasyRMM installs the agent from that list, and agents update themselves from
it. Until now an administrator downloaded each release's packages and copied
them into a mounted directory. A deployment missing that step installs no
agents, and nothing says why.

Each package has a release signature (`.sig`). The release workflow makes
them with a private key held in the `easypatch-release` environment, and
agents check them before updating, against the public key built into them.
The engine cannot check them, because it has no key, so whoever puts files in
that directory decides what agents are offered.

## Decision
* **The engine's image carries the agent packages of its own version.** The
  release workflow's image job waits for the signed Windows and Linux
  packages. `scripts/stage-agent-packages.sh` copies them into the build
  context only after checking every signature against the committed release
  public key, and stops if a format or architecture is missing. The
  Dockerfile copies them to `/app/agent-packages`, owned by root and
  read-only to the engine's user. After the build,
  `scripts/check-image-agent-packages.sh` checks that the image holds exactly
  those files, byte for byte, and that the engine's user cannot write there.
* **macOS packages stay out** while they are experimental.
* **EasyRMM's compose file no longer mounts a package directory**, which
  would hide the image's packages, and `setup.sh` no longer creates one.
* **CI images carry test packages.** `scripts/build-test-agent-packages.sh`
  makes a key pair for the run, builds the Linux agent with that public key
  built in, signs the packages with it, and deletes the private key. Agents
  in those packages trust that key only. The script checks that the release
  key refuses every one of the packages, so a test image cannot pass as a
  release. CI's image job checks the result as the release does.
* **No default key.** The staging and test scripts take keys only from their
  arguments, never from a developer's `~/.easypatch`.

## Consequences
* A bundled install offers the agent as soon as the engine runs. Upgrading
  the image upgrades the packages, and agents set to *Automatic* follow.
* The server image grows by the six packages; each Linux package is about
  30 MB.
* An image Compose builds from source carries no packages unless they are
  staged first. Until releases carry the engine's image (phase B8), EasyRMM
  cannot install the EasyPatch agent from such an image; test-signed packages
  are enough to try it.
* The standalone compose file (until phase R) still mounts
  `data/agent-packages/` over the image's packages, so its installation guide
  stays correct.
