# Code signing policy

EasyRMM's releases are built and signed only by the release workflow
([`.github/workflows/release.yml`](.github/workflows/release.yml)) on
GitHub-hosted runners, from the commit a release tag names. Nothing is
signed or published from a developer's computer. This page says what is
signed, with which key, who can sign, and how to check a signature.

## Roles

| Role | Who | What it means |
|---|---|---|
| Author | The maintainer, [Paul Mataruso](https://github.com/paulmataruso) (DHI Technical Services LLC) | Commits to this repository. The maintainer's account is the only one with write access |
| Reviewer | The maintainer | Reviews every pull request from anyone else before it is merged |
| Approver | The maintainer | Decides that a commit is released and signed, by pushing an `easyrmm-v*` tag |

The release signing key is available only to workflow runs started by an
`easyrmm-v*` tag (the `easypatch-release` environment's deployment rule).
Pull requests, including those from forks, never reach it.

## What is signed

| What | Signature | Key | Checked by |
|---|---|---|---|
| **EasyPatch agent packages**: the Windows MSIs (x64, arm64) and the Linux DEB and RPM packages in the patching engine's image | ECDSA P-256 over the package's file name, version, architecture, size and SHA-256, in a `.sig` file beside each package | The **release key**, key ID `75435ab3040ce415`; public key in [`easypatch/keys/easypatch-release-key.pub.pem`](easypatch/keys/easypatch-release-key.pub.pem) (SHA-256 of the key `75435ab3040ce4151b0de211435dacde005fed7c8e848ceb9db950bdca8c425c`) | The EasyPatch agent, before it updates itself: it installs only a package signed by a key it carries |
| **Release files**: the deployment bundle, its manifest, the EasyRMM agents and `SHA256SUMS` | A GitHub artifact attestation (Sigstore), tied to the release workflow run and the tagged commit; `SHA256SUMS` lists every file | No long-lived key: the workflow's GitHub identity, through Sigstore | `gh attestation verify` (below) |
| **Container images**: `ghcr.io/paulmataruso/easyrmm-server` and `ghcr.io/paulmataruso/easypatch-server` | A GitHub attestation, with an SBOM and build provenance | As above | `gh attestation verify oci://…` (below) |

The release key's private half is held by the maintainer, offline, and as
the secret `EASYPATCH_RELEASE_KEY` of this repository's `easypatch-release`
environment. It is never committed (see [`.gitignore`](.gitignore) and
[SECURITY.md](SECURITY.md)), never printed in logs, and used only by the
release workflow's signing step.

### Signed by each deployment, not by us

Inside a deployment, the server signs what it sends to its agents with its
own key, made when it was installed: script jobs, and the instruction to
update an agent, which names the new build's SHA-256
([ADR-0027](docs/architecture/adr/0027-agent-updates.md)).
The agent checks the signature against the key it pinned when it
enrolled, then the download's size and SHA-256. Those keys belong to the
operator; we never hold them.

Operators can also sign the Windows EasyRMM agent with their own code
signing certificate ([ADR-0049](docs/architecture/adr/0049-operators-sign-windows-agents.md)):
they download the server's Windows builds from **Settings → Agent
updates**, sign them with their own tools and key, and upload them there.
The server checks that each file is its own build with only an
Authenticode signature added, and hands it out instead; Windows then names
the operator as the publisher. The server never holds the operator's key
([guide](docs/deployment/agents.md#signing-the-windows-agent)).

## Not signed yet

* **Windows code signing (Authenticode).** EasyRMM has no code signing
  certificate from a public certificate authority yet, so `easyrmm-agent.exe`
  and the EasyPatch agent's MSIs carry no Authenticode signature, and
  Windows names no publisher for them. Their integrity rests on HTTPS, the
  checksums above, the release key (EasyPatch agent) and the server's
  signed instructions (EasyRMM agent). The EasyPatch agent's build can
  apply an Authenticode signature when given a certificate; the EasyRMM
  agent's build cannot. Operators can sign the EasyRMM agent with their
  own certificate (above); the EasyPatch agent's MSIs cannot be signed
  that way yet.
* **Git tags and commits** are not signed with a GPG or SSH key. Commits
  carry a `Signed-off-by` line ([CONTRIBUTING.md](CONTRIBUTING.md)), which
  is a statement, not a signature. Merge commits made on GitHub are signed
  by GitHub.
* **macOS packages** of the EasyPatch agent are experimental and not
  released.

## Verifying a release

```bash
sha256sum -c SHA256SUMS
gh attestation verify easyrmm-v1.2.3-deploy.tar.gz --repo paulmataruso/EasyRMM
gh attestation verify oci://ghcr.io/paulmataruso/easyrmm-server:1.2.3 --repo paulmataruso/EasyRMM
gh attestation verify oci://ghcr.io/paulmataruso/easypatch-server:<engine version> --repo paulmataruso/EasyRMM
```

An EasyPatch agent package and its `.sig` file can be checked with the
release signer:

```bash
dotnet run --project easypatch/tools/EasyPatch.ReleaseSigner -- \
  verify --public-key easypatch/keys/easypatch-release-key.pub.pem EasyPatchAgent-<version>-x64.msi
```

## If the release key is lost or exposed

1. Remove the secret from the `easypatch-release` environment, so no
   release can be signed with it.
2. Publish a security advisory naming the key ID and the releases
   affected.
3. Release EasyPatch agents that carry a new key beside the old one, then
   sign with the new key only, and release agents that no longer carry
   the old one. An agent installs only what a key it carries has signed,
   so it moves to the new key through a release signed with the old one.

A lost key whose secret is still in the environment can be rotated the
same way, without the advisory.

## Privacy

What EasyRMM collects and every connection it makes on its own are in the
[privacy policy](PRIVACY.md). In short: this program will not transfer any
information to other networked systems unless specifically requested by
the user or the person installing or operating it.
