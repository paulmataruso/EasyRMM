
## Install or upgrade

**Server** (x64 or ARM64 Linux): image `ghcr.io/paulmataruso/easypatch-server:@VERSION@`. EasyPatch is EasyRMM's
patching engine and runs in EasyRMM's deployment, which names the engine image it runs; it has no installation of its
own. A standalone EasyPatch server (1.4 to 1.10) moves into EasyRMM:
[Importing a standalone EasyPatch](https://github.com/paulmataruso/EasyRMM/blob/easypatch-v@VERSION@/docs/operations/import-easypatch.md).

**Agents**: the server image carries this release's Windows and Linux packages with their `.sig` files, so the server
offers them as soon as it runs. Agents (Windows 1.2.0 and later, all Linux agents) then update themselves when the
*Agent updates* policy is *Automatic*.

| File | For |
|---|---|
| `EasyPatchAgent-@VERSION@-x64.msi`, `-arm64.msi` | Windows 10, 11 and Server 2016 or later |
| `EasyPatchAgent-@VERSION@-x64.deb`, `-arm64.deb` | Debian and Ubuntu |
| `EasyPatchAgent-@VERSION@-x64.rpm`, `-arm64.rpm` | RHEL, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream and Fedora |
| `EasyPatchAgent-@VERSION@-x64.pkg`, `-arm64.pkg` | **Experimental, not for production use:** macOS 14 or later on Intel (`x64`) and Apple silicon (`arm64`); see [docs/macos-agent.md](https://github.com/paulmataruso/EasyRMM/blob/easypatch-v@VERSION@/easypatch/docs/macos-agent.md) |
| `*.sig` | Release signatures, verified by the agents before they update |
| `easypatch-release-key.pub.pem` | The release public key built into these agents |
| `SHA256SUMS` | SHA-256 of every file: `sha256sum --check --ignore-missing SHA256SUMS` |

The MSIs are not Authenticode-signed, so Windows SmartScreen may warn when one is opened by hand.

> [!WARNING]
> **The macOS agent is experimental: it is in development and not for production use.** It has not yet been used to
> patch a real Mac. On Apple silicon it cannot install macOS updates (Apple allows only a volume owner or MDM to), it
> restarts without an on-screen warning, and the `.pkg` is not signed with an Apple Developer ID or notarized. Use it
> only on test Macs. The server image does not carry the `.pkg` files.

## License

EasyPatch, part of EasyRMM, is licensed under the [Functional Source License 1.1, ALv2 Future License](https://github.com/paulmataruso/EasyRMM/blob/easypatch-v@VERSION@/LICENSE.md):
free to use, including by MSPs for their clients' computers, but not to sell or offer as a competing product or service.
Each release becomes available under the Apache License 2.0 two years after it is published.
