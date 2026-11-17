
## Install or upgrade

**Server** (Docker Compose, x64 or ARM64 Linux): images `ghcr.io/paulmataruso/easypatch-server:@VERSION@` and
`ghcr.io/paulmataruso/easypatch-proxy:@VERSION@`. New installation: [docs/installation.md](https://github.com/paulmataruso/EasyPatch/blob/v@VERSION@/docs/installation.md).
Upgrade: back up, check out `v@VERSION@`, set `EASYPATCH_VERSION=@VERSION@` in `.env`, then `docker compose pull && docker compose up -d`.

**Agents**: copy the packages you need, with their `.sig` files, into the server's `data/agent-packages/` directory.
Agents (Windows 1.2.0 and later, all Linux agents) then update themselves when the *Agent updates* policy is *Automatic*.

| File | For |
|---|---|
| `EasyPatchAgent-@VERSION@-x64.msi`, `-arm64.msi` | Windows 10, 11 and Server 2016 or later |
| `EasyPatchAgent-@VERSION@-x64.deb`, `-arm64.deb` | Debian and Ubuntu |
| `EasyPatchAgent-@VERSION@-x64.rpm`, `-arm64.rpm` | RHEL, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream and Fedora |
| `EasyPatchAgent-@VERSION@-x64.pkg`, `-arm64.pkg` | **Experimental, not for production use:** macOS 14 or later on Intel (`x64`) and Apple silicon (`arm64`); see [docs/macos-agent.md](https://github.com/paulmataruso/EasyPatch/blob/v@VERSION@/docs/macos-agent.md) |
| `*.sig` | Release signatures, verified by the agents before they update |
| `easypatch-release-key.pub.pem` | The release public key built into these agents |
| `SHA256SUMS` | SHA-256 of every file: `sha256sum --check --ignore-missing SHA256SUMS` |

The MSIs are not Authenticode-signed, so Windows SmartScreen may warn when one is opened by hand.

> [!WARNING]
> **The macOS agent is experimental: it is in development and not for production use.** It has not yet been used to
> patch a real Mac. On Apple silicon it cannot install macOS updates (Apple allows only a volume owner or MDM to), it
> restarts without an on-screen warning, and the `.pkg` is not signed with an Apple Developer ID or notarized. Use it
> only on test Macs. Leave the `.pkg` files out of `data/agent-packages/` unless you are testing it.

## License

EasyPatch is licensed under the [Functional Source License 1.1, ALv2 Future License](https://github.com/paulmataruso/EasyPatch/blob/v@VERSION@/LICENSE.md):
free to use, including by MSPs for their clients' computers, but not to sell or offer as a competing product or service.
Each release becomes available under the Apache License 2.0 two years after it is published.
