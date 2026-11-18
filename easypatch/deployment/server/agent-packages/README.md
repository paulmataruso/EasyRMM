# Agent packages for the server image

The server image's build copies the `EasyPatchAgent-*` files in this
directory to `/app/agent-packages`, from where the server offers them. They
are staged here, never committed:

* **Releases:** the release workflow stages the packages it built and
  release-signed, with `scripts/stage-agent-packages.sh`, after checking
  every signature against `keys/easypatch-release-key.pub.pem`.
* **CI and tests:** `scripts/build-test-agent-packages.sh` stages Linux
  packages signed with a throwaway key. Their agents trust only that key, and
  no released agent trusts it. Such an image must never be published.

A build with nothing staged carries no packages.
`scripts/check-image-agent-packages.sh <image>` checks that an image carries
exactly what is staged.
