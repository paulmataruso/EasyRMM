#!/usr/bin/env bash
# Builds the EasyPatch Linux agent packages: publishes easypatch-agent (self-contained, single file) and packages it as
# a .deb (Debian, Ubuntu) and an .rpm (RHEL, Rocky, AlmaLinux, Oracle Linux 8+) per architecture, in a pinned container
# (agent/Installer/linux-packages/Dockerfile) with networking disabled.
#
#   scripts/build-linux-packages.sh [--version 1.10.0] [--arch x64|arm64|all] [--no-test]
#
# Output: artifacts/linux/EasyPatchAgent-<version>-<arch>.deb and .rpm, each with .sha256. The release public key
# (EASYPATCH_RELEASE_PUBLIC_KEY, default ~/.easypatch/easypatch-release-key.pub.pem) is built into the agent, and each
# package gets a release signature (<package>.sig) made with the private key (EASYPATCH_RELEASE_KEY, default
# ~/.easypatch/easypatch-release-key.pem). Copy the packages and their .sig files to the server's agent-packages directory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.10.0"
arches=("x64")
run_tests=1
image="easypatch-linux-package-builder:rpm6.0.1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch)
      if [[ "$2" == "all" ]]; then arches=("x64" "arm64"); else arches=("$2"); fi
      shift 2 ;;
    --no-test) run_tests=0; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}$ ]]; then
  echo "version must be MAJOR.MINOR.BUILD, got '$version'" >&2
  exit 2
fi

for arch in "${arches[@]}"; do
  [[ "$arch" == "x64" || "$arch" == "arm64" ]] || { echo "unsupported architecture: $arch" >&2; exit 2; }
done

export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
cd "$repo_root"

public_key="${EASYPATCH_RELEASE_PUBLIC_KEY:-$HOME/.easypatch/easypatch-release-key.pub.pem}"
key_args=()
if [[ -f "$public_key" ]]; then
  public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
  grep -q "BEGIN PUBLIC KEY" "$public_key" || { echo "$public_key is not a PEM public key" >&2; exit 2; }
  key_args=("-p:EasyPatchReleasePublicKey=$public_key")
  echo "==> Release public key: $public_key (agents install only updates signed with its private key)"
else
  echo "WARNING: no release public key at $public_key: this agent will not be able to update itself." >&2
fi

echo "==> Building the Linux agent ($version, warnings are errors)"
for project in agent/EasyPatch.Linux/EasyPatch.Linux.csproj agent/EasyPatch.Agent.Linux/EasyPatch.Agent.Linux.csproj agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj; do
  dotnet build "$project" -c Release "-p:Version=$version" "${key_args[@]}"
done

if [[ $run_tests -eq 1 ]]; then
  echo "==> Running agent tests"
  dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj -c Release --no-build
fi

echo "==> Building the package builder image ($image)"
docker build -q -t "$image" agent/Installer/linux-packages >/dev/null

mkdir -p artifacts/linux
built=()
for arch in "${arches[@]}"; do
  publish="artifacts/agent/linux-$arch"
  echo "==> Publishing linux-$arch to $publish"
  rm -rf "$publish"
  dotnet publish agent/EasyPatch.Agent.Linux/EasyPatch.Agent.Linux.csproj -c Release -r "linux-$arch" -o "$publish" \
    "-p:Version=$version" -p:ContinuousIntegrationBuild=true -p:DebugType=none "${key_args[@]}"
  extra="$(find "$publish" -type f ! -name easypatch-agent | head -5)"
  [[ -z "$extra" ]] || { echo "unexpected files next to the single-file agent: $extra" >&2; exit 1; }

  case "$arch" in
    x64) deb_arch=amd64; rpm_arch=x86_64 ;;
    arm64) deb_arch=arm64; rpm_arch=aarch64 ;;
  esac
  deb="EasyPatchAgent-$version-$arch.deb"
  rpm="EasyPatchAgent-$version-$arch.rpm"
  rm -f "artifacts/linux/$deb"* "artifacts/linux/$rpm"*
  echo "==> Building $deb and $rpm"
  docker run --rm --network none \
    -v "$repo_root/agent/Installer/linux-packages:/pkg:ro" \
    -v "$repo_root/$publish:/publish:ro" \
    -v "$repo_root/artifacts/linux:/out" \
    "$image" sh -euc '
      version="$1"; deb_arch="$2"; rpm_arch="$3"; deb="$4"; rpm="$5"

      # ---- .deb
      root=/tmp/deb
      install -d -m 0755 "$root/DEBIAN" "$root/opt/easypatch" "$root/usr/sbin" "$root/usr/lib/systemd/system" "$root/etc/needrestart/conf.d"
      install -m 0755 /publish/easypatch-agent "$root/opt/easypatch/easypatch-agent"
      ln -s ../../opt/easypatch/easypatch-agent "$root/usr/sbin/easypatch-agent"
      install -m 0644 /pkg/easypatch-agent.service "$root/usr/lib/systemd/system/easypatch-agent.service"
      install -m 0644 /pkg/needrestart.conf "$root/etc/needrestart/conf.d/easypatch-agent.conf"
      install -m 0644 /pkg/deb/conffiles "$root/DEBIAN/conffiles"
      for script in postinst prerm postrm; do install -m 0755 "/pkg/deb/$script" "$root/DEBIAN/$script"; done
      size="$(du -sk --exclude=DEBIAN "$root" | cut -f1)"
      sed -e "s/@VERSION@/$version/" -e "s/@DEBARCH@/$deb_arch/" -e "s/@SIZE@/$size/" /pkg/deb/control.in > "$root/DEBIAN/control"
      dpkg-deb --root-owner-group -Zxz --build "$root" "/out/$deb" >/dev/null
      dpkg-deb --info "/out/$deb" | grep -q "Package: easypatch-agent"

      # ---- .rpm
      mkdir -p /tmp/src
      install -m 0755 /publish/easypatch-agent /tmp/src/easypatch-agent
      install -m 0644 /pkg/easypatch-agent.service /tmp/src/easypatch-agent.service
      rpmbuild -bb --quiet --target "$rpm_arch" \
        --define "_topdir /tmp/rpmbuild" --define "ep_version $version" --define "ep_source /tmp/src" \
        /pkg/rpm/easypatch-agent.spec >/dev/null
      cp "/tmp/rpmbuild/RPMS/$rpm_arch/easypatch-agent-$version-1.$rpm_arch.rpm" "/out/$rpm"
      rpm -qp --qf "%{NAME} %{VERSION} %{ARCH}\n" "/out/$rpm" | grep -q "^easypatch-agent $version $rpm_arch$"

      # The packaged agent must be byte-identical to the published one (no stripping).
      want="$(sha256sum /publish/easypatch-agent | cut -d" " -f1)"
      dpkg-deb --fsys-tarfile "/out/$deb" > /tmp/payload.tar
      tar -xOf /tmp/payload.tar ./opt/easypatch/easypatch-agent | sha256sum | grep -q "^$want "
      rpm2cpio "/out/$rpm" > /tmp/payload.cpio
      (cd /tmp && cpio -id --quiet ./opt/easypatch/easypatch-agent < /tmp/payload.cpio)
      sha256sum /tmp/opt/easypatch/easypatch-agent | grep -q "^$want "
      chown "$(stat -c %u:%g /out)" "/out/$deb" "/out/$rpm"' sh "$version" "$deb_arch" "$rpm_arch" "$deb" "$rpm"

  for name in "$deb" "$rpm"; do
    hash="$(sha256sum "artifacts/linux/$name" | cut -d' ' -f1)"
    printf '%s  %s' "$hash" "$name" > "artifacts/linux/$name.sha256"
    echo "    artifacts/linux/$name"
    echo "    SHA-256 $hash"
    built+=("artifacts/linux/$name")
  done
done

release_key="${EASYPATCH_RELEASE_KEY:-$HOME/.easypatch/easypatch-release-key.pem}"
if [[ -f "$release_key" ]]; then
  echo "==> Signing the release (agent self-update)"
  dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- sign --key "$release_key" "${built[@]}"
  if [[ -f "$public_key" ]]; then
    # The packages must verify against the public key built into the agent, or no agent will install them.
    dotnet run --project tools/EasyPatch.ReleaseSigner -c Release --no-build -- verify --public-key "$public_key" "${built[@]}"
  fi
else
  rm -f "${built[@]/%/.sig}"
  echo "WARNING: no release key at $release_key: the packages are not signed, so agents will not update themselves to them." >&2
fi
