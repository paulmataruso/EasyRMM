#!/bin/sh
# Assembles the macOS agent installer package in the package builder image (Dockerfile), the way pkgbuild and
# productbuild do: a component package (Bom, Payload, Scripts, PackageInfo) inside a product archive with a
# Distribution, all in a xar archive. Called by scripts/build-macos-packages.sh with networking disabled:
#
#   build-pkg.sh <version> <x64|arm64> <source date epoch>
#
# Reads the installer files from /pkg and the published agent from /publish; writes /out/EasyPatchAgent-<version>-<arch>.pkg.
# Payload, Scripts, Bom, PackageInfo and Distribution are reproducible (fixed owners, modes, order and timestamps);
# the xar wrapper records its creation time.
set -eu

version="$1"
arch="$2"
epoch="$3"
identifier=com.dhitechnical.easypatch.agent
component=easypatch-agent.pkg
name="EasyPatchAgent-$version-$arch.pkg"

case "$arch" in
    x64) host_arch=x86_64 ;;
    arm64) host_arch=arm64 ;;
    *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

umask 022
work="$(mktemp -d)"
root="$work/root"
scripts="$work/scripts"
flat="$work/flat"

# ---- payload: installed relative to /, everything root:wheel (0:0); directories 0755 like the system's own
install -d -m 0755 "$root" "$root/Library" "$root/Library/EasyPatch" "$root/Library/LaunchDaemons"
install -m 0755 /publish/easypatch-agent "$root/Library/EasyPatch/easypatch-agent"
install -m 0755 /pkg/uninstall.sh "$root/Library/EasyPatch/uninstall.sh"
install -m 0644 "/pkg/$identifier.plist" "$root/Library/LaunchDaemons/$identifier.plist"
install -d -m 0755 "$scripts"
install -m 0755 /pkg/scripts/postinstall "$scripts/postinstall"
find "$root" "$scripts" -exec touch -h -d "@$epoch" {} +

# cpio (odc) of the sorted tree, like pkgbuild's: owners 0:0, device numbers 0, inodes renumbered from 0 (GNU cpio
# leaves out the leading "./" of member names that pkgbuild writes); gzip without a name or time stamp.
archive() {
    (cd "$1" && find . | LC_ALL=C sort | cpio -o --quiet --format odc --owner 0:0 --reproducible) | gzip -9 -n
}

install -d -m 0755 "$flat" "$flat/$component"
archive "$root" > "$flat/$component/Payload"
archive "$scripts" > "$flat/$component/Scripts"
mkbom -u 0 -g 0 "$root" "$flat/$component/Bom"

files="$(find "$root" | wc -l)"
kbytes="$(find "$root" -type f -printf '%s\n' | awk '{ total += $1 } END { printf "%d", (total + 1023) / 1024 }')"
sed -e "s/@VERSION@/$version/g" -e "s/@FILES@/$files/g" -e "s/@KBYTES@/$kbytes/g" /pkg/PackageInfo.in > "$flat/$component/PackageInfo"
sed -e "s/@VERSION@/$version/g" -e "s/@KBYTES@/$kbytes/g" -e "s/@HOSTARCH@/$host_arch/g" /pkg/Distribution.in > "$flat/Distribution"
find "$flat" -exec touch -h -d "@$epoch" {} +

# xar prints a deprecation notice on every run: show its messages only when it fails.
run_xar() {
    xar "$@" 2> "$work/xar.log" || { cat "$work/xar.log" >&2; return 1; }
}

# Like productbuild: zlib-compressed Distribution, PackageInfo and Bom; Payload and Scripts (already gzip) stored;
# SHA-1 TOC and file checksums (xar's defaults).
(cd "$flat" && run_xar --compression gzip --no-compress 'Payload$' --no-compress 'Scripts$' -cf "$work/$name" Distribution "$component")

# ---- checks: the real tools first, then the structural check of everything in the package
listing="$(run_xar -tf "$work/$name" | LC_ALL=C sort | tr '\n' ' ')"
expected="Distribution $component $component/Bom $component/PackageInfo $component/Payload $component/Scripts "
[ "$listing" = "$expected" ] || { echo "unexpected xar contents: $listing" >&2; exit 1; }
mkdir "$work/check"
(cd "$work/check" && run_xar -xf "$work/$name" && gzip -dc "$component/Payload" | cpio -id --quiet)
cmp -s /publish/easypatch-agent "$work/check/Library/EasyPatch/easypatch-agent" || { echo "the packaged agent differs from the published one" >&2; exit 1; }
# The Bom (the installer's receipt of what was installed) must list the payload with the same owners, modes, sizes
# and CRC-32 checksums (cksum's).
bom="$(lsbom -d -p fmug "$work/check/$component/Bom"; lsbom -f -p fmugsc "$work/check/$component/Bom")"
want="$(
    cd "$work/check"
    for path in . ./Library ./Library/EasyPatch ./Library/LaunchDaemons; do
        printf '%s\t40755\t0\t0\n' "$path"
    done
    for entry in 100755:./Library/EasyPatch/easypatch-agent 100755:./Library/EasyPatch/uninstall.sh \
        "100644:./Library/LaunchDaemons/$identifier.plist"; do
        path="${entry#*:}"
        cksum < "$path" | { read -r crc size; printf '%s\t%s\t0\t0\t%s\t%s\n' "$path" "${entry%%:*}" "$size" "$crc"; }
    done
)"
if [ "$(printf '%s\n' "$bom" | LC_ALL=C sort)" != "$(printf '%s\n' "$want" | LC_ALL=C sort)" ]; then
    printf 'The Bom does not match the payload:\n%s\nexpected:\n%s\n' "$bom" "$want" >&2
    exit 1
fi
python3 -I /pkg/check-pkg.py --agent /publish/easypatch-agent "$work/$name"

cp "$work/$name" "/out/$name"
chown "$(stat -c %u:%g /out)" "/out/$name"
