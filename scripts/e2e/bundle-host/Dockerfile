# The Linux machine of the bundle test (scripts/e2e/bundle.sh): Debian with
# systemd as init, as the EasyPatch agent's package needs, run on the host's
# network. Its only package source is a local repository offering a newer
# version of a synthetic package, easyrmm-e2e-demo, so the test installs a
# real update without depending on what a public mirror offers that day.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

# What a server would have: systemd, sudo and curl for the console's install
# command, and the EasyPatch agent's package dependencies.
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      systemd systemd-sysv dbus sudo curl ca-certificates libssl3 apt-utils \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service console-getty.service

# easyrmm-e2e-demo 1.0.0 is installed; 1.1.0 waits in /srv/apt.
RUN set -eu; \
    for v in 1.0.0 1.1.0; do \
      d="/tmp/easyrmm-e2e-demo-$v"; \
      mkdir -p "$d/DEBIAN" "$d/usr/share/easyrmm-e2e-demo"; \
      printf 'Package: easyrmm-e2e-demo\nVersion: %s\nArchitecture: all\nMaintainer: EasyRMM tests <tests@example.invalid>\nSection: misc\nPriority: optional\nDescription: Synthetic package for the EasyRMM bundle test\n' "$v" > "$d/DEBIAN/control"; \
      echo "$v" > "$d/usr/share/easyrmm-e2e-demo/version"; \
      dpkg-deb --build --root-owner-group "$d" "/tmp/easyrmm-e2e-demo_${v}_all.deb" > /dev/null; \
    done; \
    dpkg -i /tmp/easyrmm-e2e-demo_1.0.0_all.deb; \
    mkdir -p /srv/apt; \
    mv /tmp/easyrmm-e2e-demo_1.1.0_all.deb /srv/apt/; \
    cd /srv/apt; \
    apt-ftparchive packages . > Packages; \
    apt-ftparchive release . > Release; \
    rm -rf /tmp/easyrmm-e2e-demo-* /tmp/*.deb; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    echo 'deb [trusted=yes] file:/srv/apt ./' > /etc/apt/sources.list.d/easyrmm-e2e.list

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
