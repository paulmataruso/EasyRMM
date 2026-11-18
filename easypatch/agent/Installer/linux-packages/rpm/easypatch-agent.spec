# Built by scripts/build-linux-packages.sh from an already published agent; nothing is compiled here.
%global debug_package %{nil}
%global __strip /bin/true
# The agent is a single-file .NET bundle: stripping or any other post-processing would corrupt it.
%global __os_install_post %{nil}
%define _build_id_links none
# gzip payload and SHA-256 digests: readable by rpm 4.14 (Enterprise Linux 8) and later.
%define _binary_payload w9.gzdio
%define _source_payload w9.gzdio
%define _binary_filedigest_algorithm 8

Name:           easypatch-agent
Version:        %{ep_version}
Release:        1
Summary:        EasyPatch patch management agent
License:        FSL-1.1-ALv2
Vendor:         DHI Technical Services LLC
Packager:       DHI Technical Services LLC <paulmataruso@dhitechnical.com>
AutoReqProv:    no
Requires:       glibc, libgcc, libstdc++, openssl-libs, ca-certificates, systemd

%description
Reports missing package updates to an EasyPatch server and installs the updates an administrator approves, with dnf.
Runs as the easypatch-agent systemd service. Enroll with "easypatch-agent enroll" or the install script from the
EasyPatch console.

%install
mkdir -p %{buildroot}/opt/easypatch %{buildroot}/usr/sbin %{buildroot}/usr/lib/systemd/system %{buildroot}/etc/easypatch
install -m 0755 %{ep_source}/easypatch-agent %{buildroot}/opt/easypatch/easypatch-agent
ln -s ../../opt/easypatch/easypatch-agent %{buildroot}/usr/sbin/easypatch-agent
install -m 0644 %{ep_source}/easypatch-agent.service %{buildroot}/usr/lib/systemd/system/easypatch-agent.service

%files
%dir %attr(0755,root,root) /opt/easypatch
%attr(0755,root,root) /opt/easypatch/easypatch-agent
/usr/sbin/easypatch-agent
%attr(0644,root,root) /usr/lib/systemd/system/easypatch-agent.service
%dir %attr(0700,root,root) /etc/easypatch

%post
install -d -m 0700 -o root -g root /var/lib/easypatch
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -eq 1 ]; then
        systemctl enable easypatch-agent.service >/dev/null 2>&1 || :
        systemctl start easypatch-agent.service || :
    else
        # Upgrade: restart only if it is running (an unenrolled agent stays stopped).
        systemctl try-restart easypatch-agent.service || :
    fi
fi

%preun
if [ "$1" -eq 0 ]; then
    if [ -d /run/systemd/system ]; then
        systemctl disable --now easypatch-agent.service >/dev/null 2>&1 || :
    fi
    # Best effort, like the Windows uninstaller: tell the server and delete the agent identity. Never on upgrade.
    if [ -x /opt/easypatch/easypatch-agent ]; then
        /opt/easypatch/easypatch-agent unenroll --reason "Agent uninstalled" >/dev/null || :
    fi
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
