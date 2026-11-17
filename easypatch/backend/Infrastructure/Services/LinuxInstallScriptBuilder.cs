using System.Globalization;
using System.Text;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Infrastructure.Services;

/// <summary>
/// Builds the tokenless Linux installer (<c>curl -fsSL …/downloads/install/&lt;code&gt;.sh | sudo sh</c>). The script picks the
/// deb or rpm package for the distribution and CPU, verifies its SHA-256 against the value embedded here, writes the
/// server URL and deployment code to <c>/etc/easypatch/agent.conf</c> and installs the package with apt or dnf. The
/// endpoint then waits for an administrator's approval. The script contains no secrets.
/// </summary>
public static class LinuxInstallScriptBuilder
{
    /// <summary>Builds the script for the newest deb and rpm packages of each architecture.</summary>
    /// <exception cref="InvalidOperationException">There is no deb or rpm package.</exception>
    public static string Build(string publicUrl, IReadOnlyList<AgentPackage> packages, string deploymentCode, string label, DateTimeOffset generatedAt)
    {
        ArgumentNullException.ThrowIfNull(packages);
        var server = publicUrl.TrimEnd('/');
        var newest = Newest(packages);
        if (newest.Count == 0)
        {
            throw new InvalidOperationException("There is no Linux (deb or rpm) agent package.");
        }

        var sb = new StringBuilder();
        sb.Append("#!/bin/sh\n");
        sb.Append(CultureInfo.InvariantCulture, $"# EasyPatch Linux agent installer for deployment code {deploymentCode} ({OneLine(label)})\n");
        sb.Append(CultureInfo.InvariantCulture, $"# Generated {generatedAt:u}. The endpoint will appear under Pending Approvals in the EasyPatch console.\n");
        sb.Append("# This script contains no secrets: an administrator must approve the endpoint before it is managed.\n");
        sb.Append("# Optional: EASYPATCH_PROXY_URL=http://proxy:3128 (used by the agent to reach the server, not by apt/dnf).\n");
        sb.Append("set -eu\n");
        sb.Append(CultureInfo.InvariantCulture, $"SERVER_URL={Quote(server)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"DEPLOYMENT_CODE={Quote(deploymentCode)}\n");
        sb.Append("""
            fail() { echo "easypatch: $*" >&2; exit 1; }
            [ "$(id -u)" -eq 0 ] || fail "run this script as root, e.g. curl -fsSL <url> | sudo sh"
            [ -r /etc/os-release ] || fail "/etc/os-release is missing; this distribution is not supported."
            os_field() { sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d "\"'"; }
            os_id=$(os_field ID)
            os_like=$(os_field ID_LIKE)
            case " $os_id $os_like " in
              *" debian "*|*" ubuntu "*) format=deb ;;
              *" rhel "*|*" fedora "*|*" centos "*) format=rpm ;;
              *) fail "unsupported distribution '$os_id' (supported: Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream, Fedora)." ;;
            esac
            case "$(uname -m)" in
              x86_64|amd64) arch=x64 ;;
              aarch64|arm64) arch=arm64 ;;
              *) fail "unsupported CPU architecture $(uname -m)." ;;
            esac
            command -v systemctl >/dev/null 2>&1 || fail "systemd is required."
            case "$format-$arch" in

            """);
        foreach (var p in newest)
        {
            sb.Append(CultureInfo.InvariantCulture,
                $"  {p.Format}-{p.Architecture}) file={Quote(p.FileName)}; sha256={Quote(p.Sha256.ToLowerInvariant())} ;;\n");
        }

        sb.Append("""
              *) fail "the server has no $format agent package for $arch." ;;
            esac
            # An installed agent that is enrolled (or waiting for approval) keeps its enrollment; an installed agent that never
            # enrolled gets the settings below and is restarted so that it enrolls now.
            preinstalled=no
            enrolled=no
            if [ -x /usr/sbin/easypatch-agent ]; then
              preinstalled=yes
              if /usr/sbin/easypatch-agent status 2>/dev/null | grep -Eq "^Status: +(PendingApproval|Active)"; then
                enrolled=yes
                echo "easypatch: this computer is already enrolled or waiting for approval; the package is upgraded if needed and the enrollment is kept."
              fi
            fi
            work=$(mktemp -d)
            trap 'rm -rf "$work"' EXIT
            chmod 755 "$work"
            url="$SERVER_URL/downloads/agent/$file"
            echo "Downloading $url"
            if command -v curl >/dev/null 2>&1; then
              curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$url" || fail "download failed."
            elif command -v wget >/dev/null 2>&1; then
              wget -q --https-only -O "$work/$file" "$url" || fail "download failed."
            else
              fail "curl or wget is required."
            fi
            actual=$(sha256sum "$work/$file" | cut -d ' ' -f 1)
            [ "$actual" = "$sha256" ] || fail "package hash $actual does not match the expected $sha256. Aborting."
            chmod 644 "$work/$file"
            if [ "$enrolled" = no ]; then
              umask 077
              mkdir -p /etc/easypatch
              chmod 700 /etc/easypatch
              {
                echo "# EasyPatch agent bootstrap settings (written by the install script)."
                echo "ServerUrl=$SERVER_URL"
                echo "DeploymentCode=$DEPLOYMENT_CODE"
                if [ -n "${EASYPATCH_PROXY_URL:-}" ]; then echo "ProxyUrl=$EASYPATCH_PROXY_URL"; fi
              } > /etc/easypatch/agent.conf.new
              chmod 600 /etc/easypatch/agent.conf.new
              mv -f /etc/easypatch/agent.conf.new /etc/easypatch/agent.conf
              umask 022
            fi
            echo "Installing $file"
            if [ "$format" = deb ]; then
              DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$work/$file" || fail "apt-get could not install the package."
            elif command -v dnf >/dev/null 2>&1; then
              dnf install -y -q "$work/$file" || fail "dnf could not install the package."
            else
              fail "dnf is required (RHEL 8 or later)."
            fi
            if [ "$enrolled" = no ] && [ "$preinstalled" = yes ]; then
              systemctl restart easypatch-agent.service || fail "could not restart the easypatch-agent service."
            fi
            i=0
            while [ $i -lt 12 ]; do
              sleep 5
              if status=$(/usr/sbin/easypatch-agent status 2>/dev/null) && echo "$status" | grep -Eq "^Status: +(PendingApproval|Active)"; then
                echo "$status"
                break
              fi
              i=$((i + 1))
            done
            echo "EasyPatch agent installed. Approve this endpoint in the EasyPatch console (Pending Approvals) after comparing the key fingerprint."

            """);
        return sb.ToString();
    }

    public static string OneLiner(string publicUrl, string deploymentCode) =>
        $"curl -fsSL {publicUrl.TrimEnd('/')}/downloads/install/{deploymentCode}.sh | sudo sh";

    /// <summary>Enrolls with a token after the package is installed. The token is read from standard input, so it never
    /// appears in the process list (command-line arguments are visible to every user on Linux).</summary>
    public static string TokenEnrollCommand(string publicUrl, string token) =>
        $"printf '%s' '{token}' | sudo easypatch-agent enroll --server {publicUrl.TrimEnd('/')} --token-file -";

    /// <summary>The newest deb and rpm package per architecture.</summary>
    public static IReadOnlyList<AgentPackage> Newest(IReadOnlyList<AgentPackage> packages)
    {
        ArgumentNullException.ThrowIfNull(packages);
        return packages.Where(p => p.Format is AgentRelease.FormatDeb or AgentRelease.FormatRpm)
            .GroupBy(p => (p.Format, p.Architecture))
            .Select(g => g.OrderByDescending(p => Version.TryParse(p.Version, out var v) ? v : new Version(0, 0)).First())
            .OrderBy(p => p.Format, StringComparer.Ordinal).ThenBy(p => p.Architecture, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Single-quoted shell literal (the values are server-generated, but quote them anyway).</summary>
    private static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    private static string OneLine(string value) =>
        value.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
