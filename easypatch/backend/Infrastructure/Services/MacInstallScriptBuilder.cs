using System.Globalization;
using System.Text;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Infrastructure.Services;

/// <summary>
/// Builds the tokenless installer for the experimental macOS agent (<c>curl -fsSL …/downloads/install/macos/&lt;code&gt;.sh | sudo sh</c>).
/// The script refuses anything but macOS 14 or later, picks the pkg package for the CPU (Apple silicon or Intel), verifies its
/// SHA-256 against the value embedded here, writes the server URL and deployment code to <c>/Library/EasyPatch/agent.conf</c>
/// and then installs the package with <c>installer</c>; the package's postinstall script starts the launchd daemon, which reads
/// that file. The endpoint then waits for an administrator's approval. The script contains no secrets. Like the Linux script it
/// has no option to skip the certificate check: the Mac must trust the server's certificate.
/// </summary>
public static class MacInstallScriptBuilder
{
    /// <summary>Shown wherever the macOS agent is offered.</summary>
    public const string ExperimentalNotice = "Experimental: the macOS agent is in development and not for production use.";

    /// <summary>The agent's folder (root:wheel, mode 0755), which holds <see cref="AgentPath"/> and <see cref="SettingsPath"/>.</summary>
    public const string InstallDirectory = "/Library/EasyPatch";

    /// <summary>Where the package installs the agent (also linked as <see cref="AgentCommand"/>).</summary>
    public const string AgentPath = InstallDirectory + "/easypatch-agent";

    /// <summary>The link to the agent on the default PATH.</summary>
    public const string AgentCommand = "/usr/local/bin/easypatch-agent";

    /// <summary>The agent's settings file (root-only, mode 0600; same keys as the Linux <c>/etc/easypatch/agent.conf</c>).</summary>
    public const string SettingsPath = InstallDirectory + "/agent.conf";

    /// <summary>Label of the agent's launchd daemon.</summary>
    public const string DaemonLabel = "com.dhitechnical.easypatch.agent";

    /// <summary>The oldest supported macOS major version (macOS 14 Sonoma).</summary>
    public const int MinimumMajorVersion = 14;

    /// <summary>Builds the script for the newest pkg package of each architecture.</summary>
    /// <exception cref="InvalidOperationException">There is no pkg package.</exception>
    public static string Build(string publicUrl, IReadOnlyList<AgentPackage> packages, string deploymentCode, string label, DateTimeOffset generatedAt)
    {
        ArgumentNullException.ThrowIfNull(packages);
        var server = publicUrl.TrimEnd('/');
        var newest = Newest(packages);
        if (newest.Count == 0)
        {
            throw new InvalidOperationException("There is no macOS (pkg) agent package.");
        }

        var sb = new StringBuilder();
        sb.Append("#!/bin/sh\n");
        sb.Append(CultureInfo.InvariantCulture, $"# EasyPatch macOS agent installer for deployment code {deploymentCode} ({OneLine(label)})\n");
        sb.Append(CultureInfo.InvariantCulture, $"# Generated {generatedAt:u}. The endpoint will appear under Pending Approvals in the EasyPatch console.\n");
        sb.Append("# This script contains no secrets: an administrator must approve the endpoint before it is managed.\n");
        sb.Append(CultureInfo.InvariantCulture, $"# {ExperimentalNotice}\n");
        sb.Append("# Optional: EASYPATCH_PROXY_URL=http://proxy:3128 (used by the agent to reach the server, not by this script's download).\n");
        sb.Append("set -eu\n");
        sb.Append(CultureInfo.InvariantCulture, $"SERVER_URL={Quote(server)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"DEPLOYMENT_CODE={Quote(deploymentCode)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"AGENT={Quote(AgentPath)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"CONF_DIR={Quote(InstallDirectory)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"CONF={Quote(SettingsPath)}\n");
        sb.Append("fail() { echo \"easypatch: $*\" >&2; exit 1; }\n");
        sb.Append(CultureInfo.InvariantCulture, $"echo {Quote("easypatch: " + ExperimentalNotice)}\n");
        sb.Append("""
            [ "$(uname -s)" = Darwin ] || fail "this script is for macOS; use the Linux install script on Linux."
            [ "$(id -u)" -eq 0 ] || fail "run this script as root, e.g. curl -fsSL <url> | sudo sh"
            os_version=$(sw_vers -productVersion 2>/dev/null || true)
            os_major=${os_version%%.*}
            case "$os_major" in
              ''|*[!0-9]*) fail "could not read the macOS version (sw_vers -productVersion)." ;;
            esac

            """);
        sb.Append(CultureInfo.InvariantCulture,
            $"[ \"$os_major\" -ge {MinimumMajorVersion} ] || fail \"macOS $os_version is not supported (macOS {MinimumMajorVersion} Sonoma or later is required).\"\n");
        sb.Append("""
            # hw.optional.arm64 is 1 on Apple silicon, also when this shell runs under Rosetta (which reports the machine as x86_64).
            if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64; else arch=x64; fi
            case "$arch" in

            """);
        foreach (var p in newest)
        {
            sb.Append(CultureInfo.InvariantCulture,
                $"  {p.Architecture}) file={Quote(p.FileName)}; sha256={Quote(p.Sha256.ToLowerInvariant())} ;;\n");
        }

        sb.Append("""
              *) fail "the server has no macOS agent package for $arch." ;;
            esac
            # An installed agent that is enrolled (or waiting for approval) keeps its enrollment; an installed agent that never
            # enrolled gets the settings below and is restarted so that it enrolls now.
            preinstalled=no
            enrolled=no
            if [ -x "$AGENT" ]; then
              preinstalled=yes
              if "$AGENT" status 2>/dev/null | grep -Eq "^Status: +(PendingApproval|Active)"; then
                enrolled=yes
                echo "easypatch: this Mac is already enrolled or waiting for approval; the package is upgraded if needed and the enrollment is kept."
              fi
            fi
            work=$(mktemp -d "${TMPDIR:-/tmp}/easypatch.XXXXXX")
            trap 'rm -rf "$work"' EXIT
            trap 'exit 1' HUP INT TERM
            pkg="$work/$file"
            url="$SERVER_URL/downloads/agent/$file"
            echo "Downloading $url"
            curl -fsSL --proto '=https' --tlsv1.2 -o "$pkg" "$url" || fail "download failed."
            actual=$(shasum -a 256 "$pkg" | cut -d ' ' -f 1)
            [ "$actual" = "$sha256" ] || fail "package hash $actual does not match the expected $sha256. Aborting."
            # The settings are written before the package is installed: its postinstall script starts the daemon, which reads them.
            if [ "$enrolled" = no ]; then
              umask 077
              mkdir -p "$CONF_DIR"
              chown root:wheel "$CONF_DIR"
              chmod 755 "$CONF_DIR"
              {
                echo "# EasyPatch agent bootstrap settings (written by the install script)."
                printf 'ServerUrl=%s\n' "$SERVER_URL"
                printf 'DeploymentCode=%s\n' "$DEPLOYMENT_CODE"
                if [ -n "${EASYPATCH_PROXY_URL:-}" ]; then printf 'ProxyUrl=%s\n' "$EASYPATCH_PROXY_URL"; fi
              } > "$CONF.new"
              chown root:wheel "$CONF.new"
              chmod 600 "$CONF.new"
              mv -f "$CONF.new" "$CONF"
              umask 022
            fi
            echo "Installing $file"
            installer -pkg "$pkg" -target / || fail "installer could not install the package."

            """);
        sb.Append(CultureInfo.InvariantCulture, $"""
            if [ "$enrolled" = no ] && [ "$preinstalled" = yes ]; then
              launchctl kickstart -k system/{DaemonLabel} || fail "could not restart the EasyPatch agent daemon ({DaemonLabel})."
            fi

            """);
        sb.Append("""
            i=0
            while [ $i -lt 12 ]; do
              sleep 5
              if status=$("$AGENT" status 2>/dev/null) && echo "$status" | grep -Eq "^Status: +(PendingApproval|Active)"; then
                echo "$status"
                break
              fi
              i=$((i + 1))
            done
            echo "EasyPatch agent installed. Approve this endpoint in the EasyPatch console (Pending Approvals) after comparing the key fingerprint."

            """);
        return sb.ToString();
    }

    public static string ScriptUrl(string publicUrl, string deploymentCode) =>
        $"{publicUrl.TrimEnd('/')}/downloads/install/macos/{deploymentCode}.sh";

    public static string OneLiner(string publicUrl, string deploymentCode) => $"curl -fsSL {ScriptUrl(publicUrl, deploymentCode)} | sudo sh";

    /// <summary>Enrolls with a token after the package is installed. The token is read from standard input, so it never
    /// appears in the process list (command-line arguments are visible to every user on macOS).</summary>
    public static string TokenEnrollCommand(string publicUrl, string token) =>
        $"printf '%s' '{token}' | sudo {AgentCommand} enroll --server {publicUrl.TrimEnd('/')} --token-file -";

    /// <summary>The newest pkg package per architecture.</summary>
    public static IReadOnlyList<AgentPackage> Newest(IReadOnlyList<AgentPackage> packages)
    {
        ArgumentNullException.ThrowIfNull(packages);
        return packages.Where(p => p.Format == AgentRelease.FormatPkg)
            .GroupBy(p => p.Architecture)
            .Select(g => g.OrderByDescending(p => Version.TryParse(p.Version, out var v) ? v : new Version(0, 0)).First())
            .OrderBy(p => p.Architecture, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Single-quoted shell literal (the values are server-generated, but quote them anyway).</summary>
    private static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    private static string OneLine(string value) =>
        value.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
