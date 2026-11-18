using System.Text.RegularExpressions;
using EasyPatch.Infrastructure.Services;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class InstallScriptTests
{
    private static readonly AgentPackage Package = new("EasyPatchAgent-1.2.0-x64.msi", "1.2.0", "x64", 12_345_678,
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", DateTimeOffset.UnixEpoch);

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EasyPatch.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    [Fact]
    public void Script_verifies_the_package_and_carries_no_secret()
    {
        var script = InstallScriptBuilder.Build("https://patch.example.com/", Package, "EPD-ABCDEFGHJKMNPQRS", "RMM 'rollout'", requireSignature: true,
            DateTimeOffset.UnixEpoch);

        Assert.Contains("$ExpectedSha256 = '" + Package.Sha256 + "'", script, StringComparison.Ordinal);
        Assert.Contains("$RequireSignature = $true", script, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", script, StringComparison.Ordinal);
        Assert.Contains("'https://patch.example.com/downloads/agent/EasyPatchAgent-1.2.0-x64.msi'", script, StringComparison.Ordinal);
        Assert.Contains("DEPLOYMENTCODE=$DeploymentCode", script, StringComparison.Ordinal);
        Assert.DoesNotContain("ENROLLMENTTOKEN", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Restart-Computer", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Script_looks_for_the_agent_where_the_msi_installs_it()
    {
        var wxs = File.ReadAllText(Path.Combine(RepositoryRoot(), "agent", "Installer", "Package.wxs"));
        var folder = Regex.Match(wxs, "<Directory Id=\"INSTALLFOLDER\" Name=\"(?<name>[^\"]+)\"").Groups["name"].Value;
        Assert.False(string.IsNullOrEmpty(folder));

        var script = InstallScriptBuilder.Build("https://patch.example.com", Package, "EPD-ABCDEFGHJKMNPQRS", "x", false, DateTimeOffset.UnixEpoch);
        Assert.Contains($"Join-Path $env:ProgramFiles '{folder}\\EasyPatch.Agent.exe'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Msi_keeps_the_enrollment_token_out_of_its_logs()
    {
        var wxs = File.ReadAllText(Path.Combine(RepositoryRoot(), "agent", "Installer", "Package.wxs"));

        Assert.Matches("<Property Id=\"ENROLLMENTTOKEN\"[^>]*Hidden=\"yes\"", wxs);
        // The token is written by WriteRegistryValues; its progress template must not include the value ([3]).
        var template = Regex.Match(wxs, "<ProgressText Action=\"WriteRegistryValues\"[^>]*Template=\"(?<t>[^\"]*)\"").Groups["t"].Value;
        Assert.False(string.IsNullOrEmpty(template));
        Assert.DoesNotContain("[3]", template, StringComparison.Ordinal);
    }

    [Fact]
    public void Skipping_the_certificate_check_passes_the_published_ca_to_the_msi_and_restores_checking()
    {
        var plain = InstallScriptBuilder.Build("https://patch.example.com", Package, "EPD-ABCDEFGHJKMNPQRS", "x", false, DateTimeOffset.UnixEpoch);
        Assert.Contains("$SkipCertificateCheck = $false", plain, StringComparison.Ordinal);

        var script = InstallScriptBuilder.Build("https://patch.example.com/", Package, "EPD-ABCDEFGHJKMNPQRS", "x", false, DateTimeOffset.UnixEpoch,
            skipCertificateCheck: true);
        Assert.Contains("$SkipCertificateCheck = $true", script, StringComparison.Ordinal);
        Assert.Contains("$ServerCaUrl = 'https://patch.example.com/server-ca.crt'", script, StringComparison.Ordinal);
        Assert.Contains("if ($serverCa) { $arguments += \"SERVERCACERT=$serverCa\" }", script, StringComparison.Ordinal);
        Assert.Contains("CertificateAuthority", script, StringComparison.Ordinal);
        // Checking is switched back on when the script ends, and the package hash is still verified.
        Assert.Contains("[Net.ServicePointManager]::ServerCertificateValidationCallback = $null", script, StringComparison.Ordinal);
        Assert.Contains("if ($hash -ne $ExpectedSha256)", script, StringComparison.Ordinal);
    }

    [Fact]
    public void One_liner_skips_the_certificate_check_only_when_asked_and_contains_no_variables()
    {
        var plain = InstallScriptBuilder.OneLiner("https://patch.example.com/", "EPD-ABC");
        Assert.DoesNotContain("ServerCertificateValidationCallback", plain, StringComparison.Ordinal);
        Assert.EndsWith("DownloadString('https://patch.example.com/downloads/install/EPD-ABC.ps1'))\"", plain, StringComparison.Ordinal);

        var skip = InstallScriptBuilder.OneLiner("https://patch.example.com/", "EPD-ABC", requireSignature: true, skipCertificateCheck: true);
        Assert.Contains("[Net.ServicePointManager]::ServerCertificateValidationCallback={[bool]1}; iex", skip, StringComparison.Ordinal);
        Assert.Contains("'https://patch.example.com/downloads/install/EPD-ABC.ps1?requireSignature=true&skipCertificateCheck=true'", skip, StringComparison.Ordinal);
        // No $ anywhere: a PowerShell prompt would expand variables inside the double-quoted -Command argument.
        Assert.DoesNotContain("$", skip, StringComparison.Ordinal);
    }

    [Fact]
    public void The_msi_records_the_server_ca_where_the_agent_reads_it_and_the_lab_proxy_publishes_it()
    {
        var root = RepositoryRoot();
        var wxs = File.ReadAllText(Path.Combine(root, "agent", "Installer", "Package.wxs"));
        Assert.Matches("<Property Id=\"SERVERCACERT\" Secure=\"yes\" />", wxs);
        Assert.Matches("Name=\"ServerCaCertificate\" Type=\"string\" Value=\"\\[SERVERCACERT\\]\"", wxs);
        Assert.Contains("<SetProperty Id=\"SERVERCACERT\" Value=\"[SAVEDSERVERCACERT]\"", wxs, StringComparison.Ordinal);

        var source = File.ReadAllText(Path.Combine(root, "agent", "EasyPatch.Agent", "Platform", "RegistryBootstrapConfigSource.cs"));
        Assert.Contains("ServerCaCertificateValue = \"ServerCaCertificate\"", source, StringComparison.Ordinal);

        var caddy = File.ReadAllText(Path.Combine(root, "deployment", "caddy", "Caddyfile.dev"));
        Assert.Contains($"handle {InstallScriptBuilder.ServerCaPath} {{", caddy, StringComparison.Ordinal);
        Assert.Contains("rewrite * /root.crt", caddy, StringComparison.Ordinal);
        Assert.DoesNotContain(InstallScriptBuilder.ServerCaPath, File.ReadAllText(Path.Combine(root, "deployment", "caddy", "Caddyfile")), StringComparison.Ordinal);
    }

    [Fact]
    public void One_liner_and_msiexec_commands_point_at_the_public_url()
    {
        Assert.Contains("https://patch.example.com/downloads/install/EPD-ABC.ps1", InstallScriptBuilder.OneLiner("https://patch.example.com/", "EPD-ABC"),
            StringComparison.Ordinal);
        Assert.Equal("msiexec /i EasyPatchAgent-1.2.0-x64.msi /qn /norestart SERVERURL=\"https://patch.example.com\" ENROLLMENTTOKEN=\"ept_x\"",
            InstallScriptBuilder.MsiExecCommand("https://patch.example.com/", "ept_x", "EasyPatchAgent-1.2.0-x64.msi"));
    }
}

public sealed class LinuxInstallScriptTests
{
    private static AgentPackage Package(string version, string architecture, string format) =>
        new($"EasyPatchAgent-{version}-{architecture}.{format}", version, architecture, 30_000_000, new string('a', 64), DateTimeOffset.UnixEpoch, Format: format);

    [Fact]
    public void The_newest_package_of_each_format_and_architecture_is_offered()
    {
        var newest = LinuxInstallScriptBuilder.Newest(
        [
            Package("1.3.0", "x64", "deb"), Package("1.3.1", "x64", "deb"), Package("1.3.0", "x64", "rpm"), Package("1.3.0", "arm64", "deb"),
            Package("1.4.0", "x64", "msi"),
        ]);

        Assert.Equal(["EasyPatchAgent-1.3.0-arm64.deb", "EasyPatchAgent-1.3.0-x64.rpm", "EasyPatchAgent-1.3.1-x64.deb"],
            newest.Select(p => p.FileName).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_script_verifies_the_package_hash_carries_no_secret_and_never_restarts()
    {
        var script = LinuxInstallScriptBuilder.Build("https://patch.example.com/", [Package("1.3.0", "x64", "deb"), Package("1.3.0", "x64", "rpm")],
            "EPD-ABCDEFGHJKMNPQRS", "it's a 'test'\nid -u", DateTimeOffset.UnixEpoch);

        Assert.Contains("SERVER_URL='https://patch.example.com'", script, StringComparison.Ordinal);
        Assert.Contains("sha256sum", script, StringComparison.Ordinal);
        Assert.Contains("--proto '=https'", script, StringComparison.Ordinal);
        Assert.Contains("deb-x64) file='EasyPatchAgent-1.3.0-x64.deb'; sha256='" + new string('a', 64) + "'", script, StringComparison.Ordinal);
        Assert.Contains("chmod 600 /etc/easypatch/agent.conf.new", script, StringComparison.Ordinal);
        // An installed agent keeps its enrollment only when it is enrolled or waiting for approval; one that never enrolled
        // gets the settings and is restarted.
        Assert.Contains("grep -Eq \"^Status: +(PendingApproval|Active)\"", script, StringComparison.Ordinal);
        Assert.Contains("systemctl restart easypatch-agent.service", script, StringComparison.Ordinal);
        Assert.DoesNotContain("agent-state.json", script, StringComparison.Ordinal);
        Assert.DoesNotContain("EnrollmentToken", script, StringComparison.Ordinal);
        Assert.DoesNotContain("reboot", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shutdown", script, StringComparison.OrdinalIgnoreCase);
        // The label only appears in the header comment and cannot start a new line of shell.
        var labelLines = script.Split('\n').Where(l => l.Contains("'test'", StringComparison.Ordinal)).ToList();
        Assert.StartsWith("# EasyPatch Linux agent installer", Assert.Single(labelLines), StringComparison.Ordinal);
        Assert.DoesNotContain("\nid -u", script, StringComparison.Ordinal);
    }

    [Fact]
    public void The_script_is_valid_posix_shell()
    {
        if (!File.Exists("/bin/sh"))
        {
            return;
        }

        var script = LinuxInstallScriptBuilder.Build("https://patch.example.com", [Package("1.3.0", "x64", "deb")], "EPD-ABCDEFGHJKMNPQRS", "Rollout",
            DateTimeOffset.UnixEpoch);
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, script);
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-n", path])
            {
                RedirectStandardError = true,
            })!;
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void The_token_command_reads_the_token_from_standard_input()
    {
        var command = LinuxInstallScriptBuilder.TokenEnrollCommand("https://patch.example.com", "ept_abc");

        Assert.Contains("--token-file -", command, StringComparison.Ordinal);
        Assert.DoesNotContain("--token ", command, StringComparison.Ordinal);
    }
}

public sealed class MacInstallScriptTests
{
    private static AgentPackage Package(string version, string architecture, string format = "pkg", char hash = 'a') =>
        new($"EasyPatchAgent-{version}-{architecture}.{format}", version, architecture, 40_000_000, new string(hash, 64), DateTimeOffset.UnixEpoch, Format: format);

    private static string Script(string label = "Rollout") =>
        MacInstallScriptBuilder.Build("https://patch.example.com/", [Package("1.9.0", "x64", hash: 'b'), Package("1.9.0", "arm64", hash: 'c')],
            "EPD-ABCDEFGHJKMNPQRS", label, DateTimeOffset.UnixEpoch);

    [Fact]
    public void Only_the_newest_pkg_package_of_each_architecture_is_offered()
    {
        var newest = MacInstallScriptBuilder.Newest(
        [
            Package("1.9.0", "x64"), Package("1.9.1", "x64"), Package("1.9.0", "arm64"), Package("1.9.2", "arm64", "deb"), Package("1.9.2", "x64", "msi"),
        ]);

        Assert.Equal(["EasyPatchAgent-1.9.0-arm64.pkg", "EasyPatchAgent-1.9.1-x64.pkg"], newest.Select(p => p.FileName));
        Assert.Throws<InvalidOperationException>(() =>
            MacInstallScriptBuilder.Build("https://patch.example.com", [Package("1.9.0", "x64", "deb")], "EPD-ABC", "x", DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void The_script_verifies_each_package_hash_and_carries_no_secret()
    {
        var script = Script("it's a 'test'\nid -u");

        Assert.Contains("SERVER_URL='https://patch.example.com'", script, StringComparison.Ordinal);
        Assert.Contains("DEPLOYMENT_CODE='EPD-ABCDEFGHJKMNPQRS'", script, StringComparison.Ordinal);
        Assert.Contains("  x64) file='EasyPatchAgent-1.9.0-x64.pkg'; sha256='" + new string('b', 64) + "' ;;", script, StringComparison.Ordinal);
        Assert.Contains("  arm64) file='EasyPatchAgent-1.9.0-arm64.pkg'; sha256='" + new string('c', 64) + "' ;;", script, StringComparison.Ordinal);
        Assert.Contains("shasum -a 256 \"$pkg\"", script, StringComparison.Ordinal);
        Assert.Contains("--proto '=https'", script, StringComparison.Ordinal);
        Assert.Contains(MacInstallScriptBuilder.ExperimentalNotice, script, StringComparison.Ordinal);
        Assert.DoesNotContain("EnrollmentToken", script, StringComparison.Ordinal);
        Assert.DoesNotContain("--token", script, StringComparison.Ordinal);
        Assert.DoesNotContain("reboot", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shutdown", script, StringComparison.OrdinalIgnoreCase);
        // The label only appears in the header comment and cannot start a new line of shell.
        var labelLines = script.Split('\n').Where(l => l.Contains("'test'", StringComparison.Ordinal)).ToList();
        Assert.StartsWith("# EasyPatch macOS agent installer", Assert.Single(labelLines), StringComparison.Ordinal);
        Assert.DoesNotContain("\nid -u", script, StringComparison.Ordinal);
    }

    [Fact]
    public void The_script_refuses_other_systems_and_old_macos_and_detects_apple_silicon_under_rosetta()
    {
        var script = Script();

        Assert.Contains("[ \"$(uname -s)\" = Darwin ] || fail", script, StringComparison.Ordinal);
        Assert.Contains("[ \"$(id -u)\" -eq 0 ] || fail", script, StringComparison.Ordinal);
        Assert.Contains("sw_vers -productVersion", script, StringComparison.Ordinal);
        Assert.Contains("[ \"$os_major\" -ge 14 ] || fail", script, StringComparison.Ordinal);
        Assert.Contains("sysctl -n hw.optional.arm64", script, StringComparison.Ordinal);
        Assert.DoesNotContain("uname -m", script, StringComparison.Ordinal);
        // Darwin is checked before anything macOS-specific runs.
        Assert.True(script.IndexOf("uname -s", StringComparison.Ordinal) < script.IndexOf("sw_vers", StringComparison.Ordinal));
    }

    [Fact]
    public void The_settings_are_written_root_only_before_the_package_is_installed()
    {
        var script = Script();

        Assert.Contains("CONF='/Library/EasyPatch/agent.conf'", script, StringComparison.Ordinal);
        Assert.Contains("umask 077", script, StringComparison.Ordinal);
        Assert.Contains("chown root:wheel \"$CONF_DIR\"", script, StringComparison.Ordinal);
        Assert.Contains("chmod 755 \"$CONF_DIR\"", script, StringComparison.Ordinal);
        Assert.Contains("chmod 600 \"$CONF.new\"", script, StringComparison.Ordinal);
        Assert.Contains("printf 'DeploymentCode=%s\\n' \"$DEPLOYMENT_CODE\"", script, StringComparison.Ordinal);
        var written = script.IndexOf("mv -f \"$CONF.new\" \"$CONF\"", StringComparison.Ordinal);
        var installed = script.IndexOf("installer -pkg \"$pkg\" -target /", StringComparison.Ordinal);
        Assert.True(written > 0 && installed > written, "agent.conf must be in place before installer runs the postinstall script.");
        // An enrolled agent keeps its enrollment; one that never enrolled is restarted to pick up the settings.
        Assert.Contains("grep -Eq \"^Status: +(PendingApproval|Active)\"", script, StringComparison.Ordinal);
        Assert.Contains($"launchctl kickstart -k system/{MacInstallScriptBuilder.DaemonLabel}", script, StringComparison.Ordinal);
        Assert.Contains("trap 'rm -rf \"$work\"' EXIT", script, StringComparison.Ordinal);
    }

    [Fact]
    public void The_script_is_valid_posix_shell()
    {
        if (!File.Exists("/bin/sh"))
        {
            return;
        }

        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, Script());
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-n", path])
            {
                RedirectStandardError = true,
            })!;
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void The_one_liner_and_token_command_point_at_the_macos_script_and_agent()
    {
        Assert.Equal("curl -fsSL https://patch.example.com/downloads/install/macos/EPD-ABC.sh | sudo sh",
            MacInstallScriptBuilder.OneLiner("https://patch.example.com/", "EPD-ABC"));

        var command = MacInstallScriptBuilder.TokenEnrollCommand("https://patch.example.com/", "ept_abc");
        Assert.Equal("printf '%s' 'ept_abc' | sudo /usr/local/bin/easypatch-agent enroll --server https://patch.example.com --token-file -", command);
        Assert.DoesNotContain("--token ", command, StringComparison.Ordinal);
    }
}
