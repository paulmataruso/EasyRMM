using System.Text.RegularExpressions;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>The Windows agent's MSI, as EasyRMM installs it.</summary>
public sealed class AgentInstallerTests
{
    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EasyPatch.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static string Wxs() => File.ReadAllText(Path.Combine(RepositoryRoot(), "agent", "Installer", "Package.wxs"));

    [Fact]
    public void EasyRMM_looks_for_the_agent_where_the_msi_installs_it()
    {
        var folder = Regex.Match(Wxs(), "<Directory Id=\"INSTALLFOLDER\" Name=\"(?<name>[^\"]+)\"").Groups["name"].Value;
        Assert.False(string.IsNullOrEmpty(folder));

        // EasyRMM's agent runs "<Program Files>\<folder>\EasyPatch.Agent.exe enroll" after msiexec.
        var installer = File.ReadAllText(Path.Combine(RepositoryRoot(), "..", "agent", "easypatch", "system_windows.go"));
        Assert.Contains($"filepath.Join(dir, \"{folder}\", \"EasyPatch.Agent.exe\")", installer, StringComparison.Ordinal);
    }

    [Fact]
    public void Msi_keeps_the_enrollment_token_out_of_its_logs()
    {
        var wxs = Wxs();

        Assert.Matches("<Property Id=\"ENROLLMENTTOKEN\"[^>]*Hidden=\"yes\"", wxs);
        // The token is written by WriteRegistryValues; its progress template must not include the value ([3]).
        var template = Regex.Match(wxs, "<ProgressText Action=\"WriteRegistryValues\"[^>]*Template=\"(?<t>[^\"]*)\"").Groups["t"].Value;
        Assert.False(string.IsNullOrEmpty(template));
        Assert.DoesNotContain("[3]", template, StringComparison.Ordinal);
    }

    [Fact]
    public void The_msi_records_the_server_ca_where_the_agent_reads_it()
    {
        var wxs = Wxs();
        Assert.Matches("<Property Id=\"SERVERCACERT\" Secure=\"yes\" />", wxs);
        Assert.Matches("Name=\"ServerCaCertificate\" Type=\"string\" Value=\"\\[SERVERCACERT\\]\"", wxs);
        Assert.Contains("<SetProperty Id=\"SERVERCACERT\" Value=\"[SAVEDSERVERCACERT]\"", wxs, StringComparison.Ordinal);

        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "agent", "EasyPatch.Agent", "Platform", "RegistryBootstrapConfigSource.cs"));
        Assert.Contains("ServerCaCertificateValue = \"ServerCaCertificate\"", source, StringComparison.Ordinal);
    }
}
