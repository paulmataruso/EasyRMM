using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using EasyPatch.Agent.Core.Applications;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>The agent installs winget for all users when the computer has none, from GitHub or the EasyPatch server,
/// and only from files that match the pinned release.</summary>
public sealed class WingetSetupTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "easypatch-winget-tests", Guid.NewGuid().ToString("N"));
    private readonly Dictionary<string, byte[]> _files;
    private readonly WingetRelease _release;

    public WingetSetupTests()
    {
        Directory.CreateDirectory(_dir);
        _files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["App.msixbundle"] = Encoding.UTF8.GetBytes("the App Installer bundle"),
            ["Deps.zip"] = DependencyArchive(),
            ["License.xml"] = Encoding.UTF8.GetBytes("<License/>"),
        };
        _release = new WingetRelease("1.29.380", _files.Select(f => new WingetFile(f.Key, f.Value.Length, Sha256(f.Value))).ToList(),
            "App.msixbundle", "Deps.zip", "License.xml");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task A_computer_with_winget_is_left_alone()
    {
        var runner = new FakeRunner { Installed = true, Version = "v1.9.25200" };
        var provisioner = new FakeProvisioner(runner);
        var github = new FakeSource("GitHub", _files);
        var (setup, state) = Create(runner, provisioner, github);

        Assert.True(await setup.EnsureAsync(Ct));

        Assert.Empty(github.Requests);
        Assert.Empty(provisioner.Calls);
        Assert.Equal(("1.9.25200", false, (string?)null), (setup.Report!.Version, setup.Report.InstalledByAgent, setup.Report.SetupError));
        Assert.Equal(0, state.Read(s => s.Winget.Failures));
    }

    [Fact]
    public async Task Missing_winget_is_downloaded_from_GitHub_verified_and_installed_for_all_users()
    {
        var runner = new FakeRunner { Installed = false };
        var provisioner = new FakeProvisioner(runner);
        var github = new FakeSource("GitHub", _files);
        var server = new FakeSource("the EasyPatch server", _files);
        var (setup, _) = Create(runner, provisioner, github, server);

        Assert.True(await setup.EnsureAsync(Ct));

        var call = Assert.Single(provisioner.Calls);
        Assert.Equal(_files["App.msixbundle"], call.Bundle);
        Assert.Equal(_files["License.xml"], call.License);
        // Only this architecture's packages, and only plain package files directly in its folder.
        Assert.Equal(["Microsoft.UI.Xaml.appx", "Microsoft.VCLibs.140.00_x64.appx"], call.Dependencies.Order(StringComparer.Ordinal));
        Assert.Empty(server.Requests);
        Assert.Equal(("1.29.380", true, (string?)null), (setup.Report!.Version, setup.Report.InstalledByAgent, setup.Report.SetupError));
        Assert.False(Directory.Exists(Path.Combine(_dir, "work")), "the downloads are deleted afterwards");
    }

    [Fact]
    public async Task The_server_copy_is_used_when_GitHub_fails_or_sends_a_different_file()
    {
        var runner = new FakeRunner { Installed = false };
        var provisioner = new FakeProvisioner(runner);
        var tampered = new Dictionary<string, byte[]>(_files) { ["Deps.zip"] = DependencyArchive(extra: "x64/Evil.appx") };
        tampered.Remove("App.msixbundle"); // GitHub unreachable for this one
        var github = new FakeSource("GitHub", tampered);
        var server = new FakeSource("the EasyPatch server", _files);
        var (setup, _) = Create(runner, provisioner, github, server);

        Assert.True(await setup.EnsureAsync(Ct));

        Assert.Equal(["App.msixbundle", "Deps.zip"], server.Requests);
        Assert.DoesNotContain("Evil.appx", Assert.Single(provisioner.Calls).Dependencies);
    }

    [Fact]
    public async Task Nothing_is_installed_unless_the_files_match_the_pinned_release()
    {
        var runner = new FakeRunner { Installed = false };
        var provisioner = new FakeProvisioner(runner);
        var wrong = _files.ToDictionary(f => f.Key, f => f.Key == "License.xml" ? Encoding.UTF8.GetBytes("<License>!</License>") : f.Value);
        var (setup, state) = Create(runner, provisioner, new FakeSource("GitHub", wrong), new FakeSource("the EasyPatch server", wrong));

        Assert.False(await setup.EnsureAsync(Ct));

        Assert.Empty(provisioner.Calls);
        Assert.Contains("License.xml", setup.Report!.SetupError, StringComparison.Ordinal);
        Assert.Null(setup.Report.Version);
        Assert.Equal(1, state.Read(s => s.Winget.Failures));
    }

    [Fact]
    public async Task An_installation_failure_is_reported_and_an_old_winget_is_replaced()
    {
        var runner = new FakeRunner { Installed = true, Version = "v1.5.1101" }; // older than the minimum
        var provisioner = new FakeProvisioner(runner) { Failure = "DISM could not install App Installer (exit code 0x80073CF3)." };
        var (setup, state) = Create(runner, provisioner, new FakeSource("GitHub", _files));

        Assert.False(await setup.EnsureAsync(Ct));
        Assert.Equal(("1.5.1101", "DISM could not install App Installer (exit code 0x80073CF3)."), (setup.Report!.Version, setup.Report.SetupError));

        provisioner.Failure = null;
        Assert.True(await setup.EnsureAsync(Ct));
        Assert.Equal(2, provisioner.Calls.Count);
        Assert.Equal(("1.29.380", (string?)null), (setup.Report!.Version, setup.Report.SetupError));
        Assert.Equal(0, state.Read(s => s.Winget.Failures));
    }

    [Fact]
    public async Task Windows_versions_without_winget_support_are_reported_without_downloading()
    {
        var runner = new FakeRunner { Installed = false };
        var provisioner = new FakeProvisioner(runner) { Unsupported = "winget needs Windows 10 version 1809 or later." };
        var github = new FakeSource("GitHub", _files);
        var (setup, _) = Create(runner, provisioner, github);

        Assert.False(await setup.EnsureAsync(Ct));

        Assert.Empty(github.Requests);
        Assert.Equal("winget needs Windows 10 version 1809 or later.", setup.Report!.SetupError);
    }

    [Fact]
    public async Task The_agent_falls_back_to_the_server_copy_and_reports_winget_at_check_in()
    {
        var runner = new FakeRunner { Installed = false };
        var provisioner = new FakeProvisioner(runner);
        using var github = new HttpClient(new Unreachable());
        using var h = new AgentHarness(o => o with { WingetHttpClient = github, WingetRelease = _release },
            configurePlatform: p => p with { WingetRunner = runner, WingetProvisioner = provisioner });
        await h.EnrollWithTokenAsync();

        // The server has no copy yet (503 while it fetches one): nothing is installed, and the failure is reported.
        Assert.False(await h.Runtime.EnsureWingetAsync(Ct));
        await h.Runtime.CheckInOnceAsync(Ct);
        var failed = h.Server.CheckIns[^1].Winget;
        Assert.NotNull(failed);
        Assert.Null(failed.Version);
        Assert.Contains("GitHub", failed.SetupError, StringComparison.Ordinal);
        Assert.Contains("503", failed.SetupError, StringComparison.Ordinal);

        foreach (var (name, bytes) in _files)
        {
            h.Server.WingetFiles[name] = bytes;
        }

        Assert.True(await h.Runtime.EnsureWingetAsync(Ct));
        Assert.Single(provisioner.Calls);
        await h.Runtime.CheckInOnceAsync(Ct);
        var ready = h.Server.CheckIns[^1].Winget;
        Assert.NotNull(ready);
        Assert.Equal(("1.29.380", true, (string?)null), (ready.Version, ready.InstalledByAgent, ready.SetupError));
    }

    private (WingetSetupService Setup, AgentStateStore State) Create(FakeRunner runner, FakeProvisioner provisioner, params IWingetFileSource[] sources)
    {
        var state = new AgentStateStore(Path.Combine(_dir, "state"));
        var setup = new WingetSetupService(runner, provisioner, sources, state, Path.Combine(_dir, "work"), () => false, TimeProvider.System,
            NullLogger<WingetSetupService>.Instance, _release, _ => 10L * 1024 * 1024 * 1024);
        return (setup, state);
    }

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static byte[] DependencyArchive(string? extra = null)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var name in new[]
                     {
                         "x64/Microsoft.VCLibs.140.00_x64.appx", "x64/Microsoft.UI.Xaml.appx", "arm64/Microsoft.VCLibs.140.00_arm64.appx",
                         "x86/Microsoft.VCLibs.140.00_x86.appx", "x64/nested/Other.appx", "x64/../Escape.appx", "x64/readme.txt",
                     }.Concat(extra is null ? [] : [extra]))
            {
                using var entry = zip.CreateEntry(name).Open();
                entry.Write(Encoding.UTF8.GetBytes(name));
            }
        }

        return buffer.ToArray();
    }

    private sealed class FakeRunner : IWingetRunner
    {
        public bool Installed { get; set; }
        public string Version { get; set; } = "v1.29.380";

        public string? Locate() => Installed ? @"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_x64\winget.exe" : null;

        public Task<WingetRunResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Installed ? Task.FromResult(new WingetRunResult(0, Version + "\n")) : throw new WingetException("winget is not installed.");
    }

    private sealed class FakeProvisioner(FakeRunner runner) : IWingetProvisioner
    {
        public string Architecture => "x64";
        public string? Unsupported { get; set; }
        public string? UnsupportedReason => Unsupported;
        public string? Failure { get; set; }
        public List<(byte[] Bundle, List<string> Dependencies, byte[] License)> Calls { get; } = [];

        public Task ProvisionAsync(string bundlePath, IReadOnlyList<string> dependencyPaths, string licensePath, CancellationToken cancellationToken)
        {
            Calls.Add((File.ReadAllBytes(bundlePath), dependencyPaths.Select(p => Path.GetFileName(p)).ToList(), File.ReadAllBytes(licensePath)));
            if (Failure is not null)
            {
                throw new WingetException(Failure);
            }

            runner.Installed = true;
            runner.Version = "v1.29.380";
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSource(string name, Dictionary<string, byte[]> files) : IWingetFileSource
    {
        public string Name => name;
        public List<string> Requests { get; } = [];

        public async Task DownloadAsync(WingetFile file, Stream destination, CancellationToken cancellationToken)
        {
            Requests.Add(file.Name);
            if (!files.TryGetValue(file.Name, out var bytes))
            {
                throw new HttpRequestException("Connection refused.");
            }

            await destination.WriteAsync(bytes, cancellationToken);
        }
    }

    private sealed class Unreachable : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("No such host is known. (github.com:443)", null, HttpStatusCode.ServiceUnavailable);
    }
}
