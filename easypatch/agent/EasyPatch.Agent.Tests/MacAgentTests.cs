using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.MacOS;
using EasyPatch.MacOS.Platform;
using EasyPatch.MacOS.SoftwareUpdate;
using EasyPatch.Unix.Processes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>The experimental macOS agent: softwareupdate parsing, scans, installations and the launchd jobs, against a
/// scripted <c>softwareupdate</c>.</summary>
public sealed class MacAgentTests : IDisposable
{
    private const string SequoiaLabel = "macOS Sequoia 15.7.2-24G325";
    private readonly TempDirectory _directory = new();
    private readonly FixedBootTime _boot = new(DateTimeOffset.Parse("2026-11-16T08:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

    public void Dispose() => _directory.Dispose();

    private static readonly MacSystemInfo Intel = new("15.7.1", "24G231", AppleSilicon: false);
    private static readonly MacSystemInfo AppleSilicon = Intel with { AppleSilicon = true };

    private SoftwareUpdateService Service(FakeSoftwareUpdate fake, MacSystemInfo? system = null) =>
        new(fake, system ?? Intel, Path.Combine(_directory.Path, "ledger.json"), _boot, TimeProvider.System, NullLogger<SoftwareUpdateService>.Instance);

    private static FakeSoftwareUpdate WithSequoiaAndTools()
    {
        var fake = new FakeSoftwareUpdate();
        fake.Available.Add(new SoftwareUpdateItem(SequoiaLabel, "macOS Sequoia 15.7.2", "15.7.2", 6887516L * 1024, true, true));
        fake.Available.Add(new SoftwareUpdateItem("Command Line Tools for Xcode-16.4", "Command Line Tools for Xcode", "16.4", 707085L * 1024, true, false));
        return fake;
    }

    // ------------------------------------------------------------------ parsing

    [Fact]
    public void Lists_are_parsed_and_unreadable_output_is_never_an_empty_list()
    {
        var output = """
            Software Update Tool

            Finding available software
            Software Update found the following new or updated software:
            * Label: macOS Sequoia 15.7.2-24G325
            	Title: macOS Sequoia 15.7.2, Version: 15.7.2, Size: 6887516KiB, Recommended: YES, Action: restart,
            * Label: Safari18.6SequoiaAuto-18.6
            	Title: Safari, Version: 18.6, Size: 210000K, Recommended: YES,
            * Label: Odd, Inc. Tool-2.0
            	Title: Odd, Inc. Tool, Version: 2.0, Size: 12KiB, Recommended: NO,
            """;
        var items = SoftwareUpdateParser.ParseList(output);
        Assert.Equal(3, items.Count);
        Assert.Equal(new SoftwareUpdateItem(SequoiaLabel, "macOS Sequoia 15.7.2", "15.7.2", 6887516L * 1024, true, true), items[0]);
        Assert.Equal(("Safari", "18.6", 210000L * 1024, false), (items[1].Title, items[1].Version, items[1].SizeBytes, items[1].RestartRequired));
        Assert.Equal(("Odd, Inc. Tool", "2.0", false), (items[2].Title, items[2].Version, items[2].Recommended));

        Assert.Empty(SoftwareUpdateParser.ParseList("Software Update Tool\n\nFinding available software\nNo new software available.\n"));

        // No network, a catalog error, a truncated listing: an exception, never "no updates".
        var offline = Assert.Throws<SoftwareUpdateException>(() =>
            SoftwareUpdateParser.ParseList("Software Update Tool\n\nFinding available software\nCan't connect to the Apple Software Update server.\n"));
        Assert.Equal("softwareupdate_failed", offline.Code);
        Assert.Throws<SoftwareUpdateException>(() => SoftwareUpdateParser.ParseList(""));
        Assert.Throws<SoftwareUpdateException>(() =>
            SoftwareUpdateParser.ParseList("Software Update found the following new or updated software:\n"));
        Assert.Throws<SoftwareUpdateException>(() =>
            SoftwareUpdateParser.ParseList("Software Update found the following new or updated software:\n* Label: X-1\n"));
    }

    [Fact]
    public void History_and_versions_are_parsed()
    {
        var history = SoftwareUpdateParser.ParseHistory("""
            Display Name                                       Version    Date
            ------------                                       -------    ----
            macOS Sequoia 15.7.2                               15.7.2     11/04/2026, 18:25:43
            macOS Ventura 13.4.1 (a)                           13.4.1 (a) 07/10/2023, 09:00:00
            Command Line Tools for Xcode                       16.4       06/01/2026, 07:05:00
            garbage line
            """);
        Assert.Equal(["macOS Sequoia 15.7.2", "macOS Ventura 13.4.1 (a)", "Command Line Tools for Xcode"], history.Select(h => h.Title));
        Assert.Equal(["15.7.2", "13.4.1 (a)", "16.4"], history.Select(h => h.Version));
        Assert.All(history, h => Assert.NotNull(h.Date));

        Assert.True(SoftwareUpdateParser.CompareVersions("15.10", "15.9") > 0);
        Assert.True(SoftwareUpdateParser.CompareVersions("15.7.2", "15.7") > 0);
        Assert.Equal(0, SoftwareUpdateParser.CompareVersions("18.6", "18.6.0"));
    }

    [Fact]
    public void Apple_updates_are_classified_and_identified()
    {
        var point = new SoftwareUpdateItem(SequoiaLabel, "macOS Sequoia 15.7.2", "15.7.2", null, true, true);
        var upgrade = new SoftwareUpdateItem("macOS Tahoe 26.1-25B78", "macOS Tahoe 26.1", "26.1", null, true, true);
        var response = new SoftwareUpdateItem("macOS Background Security Improvement 26.1 (a)-25B78a", "Background Security Improvement", "26.1 (a)", null, true, true);
        var safari = new SoftwareUpdateItem("Safari18.6SequoiaAuto-18.6", "Safari", "18.6", null, true, false);

        Assert.Equal("Security Updates", SoftwareUpdateCatalog.ClassificationOf(point, 15));
        Assert.Equal("Upgrades", SoftwareUpdateCatalog.ClassificationOf(upgrade, 15));
        Assert.Equal("Security Updates", SoftwareUpdateCatalog.ClassificationOf(response, 26));
        Assert.Equal("Updates", SoftwareUpdateCatalog.ClassificationOf(safari, 15));
        Assert.Equal("macOS Sequoia", SoftwareUpdateCatalog.LineOf(point.Title, point.Version));

        var reported = SoftwareUpdateCatalog.Describe(point, 15);
        Assert.Equal(UpdateCategory.Security, UpdateClassifier.Classify(reported));
        Assert.Equal(UpdateCategory.Feature, UpdateClassifier.Classify(SoftwareUpdateCatalog.Describe(upgrade, 15)));
        Assert.Equal(UpdateCategory.Other, UpdateClassifier.Classify(SoftwareUpdateCatalog.Describe(safari, 15)));
        Assert.Equal((1, "macOS Sequoia 15.7.2", "Safari 18.6"), (reported.RebootBehavior, reported.Title, SoftwareUpdateCatalog.Describe(safari, 15).Title));
        Assert.Contains(SequoiaLabel, reported.Description, StringComparison.Ordinal);

        // The same Apple update is the same update on every Mac, and matches its history entry.
        Assert.Equal(reported.UpdateGuid, SoftwareUpdateCatalog.Describe(point with { Label = "other-label", SizeBytes = 1 }, 15).UpdateGuid);
        Assert.Equal(SoftwareUpdateCatalog.InstalledKey("macOS Sequoia 15.7.2", "15.7.2"), SoftwareUpdateCatalog.InstalledKey("macOS Sequoia", "15.7.2"));
    }

    [Fact]
    public void System_details_are_parsed()
    {
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1731700000),
            MacSystemInfo.ParseBootTime("{ sec = 1731700000, usec = 123456 } Sat Nov 16 04:00:00 2024"));
        Assert.Null(MacSystemInfo.ParseBootTime("garbage"));
        Assert.Equal("macOS Sequoia 15.7.1", Intel.Caption);
        Assert.Equal("macOS 27.0", (Intel with { ProductVersion = "27.0" }).Caption);

        var hardware = MacSystemInfo.ParseHardware("""
            {"SPHardwareDataType":[{"_name":"hardware_overview","chip_type":"Apple M2","machine_model":"Mac14,2","machine_name":"MacBook Air",
              "platform_UUID":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","serial_number":"C02ABCDEF123"}]}
            """);
        Assert.Equal(new MacSystemInfo.Hardware("MacBook Air", "Mac14,2", "Apple M2", "C02ABCDEF123", "3F2504E0-4F89-11D3-9A0C-0305E82C3301"), hardware);
        Assert.Null(MacSystemInfo.ParseHardware("not json"));
        Assert.Equal("Intel(R) Core(TM) i7-8700B CPU @ 3.20GHz", MacSystemInfo.ProcessorName("Intel(R) Core(TM) i7-8700B CPU @ 3.20GHz\n", "Unknown"));
        Assert.Equal("Apple M2", MacSystemInfo.ProcessorName(null, "Apple M2"));
        Assert.Null(MacSystemInfo.ProcessorName("", "Unknown"));

        Assert.True(MacUpdateSourceDetector.IsMdmEnrolled("Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n"));
        Assert.False(MacUpdateSourceDetector.IsMdmEnrolled("Enrolled via DEP: No\nMDM enrollment: No\n"));
        Assert.False(MacUpdateSourceDetector.IsMdmEnrolled(null));
    }

    // ------------------------------------------------------------------ scans

    [Fact]
    public async Task An_update_that_disappears_is_installed_only_when_the_history_records_it()
    {
        var fake = WithSequoiaAndTools();
        using var service = Service(fake);
        using (var first = await service.ScanAsync(includeInstalled: true, CancellationToken.None))
        {
            Assert.Equal(["macOS Sequoia 15.7.2", "Command Line Tools for Xcode 16.4"], first.Missing.Select(c => c.Update.Title));
            Assert.Empty(first.Installed);
            Assert.All(first.Missing, c => Assert.False(c.Update.IsDownloaded));
        }

        // Both disappear; only the tools are in the history (macOS Sequoia was, say, withdrawn by Apple).
        fake.Available.Clear();
        fake.History.Add(("Command Line Tools for Xcode", "16.4"));
        using var second = await service.ScanAsync(includeInstalled: true, CancellationToken.None);
        Assert.Empty(second.Missing);
        var installed = Assert.Single(second.Installed);
        Assert.Equal(("Command Line Tools for Xcode 16.4", true), (installed.Title, installed.IsInstalled));
    }

    [Fact]
    public async Task A_newer_version_supersedes_the_one_seen_before()
    {
        var fake = new FakeSoftwareUpdate();
        fake.Available.Add(new SoftwareUpdateItem("Safari18.5SequoiaAuto-18.5", "Safari", "18.5", null, true, false));
        using var service = Service(fake);
        Guid old;
        using (var first = await service.ScanAsync(false, CancellationToken.None))
        {
            old = Assert.Single(first.Missing).Update.UpdateGuid;
        }

        fake.Available[0] = new SoftwareUpdateItem("Safari18.6SequoiaAuto-18.6", "Safari", "18.6", null, true, false);
        using var second = await service.ScanAsync(false, CancellationToken.None);
        Assert.Equal([old], Assert.Single(second.Missing).Update.SupersededUpdateGuids);
    }

    [Fact]
    public async Task A_failed_listing_fails_the_scan()
    {
        var fake = new FakeSoftwareUpdate { ListOutput = "Software Update Tool\n\nFinding available software\nCan't connect to the Apple Software Update server.\n" };
        using var service = Service(fake);
        var ex = await Assert.ThrowsAsync<SoftwareUpdateException>(() => service.ScanAsync(false, CancellationToken.None));
        Assert.Equal("softwareupdate_failed", service.DescribeFailure(ex).Code);
    }

    // ------------------------------------------------------------------ installations

    [Fact]
    public async Task Apple_silicon_never_attempts_updates_that_need_a_restart()
    {
        var fake = WithSequoiaAndTools();
        using var service = Service(fake, AppleSilicon);
        using var scan = await service.ScanAsync(false, CancellationToken.None);
        var sequoia = scan.Missing.Single(c => c.Update.RebootBehavior == 1);

        var download = await service.DownloadAsync(sequoia.Handle, null, CancellationToken.None);
        var install = await service.InstallAsync(sequoia.Handle, true, null, CancellationToken.None);
        Assert.Equal((false, SoftwareUpdateService.OwnerRequiredCode), (download.IsSuccess, download.ErrorCode));
        Assert.Equal((false, SoftwareUpdateService.OwnerRequiredCode), (install.IsSuccess, install.ErrorCode));
        Assert.Contains("System Settings", install.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(fake.Commands, c => c.Contains("--install", StringComparison.Ordinal) || c.Contains("--download", StringComparison.Ordinal));

        // Updates without a restart install on Apple silicon too.
        var tools = scan.Missing.Single(c => c.Update.RebootBehavior == 0);
        Assert.True((await service.InstallAsync(tools.Handle, true, null, CancellationToken.None)).IsSuccess);
        Assert.Contains(fake.Commands, c => c == "/usr/sbin/softwareupdate --install Command Line Tools for Xcode-16.4");
    }

    [Fact]
    public async Task An_installation_succeeds_only_when_softwareupdate_confirms_it()
    {
        var fake = WithSequoiaAndTools();
        using var service = Service(fake);
        var detector = new MacRebootDetector(service);
        using var scan = await service.ScanAsync(false, CancellationToken.None);
        var sequoia = scan.Missing.Single(c => c.Update.RebootBehavior == 1).Handle;
        var tools = scan.Missing.Single(c => c.Update.RebootBehavior == 0).Handle;

        // Still listed afterwards, no restart involved: not installed.
        fake.StayListed.Add("Command Line Tools for Xcode-16.4");
        var failed = await service.InstallAsync(tools, true, null, CancellationToken.None);
        Assert.Equal((false, "softwareupdate_not_installed"), (failed.IsSuccess, failed.ErrorCode));

        // softwareupdate exits with an error: failed, with its output.
        fake.FailInstall = true;
        var error = await service.InstallAsync(tools, true, null, CancellationToken.None);
        Assert.Equal((false, "softwareupdate_install_failed"), (error.IsSuccess, error.ErrorCode));
        Assert.Contains("simulated failure", error.Message, StringComparison.Ordinal);
        fake.FailInstall = false;

        // The check afterwards fails: not confirmed, so not reported as installed.
        fake.StayListed.Clear();
        fake.ListOutputAfterInstall = "Software Update Tool\n\nFinding available software\nCan't connect to the Apple Software Update server.\n";
        var unconfirmed = await service.InstallAsync(tools, true, null, CancellationToken.None);
        Assert.Equal((false, "softwareupdate_unconfirmed"), (unconfirmed.IsSuccess, unconfirmed.ErrorCode));
        fake.ListOutputAfterInstall = null;

        // An Intel Mac prepares the macOS update; it is listed until the restart: installed, waiting for the restart.
        fake.StayListed.Add(SequoiaLabel);
        Assert.False((await detector.DetectAsync(CancellationToken.None)).Pending);
        var prepared = await service.InstallAsync(sequoia, true, null, CancellationToken.None);
        Assert.Equal((true, true), (prepared.IsSuccess, prepared.RebootRequired));
        Assert.DoesNotContain(fake.Commands, c => c.Contains("--restart", StringComparison.Ordinal) || c.Contains("-R", StringComparison.Ordinal));
        var status = await detector.DetectAsync(CancellationToken.None);
        Assert.True(status.Pending);
        Assert.Contains("macOS Sequoia 15.7.2", Assert.Single(status.Reasons), StringComparison.Ordinal);
        using (var rescan = await service.ScanAsync(false, CancellationToken.None))
        {
            Assert.True(rescan.Missing.Single(c => c.Update.RebootBehavior == 1).Update.RebootRequired);
        }

        // After the restart (new boot time) nothing is pending any more.
        _boot.Value = _boot.Value.AddHours(1);
        Assert.False((await detector.DetectAsync(CancellationToken.None)).Pending);
    }

    [Fact]
    public void The_macOS_agent_does_not_offer_downloads_ahead_of_the_window()
    {
        using var service = Service(new FakeSoftwareUpdate());
        var platform = new AgentPlatform(service, new NoInventory(), new MacRebootDetector(service), new MacUpdateSourceDetector(new FakeSoftwareUpdate()),
            new FilePermissionSecretProtector(), new NoBootstrap(), _boot);
        Assert.DoesNotContain(AgentCapabilities.DownloadUpdates, platform.Capabilities);
        Assert.False(platform.SupportsDownloadOnly);
    }

    // ------------------------------------------------------------------ restarts, keys, launchd jobs

    [Fact]
    public void Restarts_keys_and_launchd_jobs()
    {
        Assert.Equal(["-r", "now"], MacSystemRestart.Arguments(TimeSpan.Zero, null));
        Assert.Equal(["-r", "+5", "Updates were installed"], MacSystemRestart.Arguments(TimeSpan.FromMinutes(4.5), "Updates were\n installed".Replace("\n ", " ", StringComparison.Ordinal)));
        Assert.Equal(["-r", "+1", "ab"], MacSystemRestart.Arguments(TimeSpan.FromSeconds(10), "a\u0007b"));

        var protector = new FilePermissionSecretProtector();
        Assert.Equal(new byte[] { 1, 2, 3 }, protector.Unprotect(protector.Protect([1, 2, 3])));
        Assert.Equal("file-permissions", ((ISecretProtector)protector).Kind);

        var plist = LaunchdJobRunner.PropertyList(MacPaths.UpdateJobLabel, ["/bin/sh", "-c", "a <b> & \"c\"", "/x/y.pkg"]);
        Assert.Contains("<string>a &lt;b&gt; &amp; &quot;c&quot;</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<key>LaunchOnlyOnce</key>", plist, StringComparison.Ordinal);
        Assert.Contains($"<string>{MacPaths.UpdateJobLabel}</string>", plist, StringComparison.Ordinal);

        // The shell only ever sees fixed text; paths are positional parameters.
        Assert.DoesNotContain("{", MacAgentInstaller.InstallScript, StringComparison.Ordinal);
        Assert.Contains("\"$0\"", MacAgentInstaller.InstallScript, StringComparison.Ordinal);
        Assert.True(MacAgentInstaller.SafePath("/Library/EasyPatch/data/updates/EasyPatchAgent-1.9.0-arm64.pkg"));
        Assert.False(MacAgentInstaller.SafePath("/tmp/a b.pkg"));
        Assert.False(MacAgentInstaller.SafePath("/tmp/$(reboot).pkg"));
        Assert.False(MacAgentInstaller.SafePath("relative/x.pkg"));

        var installer = new MacAgentInstaller(new LaunchdJobRunner(new FakeSoftwareUpdate(), _directory.Path), new FakeSoftwareUpdate());
        Assert.Equal(AgentRelease.FormatPkg, installer.PackageFormat);
        Assert.Throws<ArgumentException>(() => installer.Start("/Library/EasyPatch/data/updates/EasyPatchAgent-1.9.0-arm64.deb", "/Library/EasyPatch/data/x.log"));
        Assert.Throws<ArgumentException>(() => installer.Start("/tmp/x y/EasyPatchAgent-1.9.0-arm64.pkg", "/Library/EasyPatch/data/x.log"));

        File.WriteAllText(Path.Combine(_directory.Path, "install.log.exit"), "0\n");
        Assert.Equal(0, installer.ReadResult(Path.Combine(_directory.Path, "install.log")));
        Assert.Null(installer.ReadResult(Path.Combine(_directory.Path, "missing.log")));
        Assert.False(new MacAgentUninstaller(new LaunchdJobRunner(new FakeSoftwareUpdate(), _directory.Path), new FakeSoftwareUpdate(),
            Path.Combine(_directory.Path, "uninstall.sh")).IsAvailable);
    }

    [Fact]
    public async Task Launchd_jobs_are_started_from_a_plist_in_the_data_directory()
    {
        var fake = new FakeSoftwareUpdate();
        var jobs = new LaunchdJobRunner(fake, Path.Combine(_directory.Path, "launchd"));
        var log = Path.Combine(_directory.Path, "install.log");
        File.WriteAllText(log + ".exit", "1");
        await jobs.StartAsync(MacPaths.UpdateJobLabel, ["/bin/sh", "-c", MacAgentInstaller.InstallScript, "/p.pkg", log], log, CancellationToken.None);

        Assert.False(File.Exists(log + ".exit"));
        var plist = Path.Combine(_directory.Path, "launchd", MacPaths.UpdateJobLabel + ".plist");
        Assert.True(File.Exists(plist));
        Assert.Equal(
            [$"/bin/launchctl bootout system/{MacPaths.UpdateJobLabel}", $"/bin/launchctl bootstrap system {plist}"],
            fake.Commands.Where(c => c.StartsWith("/bin/launchctl", StringComparison.Ordinal)));

        File.WriteAllText(log + ".exit", "0\n");
        Assert.Equal(0, await jobs.WaitAsync(MacPaths.UpdateJobLabel, log, TimeSpan.FromMinutes(1), CancellationToken.None));
    }

    // ------------------------------------------------------------------ fakes

    private sealed class FixedBootTime(DateTimeOffset value) : IBootTimeProvider
    {
        public DateTimeOffset Value { get; set; } = value;

        public DateTimeOffset GetLastBootTime() => Value;
    }

    private sealed class NoInventory : IInventoryCollector
    {
        public Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class NoBootstrap : IBootstrapConfigSource
    {
        public BootstrapConfig Read() => BootstrapConfig.Empty;

        public void ClearEnrollmentSecrets()
        {
        }
    }

    /// <summary>A scripted softwareupdate (plus launchctl, which always succeeds).</summary>
    private sealed class FakeSoftwareUpdate : ICommandRunner
    {
        public List<SoftwareUpdateItem> Available { get; } = [];

        public List<(string Title, string Version)> History { get; } = [];

        /// <summary>Labels that stay listed after their installation.</summary>
        public HashSet<string> StayListed { get; } = new(StringComparer.Ordinal);

        public List<string> Commands { get; } = [];

        public string? ListOutput { get; set; }

        public string? ListOutputAfterInstall { get; set; }

        public bool FailInstall { get; set; }

        private bool _installed;

        public string? Find(string program) => program.StartsWith('/') ? program : "/usr/bin/" + program;

        public Task<CommandResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
            IReadOnlyDictionary<string, string>? environment = null, byte[]? standardInput = null)
        {
            Commands.Add(program + " " + string.Join(' ', arguments));
            if (program != "/usr/sbin/softwareupdate")
            {
                return Task.FromResult(new CommandResult(program.EndsWith("launchctl", StringComparison.Ordinal) && arguments[0] == "print" ? 113 : 0, string.Empty, string.Empty));
            }

            switch (arguments[0])
            {
                case "--list":
                    var output = _installed && ListOutputAfterInstall is not null ? ListOutputAfterInstall : ListOutput ?? Listing();
                    _installed = false;
                    return Task.FromResult(new CommandResult(0, output, string.Empty));
                case "--history":
                    return Task.FromResult(new CommandResult(0,
                        "Display Name                                       Version    Date\n------------                                       -------    ----\n" +
                        string.Concat(History.Select(h => $"{h.Title,-50} {h.Version,-10} 11/15/2026, 10:00:00\n")), string.Empty));
                case "--download":
                    return Task.FromResult(new CommandResult(0, "Downloading " + arguments[1] + "\nDone.\n", string.Empty));
                case "--install":
                    if (FailInstall)
                    {
                        return Task.FromResult(new CommandResult(1, string.Empty, "simulated failure"));
                    }

                    var item = Available.Single(i => i.Label == arguments[1]);
                    if (!StayListed.Contains(item.Label))
                    {
                        Available.Remove(item);
                    }

                    _installed = true;
                    return Task.FromResult(new CommandResult(0,
                        $"Installing {item.Title}\nDone with {item.Label}\n" + (item.RestartRequired ? "Please restart immediately.\n" : "Done.\n"), string.Empty));
                default:
                    return Task.FromResult(new CommandResult(1, string.Empty, "usage"));
            }
        }

        private string Listing() => Available.Count == 0
            ? "Software Update Tool\n\nFinding available software\nNo new software available.\n"
            : "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n" + string.Concat(Available.Select(i =>
                $"* Label: {i.Label}\n\tTitle: {i.Title}, Version: {i.Version}, Size: {(i.SizeBytes ?? 0) / 1024}KiB, Recommended: {(i.Recommended ? "YES" : "NO")}, " +
                (i.RestartRequired ? "Action: restart, " : string.Empty) + "\n"));

        public Task<(int ExitCode, byte[] Output, string Error)> RunBinaryAsync(string program, IReadOnlyList<string> arguments, byte[] standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
