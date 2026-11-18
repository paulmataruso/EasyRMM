using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Applications;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>winget application updates: output parsing, verification after an upgrade, and routing next to Windows Update.</summary>
public sealed class ApplicationUpdateTests
{
    private const string Header = "Name            Id              Version  Available Source\n----------------------------------------------------------\n";

    /// <summary>Scripted winget: answers by the first argument and the package ID.</summary>
    private sealed class FakeWinget : IWingetRunner
    {
        public bool Installed { get; set; } = true;
        public string Version { get; set; } = "v1.9.25200";
        public Dictionary<string, (string Installed, string? Available)> Apps { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ListExitCodes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<IReadOnlyList<string>> Calls { get; } = [];

        /// <summary>Upgrade behaviour: the exit code and whether the version really changes.</summary>
        public int UpgradeExitCode { get; set; }
        public bool UpgradeTakesEffect { get; set; } = true;

        public string? Locate() => Installed ? @"C:\Program Files\WindowsApps\winget.exe" : null;

        public Task<WingetRunResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add(arguments);
            switch (arguments[0])
            {
                case "--version":
                    return Task.FromResult(new WingetRunResult(0, Version + "\n"));
                case "list":
                {
                    var id = arguments[2];
                    if (!Apps.TryGetValue(id, out var app))
                    {
                        return Task.FromResult(new WingetRunResult(ListExitCodes.GetValueOrDefault(id, WingetExitCodes.NoApplicationsFound),
                            "   -\r   \\\r   |\rNo installed package found matching input criteria.\n"));
                    }

                    var line = $"Some App        {id} {app.Installed} {app.Available ?? ""} winget";
                    return Task.FromResult(new WingetRunResult(0, "   -\r   \\\r" + Header + line + "\n"));
                }

                case "upgrade":
                {
                    var id = arguments[2];
                    var version = arguments[5];
                    if (UpgradeTakesEffect)
                    {
                        Apps[id] = (version, null);
                    }

                    return Task.FromResult(new WingetRunResult(UpgradeExitCode, "Found Some App [" + id + "] Version " + version + "\nSuccessfully installed\n"));
                }

                default:
                    throw new InvalidOperationException("unexpected winget command " + arguments[0]);
            }
        }
    }

    private static WingetApplicationUpdateService Service(FakeWinget winget) => new(winget, NullLogger<WingetApplicationUpdateService>.Instance);

    [Fact]
    public void Rows_are_found_by_package_id_whatever_the_header_language()
    {
        var output = "   -\r   \\\r   |\r" +
                     "Nom                     ID                         Version Disponible Source\n" +
                     "-----------------------------------------------------------------------------\n" +
                     "Mozilla Firefox (x64 fr) Mozilla.Firefox            132.0.1 133.0      winget\n";
        var row = WingetOutput.FindRow(output, "mozilla.firefox");
        Assert.NotNull(row);
        Assert.Equal("Mozilla.Firefox", row.Id);
        Assert.Equal("Mozilla Firefox (x64 fr)", row.Name);
        Assert.Equal("132.0.1", row.InstalledVersion);
        Assert.Equal("133.0", row.AvailableVersion);

        // No upgrade: winget leaves out the Available column.
        var current = WingetOutput.FindRow("Name Id Version Source\n-----\n7-Zip 24.08 (x64) 7zip.7zip 24.08 winget\n", "7zip.7zip");
        Assert.Equal(("24.08", (string?)null), (current!.InstalledVersion, current.AvailableVersion));

        // A shortened ID still matches; the configured ID is reported.
        var shortened = WingetOutput.FindRow("Microsoft Visual Studio Code Microsoft.VisualStudioCo… 1.95.0 1.95.3 winget\n", "Microsoft.VisualStudioCode");
        Assert.Equal(("Microsoft.VisualStudioCode", "1.95.0", "1.95.3"), (shortened!.Id, shortened.InstalledVersion, shortened.AvailableVersion));

        // Version ranges are not concrete versions.
        var range = WingetOutput.FindRow("Zoom Zoom.Zoom < 6.2.0 6.2.5 winget\n", "Zoom.Zoom");
        Assert.Equal(("< 6.2.0", "6.2.5"), (range!.InstalledVersion, range.AvailableVersion));
        Assert.False(ApplicationIds.IsValidVersion(range.InstalledVersion));

        Assert.Null(WingetOutput.FindRow("No installed package found matching input criteria.\n", "Mozilla.Firefox"));
        Assert.Null(WingetOutput.FindRow("Mozilla Firefox Mozilla.Firefox.ESR 128.0 winget\n", "Mozilla.Firefox"));
        Assert.Equal(new Version(1, 9, 25200), WingetOutput.ParseWingetVersion("v1.9.25200\n"));
        Assert.Equal("0x8A150014", WingetOutput.FormatExitCode(WingetExitCodes.NoApplicationsFound));
    }

    [Theory]
    [InlineData("Mozilla.Firefox", true)]
    [InlineData("7zip.7zip", true)]
    [InlineData("Notepad++.Notepad++", true)]
    [InlineData("Adobe.Acrobat.Reader.64-bit", true)]
    [InlineData("Firefox", false)]
    [InlineData("Mozilla.Firefox; calc", false)]
    [InlineData("Mozilla.Firefox --force", false)]
    [InlineData("-Mozilla.Firefox", false)]
    [InlineData("Mozilla..Firefox", false)]
    [InlineData("9NBLGGH4NNS1", false)]
    public void Only_plain_winget_package_ids_are_accepted(string id, bool valid) => Assert.Equal(valid, ApplicationIds.IsValid(id));

    [Fact]
    public async Task Scans_report_installed_versions_and_upgrades_of_approved_applications_only()
    {
        var winget = new FakeWinget();
        winget.Apps["Mozilla.Firefox"] = ("132.0.1", "133.0");
        winget.Apps["7zip.7zip"] = ("24.08", null);
        winget.Apps["VideoLAN.VLC"] = ("3.0.20", "3.0.21"); // installed but not approved
        var result = await Service(winget).ScanAsync(["Mozilla.Firefox", "7zip.7zip", "Google.Chrome"], CancellationToken.None);

        Assert.True(result.Report.Succeeded);
        Assert.Equal("1.9.25200", result.Report.WingetVersion);
        Assert.Equal(3, result.Report.Checked);
        var update = Assert.Single(result.Missing);
        Assert.Equal(ApplicationIds.UpdateGuidFor("mozilla.firefox", "133.0"), update.Update.UpdateGuid);
        Assert.Equal(UpdateCategory.Application, UpdateClassifier.Classify(update.Update));
        Assert.Equal("132.0.1", update.Update.Application!.InstalledVersion);
        Assert.True(update.Update.IsDownloaded);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], result.Installed.Select(i => i.Application!.Id));
        Assert.DoesNotContain(winget.Calls, c => c.Contains("VideoLAN.VLC"));
        Assert.All(winget.Calls.Where(c => c[0] == "list"), c => Assert.Equal(["--source", "winget"], c.Skip(4).Take(2)));
    }

    [Fact]
    public async Task Scan_failures_are_reported_without_hiding_the_other_applications()
    {
        var winget = new FakeWinget();
        winget.Apps["Mozilla.Firefox"] = ("132.0.1", "133.0");
        winget.ListExitCodes["Google.Chrome"] = unchecked((int)0x8A15000F);
        var result = await Service(winget).ScanAsync(["Mozilla.Firefox", "Google.Chrome"], CancellationToken.None);
        Assert.False(result.Report.Succeeded);
        Assert.Contains("Google.Chrome: winget exited with 0x8A15000F", result.Report.ErrorMessage, StringComparison.Ordinal);
        Assert.Single(result.Missing);

        Assert.Equal("winget_not_found", (await Service(new FakeWinget { Installed = false }).ScanAsync(["Mozilla.Firefox"], CancellationToken.None)).Report.ErrorCode);
        var old = await Service(new FakeWinget { Version = "v1.5.1572" }).ScanAsync(["Mozilla.Firefox"], CancellationToken.None);
        Assert.Equal(("winget_too_old", "1.5.1572"), (old.Report.ErrorCode, old.Report.WingetVersion));
    }

    [Fact]
    public async Task An_upgrade_succeeds_only_when_winget_then_lists_the_target_version()
    {
        var winget = new FakeWinget();
        winget.Apps["Mozilla.Firefox"] = ("132.0.1", "133.0");
        var service = Service(winget);

        var ok = await service.InstallAsync(new ApplicationUpdateHandle("Mozilla.Firefox", "133.0", "132.0.1"), CancellationToken.None);
        Assert.True(ok.IsSuccess);
        Assert.Equal(["upgrade", "--id", "Mozilla.Firefox", "--exact", "--version", "133.0", "--silent", "--accept-package-agreements", "--source", "winget",
            "--accept-source-agreements", "--disable-interactivity"], winget.Calls[0]);
        Assert.DoesNotContain(winget.Calls.SelectMany(c => c), a => a is "--force" or "--ignore-security-hash" or "msstore");

        // Exit code 0 is not enough.
        winget.Apps["Mozilla.Firefox"] = ("133.0", "134.0");
        winget.UpgradeTakesEffect = false;
        var unverified = await service.InstallAsync(new ApplicationUpdateHandle("Mozilla.Firefox", "134.0", "133.0"), CancellationToken.None);
        Assert.False(unverified.IsSuccess);
        Assert.Equal("not_verified", unverified.ErrorCode);
        Assert.Contains("133.0 is installed instead of 134.0", unverified.Message, StringComparison.Ordinal);

        // A restart is needed to finish: not installed yet, and EasyPatch never restarts on its own.
        winget.UpgradeExitCode = WingetExitCodes.RebootRequiredToFinish;
        var reboot = await service.InstallAsync(new ApplicationUpdateHandle("Mozilla.Firefox", "134.0", "133.0"), CancellationToken.None);
        Assert.False(reboot.IsSuccess);
        Assert.True(reboot.RebootRequired);
        Assert.Contains("restart is needed", reboot.Message, StringComparison.Ordinal);

        var invalid = await service.InstallAsync(new ApplicationUpdateHandle("Mozilla.Firefox", "134.0 --force", "133.0"), CancellationToken.None);
        Assert.Equal("invalid_application", invalid.ErrorCode);
    }

    [Fact]
    public async Task The_composite_service_checks_applications_only_while_policy_enables_them_and_routes_installs()
    {
        var windowsUpdate = new FakeWindowsUpdate();
        windowsUpdate.Add("2026-11 Cumulative Update", MicrosoftClassifications.SecurityUpdates, "KB5070001");
        var winget = new FakeWinget();
        winget.Apps["Mozilla.Firefox"] = ("132.0.1", "133.0");
        ApplicationUpdatesConfig? config = null;
        var composite = new CompositeUpdateService(windowsUpdate, Service(winget), () => config, NullLogger<CompositeUpdateService>.Instance);

        using (var off = await composite.ScanAsync(includeInstalled: true, CancellationToken.None))
        {
            Assert.Single(off.Missing);
            Assert.Null(off.Applications);
            Assert.Empty(winget.Calls);
        }

        config = new ApplicationUpdatesConfig { Enabled = true, ApprovedApps = ["Mozilla.Firefox", "not valid"] };
        using var on = await composite.ScanAsync(includeInstalled: true, CancellationToken.None);
        Assert.Equal(2, on.Missing.Count);
        Assert.True(on.Applications!.Succeeded);
        Assert.Equal(1, on.Applications.Checked);

        var app = on.Missing.Single(m => m.Update.Application is not null);
        Assert.True((await composite.DownloadAsync(app.Handle, null, CancellationToken.None)).IsSuccess);
        Assert.True((await composite.InstallAsync(app.Handle, acceptEula: true, null, CancellationToken.None)).IsSuccess);
        var system = on.Missing.Single(m => m.Update.Application is null);
        await composite.InstallAsync(system.Handle, acceptEula: true, null, CancellationToken.None);
        Assert.Equal(1, windowsUpdate.InstallCount(system.Update.UpdateGuid));
    }

    [Fact]
    public void Application_updates_are_installed_only_while_approved()
    {
        var update = new ReportedUpdate
        {
            UpdateGuid = ApplicationIds.UpdateGuidFor("Mozilla.Firefox", "133.0"),
            Title = "Mozilla Firefox 133.0",
            Application = new ApplicationUpdateInfo { Id = "Mozilla.Firefox", Version = "133.0", InstalledVersion = "132.0" },
        };
        var all = new InstallUpdatesPayload { Mode = InstallMode.AllEligible, Filter = new InstallFilterOptions { Categories = [.. Enum.GetValues<UpdateCategory>()] } };
        Assert.Equal(SkipReasons.ApplicationNotApproved, InstallFilter.Evaluate(update, all).SkipReason);
        Assert.True(InstallFilter.Evaluate(update, all with { Filter = all.Filter with { ApprovedApplications = ["mozilla.firefox"] } }).Install);

        var selected = new InstallUpdatesPayload { Mode = InstallMode.Selected, SelectedUpdateGuids = [update.UpdateGuid], Filter = new InstallFilterOptions() };
        Assert.Equal(SkipReasons.ApplicationNotApproved, InstallFilter.Evaluate(update, selected).SkipReason);
        Assert.True(InstallFilter.Evaluate(update, selected with { Filter = new InstallFilterOptions { ApprovedApplications = ["Mozilla.Firefox"] } }).Install);
    }
}
