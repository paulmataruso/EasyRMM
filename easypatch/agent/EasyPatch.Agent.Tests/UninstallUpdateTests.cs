using System.Text;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Removal;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Removing an installed update: Windows Update's own uninstall when it supports the update, otherwise DISM's
/// /Remove-Package for the KB's servicing package, confirmed afterwards. Nothing restarts the computer.</summary>
public sealed class UninstallUpdateTests
{
    private const string Lcu24H2 = "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2314.1.10";
    private const string OlderLcu24H2 = "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2033.1.6";
    private const string Lcu1809 = "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6532.1.11";
    private const string OlderLcu1809 = "Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.6414.1.8";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static UninstallUpdatePayload Lcu(string title, string kb) => new()
    {
        UpdateGuid = Guid.NewGuid(), Title = title, KbNumber = kb, Category = UpdateCategory.Cumulative,
    };

    private static WindowsUpdateRemover Remover(FakeWuaUninstaller wua, FakeDism dism) =>
        new(wua, dism, NullLogger<WindowsUpdateRemover>.Instance);

    [Fact]
    public void The_package_listing_is_read_and_only_plain_package_names_are_kept()
    {
        var output = FakeDism.Listing(
        [
            new DismPackage(Lcu24H2, "Installed", "Security Update"),
            new DismPackage("Package_for_KB5034441~31bf3856ad364e35~amd64~~10.0.1.0", "Install Pending", "Update"),
            new DismPackage("Package_for_KB1 & calc.exe", "Installed", "Update"),
            new DismPackage("Package_for_ServicingStack_2304~31bf3856ad364e35~amd64~~26100.2304.1.0", "Installed", "Update"),
        ]);

        var packages = DismPackages.Parse(output);

        Assert.Equal(
            [(Lcu24H2, "Installed", "Security Update"), ("Package_for_KB5034441~31bf3856ad364e35~amd64~~10.0.1.0", "Install Pending", "Update"),
             ("Package_for_ServicingStack_2304~31bf3856ad364e35~amd64~~26100.2304.1.0", "Installed", "Update")],
            packages.Select(p => (p.Identity, p.State, p.ReleaseType)));
        Assert.Equal("26100.2314.1.10", packages[0].Version);
    }

    [Fact]
    public void Packages_are_matched_to_a_KB_exactly()
    {
        var packages = new[]
        {
            new DismPackage("Package_for_KB5034441~31bf3856ad364e35~amd64~~10.0.1.0", "Installed", "Update"),
            new DismPackage("Package_for_KB50344410~31bf3856ad364e35~amd64~~10.0.1.0", "Installed", "Update"),
            new DismPackage(Lcu24H2, "Installed", "Security Update"),
            new DismPackage(OlderLcu24H2, "Superseded", "Security Update"),
            new DismPackage("Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9277.1", "Installed", "Update"),
        };

        Assert.Equal(["Package_for_KB5034441~31bf3856ad364e35~amd64~~10.0.1.0"], DismPackages.NamedForKb(packages, "5034441").Select(p => p.Identity));
        Assert.Empty(DismPackages.NamedForKb(packages, "503444"));
        Assert.Equal([Lcu24H2, "Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9277.1"],
            DismPackages.RollupCandidates(packages).Select(p => p.Identity));

        Assert.Equal("26100.2314",
            DismPackages.BuildFromTitle("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)"));
        Assert.Null(DismPackages.BuildFromTitle("2024-11 Cumulative Update for Windows Server 2019 (1809) for x64-based Systems (KB5046615)"));
        Assert.True(DismPackages.IsBuild(packages[2], "26100.2314"));
        Assert.False(DismPackages.IsBuild(packages[2], "26100.231"));

        Assert.True(DismPackages.MentionsKb("Description : Fix for KB5046615\nSupport Information : http://support.microsoft.com/?kbid=5046615", "5046615"));
        Assert.True(DismPackages.MentionsKb("Support Information : https://support.microsoft.com/help/5046615", "5046615"));
        Assert.False(DismPackages.MentionsKb("Description : Fix for KB50466150", "5046615"));
        Assert.False(DismPackages.MentionsKb("Product Version : 17763.5046615.1.1", "5046615"));
    }

    [Fact]
    public async Task An_update_Windows_Update_can_uninstall_is_removed_by_Windows_Update()
    {
        var wua = new FakeWuaUninstaller { Result = new WuaUninstallResult(WuaUninstallStatus.Attempted, new UpdateOperationResult(2, 0, true)) };
        var dism = new FakeDism();
        var update = Lcu("Security Update for Microsoft Office (KB5002651)", "5002651");

        var result = await Remover(wua, dism).RemoveAsync(update, Ct);

        Assert.Equal((UpdateRemovalStatus.Removed, true, "Windows Update"), (result.Status, result.RebootRequired, result.Method));
        Assert.Equal([update.UpdateGuid], wua.Calls);
        Assert.Empty(dism.Commands);
    }

    [Fact]
    public async Task A_cumulative_update_is_removed_with_DISM_by_the_build_in_its_title_and_never_restarts_the_computer()
    {
        var wua = new FakeWuaUninstaller { Result = new WuaUninstallResult(WuaUninstallStatus.NotUninstallable) };
        var dism = new FakeDism { RemoveExitCode = DismPackages.RestartRequired, StateAfterRemoval = DismPackages.UninstallPending };
        dism.Add(OlderLcu24H2, "Superseded");
        dism.Add(Lcu24H2, "Installed");
        dism.Add("Package_for_ServicingStack_2304~31bf3856ad364e35~amd64~~26100.2304.1.0", "Installed");

        var result = await Remover(wua, dism).RemoveAsync(
            Lcu("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)", "5046617"), Ct);

        Assert.Equal((UpdateRemovalStatus.Removed, true, "DISM"), (result.Status, result.RebootRequired, result.Method));
        Assert.Contains(Lcu24H2, result.Message, StringComparison.Ordinal);
        var removal = Assert.Single(dism.Commands, c => c[1] == "/Remove-Package");
        Assert.Equal(["/Online", "/Remove-Package", "/PackageName:" + Lcu24H2, "/Quiet", "/NoRestart", "/English", "/LogPath:" + dism.LogPath], removal);
        Assert.DoesNotContain(dism.Commands, c => c[1] == "/Get-PackageInfo");
        Assert.All(dism.Commands.Where(c => c[1] != "/Get-Packages"), c => Assert.Contains("/NoRestart", c));
        Assert.Equal(DismPackages.UninstallPending, dism.StateOf(Lcu24H2));
        Assert.Equal("Superseded", dism.StateOf(OlderLcu24H2));
    }

    [Fact]
    public async Task Without_a_build_in_the_title_the_package_information_must_name_the_KB()
    {
        var wua = new FakeWuaUninstaller { Result = new WuaUninstallResult(WuaUninstallStatus.NotUninstallable) };
        var dism = new FakeDism { StateAfterRemoval = null };
        dism.Add(OlderLcu1809, "Superseded", info: "Description : Fix for KB5044277");
        dism.Add(Lcu1809, "Installed", info: "Description : Fix for KB5046615\nSupport Information : http://support.microsoft.com/?kbid=5046615");
        dism.Add("Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9277.1", "Installed", info: "Description : Fix for KB5045627");

        var result = await Remover(wua, dism).RemoveAsync(
            Lcu("2024-11 Cumulative Update for Windows Server 2019 (1809) for x64-based Systems (KB5046615)", "5046615"), Ct);

        Assert.Equal((UpdateRemovalStatus.Removed, false), (result.Status, result.RebootRequired));
        Assert.Equal(["/PackageName:" + Lcu1809], dism.Commands.Where(c => c[1] == "/Remove-Package").Select(c => c[2]));
        Assert.DoesNotContain(dism.Commands, c => c[1] == "/Get-PackageInfo" && c[2] == "/PackageName:" + OlderLcu1809);
        Assert.Null(dism.StateOf(Lcu1809));
    }

    [Fact]
    public async Task Updates_Windows_will_not_remove_are_reported_as_not_removable()
    {
        // A permanent package: DISM refuses.
        var dism = new FakeDism { RemoveExitCode = DismPackages.PermanentPackage };
        dism.Add("Package_for_KB5005112~31bf3856ad364e35~amd64~~17763.1971.1.0", "Installed");
        var permanent = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, dism)
            .RemoveAsync(Lcu("2021-08 Servicing Stack Update for Windows Server 2019 (KB5005112)", "5005112"), Ct);
        Assert.Equal((UpdateRemovalStatus.NotRemovable, "update_not_removable"), (permanent.Status, permanent.ErrorCode));

        // Installed according to Windows Update, but neither uninstallable nor a servicing package (a definition update).
        var definition = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, new FakeDism())
            .RemoveAsync(Lcu("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1.0)", "2267602"), Ct);
        Assert.Equal(UpdateRemovalStatus.NotRemovable, definition.Status);

        // No KB number and not uninstallable: nothing else can be tried.
        var noKb = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, new FakeDism())
            .RemoveAsync(new UninstallUpdatePayload { UpdateGuid = Guid.NewGuid(), Title = "Intel - System - 10.1.1.44" }, Ct);
        Assert.Equal(UpdateRemovalStatus.NotRemovable, noKb.Status);
    }

    [Fact]
    public async Task An_update_that_is_already_gone_or_queued_for_removal_is_not_removed_again()
    {
        var gone = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotInstalled) }, new FakeDism())
            .RemoveAsync(Lcu("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)", "5046617"), Ct);
        Assert.Equal(UpdateRemovalStatus.NotInstalled, gone.Status);

        var dism = new FakeDism();
        dism.Add(Lcu24H2, DismPackages.UninstallPending);
        var queued = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, dism)
            .RemoveAsync(Lcu("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)", "5046617"), Ct);
        Assert.Equal((UpdateRemovalStatus.Removed, true), (queued.Status, queued.RebootRequired));
        Assert.DoesNotContain(dism.Commands, c => c[1] == "/Remove-Package");
    }

    [Fact]
    public async Task A_removal_counts_only_when_DISM_no_longer_lists_the_package_as_installed()
    {
        var dism = new FakeDism { StateAfterRemoval = DismPackages.Installed };
        dism.Add(Lcu24H2, "Installed");
        var result = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, dism)
            .RemoveAsync(Lcu("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)", "5046617"), Ct);
        Assert.Equal((UpdateRemovalStatus.Failed, "update_still_installed"), (result.Status, result.ErrorCode));

        var failing = new FakeDism { RemoveExitCode = unchecked((int)0x800F082F), RemoveOutput = "Error: 0x800f082f\n\nThe operation could not be completed because a restart is pending." };
        failing.Add(Lcu24H2, "Installed");
        var refused = await Remover(new FakeWuaUninstaller { Result = new(WuaUninstallStatus.NotUninstallable) }, failing)
            .RemoveAsync(Lcu("2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)", "5046617"), Ct);
        Assert.Equal((UpdateRemovalStatus.Failed, "0x800F082F"), (refused.Status, refused.ErrorCode));
        Assert.Contains("restart is pending", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_job_removes_the_update_scans_and_reports_that_a_restart_is_needed_without_restarting()
    {
        var remover = new FakeRemover { Result = new UpdateRemovalResult(UpdateRemovalStatus.Removed, "Removed KB5046617 with DISM.", true, Method: "DISM") };
        using var h = new AgentHarness(configurePlatform: p => p with { UpdateRemover = remover });
        await h.EnrollWithTokenAsync();
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Contains(AgentCapabilities.UninstallUpdates, h.Server.CheckIns[^1].Capabilities);

        var job = RemovalJob("5046617");
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        Assert.Equal([job.UninstallUpdate!.UpdateGuid], remover.Calls.Select(c => c.UpdateGuid));
        var reports = h.Server.StatusesFor(job.JobId);
        Assert.Equal(["Removing", "Verifying", "Completed"], reports.Select(r => r.Phase));
        var final = reports[^1];
        Assert.Equal((JobStatus.Completed, true), (final.Status, final.RebootRequired));
        var item = Assert.Single(final.Items);
        Assert.Equal((JobItemStatus.Succeeded, true, "KB5046617", UpdateCategory.Cumulative), (item.Status, item.RebootRequired, item.KbNumber, item.Category));
        Assert.Equal((1, 0, 0, true), (final.Result!.Succeeded, final.Result.Failed, final.Result.Skipped, final.Result.RebootRequired));
        Assert.Equal(ScanTrigger.PostInstall, Assert.Single(h.Server.ScanReports).Trigger);
        Assert.Equal(final.Result.PostInstallScanId, h.Server.ScanReports[0].ScanId);
        Assert.Empty(h.SystemRestart.Requests);
    }

    [Fact]
    public async Task A_removal_Windows_refuses_fails_the_job_and_an_update_that_is_not_installed_is_skipped()
    {
        var remover = new FakeRemover
        {
            Result = new UpdateRemovalResult(UpdateRemovalStatus.NotRemovable, "Windows does not allow KB5005112 to be removed.", ErrorCode: "update_not_removable"),
        };
        using var h = new AgentHarness(configurePlatform: p => p with { UpdateRemover = remover });
        await h.EnrollWithTokenAsync();

        var refused = RemovalJob("5005112");
        await h.DeliverAsync(refused);
        await h.RunJobsAndFlushAsync();
        var failed = h.Server.StatusesFor(refused.JobId)[^1];
        Assert.Equal((JobStatus.Failed, "update_not_removable"), (failed.Status, failed.ErrorCode));
        Assert.Equal(JobItemStatus.Failed, Assert.Single(failed.Items).Status);

        remover.Result = new UpdateRemovalResult(UpdateRemovalStatus.NotInstalled, "KB5046617 is not installed.");
        var gone = RemovalJob("5046617");
        await h.DeliverAsync(gone);
        await h.RunJobsAndFlushAsync();
        var skipped = h.Server.StatusesFor(gone.JobId)[^1];
        Assert.Equal(JobStatus.Completed, skipped.Status);
        Assert.Equal((JobItemStatus.Skipped, SkipReasons.NotInstalled), (skipped.Items[0].Status, skipped.Items[0].SkipReason));
    }

    [Fact]
    public async Task Agents_without_a_remover_and_jobs_without_a_valid_update_are_refused()
    {
        using (var withoutRemover = new AgentHarness())
        {
            await withoutRemover.EnrollWithTokenAsync();
            await withoutRemover.Runtime.CheckInOnceAsync(Ct);
            Assert.DoesNotContain(AgentCapabilities.UninstallUpdates, withoutRemover.Server.CheckIns[^1].Capabilities);
            var job = RemovalJob("5046617");
            withoutRemover.Server.EnqueueJob(job);
            await withoutRemover.Runtime.CheckInOnceAsync(Ct);
            await withoutRemover.RunJobsAndFlushAsync();
            Assert.Equal("unsupported_job", withoutRemover.Server.StatusesFor(job.JobId)[^1].ErrorCode);
        }

        var remover = new FakeRemover();
        using var h = new AgentHarness(configurePlatform: p => p with { UpdateRemover = remover });
        await h.EnrollWithTokenAsync();
        foreach (var bad in new[] { "KB5046617", "50466 17", "12345678901" })
        {
            var job = RemovalJob(bad);
            h.Server.EnqueueJob(job);
            await h.Runtime.CheckInOnceAsync(Ct);
            await h.RunJobsAndFlushAsync();
            Assert.Equal("unsupported_job", h.Server.StatusesFor(job.JobId)[^1].ErrorCode);
        }

        Assert.Empty(remover.Calls);
    }

    private static AgentJob RemovalJob(string kb) => new()
    {
        JobId = Guid.NewGuid(),
        Type = JobType.UninstallUpdate,
        Trigger = JobTrigger.Manual,
        ExpiresAt = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        UninstallUpdate = new UninstallUpdatePayload
        {
            UpdateGuid = Guid.NewGuid(),
            Title = "2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)",
            KbNumber = kb,
            Category = UpdateCategory.Cumulative,
        },
    };

    private sealed class FakeRemover : IUpdateRemover
    {
        public UpdateRemovalResult Result { get; set; } = new(UpdateRemovalStatus.Removed, "Removed.");
        public List<UninstallUpdatePayload> Calls { get; } = [];

        public Task<UpdateRemovalResult> RemoveAsync(UninstallUpdatePayload update, CancellationToken cancellationToken)
        {
            Calls.Add(update);
            return Task.FromResult(Result);
        }
    }

    private sealed class FakeWuaUninstaller : IWindowsUpdateUninstaller
    {
        public WuaUninstallResult Result { get; set; } = new(WuaUninstallStatus.NotInstalled);
        public List<Guid> Calls { get; } = [];

        public Task<WuaUninstallResult> UninstallAsync(Guid updateGuid, CancellationToken cancellationToken)
        {
            Calls.Add(updateGuid);
            return Task.FromResult(Result);
        }
    }

    /// <summary>DISM's /Get-Packages, /Get-PackageInfo and /Remove-Package over an in-memory package list.</summary>
    private sealed class FakeDism : IDismRunner
    {
        private readonly List<(string Identity, string State, string? Info)> _packages = [];

        public string LogPath => @"C:\ProgramData\EasyPatch\logs\update-removal.log";
        public List<IReadOnlyList<string>> Commands { get; } = [];
        public int RemoveExitCode { get; set; }
        public string RemoveOutput { get; set; } = "The operation completed successfully.";

        /// <summary>The removed package's state afterwards; null removes it from the listing.</summary>
        public string? StateAfterRemoval { get; set; } = DismPackages.UninstallPending;

        public void Add(string identity, string state, string? info = null) => _packages.Add((identity, state, info));

        public string? StateOf(string identity) => _packages.Where(p => p.Identity == identity).Select(p => p.State).FirstOrDefault();

        public static string Listing(IEnumerable<DismPackage> packages)
        {
            var text = new StringBuilder("\r\nDeployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1150\r\n\r\nImage Version: 10.0.26100.2314\r\n\r\nPackages listing:\r\n\r\n");
            foreach (var p in packages)
            {
                text.Append($"Package Identity : {p.Identity}\r\nState : {p.State}\r\nRelease Type : {p.ReleaseType}\r\nInstall Time : 11/13/2024 3:01 AM\r\n\r\n");
            }

            return text.Append("The operation completed successfully.\r\n").ToString();
        }

        public Task<DismResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Commands.Add(arguments.ToList());
            var name = arguments.Count > 2 && arguments[2].StartsWith("/PackageName:", StringComparison.Ordinal) ? arguments[2]["/PackageName:".Length..] : null;
            switch (arguments[1])
            {
                case "/Get-Packages":
                    return Task.FromResult(new DismResult(0, Listing(_packages.Select(p => new DismPackage(p.Identity, p.State, "Security Update")))));
                case "/Get-PackageInfo":
                    var info = _packages.First(p => p.Identity == name).Info ?? string.Empty;
                    return Task.FromResult(new DismResult(0, $"Package Identity : {name}\r\n{info}\r\nState : Installed\r\n"));
                case "/Remove-Package":
                    if (RemoveExitCode is 0 or DismPackages.RestartRequired)
                    {
                        var index = _packages.FindIndex(p => p.Identity == name);
                        if (StateAfterRemoval is null)
                        {
                            _packages.RemoveAt(index);
                        }
                        else
                        {
                            _packages[index] = _packages[index] with { State = StateAfterRemoval };
                        }
                    }

                    return Task.FromResult(new DismResult(RemoveExitCode, RemoveOutput));
                default:
                    throw new InvalidOperationException("Unexpected DISM command " + string.Join(' ', arguments));
            }
        }
    }
}
