using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class UpdateReconcilerTests
{
    private static readonly Guid EndpointId = Guid.NewGuid();
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    private static ReconcileItem Item(Guid guid, bool reboot = false, params Guid[] supersedes) => new(guid, Guid.NewGuid(), reboot, supersedes);

    private static ReconcileResult Run(Dictionary<Guid, EndpointUpdate> existing, IReadOnlyList<ReconcileItem> missing, IReadOnlyList<ReconcileItem> installed,
        Func<Guid, bool>? excluded = null) =>
        UpdateReconciler.Reconcile(EndpointId, existing, missing, installed, excluded ?? (_ => false), (_, _) => true, Guid.NewGuid(), Now);

    [Fact]
    public void Missing_and_installed_updates_are_recorded()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var result = Run(existing, [Item(a)], [Item(b)]);
        Assert.Equal(2, result.Added.Count);
        Assert.Equal(EndpointUpdateState.Missing, existing[a].State);
        Assert.Equal(EndpointUpdateState.Installed, existing[b].State);
        Assert.Null(existing[b].InstalledAt); // install date unknown for pre-existing updates; history ingestion backfills it
    }

    [Fact]
    public void Only_a_scan_marks_an_update_installed()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var a = Guid.NewGuid();
        Run(existing, [Item(a)], []);
        existing[a].State = EndpointUpdateState.PendingVerification; // agent reported success, not yet confirmed
        Run(existing, [], [Item(a)]);
        Assert.Equal(EndpointUpdateState.Installed, existing[a].State);
        Assert.Equal(Now, existing[a].InstalledAt);
    }

    [Fact]
    public void An_update_offered_again_after_a_successful_install_is_reoffered_until_a_new_revision_appears()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var a = Guid.NewGuid();
        var revision204 = new ReconcileItem(a, Guid.NewGuid(), false, []);
        Run(existing, [revision204], []);
        UpdateReconciler.ApplyInstallOutcome(existing[a], succeeded: true, rebootRequired: false, null, null, Guid.NewGuid(), Now);
        Assert.Equal(EndpointUpdateState.PendingVerification, existing[a].State);

        // Windows still offers the same revision: neither installed nor failed, and it stays that way.
        Run(existing, [revision204], []);
        Assert.Equal(EndpointUpdateState.Reoffered, existing[a].State);
        Assert.Equal((UpdateReconciler.ReofferedCode, UpdateReconciler.ReofferedMessage, 0),
            (existing[a].ErrorCode, existing[a].ErrorMessage, existing[a].FailedAttempts));
        Run(existing, [revision204], []);
        Assert.Equal(EndpointUpdateState.Reoffered, existing[a].State);
        Assert.Equal(new UpdateCounts(0, 0, 0, 0, 0), ComplianceCalculator.Count(existing.Values));

        // A new revision of the same update may install correctly: it is missing again.
        Run(existing, [revision204 with { UpdateId = Guid.NewGuid() }], []);
        Assert.Equal(EndpointUpdateState.Missing, existing[a].State);
        Assert.Null(existing[a].ErrorCode);
        Assert.Null(existing[a].ErrorMessage);

        // Only a scan that lists it as installed makes it Installed.
        existing[a].State = EndpointUpdateState.Reoffered;
        Run(existing, [], [revision204]);
        Assert.Equal(EndpointUpdateState.Installed, existing[a].State);
    }

    [Fact]
    public void A_reoffered_update_still_counts_as_known_exploited()
    {
        var row = new EndpointUpdate { State = EndpointUpdateState.Reoffered, IsRequired = true, KnownExploited = true };
        Assert.Equal(new UpdateCounts(0, 0, 0, 0, 0, 0, KnownExploitedMissing: 1), ComplianceCalculator.Count([row]));
        Assert.True(VulnerabilityRules.IsOpen(EndpointUpdateState.Reoffered));
    }

    [Fact]
    public void Reboot_required_updates_are_pending_reboot_not_installed()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var a = Guid.NewGuid();
        Run(existing, [Item(a, reboot: true)], []);
        Assert.Equal(EndpointUpdateState.PendingReboot, existing[a].State);
    }

    [Fact]
    public void Superseded_and_excluded_updates_are_classified()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var old = Guid.NewGuid();
        var replacement = Guid.NewGuid();
        var excluded = Guid.NewGuid();
        Run(existing, [Item(old), Item(replacement, false, old), Item(excluded)], [], g => g == excluded);
        Assert.Equal(EndpointUpdateState.Superseded, existing[old].State);
        Assert.Equal(EndpointUpdateState.Missing, existing[replacement].State);
        Assert.Equal(EndpointUpdateState.Excluded, existing[excluded].State);
    }

    [Fact]
    public void Updates_no_longer_reported_become_not_applicable_but_installed_ones_stay_installed()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var gone = Guid.NewGuid();
        var installed = Guid.NewGuid();
        Run(existing, [Item(gone)], [Item(installed)]);
        Run(existing, [], []);
        Assert.Equal(EndpointUpdateState.NotApplicable, existing[gone].State);
        Assert.Equal(EndpointUpdateState.Installed, existing[installed].State);
    }
}

public sealed class ComplianceCalculatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(null, false, 0, 0, 0, ComplianceStatus.NeverScanned)]
    [InlineData(72, false, 5, 1, 0, ComplianceStatus.ScanStale)]
    [InlineData(1, true, 5, 1, 0, ComplianceStatus.FailedUpdates)]
    [InlineData(1, true, 5, 0, 0, ComplianceStatus.MissingUpdates)]
    [InlineData(1, true, 0, 0, 0, ComplianceStatus.RebootRequired)]
    [InlineData(1, false, 0, 0, 2, ComplianceStatus.RebootRequired)]
    [InlineData(1, false, 0, 0, 0, ComplianceStatus.Compliant)]
    public void Status_precedence(int? scanHoursAgo, bool reboot, int missing, int failed, int pendingReboot, ComplianceStatus expected)
    {
        DateTimeOffset? lastScan = scanHoursAgo is { } h ? Now.AddHours(-h) : null;
        var counts = new UpdateCounts(missing, missing, failed, 10, pendingReboot);
        Assert.Equal(expected, ComplianceCalculator.Evaluate(lastScan, reboot, counts, 48, Now));
    }

    [Fact]
    public void Percentage_handles_empty_fleet() => Assert.Equal(0, ComplianceCalculator.Percentage(0, 0));

    [Fact]
    public void Percentage_rounds_to_one_decimal() => Assert.Equal(66.7, ComplianceCalculator.Percentage(2, 3));
}

public sealed class PolicyResolverTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Most_specific_value_wins_and_sources_are_reported()
    {
        var global = PolicyDefaults.CreateGlobal(Now);
        var org = new Policy { Scope = PolicyScope.Organization, ScanIntervalMinutes = 120, ExcludedKbs = ["KB1"] };
        var site = new Policy { Scope = PolicyScope.Site, CheckInIntervalSeconds = 30, ExcludedKbs = ["kb2"] };
        var p = PolicyResolver.Resolve(global, org, site);
        Assert.Equal(30, p.CheckInIntervalSeconds);
        Assert.Equal(120, p.ScanIntervalMinutes);
        Assert.Equal(1440, p.InventoryIntervalMinutes);
        Assert.Equal(PolicyScope.Site, p.Sources[nameof(EffectivePolicy.CheckInIntervalSeconds)]);
        Assert.Equal(PolicyScope.Organization, p.Sources[nameof(EffectivePolicy.ScanIntervalMinutes)]);
        Assert.Equal(PolicyScope.Global, p.Sources[nameof(EffectivePolicy.InventoryIntervalMinutes)]);
        Assert.Equal(["KB1", "KB2"], p.ExcludedKbs.Order().ToArray()); // merged and normalized
    }

    [Fact]
    public void Defaults_exclude_drivers_and_feature_updates_and_never_auto_install()
    {
        var p = PolicyResolver.Resolve(PolicyDefaults.CreateGlobal(Now), null, null);
        Assert.DoesNotContain(UpdateCategory.Driver, p.AllowedCategories);
        Assert.DoesNotContain(UpdateCategory.Feature, p.AllowedCategories);
        Assert.Contains(UpdateCategory.Security, p.AllowedCategories);
        Assert.False(p.AutoInstallEnabled);
        Assert.Null(p.MaintenanceWindow); // no days configured
    }

    [Fact]
    public void Maintenance_window_is_overridden_as_a_unit()
    {
        var global = PolicyDefaults.CreateGlobal(Now);
        global.MaintenanceDays = [6];
        var site = new Policy { Scope = PolicyScope.Site, MaintenanceDays = [0, 3], MaintenanceStart = new TimeOnly(23, 0) };
        var p = PolicyResolver.Resolve(global, null, site);
        Assert.NotNull(p.MaintenanceWindow);
        Assert.Equal([DayOfWeek.Sunday, DayOfWeek.Wednesday], p.MaintenanceWindow!.Days);
        Assert.Equal(new TimeOnly(23, 0), p.MaintenanceWindow.Start);
        Assert.Equal(180, p.MaintenanceWindow.DurationMinutes); // site did not set a duration: unit default, not global's
    }

    [Fact]
    public void Invalid_policy_values_are_rejected()
    {
        var errors = PolicyResolver.ValidatePolicy(new Policy { CheckInIntervalSeconds = 1, MaintenanceDays = [9], AllowedCategories = ["Bogus"] });
        Assert.NotEmpty(errors);
        Assert.NotEmpty(PolicyResolver.ValidatePolicy(new Policy { AllowedCategories = ["Security", "Application"] }));
        Assert.NotEmpty(PolicyResolver.ValidatePolicy(new Policy
        {
            ApplicationUpdates = new ApplicationUpdateSettings { Enabled = true, ApprovedApps = ["Mozilla.Firefox", "& calc.exe"] },
        }));
    }

    [Fact]
    public void Application_updates_are_off_by_default_and_overridden_as_a_unit()
    {
        var global = PolicyDefaults.CreateGlobal(Now);
        var none = PolicyResolver.Resolve(global, null, null);
        Assert.False(none.ApplicationUpdates.IsActive);
        Assert.Null(none.ToAgentConfig().Applications);
        Assert.Empty(none.ToFilter().ApprovedApplications);

        var org = new Policy
        {
            Scope = PolicyScope.Organization,
            ApplicationUpdates = new ApplicationUpdateSettings { Enabled = true, ApprovedApps = ["Mozilla.Firefox", "7zip.7zip"] },
        };
        var on = PolicyResolver.Resolve(global, org, null);
        Assert.Equal(PolicyScope.Organization, on.Sources[nameof(EffectivePolicy.ApplicationUpdates)]);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], on.ToAgentConfig().Applications!.ApprovedApps);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], on.ToFilter().ApprovedApplications);
        Assert.DoesNotContain(UpdateCategory.Application, on.ToFilter().Categories);

        // The site's list replaces the organization's (no merging), and an empty enabled list checks nothing.
        var site = new Policy { Scope = PolicyScope.Site, ApplicationUpdates = new ApplicationUpdateSettings { Enabled = true, ApprovedApps = ["Zoom.Zoom"] } };
        Assert.Equal(["Zoom.Zoom"], PolicyResolver.Resolve(global, org, site).ToFilter().ApprovedApplications);
        var off = new Policy { Scope = PolicyScope.Site, ApplicationUpdates = new ApplicationUpdateSettings { Enabled = false } };
        var resolved = PolicyResolver.Resolve(global, org, off);
        Assert.Null(resolved.ToAgentConfig().Applications);
        Assert.Empty(resolved.ToFilter().ApprovedApplications);
    }
}

public sealed class InstallFilterTests
{
    private static ReportedUpdate Update(Guid classification, string title = "Update", string? kb = "KB5001234", bool browseOnly = false,
        bool installed = false, bool rebootRequired = false, bool driver = false) => new()
    {
        UpdateGuid = Guid.NewGuid(),
        Title = title,
        KbNumbers = kb is null ? [] : [kb],
        Categories = [new UpdateCategoryRef { Id = classification, Name = "c", Type = "UpdateClassification" }],
        BrowseOnly = browseOnly,
        IsInstalled = installed,
        RebootRequired = rebootRequired,
        IsDriver = driver,
    };

    private static InstallUpdatesPayload Payload(InstallMode mode = InstallMode.AllEligible, IReadOnlyList<Guid>? selected = null,
        IReadOnlyList<string>? excludedKbs = null, bool includeOptional = false) => new()
    {
        Mode = mode,
        SelectedUpdateGuids = selected ?? [],
        Filter = new InstallFilterOptions
        {
            Categories = UpdateClassifier.DefaultInstallCategories,
            ExcludedKbs = excludedKbs ?? [],
            IncludeOptional = includeOptional,
        },
    };

    [Fact]
    public void Security_updates_are_installed_by_default() =>
        Assert.True(InstallFilter.Evaluate(Update(MicrosoftClassifications.SecurityUpdates), Payload()).Install);

    [Fact]
    public void Drivers_and_feature_updates_are_excluded_by_default()
    {
        Assert.False(InstallFilter.Evaluate(Update(MicrosoftClassifications.Drivers, driver: true), Payload()).Install);
        Assert.False(InstallFilter.Evaluate(Update(MicrosoftClassifications.Upgrades, "Windows 11, version 25H2"), Payload()).Install);
    }

    [Fact]
    public void Excluded_kb_is_skipped_regardless_of_format()
    {
        var decision = InstallFilter.Evaluate(Update(MicrosoftClassifications.SecurityUpdates, kb: "KB5001234"), Payload(excludedKbs: ["5001234"]));
        Assert.False(decision.Install);
        Assert.Equal(SkipReasons.Excluded, decision.SkipReason);
    }

    [Fact]
    public void Optional_updates_need_opt_in()
    {
        var optional = Update(MicrosoftClassifications.SecurityUpdates, browseOnly: true);
        Assert.False(InstallFilter.Evaluate(optional, Payload()).Install);
        Assert.True(InstallFilter.Evaluate(optional, Payload(includeOptional: true)).Install);
    }

    [Fact]
    public void Installed_and_pending_reboot_updates_are_skipped()
    {
        Assert.Equal(SkipReasons.AlreadyInstalled, InstallFilter.Evaluate(Update(MicrosoftClassifications.SecurityUpdates, installed: true), Payload()).SkipReason);
        Assert.Equal(SkipReasons.PendingReboot, InstallFilter.Evaluate(Update(MicrosoftClassifications.SecurityUpdates, rebootRequired: true), Payload()).SkipReason);
    }

    [Fact]
    public void Selected_mode_installs_only_selected_updates_even_outside_policy_categories()
    {
        var driver = Update(MicrosoftClassifications.Drivers, driver: true);
        var security = Update(MicrosoftClassifications.SecurityUpdates);
        var payload = Payload(InstallMode.Selected, [driver.UpdateGuid]);
        Assert.False(InstallFilter.Evaluate(security, payload).Install);
        var driverDecision = InstallFilter.Evaluate(driver, payload);
        Assert.True(driverDecision.Install, driverDecision.SkipReason);
    }

    [Theory]
    [InlineData("KB5044284", "KB5044284")]
    [InlineData("kb5044284", "KB5044284")]
    [InlineData("5044284", "KB5044284")]
    [InlineData("not-a-kb", null)]
    public void Kb_numbers_are_normalized(string input, string? expected) => Assert.Equal(expected, KbNumber.Normalize(input));
}

public sealed class UpdateClassifierTests
{
    private static UpdateCategory Classify(string title, Guid classification, bool driver = false) =>
        UpdateClassifier.Classify(title, driver, [new UpdateCategoryRef { Id = classification, Name = "c", Type = "UpdateClassification" }]);

    [Fact]
    public void Classifies_common_windows_update_titles()
    {
        Assert.Equal(UpdateCategory.Cumulative,
            Classify("2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5070000)", MicrosoftClassifications.SecurityUpdates));
        Assert.Equal(UpdateCategory.Definition,
            Classify("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1)", MicrosoftClassifications.DefinitionUpdates));
        Assert.Equal(UpdateCategory.Driver, Classify("Intel - Display - 31.0.101.5000", MicrosoftClassifications.Drivers, driver: true));
        Assert.Equal(UpdateCategory.Security, Classify("Security Update for Microsoft Edge", MicrosoftClassifications.SecurityUpdates));
        Assert.Equal(UpdateCategory.Critical, Classify("Update for Windows Malicious Software Removal Tool", MicrosoftClassifications.CriticalUpdates));
    }

    [Fact]
    public void Driver_flag_takes_precedence() =>
        Assert.Equal(UpdateCategory.Driver, Classify("Cumulative Update for something", MicrosoftClassifications.SecurityUpdates, driver: true));
}

public sealed class MaintenanceWindowTests
{
    private static readonly MaintenanceWindowSettings SaturdayNight = new([DayOfWeek.Saturday], new TimeOnly(22, 0), 360);

    [Fact]
    public void Window_crossing_midnight_is_open_on_the_next_morning()
    {
        // Sunday 2026-11-15 02:00 UTC is inside Saturday 22:00 + 6h.
        var open = MaintenanceWindow.FindOpenWindow(SaturdayNight, "UTC", new DateTimeOffset(2026, 11, 15, 2, 0, 0, TimeSpan.Zero));
        Assert.NotNull(open);
        Assert.Equal(new DateTimeOffset(2026, 11, 14, 22, 0, 0, TimeSpan.Zero), open!.Value.Start);
        Assert.Equal(new DateTimeOffset(2026, 11, 15, 4, 0, 0, TimeSpan.Zero), open.Value.End);
    }

    [Fact]
    public void Window_is_closed_outside_its_hours() =>
        Assert.Null(MaintenanceWindow.FindOpenWindow(SaturdayNight, "UTC", new DateTimeOffset(2026, 11, 15, 5, 0, 0, TimeSpan.Zero)));

    [Fact]
    public void Window_uses_the_site_time_zone()
    {
        // 22:00 in New York (EST, UTC-5) is 03:00 UTC on Sunday.
        var nyc = MaintenanceWindow.FindOpenWindow(SaturdayNight, "America/New_York", new DateTimeOffset(2026, 11, 15, 3, 30, 0, TimeSpan.Zero));
        Assert.NotNull(nyc);
        Assert.Null(MaintenanceWindow.FindOpenWindow(SaturdayNight, "America/New_York", new DateTimeOffset(2026, 11, 14, 22, 30, 0, TimeSpan.Zero)));
    }

    [Theory]
    [InlineData("Europe/London", true)]
    [InlineData("UTC", true)]
    [InlineData("Mars/Olympus_Mons", false)]
    public void Time_zone_validation(string id, bool valid) => Assert.Equal(valid, MaintenanceWindow.IsValidTimeZone(id));
}

public sealed class LifecycleEvaluatorTests
{
    private static readonly IReadOnlyList<OsLifecycleEntry> Table = LifecycleEvaluator.SeedEntries();

    [Fact]
    public void Windows_10_22H2_without_esu_is_unsupported_after_october_2025()
    {
        var r = LifecycleEvaluator.Evaluate(Table, 19045, "Professional", "WorkStation", esuLicenseDetected: false, EsuOverride.Auto, new DateOnly(2026, 1, 1));
        Assert.Equal(OsSupportStatus.Unsupported, r.Status);
        Assert.Equal(new DateOnly(2025, 10, 14), r.EndOfServicing);
    }

    [Fact]
    public void Windows_10_22H2_with_esu_is_in_extended_security_updates()
    {
        Assert.Equal(OsSupportStatus.ExtendedSecurityUpdates,
            LifecycleEvaluator.Evaluate(Table, 19045, "Enterprise", "WorkStation", esuLicenseDetected: true, EsuOverride.Auto, new DateOnly(2026, 11, 13)).Status);
        Assert.Equal(OsSupportStatus.ExtendedSecurityUpdates,
            LifecycleEvaluator.Evaluate(Table, 19045, "Enterprise", "WorkStation", esuLicenseDetected: false, EsuOverride.Enrolled, new DateOnly(2026, 11, 13)).Status);
    }

    [Fact]
    public void Windows_11_24H2_pro_follows_its_own_end_of_servicing_date()
    {
        Assert.Equal(OsSupportStatus.Supported,
            LifecycleEvaluator.Evaluate(Table, 26100, "Professional", "WorkStation", false, EsuOverride.Auto, new DateOnly(2026, 10, 1)).Status);
        Assert.Equal(OsSupportStatus.Unsupported,
            LifecycleEvaluator.Evaluate(Table, 26100, "Professional", "WorkStation", false, EsuOverride.Auto, new DateOnly(2026, 10, 14)).Status);
        Assert.Equal(OsSupportStatus.Supported,
            LifecycleEvaluator.Evaluate(Table, 26100, "Enterprise", "WorkStation", false, EsuOverride.Auto, new DateOnly(2026, 10, 14)).Status);
    }

    [Theory]
    [InlineData("almalinux", "10.2", "AlmaLinux", OsSupportStatus.Supported)]
    [InlineData("ol", "10.1", "Oracle Linux", OsSupportStatus.Supported)]
    [InlineData("centos", "10", "CentOS Stream", OsSupportStatus.Supported)]
    [InlineData("centos", "9", "CentOS Stream", OsSupportStatus.Supported)]
    [InlineData("fedora", "45", "Fedora", OsSupportStatus.Supported)]
    [InlineData("ubuntu", "26.04", "Ubuntu", OsSupportStatus.Supported)]
    [InlineData("ubuntu", "26.10", "Ubuntu", OsSupportStatus.Unknown)]
    [InlineData("fedora", "46", "Fedora", OsSupportStatus.Unknown)]
    [InlineData("centos", "7", null, OsSupportStatus.Unknown)]
    public void Newer_linux_releases_have_a_support_status(string osId, string osVersion, string? product, OsSupportStatus expected)
    {
        var r = LifecycleEvaluator.EvaluateLinux(Table, osId, osVersion, esuLicenseDetected: false, EsuOverride.Auto, new DateOnly(2026, 11, 14));

        Assert.Equal(expected, r.Status);
        Assert.Equal(product, r.Product);
    }

    [Fact]
    public void Fedora_is_unsupported_after_the_end_date_in_its_os_release() =>
        Assert.Equal(OsSupportStatus.Unsupported,
            LifecycleEvaluator.EvaluateLinux(Table, "fedora", "44", false, EsuOverride.Auto, new DateOnly(2027, 5, 20)).Status);

    [Fact]
    public void Unknown_builds_are_reported_as_unknown() =>
        Assert.Equal(OsSupportStatus.Unknown, LifecycleEvaluator.Evaluate(Table, 12345, "Professional", "WorkStation", false, EsuOverride.Auto,
            new DateOnly(2026, 11, 13)).Status);

    [Fact]
    public void Windows_11_is_named_correctly_even_when_the_caption_says_windows_10() =>
        Assert.Contains("Windows 11", OsNaming.Describe("Microsoft Windows 10 Pro", 26100, "WorkStation"), StringComparison.Ordinal);
}

public sealed class JobTransitionTests
{
    [Theory]
    [InlineData(JobStatus.Delivered, JobStatus.Running, false, true)]
    [InlineData(JobStatus.Running, JobStatus.Completed, false, true)]
    [InlineData(JobStatus.Running, JobStatus.WaitingForReboot, false, true)]
    [InlineData(JobStatus.WaitingForReboot, JobStatus.Completed, false, true)]
    [InlineData(JobStatus.Delivered, JobStatus.Failed, false, true)] // unsupported job reported without ack
    [InlineData(JobStatus.Acknowledged, JobStatus.Expired, false, true)] // deadline passed before start
    [InlineData(JobStatus.Completed, JobStatus.Running, false, false)]
    [InlineData(JobStatus.Cancelled, JobStatus.Completed, false, false)]
    [InlineData(JobStatus.Queued, JobStatus.Running, false, false)]
    [InlineData(JobStatus.Running, JobStatus.Queued, false, false)]
    [InlineData(JobStatus.Failed, JobStatus.Completed, true, true)] // late genuine result after a server timeout
    [InlineData(JobStatus.Failed, JobStatus.Completed, false, false)]
    public void Agent_transitions(JobStatus from, JobStatus to, bool timedOut, bool allowed) =>
        Assert.Equal(allowed, JobTransitions.AgentMayTransition(from, to, timedOut));
}
