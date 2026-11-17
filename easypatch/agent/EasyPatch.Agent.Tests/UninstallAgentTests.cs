using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Jobs;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Platform;
using EasyPatch.Unix;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Uninstall jobs: the agent starts the removal of its own package and leaves the job for the server, which
/// completes it when the package's uninstall step unenrolls the agent. If the agent is still running afterwards, it fails.</summary>
public sealed class UninstallAgentTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static AgentHarness Harness(bool installedFromPackage = true) =>
        new(o => o with { InstallerPollInterval = TimeSpan.FromMilliseconds(1) }, installedFromPackage);

    private static AgentJob UninstallJob() => new()
    {
        JobId = Guid.NewGuid(),
        Type = JobType.UninstallAgent,
        Trigger = JobTrigger.Manual,
        ExpiresAt = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };

    /// <summary>Runs the job until the uninstaller "stops the service", then delivers the reports.</summary>
    private static async Task RunUntilTheRemovalStopsTheServiceAsync(AgentHarness h)
    {
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        h.Uninstaller.ServiceStopping = stopping;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Runtime.ProcessNextJobAsync(stopping.Token));
        h.Uninstaller.ServiceStopping = null;
        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));
    }

    [Fact]
    public async Task Only_an_agent_installed_from_its_package_offers_to_uninstall_itself()
    {
        using (var installed = Harness())
        {
            await installed.EnrollWithTokenAsync();
            await installed.Runtime.CheckInOnceAsync(Ct);
            Assert.Contains(AgentCapabilities.Uninstall, installed.Server.CheckIns[^1].Capabilities);
        }

        using var h = Harness(installedFromPackage: false);
        await h.EnrollWithTokenAsync();
        var job = UninstallJob();
        h.Server.EnqueueJob(job);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        Assert.DoesNotContain(AgentCapabilities.Uninstall, h.Server.CheckIns[^1].Capabilities);
        Assert.Equal("unsupported_job", h.Server.StatusesFor(job.JobId)[^1].ErrorCode);
    }

    [Fact]
    public async Task The_agent_offers_to_uninstall_itself_once_Windows_Installer_has_registered_it()
    {
        // Windows Installer starts the service before it registers the product, so the first check-ins find nothing.
        using var h = Harness();
        h.Uninstaller.IsAvailable = false;
        await h.EnrollWithTokenAsync();
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.DoesNotContain(AgentCapabilities.Uninstall, h.Server.CheckIns[^1].Capabilities);

        h.Uninstaller.IsAvailable = true;
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Contains(AgentCapabilities.Uninstall, h.Server.CheckIns[^1].Capabilities);
    }

    [Fact]
    public async Task The_agent_starts_its_removal_and_leaves_the_job_for_the_server_to_complete()
    {
        using var h = Harness();
        await h.EnrollWithTokenAsync();
        h.Users.TrayConnected = 1;
        h.Uninstaller.BusyChecks = 2; // another installation is running first
        var job = UninstallJob();
        await h.DeliverAsync(job);

        await RunUntilTheRemovalStopsTheServiceAsync(h);

        Assert.Equal([Path.Combine(h.Options.LogDirectory, UninstallAgentHandler.LogFileName)], h.Uninstaller.Started);
        Assert.True(h.Users.TraysSuspended); // the tray runs the same executable, so it is closed first
        var statuses = h.Server.StatusesFor(job.JobId);
        Assert.Equal(["Waiting", "Uninstalling"], statuses.Select(s => s.Phase));
        Assert.All(statuses, s => Assert.Equal(JobStatus.Running, s.Status));
        // The job stays with the agent: only the unenrollment (or a failure seen by a restarted agent) ends it.
        Assert.NotNull(h.Runtime.State.Read(s => s.FindJob(job.JobId)?.Uninstall));
    }

    [Fact]
    public async Task An_uninstaller_that_returns_while_the_agent_still_runs_fails_the_job()
    {
        using var h = Harness();
        await h.EnrollWithTokenAsync();
        h.Uninstaller.ExitCode = 1603;
        var job = UninstallJob();
        await h.DeliverAsync(job);

        await h.RunJobsAndFlushAsync();

        var last = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, last.Status);
        Assert.Equal("uninstall_failed", last.ErrorCode);
        Assert.Contains("exit code 1603 (a fatal error occurred during installation)", last.ErrorMessage, StringComparison.Ordinal);
        Assert.Contains("1.0.0 is still installed", last.ErrorMessage, StringComparison.Ordinal);
        Assert.False(h.Users.TraysSuspended);
        Assert.Null(h.Runtime.State.Read(s => s.FindJob(job.JobId)));
    }

    [Fact]
    public async Task When_the_removal_is_rolled_back_the_restarted_agent_fails_the_job()
    {
        using var h = Harness();
        await h.EnrollWithTokenAsync();
        var job = UninstallJob();
        await h.DeliverAsync(job);
        await RunUntilTheRemovalStopsTheServiceAsync(h);

        // Windows Installer rolled the removal back and started the service again.
        h.Uninstaller.Result = 1603;
        h.Restart();
        await h.RunJobsAndFlushAsync();

        Assert.Single(h.Uninstaller.Started); // not started a second time
        var last = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Failed, last.Status);
        Assert.Equal("uninstall_failed", last.ErrorCode);
        Assert.StartsWith("The agent was not removed (Windows Installer exit code 1603", last.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cancelled_uninstall_does_not_start()
    {
        using var h = Harness();
        await h.EnrollWithTokenAsync();
        var job = UninstallJob();
        await h.DeliverAsync(job);
        h.Runtime.State.Update(s => s.FindJob(job.JobId)!.CancelRequested = true);

        await h.RunJobsAndFlushAsync();

        Assert.Empty(h.Uninstaller.Started);
        Assert.Equal(JobStatus.Cancelled, h.Server.StatusesFor(job.JobId)[^1].Status);
    }

    [Fact]
    public void Linux_agents_remove_only_their_own_package()
    {
        var (apt, aptArguments) = LinuxAgentUninstaller.Command(PackageFamily.Debian);
        Assert.Equal("apt-get", apt);
        Assert.Equal(["remove", "-y", "-q", "-o", "DPkg::Lock::Timeout=1800", "easypatch-agent"], aptArguments);

        var (rpm, rpmArguments) = LinuxAgentUninstaller.Command(PackageFamily.RedHat);
        Assert.Equal("rpm", rpm);
        Assert.Equal(["-e", "easypatch-agent"], rpmArguments);
    }

    [Fact]
    public void The_packages_unenroll_the_agent_when_it_is_removed_but_not_when_it_is_upgraded()
    {
        var root = RepositoryRoot();
        var wxs = File.ReadAllText(Path.Combine(root, "agent", "Installer", "Package.wxs"));
        Assert.Contains("unenroll --reason &quot;Agent uninstalled&quot;", wxs, StringComparison.Ordinal);
        Assert.Contains("Condition=\"REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE\"", wxs, StringComparison.Ordinal);

        // The Windows uninstaller finds the product by the MSI's upgrade code.
        var upgradeCode = Regex.Match(wxs, "UpgradeCode=\"(?<code>[0-9A-F-]{36})\"").Groups["code"].Value;
        var uninstaller = File.ReadAllText(Path.Combine(root, "agent", "EasyPatch.Agent", "Platform", "WindowsAgentUninstaller.cs"));
        Assert.Contains($"UpgradeCode = \"{{{upgradeCode}}}\"", uninstaller, StringComparison.Ordinal);

        var prerm = File.ReadAllText(Path.Combine(root, "agent", "Installer", "linux-packages", "deb", "prerm"));
        Assert.Matches(new Regex("if \\[ \"\\$1\" = \"remove\" \\]; then(?s:.*)/opt/easypatch/easypatch-agent unenroll --reason \"Agent uninstalled\" >/dev/null \\|\\| true"), prerm);
        var spec = File.ReadAllText(Path.Combine(root, "agent", "Installer", "linux-packages", "rpm", "easypatch-agent.spec"));
        Assert.Matches(new Regex("%preun\\s+if \\[ \"\\$1\" -eq 0 \\]; then(?s:.*)/opt/easypatch/easypatch-agent unenroll --reason \"Agent uninstalled\" >/dev/null \\|\\| :"), spec);
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EasyPatch.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
