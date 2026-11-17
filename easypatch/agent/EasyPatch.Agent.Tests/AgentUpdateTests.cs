using System.Security.Cryptography;
using System.Text;
using EasyPatch.Agent.Core.Jobs;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Agent self-update: only packages signed with a built-in release key, newer, for this architecture and
/// matching their signature byte for byte are installed, and the job completes only when the new version runs.</summary>
public sealed class AgentUpdateTests
{
    private static readonly ECDsa Trusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly ECDsa Untrusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly string TrustedPem = Trusted.ExportSubjectPublicKeyInfoPem();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static AgentHarness Harness(string? keys = null) => new(o => o with
    {
        PackageArchitecture = "x64",
        ReleasePublicKeys = keys ?? TrustedPem,
        BackoffBase = TimeSpan.FromMilliseconds(1),
        InstallerPollInterval = TimeSpan.FromMilliseconds(1),
    });

    private static JobStatusReport Last(AgentHarness h, Guid jobId) => h.Server.StatusesFor(jobId)[^1];

    private static (AgentJob Job, byte[] Package) UpdateJob(string version = "1.2.0", string architecture = "x64", ECDsa? key = null,
        Func<AgentReleaseManifest, AgentReleaseManifest>? alterAfterSigning = null)
    {
        key ??= Trusted;
        var package = RandomNumberGenerator.GetBytes(4096);
        var manifest = new AgentReleaseManifest
        {
            FileName = $"EasyPatchAgent-{version}-{architecture}.msi",
            Version = version,
            Architecture = architecture,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(package)),
            SizeBytes = package.Length,
        };
        var signature = AgentRelease.Sign(manifest, key);
        var job = new AgentJob
        {
            JobId = Guid.NewGuid(),
            Type = JobType.AgentUpdate,
            Trigger = JobTrigger.Manual,
            ExpiresAt = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
            AgentUpdate = new AgentUpdatePayload
            {
                Package = alterAfterSigning?.Invoke(manifest) ?? manifest,
                KeyId = AgentRelease.KeyId(key),
                Signature = signature,
            },
        };
        return (job, package);
    }

    private static async Task<(AgentHarness H, AgentJob Job, byte[] Package)> DeliveredAsync(Func<AgentHarness, (AgentJob, byte[])>? make = null)
    {
        var h = Harness();
        await h.EnrollWithTokenAsync();
        var (job, package) = make?.Invoke(h) ?? UpdateJob();
        h.Server.Packages[job.AgentUpdate!.Package.FileName] = package;
        await h.DeliverAsync(job);
        return (h, job, package);
    }

    /// <summary>Runs the job until msiexec "stops the service" (the runtime's token is cancelled), then delivers the reports.</summary>
    private static async Task RunUntilWindowsInstallerStopsTheServiceAsync(AgentHarness h)
    {
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        h.Installer.ServiceStopping = stopping;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Runtime.ProcessNextJobAsync(stopping.Token));
        h.Installer.ServiceStopping = null;
        Assert.True(await h.Runtime.FlushOutboxAsync(Ct));
    }

    private static string[] PackagesOnDisk(AgentHarness h) =>
        Directory.Exists(h.Options.UpdateDirectory)
            ? Directory.GetFiles(h.Options.UpdateDirectory).Where(f => !f.EndsWith(".log", StringComparison.Ordinal)).ToArray()
            : [];

    [Fact]
    public async Task An_agent_with_a_release_key_reports_that_it_can_update_itself()
    {
        using var h = Harness();
        await h.EnrollWithTokenAsync();

        await h.Runtime.CheckInOnceAsync(Ct);

        var checkIn = h.Server.CheckIns[^1];
        Assert.Contains(AgentCapabilities.SelfUpdate, checkIn.Capabilities);
        Assert.Equal("x64", checkIn.AgentArchitecture);
        Assert.Equal([AgentRelease.KeyId(Trusted)], checkIn.ReleaseKeyIds);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")]
    [InlineData("not a key")]
    public async Task Without_a_valid_release_key_the_agent_cannot_update_and_rejects_update_jobs(string? keys)
    {
        using var h = new AgentHarness(o => o with { PackageArchitecture = "x64", ReleasePublicKeys = keys });
        await h.EnrollWithTokenAsync();
        var (job, _) = UpdateJob();

        h.Server.EnqueueJob(job);
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        var checkIn = h.Server.CheckIns[^1];
        Assert.DoesNotContain(AgentCapabilities.SelfUpdate, checkIn.Capabilities);
        Assert.Empty(checkIn.ReleaseKeyIds);
        Assert.Equal("unsupported_job", Last(h, job.JobId).ErrorCode);
        Assert.Empty(h.Installer.Started);
    }

    [Fact]
    public async Task A_P384_key_is_not_accepted_as_a_release_key()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var h = Harness(p384.ExportSubjectPublicKeyInfoPem());
        await h.EnrollWithTokenAsync();

        await h.Runtime.CheckInOnceAsync(Ct);

        Assert.DoesNotContain(AgentCapabilities.SelfUpdate, h.Server.CheckIns[^1].Capabilities);
    }

    [Fact]
    public async Task The_update_completes_only_when_the_new_version_is_running()
    {
        var (h, job, package) = await DeliveredAsync();
        using var _ = h;
        h.Users.TrayConnected = 2;

        await RunUntilWindowsInstallerStopsTheServiceAsync(h);

        var started = Assert.Single(h.Installer.Started);
        Assert.Equal(package, started.Package);
        Assert.Equal(Path.Combine(h.Options.UpdateDirectory, "EasyPatchAgent-1.2.0-x64.msi"), started.PackagePath);
        Assert.True(h.Users.TraysSuspended); // the tray runs the same executable, so it is closed first
        Assert.Equal(2, h.Users.ClosedTrays);
        var installing = Last(h, job.JobId);
        Assert.Equal(JobStatus.Running, installing.Status); // not completed: the old agent cannot know whether it worked
        Assert.Equal("Installing", installing.Phase);

        h.RestartAs("1.2.0");
        await h.RunJobsAndFlushAsync();

        var done = Last(h, job.JobId);
        Assert.Equal(JobStatus.Completed, done.Status);
        Assert.Equal("EasyPatch Agent updated from 1.0.0 to 1.2.0.", done.Message);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
        Assert.Empty(PackagesOnDisk(h));
        Assert.Single(h.Installer.Started);
    }

    [Fact]
    public async Task When_the_old_version_comes_back_the_update_fails_with_the_installer_error()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Installer.LogText = "=== Verbose logging started ===\r\nMSI (s) (A0:B4) [10:00:01:000]: MainEngineThread is returning 1603\r\n" +
                              "MSI (c) (C8:D0) [10:00:02:000]: MainEngineThread is returning 1603\r\n=== Verbose logging stopped ===\r\n";

        await RunUntilWindowsInstallerStopsTheServiceAsync(h);
        h.RestartAs("1.0.0"); // Windows Installer rolled back and started the previous version
        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("update_install_failed", failed.ErrorCode);
        Assert.Contains("Windows Installer error 1603 (a fatal error occurred during installation)", failed.ErrorMessage, StringComparison.Ordinal);
        Assert.Contains("Version 1.0.0 is still running", failed.ErrorMessage, StringComparison.Ordinal);
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task The_previous_version_waits_for_a_running_installation_and_then_gives_up()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;

        await RunUntilWindowsInstallerStopsTheServiceAsync(h);
        h.Installer.BusyChecks = int.MaxValue;
        h.Installer.OnBusyCheck = () => h.Time.Advance(TimeSpan.FromMinutes(5));
        h.RestartAs("1.0.0");
        await h.RunJobsAndFlushAsync();

        Assert.Equal("update_install_timeout", Last(h, job.JobId).ErrorCode);
    }

    [Theory]
    [InlineData(1603, "Windows Installer failed with exit code 1603 (a fatal error occurred during installation)")]
    [InlineData(1625, "installation is prohibited by system policy")]
    [InlineData(0, "reported success (exit code 0) but did not replace the running agent 1.0.0")]
    public async Task If_msiexec_exits_while_the_agent_is_still_running_the_update_fails_and_the_trays_come_back(int exitCode, string expected)
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Installer.ExitCode = exitCode;

        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.Equal("update_install_failed", failed.ErrorCode);
        Assert.Contains(expected, failed.ErrorMessage, StringComparison.Ordinal);
        Assert.False(h.Users.TraysSuspended);
        Assert.Empty(h.Runtime.State.Read(s => s.Jobs));
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task If_msiexec_cannot_be_started_the_update_fails_and_the_trays_come_back()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Installer.StartFailure = new System.ComponentModel.Win32Exception(2, "The system cannot find the file specified.");

        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal("update_install_failed", failed.ErrorCode);
        Assert.Contains("could not be started", failed.ErrorMessage, StringComparison.Ordinal);
        Assert.False(h.Users.TraysSuspended);
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task A_package_that_does_not_match_its_signature_is_never_installed()
    {
        var (h, job, package) = await DeliveredAsync();
        using var _ = h;
        var tampered = (byte[])package.Clone();
        tampered[100] ^= 0xFF;
        h.Server.Packages[job.AgentUpdate!.Package.FileName] = tampered;

        await h.RunJobsAndFlushAsync();

        Assert.Equal("update_hash_mismatch", Last(h, job.JobId).ErrorCode);
        Assert.Empty(h.Installer.Started);
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task A_download_larger_than_the_signed_size_is_abandoned()
    {
        var (h, job, package) = await DeliveredAsync();
        using var _ = h;
        h.Server.Packages[job.AgentUpdate!.Package.FileName] = [.. package, .. new byte[100]];

        await h.RunJobsAndFlushAsync();

        Assert.Equal("update_hash_mismatch", Last(h, job.JobId).ErrorCode);
        Assert.Empty(h.Installer.Started);
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task A_package_signed_with_another_key_is_not_even_downloaded()
    {
        var (h, job, _) = await DeliveredAsync(_ => UpdateJob(key: Untrusted));
        using var _ = h;

        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal("update_untrusted_key", failed.ErrorCode);
        Assert.DoesNotContain(h.Server.Requests, r => r.StartsWith("downloads/", StringComparison.Ordinal));
        Assert.Empty(h.Installer.Started);
    }

    [Fact]
    public async Task A_server_that_claims_a_trusted_key_without_its_signature_is_refused()
    {
        // The server swaps in its own package description but keeps the trusted key ID and the old signature.
        var (h, job, _) = await DeliveredAsync(_ => UpdateJob(alterAfterSigning: m => m with { Sha256 = new string('a', 64) }));
        using var _ = h;

        await h.RunJobsAndFlushAsync();

        Assert.Equal("update_signature_invalid", Last(h, job.JobId).ErrorCode);
        Assert.DoesNotContain(h.Server.Requests, r => r.StartsWith("downloads/", StringComparison.Ordinal));
        Assert.Empty(h.Installer.Started);
    }

    [Theory]
    [InlineData("1.0.0", "x64", "update_not_newer")]
    [InlineData("0.9.9", "x64", "update_not_newer")]
    [InlineData("1.2.0", "arm64", "update_wrong_architecture")]
    public async Task Downgrades_and_other_architectures_are_refused(string version, string architecture, string code)
    {
        var (h, job, _) = await DeliveredAsync(_ => UpdateJob(version, architecture));
        using var _ = h;

        await h.RunJobsAndFlushAsync();

        Assert.Equal(code, Last(h, job.JobId).ErrorCode);
        Assert.Empty(h.Installer.Started);
    }

    [Fact]
    public async Task Transient_download_failures_are_retried()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Installer.ExitCode = 1603; // stop after the download
        h.Server.FailNextRequests = 2;

        await h.RunJobsAndFlushAsync();

        Assert.Single(h.Installer.Started);
        Assert.Equal(3, h.Server.Requests.Count(r => r.StartsWith("downloads/", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_missing_package_fails_the_job()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Server.Packages.Clear();

        await h.RunJobsAndFlushAsync();

        var failed = Last(h, job.JobId);
        Assert.Equal("update_download_failed", failed.ErrorCode);
        Assert.Contains("HTTP 404", failed.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_cancellation_that_arrives_during_the_download_stops_the_update_before_it_is_installed()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Server.Override = (route, _) =>
        {
            if (route.StartsWith("downloads/", StringComparison.Ordinal))
            {
                h.Runtime.State.Update(s => s.FindJob(job.JobId)!.CancelRequested = true);
            }

            return null;
        };

        await h.RunJobsAndFlushAsync();

        Assert.Equal(JobStatus.Cancelled, Last(h, job.JobId).Status);
        Assert.Empty(h.Installer.Started);
        Assert.Empty(PackagesOnDisk(h));
    }

    [Fact]
    public async Task The_installer_waits_for_another_installation_to_finish()
    {
        var (h, job, _) = await DeliveredAsync();
        using var _ = h;
        h.Installer.BusyChecks = 3;

        await RunUntilWindowsInstallerStopsTheServiceAsync(h);

        Assert.Contains(h.Server.StatusesFor(job.JobId), s => s.Phase == "Waiting");
        Assert.Single(h.Installer.Started);
    }

    [Fact]
    public async Task Leftover_downloads_are_removed_before_a_new_one()
    {
        var (h, _, _) = await DeliveredAsync();
        using var _ = h;
        Directory.CreateDirectory(h.Options.UpdateDirectory);
        var leftover = Path.Combine(h.Options.UpdateDirectory, "EasyPatchAgent-1.1.0-x64.msi.partial");
        await File.WriteAllTextAsync(leftover, "x", Ct);
        h.Installer.ExitCode = 1603;

        await h.RunJobsAndFlushAsync();

        Assert.False(File.Exists(leftover));
    }

    [Theory]
    [InlineData("MSI (s) (A0:B4): MainEngineThread is returning 0\r\nMSI (c) (C8:D0): MainEngineThread is returning 0\r\n", true, 0)]
    [InlineData("MSI (s) (A0:B4): MainEngineThread is returning 1603\r\nMSI (c) (C8:D0): MainEngineThread is returning 1603\r\n", false, 1603)]
    [InlineData("Product: EasyPatch Agent -- Installation operation failed. Installation success or error status: 1638.\r\n", true, 1638)]
    [InlineData("=== Verbose logging started ===\r\n", true, null)]
    public void The_installer_result_is_read_from_ANSI_and_Unicode_logs(string log, bool unicode, int? expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"easypatch-msilog-{Guid.NewGuid():N}.log");
        try
        {
            File.WriteAllText(path, log, unicode ? Encoding.Unicode : Encoding.ASCII);
            Assert.Equal(expected, AgentUpdateHandler.ReadInstallerResult(path));
        }
        finally
        {
            File.Delete(path);
        }

        Assert.Null(AgentUpdateHandler.ReadInstallerResult(path));
    }
}
