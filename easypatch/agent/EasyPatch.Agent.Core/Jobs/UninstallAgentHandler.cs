using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// Uninstall jobs: removes the agent package (<see cref="IAgentUninstaller"/>). The package's uninstall steps stop this
/// service, unenroll the agent (which restores the Windows Update settings EasyPatch changed and tells the server) and
/// delete the program. The server completes the job when the unenrollment arrives; this handler only ever reports
/// that the removal started, or that it failed because this agent is still running afterwards.
/// </summary>
public sealed class UninstallAgentHandler
{
    /// <summary>How long to wait for another installation to finish before giving up.</summary>
    public static readonly TimeSpan InstallerTimeout = TimeSpan.FromMinutes(30);

    /// <summary>How long to try delivering the "uninstalling" report before the removal stops the service.</summary>
    public static readonly TimeSpan ReportTimeout = TimeSpan.FromSeconds(15);

    public const string LogFileName = "uninstall.log";

    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly JobReporter _reporter;
    private readonly Func<CancellationToken, Task<bool>> _flushReports;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public UninstallAgentHandler(AgentPlatform platform, AgentStateStore state, JobReporter reporter, Func<CancellationToken, Task<bool>> flushReports,
        AgentRuntimeOptions options, TimeProvider time, ILogger<UninstallAgentHandler> logger)
    {
        _platform = platform;
        _state = state;
        _reporter = reporter;
        _flushReports = flushReports;
        _options = options;
        _time = time;
        _logger = logger;
    }

    public bool CanUninstall => _platform.AgentUninstaller?.IsAvailable == true;

    public async Task<JobOutcome> ExecuteAsync(JobRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var jobId = record.Job.JobId;
        var uninstaller = _platform.AgentUninstaller;
        if (uninstaller is null || (!uninstaller.IsAvailable && record.Uninstall is null))
        {
            return Fail(jobId, "uninstall_not_supported", "This agent was not installed from its package and cannot uninstall itself.");
        }

        if (record.Uninstall is { } launched)
        {
            return await FailAfterLaunchAsync(jobId, uninstaller, launched, cancellationToken);
        }

        if (record.CancelRequested)
        {
            _reporter.Report(jobId, JobStatus.Cancelled, "Cancelled", null, "Uninstall cancelled by an administrator before it started.");
            return JobOutcome.Finished;
        }

        if (!await WaitForOtherInstallationsAsync(jobId, uninstaller, cancellationToken))
        {
            return Fail(jobId, "uninstall_installer_busy",
                $"Another {uninstaller.DisplayName} installation was still running after {InstallerTimeout.TotalMinutes:0} minutes, so the agent was not removed.");
        }

        var logPath = Path.Combine(_options.LogDirectory, LogFileName);
        _state.Update(s =>
        {
            if (s.FindJob(jobId) is { } r)
            {
                r.Uninstall = new UninstallProgress { LogPath = logPath, LaunchedAt = _time.GetUtcNow() };
            }
        });
        _reporter.Report(jobId, JobStatus.Running, "Uninstalling", 50,
            "Removing the EasyPatch agent. The job completes when the agent unenrolls from the server as part of the removal.");
        await TryDeliverReportsAsync(cancellationToken);
        _logger.LogWarning(AgentEventIds.AgentUninstallStarted,
            "Removing EasyPatch Agent {Version} with {Uninstaller} for an administrator's uninstall job {JobId}. Log: {LogPath}",
            _options.AgentVersion, uninstaller.DisplayName, jobId, logPath);

        SuspendTrays(true);
        await WaitForTraysToCloseAsync(cancellationToken);
        int? exitCode = null;
        string? startFailure = null;
        try
        {
            using var process = uninstaller.Start(logPath);
            exitCode = await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The removal is stopping this service: expected. The job stays with the agent in case the removal is rolled back.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            startFailure = ex.Message;
        }

        // This process is still running, so the agent was not removed.
        SuspendTrays(false);
        ClearLaunch(jobId);
        return exitCode is { } code
            ? Fail(jobId, "uninstall_failed",
                $"{uninstaller.DisplayName} finished (exit code {code}{uninstaller.DescribeResult(code)}) but EasyPatch Agent {_options.AgentVersion} is still installed. Log: {logPath}")
            : Fail(jobId, "uninstall_failed", $"{uninstaller.DisplayName} could not be started: {startFailure}");
    }

    /// <summary>The agent started again after it began removing itself: the removal failed and was rolled back, or is still running.</summary>
    private async Task<JobOutcome> FailAfterLaunchAsync(Guid jobId, IAgentUninstaller uninstaller, UninstallProgress launched, CancellationToken cancellationToken)
    {
        while (uninstaller.IsInstallerBusy())
        {
            if (_time.GetUtcNow() - launched.LaunchedAt > InstallerTimeout)
            {
                ClearLaunch(jobId);
                return Fail(jobId, "uninstall_timeout",
                    $"{uninstaller.DisplayName} was still running {InstallerTimeout.TotalMinutes:0} minutes after the removal started. Log: {launched.LogPath}");
            }

            await Task.Delay(_options.InstallerPollInterval, cancellationToken);
        }

        var code = uninstaller.ReadResult(launched.LogPath);
        ClearLaunch(jobId);
        return Fail(jobId, "uninstall_failed",
            $"The agent was not removed" + (code is { } c ? $" ({uninstaller.DisplayName} exit code {c}{uninstaller.DescribeResult(c)})" : string.Empty) +
            $". EasyPatch Agent {_options.AgentVersion} is still installed. Log: {launched.LogPath}");
    }

    private async Task<bool> WaitForOtherInstallationsAsync(Guid jobId, IAgentUninstaller uninstaller, CancellationToken cancellationToken)
    {
        var since = _time.GetUtcNow();
        var reported = false;
        while (uninstaller.IsInstallerBusy())
        {
            if (_time.GetUtcNow() - since > InstallerTimeout)
            {
                return false;
            }

            if (!reported)
            {
                reported = true;
                _reporter.Report(jobId, JobStatus.Running, "Waiting", 10, $"Waiting for another {uninstaller.DisplayName} installation to finish.");
            }

            await Task.Delay(_options.InstallerPollInterval, cancellationToken);
        }

        return true;
    }

    private async Task TryDeliverReportsAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ReportTimeout);
        try
        {
            await _flushReports(timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Best effort: the server learns the outcome from the unenrollment.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Could not deliver the uninstall report before removing the agent.");
        }
    }

    private JobOutcome Fail(Guid jobId, string code, string message)
    {
        _logger.LogWarning(AgentEventIds.AgentUninstallFailed, "Uninstall job {JobId} failed ({Code}): {Message}", jobId, code, message);
        _reporter.Report(jobId, JobStatus.Failed, "Failed", null, message, errorCode: code, errorMessage: message);
        return JobOutcome.Finished;
    }

    private void ClearLaunch(Guid jobId) => _state.Update(s =>
    {
        if (s.FindJob(jobId) is { } record)
        {
            record.Uninstall = null;
        }
    });

    private void SuspendTrays(bool suspended)
    {
        try
        {
            _platform.Users.SuspendTrays(suspended);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not {Action} the trays.", suspended ? "close" : "reopen");
        }
    }

    private async Task WaitForTraysToCloseAsync(CancellationToken cancellationToken)
    {
        for (var i = 0; i < 20; i++)
        {
            int open;
            try
            {
                open = _platform.Users.GetSessions().TrayConnected;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not count the trays.");
                return;
            }

            if (open == 0)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
        }
    }
}
