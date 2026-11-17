using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Outbox;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Core.Util;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Scanning;

/// <summary>Runs update scans (Windows Update, apt or dnf) and history syncs and queues the reports in the outbox.</summary>
public sealed class ScanService
{
    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly ReportOutbox _outbox;
    private readonly WuaOperationGate _gate;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public ScanService(
        AgentPlatform platform,
        AgentStateStore state,
        ReportOutbox outbox,
        WuaOperationGate gate,
        AgentRuntimeOptions options,
        TimeProvider time,
        ILogger<ScanService> logger)
    {
        _platform = platform;
        _state = state;
        _outbox = outbox;
        _gate = gate;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Scans and queues a <see cref="ScanResultReport"/> (also on failure, so the server sees the error).
    /// Returns null when a background scan was skipped because another Windows Update operation is running.
    /// </summary>
    /// <param name="gateHeld">True when the caller (an install job) already holds the WUA gate.</param>
    public async Task<ScanResultReport?> RunScanAsync(ScanTrigger trigger, Guid? jobId, bool gateHeld, CancellationToken cancellationToken)
    {
        if (!gateHeld)
        {
            if (trigger is ScanTrigger.Scheduled or ScanTrigger.Startup or ScanTrigger.PostReboot)
            {
                if (!_gate.TryEnter())
                {
                    _logger.LogInformation("Skipping {Trigger} scan: another update operation is in progress.", trigger);
                    return null;
                }
            }
            else
            {
                await _gate.EnterAsync(cancellationToken);
            }
        }

        try
        {
            return await ScanCoreAsync(trigger, jobId, cancellationToken);
        }
        finally
        {
            if (!gateHeld)
            {
                _gate.Exit();
            }
        }
    }

    private async Task<ScanResultReport> ScanCoreAsync(ScanTrigger trigger, Guid? jobId, CancellationToken cancellationToken)
    {
        var startedAt = _time.GetUtcNow();
        _state.Update(s => s.LastScanAttemptAt = startedAt);
        _logger.LogInformation("Starting {Trigger} {Name} scan.", trigger, _platform.Updates.Name);

        ScanResultReport report;
        try
        {
            using var scan = await _platform.Updates.ScanAsync(includeInstalled: true, cancellationToken);
            var completedAt = _time.GetUtcNow();
            report = new ScanResultReport
            {
                ScanId = Guid.NewGuid(),
                JobId = jobId,
                Trigger = trigger,
                StartedAt = startedAt,
                CompletedAt = completedAt,
                Succeeded = true,
                Source = DetectSource(scan.MicrosoftUpdateRegistered),
                Missing = scan.Missing.Select(c => c.Update).ToList(),
                // Descriptions of installed updates are not displayed; omitting them keeps reports small.
                Installed = scan.Installed.Select(u => u with { Description = null }).ToList(),
                Applications = scan.Applications,
            };
            _state.Update(s =>
            {
                s.LastScanAt = completedAt;
                s.LastScanMissingCount = report.Missing.Count;
                s.LastScanError = null;
            });
            _logger.LogInformation("Scan completed: {Missing} applicable updates not installed, {Installed} installed.",
                report.Missing.Count, report.Installed.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var (code, message) = _platform.Updates.DescribeFailure(ex);
            _logger.LogError(ex, "{Name} scan failed ({Code}).", _platform.Updates.Name, code);
            var reason = string.IsNullOrWhiteSpace(message) ? code : message;
            _state.Update(s => s.LastScanError = reason.Length > 300 ? reason[..300] : reason);
            report = new ScanResultReport
            {
                ScanId = Guid.NewGuid(),
                JobId = jobId,
                Trigger = trigger,
                StartedAt = startedAt,
                CompletedAt = _time.GetUtcNow(),
                Succeeded = false,
                ErrorCode = code,
                ErrorMessage = message,
                Source = DetectSource(microsoftUpdateRegistered: false),
            };
        }

        _outbox.EnqueueScanResults(report);
        await SyncHistoryAsync(cancellationToken);
        return report;
    }

    /// <summary>Queues Windows Update history entries newer than the last one sent.</summary>
    public async Task SyncHistoryAsync(CancellationToken cancellationToken)
    {
        try
        {
            var since = _state.Read(s => s.LastHistoryEntryDate);
            var entries = await _platform.Updates.GetHistoryAsync(since, _options.MaxHistoryEntriesPerSync, cancellationToken);
            var fresh = entries.Where(e => since is null || e.Date > since).OrderBy(e => e.Date).ToList();
            var now = _time.GetUtcNow();
            if (fresh.Count > 0)
            {
                _outbox.EnqueueHistory(new HistoryReport { Entries = fresh });
            }

            _state.Update(s =>
            {
                s.LastHistorySyncAt = now;
                if (fresh.Count > 0)
                {
                    s.LastHistoryEntryDate = fresh[^1].Date;
                }
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "{Name} history could not be read.", _platform.Updates.Name);
        }
    }

    public UpdateSourceInfo? DetectSource(bool microsoftUpdateRegistered)
    {
        try
        {
            var source = _platform.UpdateSource.Detect();
            var type = source.Type == UpdateSourceType.WindowsUpdate && microsoftUpdateRegistered
                ? UpdateSourceType.MicrosoftUpdate
                : source.Type;
            return source with
            {
                Type = type,
                MicrosoftUpdateRegistered = source.MicrosoftUpdateRegistered || microsoftUpdateRegistered,
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Update source detection failed.");
            return null;
        }
    }
}

/// <summary>Collects and queues inventory reports.</summary>
public sealed class InventoryService
{
    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly ReportOutbox _outbox;
    private readonly ScanService _scans;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public InventoryService(
        AgentPlatform platform,
        AgentStateStore state,
        ReportOutbox outbox,
        ScanService scans,
        AgentRuntimeOptions options,
        TimeProvider time,
        ILogger<InventoryService> logger)
    {
        _platform = platform;
        _state = state;
        _outbox = outbox;
        _scans = scans;
        _options = options;
        _time = time;
        _logger = logger;
    }

    public async Task<InventoryReport> CollectAsync(CancellationToken cancellationToken)
    {
        var installedAt = _state.Read(s => s.FirstStartedAt);
        var report = await _platform.Inventory.CollectAsync(new InventoryContext(_options.AgentVersion, installedAt), cancellationToken);
        RebootStatus reboot;
        try
        {
            reboot = await _platform.RebootDetector.DetectAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Reboot detection failed.");
            reboot = RebootStatus.None;
        }

        return report with
        {
            AgentVersion = _options.AgentVersion,
            AgentInstalledAt = report.AgentInstalledAt ?? installedAt,
            RebootPending = reboot.Pending,
            RebootReasons = reboot.Reasons,
            RebootDetails = reboot.Pending ? reboot.Details : null,
            KeyProtection = report.KeyProtection ?? _platform.SecretProtector.Kind,
            UpdateSource = report.UpdateSource ?? _scans.DetectSource(microsoftUpdateRegistered: false),
        };
    }

    public async Task SendInventoryAsync(CancellationToken cancellationToken)
    {
        var report = await CollectAsync(cancellationToken);
        _outbox.EnqueueInventory(report);
        _state.Update(s => s.LastInventoryAt = _time.GetUtcNow());
        _logger.LogInformation("Inventory collected for {Hostname} ({Os} build {Build}).", report.Hostname, report.OsCaption, report.OsBuildNumber);
    }
}
