using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using EasyPatch.MacOS.Platform;
using Microsoft.Extensions.Logging;

namespace EasyPatch.MacOS.SoftwareUpdate;

/// <summary>An Apple update found by the latest scan.</summary>
internal sealed class SoftwareUpdateHandle(SoftwareUpdateItem item, Guid updateGuid, string title) : IUpdateHandle
{
    public SoftwareUpdateItem Item { get; } = item;

    public Guid UpdateGuid { get; } = updateGuid;

    public string Title { get; } = title;

    public void Dispose()
    {
    }
}

/// <summary>
/// macOS updates through Apple's <c>softwareupdate</c> tool: one update per listed label, downloaded with <c>--download</c> and
/// installed with <c>--install</c> (never <c>--restart</c>: EasyPatch restarts only for an administrator's restart job). An
/// installation succeeds only when a new listing no longer shows the update, or, for an update that completes at the next
/// restart, when <c>softwareupdate</c> says so; the update is then reported as waiting for that restart. On Macs with Apple
/// silicon, Apple lets only a volume owner or MDM install updates that need a restart, so those fail at once with
/// <c>macos_owner_required</c> instead of being attempted.
/// </summary>
public sealed class SoftwareUpdateService : IUpdateService, IDisposable
{
    public const string OwnerRequiredCode = "macos_owner_required";

    private const string Program = "/usr/sbin/softwareupdate";
    private static readonly TimeSpan ListTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan HistoryTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan InstallTimeout = TimeSpan.FromHours(3);

    private readonly ICommandRunner _commands;
    private readonly MacSystemInfo _system;
    private readonly string _ledgerPath;
    private readonly IBootTimeProvider _bootTime;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _ledgerLock = new(1, 1);

    public SoftwareUpdateService(ICommandRunner commands, MacSystemInfo system, string ledgerPath, IBootTimeProvider bootTime, TimeProvider time,
        ILogger<SoftwareUpdateService> logger)
    {
        _commands = commands;
        _system = system;
        _ledgerPath = ledgerPath;
        _bootTime = bootTime;
        _time = time;
        _logger = logger;
    }

    public string Name => "softwareupdate";

    /// <summary>Downloads ahead of a maintenance window are a Windows Update feature only: whether macOS keeps what
    /// <c>softwareupdate --download</c> fetched until a later <c>--install</c> has not been validated.</summary>
    public bool KeepsDownloads => false;

    public void Dispose() => _ledgerLock.Dispose();

    public (string Code, string Message) DescribeFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception is SoftwareUpdateException update
            ? (update.Code, update.Message)
            : ("softwareupdate_failed", OutputRedactor.Redact(exception.Message));
    }

    // ------------------------------------------------------------------ scan

    public async Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken)
    {
        var items = await ListAsync(cancellationToken);
        var history = await ReadHistoryAsync(cancellationToken);
        var now = _time.GetUtcNow();
        var boot = _bootTime.GetLastBootTime();

        var listed = items.Select(item =>
        {
            var update = SoftwareUpdateCatalog.Describe(item, _system.Major);
            return (Item: item, Update: update, Line: SoftwareUpdateCatalog.LineOf(item.Title, item.Version), item.Version);
        }).GroupBy(l => l.Update.UpdateGuid).Select(g => g.First()).ToList();

        await _ledgerLock.WaitAsync(cancellationToken);
        try
        {
            var ledger = SoftwareUpdateLedger.Load(_ledgerPath);
            ledger.PrunePendingRestarts(boot);
            var pending = ledger.PendingRestarts(boot).Select(p => p.UpdateGuid).ToHashSet();
            ledger.Record(listed.Select(l => (l.Update, l.Line, l.Version)).ToList(), history, now);
            var listedGuids = listed.Select(l => l.Update.UpdateGuid).ToHashSet();

            var missing = listed.Select(l =>
            {
                var superseded = ledger.SupersededBy(l.Update.UpdateGuid, l.Line, l.Version, listedGuids);
                var update = l.Update with
                {
                    SupersededUpdateGuids = superseded,

                    // Installed by EasyPatch since the last restart: it completes when the Mac restarts.
                    RebootRequired = pending.Contains(l.Update.UpdateGuid),
                };
                return new UpdateCandidate(update, new SoftwareUpdateHandle(l.Item, update.UpdateGuid, update.Title));
            }).ToList();

            var installed = includeInstalled
                ? ledger.Installed.Select(e => e.Update with { IsInstalled = true, RebootRequired = false, SupersededUpdateGuids = [] }).ToList()
                : [];

            TrySave(ledger);
            _logger.LogInformation("softwareupdate scan: {Missing} update(s) available ({Restart} need a restart), {Installed} recently installed.",
                missing.Count, missing.Count(c => c.Update.RebootBehavior == 1), installed.Count);
            return new UpdateScanResult(missing, installed, microsoftUpdateRegistered: false);
        }
        finally
        {
            _ledgerLock.Release();
        }
    }

    /// <summary>macOS never refuses installations until a restart.</summary>
    public Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken) => Task.FromResult(false);

    /// <summary>The installations <c>softwareupdate --history</c> records (all sources: System Settings, MDM, EasyPatch).</summary>
    public async Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken)
    {
        var history = await ReadHistoryAsync(cancellationToken);
        return history
            .Where(h => h.Date is { } date && (since is null || date > since))
            .OrderByDescending(h => h.Date)
            .Take(Math.Max(0, maxEntries))
            .Select(h => new HistoryEntryReport
            {
                UpdateGuid = SoftwareUpdateCatalog.UpdateGuidFor(SoftwareUpdateCatalog.LineOf(h.Title, h.Version), h.Version),
                Title = h.Version.Length == 0 || h.Title.Contains(h.Version, StringComparison.Ordinal) ? h.Title : $"{h.Title} {h.Version}",
                Operation = "Installation",
                ResultCode = UpdateOperationResult.Succeeded,
                Date = h.Date!.Value,
            })
            .ToList();
    }

    // ------------------------------------------------------------------ download and install

    public async Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        var handle = Handle(update);
        if (NeedsOwner(handle.Item))
        {
            return OwnerRequired(handle);
        }

        var result = await RunAsync(["--download", handle.Item.Label], InstallTimeout, cancellationToken);
        if (result.ExitCode != 0)
        {
            return Failure("softwareupdate_download_failed", $"softwareupdate could not download {handle.Title}", result.Combined);
        }

        _logger.LogInformation("Downloaded {Update}.", handle.Title);
        return new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, false);
    }

    public async Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        var handle = Handle(update);
        if (NeedsOwner(handle.Item))
        {
            return OwnerRequired(handle);
        }

        _logger.LogInformation("Installing {Update} ({Label}).", handle.Title, handle.Item.Label);
        var result = await RunAsync(["--install", handle.Item.Label], InstallTimeout, cancellationToken);
        if (result.ExitCode != 0)
        {
            return Failure("softwareupdate_install_failed", $"softwareupdate could not install {handle.Title} (exit code {result.ExitCode})", result.Combined);
        }

        // Confirm with a new listing: success is what softwareupdate shows afterwards, not what it printed.
        IReadOnlyList<SoftwareUpdateItem> after;
        try
        {
            after = await ListAsync(cancellationToken);
        }
        catch (SoftwareUpdateException ex)
        {
            return Failure("softwareupdate_unconfirmed",
                $"softwareupdate finished installing {handle.Title}, but the check afterwards failed, so the installation is not confirmed: {ex.Message}", null);
        }

        var stillListed = after.Any(i => string.Equals(i.Label, handle.Item.Label, StringComparison.Ordinal) ||
                                         SoftwareUpdateCatalog.UpdateGuidFor(SoftwareUpdateCatalog.LineOf(i.Title, i.Version), i.Version) == handle.UpdateGuid);
        if (!stillListed)
        {
            if (handle.Item.RestartRequired)
            {
                await RecordPendingRestartAsync(handle, cancellationToken);
            }

            _logger.LogInformation("Installed {Update}{Restart}.", handle.Title, handle.Item.RestartRequired ? " (completes at the next restart)" : string.Empty);
            return new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, handle.Item.RestartRequired);
        }

        if (handle.Item.RestartRequired && result.Combined.Contains("restart", StringComparison.OrdinalIgnoreCase))
        {
            // Prepared: Apple lists it until the Mac restarts and finishes the installation.
            await RecordPendingRestartAsync(handle, cancellationToken);
            _logger.LogInformation("Prepared {Update}; it completes at the next restart.", handle.Title);
            return new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, true);
        }

        return Failure("softwareupdate_not_installed", $"softwareupdate finished, but still lists {handle.Title} as available", result.Combined);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Apple silicon: updates that need a restart require a volume owner's credentials or MDM.</summary>
    private bool NeedsOwner(SoftwareUpdateItem item) => _system.AppleSilicon && item.RestartRequired;

    private static UpdateOperationResult OwnerRequired(SoftwareUpdateHandle handle) => new(UpdateOperationResult.Failed, 0, false)
    {
        ErrorCode = OwnerRequiredCode,
        Message = $"On Macs with Apple silicon, Apple lets only a volume owner (an administrator in System Settings) or an MDM server install updates that " +
                  $"need a restart, so EasyPatch cannot install {handle.Title}. Install it in System Settings > General > Software Update on the Mac, or with your MDM.",
    };

    private async Task<IReadOnlyList<SoftwareUpdateItem>> ListAsync(CancellationToken cancellationToken)
    {
        var result = await RunAsync(["--list"], ListTimeout, cancellationToken);
        try
        {
            return SoftwareUpdateParser.ParseList(result.Combined);
        }
        catch (SoftwareUpdateException ex) when (result.ExitCode != 0)
        {
            throw new SoftwareUpdateException(ex.Code, $"{ex.Message} (exit code {result.ExitCode})");
        }
    }

    private async Task<IReadOnlyList<SoftwareUpdateHistoryEntry>> ReadHistoryAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunAsync(["--history"], HistoryTimeout, cancellationToken);
            return result.ExitCode == 0 ? SoftwareUpdateParser.ParseHistory(result.StandardOutput) : [];
        }
        catch (SoftwareUpdateException ex)
        {
            // Only installed reporting depends on the history; the scan itself still counts.
            _logger.LogWarning("softwareupdate --history failed: {Message}", ex.Message);
            return [];
        }
    }

    private async Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            return await _commands.RunAsync(Program, arguments, timeout, cancellationToken);
        }
        catch (CommandException ex)
        {
            throw new SoftwareUpdateException("softwareupdate_failed", OutputRedactor.Redact(ex.Message));
        }
    }

    private async Task RecordPendingRestartAsync(SoftwareUpdateHandle handle, CancellationToken cancellationToken)
    {
        await _ledgerLock.WaitAsync(cancellationToken);
        try
        {
            var ledger = SoftwareUpdateLedger.Load(_ledgerPath);
            ledger.AddPendingRestart(handle.UpdateGuid, handle.Title, _bootTime.GetLastBootTime());
            TrySave(ledger);
        }
        finally
        {
            _ledgerLock.Release();
        }
    }

    /// <summary>Updates EasyPatch installed that complete when the Mac restarts (for the restart detector).</summary>
    public IReadOnlyList<SoftwareUpdateLedger.PendingRestart> PendingRestarts()
    {
        _ledgerLock.Wait();
        try
        {
            return SoftwareUpdateLedger.Load(_ledgerPath).PendingRestarts(_bootTime.GetLastBootTime());
        }
        finally
        {
            _ledgerLock.Release();
        }
    }

    private void TrySave(SoftwareUpdateLedger ledger)
    {
        try
        {
            ledger.Save();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not save the software update ledger: {Message}", ex.Message);
        }
    }

    private static SoftwareUpdateHandle Handle(IUpdateHandle update) =>
        update as SoftwareUpdateHandle ?? throw new ArgumentException("Not a softwareupdate handle.", nameof(update));

    private static UpdateOperationResult Failure(string code, string reason, string? output)
    {
        var detail = output is null ? string.Empty : OutputRedactor.Summarize(output, 900);
        return new UpdateOperationResult(UpdateOperationResult.Failed, 0, false)
        {
            ErrorCode = code,
            Message = detail.Length == 0 ? reason.TrimEnd('.') + "." : $"{reason}: {detail}",
        };
    }
}
