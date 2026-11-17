using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Removal;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging;

namespace EasyPatch.WindowsUpdate;

/// <summary>
/// <see cref="IUpdateService"/> backed by the Windows Update Agent API (Microsoft.Update.Session).
/// Searches use the default server selection, so WSUS / Group Policy / Windows Update for Business configuration is
/// honored exactly as Windows itself would. Nothing here reports success that WUA did not report.
/// </summary>
public sealed partial class WuaWindowsUpdateService : IUpdateService, IWindowsUpdateUninstaller
{
    public const string ClientApplicationId = "EasyPatch Agent";
    private const string MicrosoftUpdateServiceId = "7971f918-a847-4430-9279-4a52d1efe18d";
    private const int EnUsLcid = 1033;
    private static readonly TimeSpan BusyTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan BusyPoll = TimeSpan.FromSeconds(15);

    private readonly ILogger<WuaWindowsUpdateService> _logger;

    public WuaWindowsUpdateService(ILogger<WuaWindowsUpdateService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken) =>
        RunAsync("search", () =>
        {
            var session = CreateSession();
            var searcher = Com.Invoke(session, "CreateUpdateSearcher")!;
            Com.TrySet(searcher, "ClientApplicationID", ClientApplicationId);
            Com.TrySet(searcher, "Online", true);

            var missing = new List<UpdateCandidate>();
            foreach (var update in Search(searcher, "IsInstalled=0 and IsHidden=0"))
            {
                missing.Add(new UpdateCandidate(Map(update), new WuaUpdateHandle(update, session)));
            }

            var installed = new List<ReportedUpdate>();
            if (includeInstalled)
            {
                foreach (var update in Search(searcher, "IsInstalled=1"))
                {
                    installed.Add(Map(update));
                    Com.Release(update);
                }
            }

            Com.Release(searcher);
            return new UpdateScanResult(missing, installed, IsMicrosoftUpdateRegistered());
        }, cancellationToken);

    public Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken) =>
        RunAsync("installer state", () =>
        {
            var session = CreateSession();
            var installer = Com.Invoke(session, "CreateUpdateInstaller")!;
            try
            {
                return Com.GetBool(installer, "RebootRequiredBeforeInstallation");
            }
            finally
            {
                Com.Release(installer);
                Com.Release(session);
            }
        }, cancellationToken);

    /// <summary>Downloads one update; <paramref name="progress"/> receives WUA's percentage while it runs.</summary>
    public Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        var handle = AsHandle(update);
        return RunAsync("download", () =>
        {
            var collection = Com.Create("Microsoft.Update.UpdateColl");
            Com.Invoke(collection, "Add", handle.Update);
            var downloader = Com.Invoke(handle.Session, "CreateUpdateDownloader")!;
            try
            {
                Com.TrySet(downloader, "ClientApplicationID", ClientApplicationId);
                Com.Set(downloader, "Updates", collection);
                var result = WuaAsyncJob.Run(downloader, "Download", progress, abortOnCancel: true, _logger, cancellationToken);
                var overall = ReadResult(result, out var overallHr);
                var perUpdate = Com.Invoke(result, "GetUpdateResult", 0)!;
                var code = ReadResult(perUpdate, out var updateHr);
                Com.Release(perUpdate);
                Com.Release(result);
                return new UpdateOperationResult(code != 0 ? code : overall, updateHr != 0 ? updateHr : overallHr, false);
            }
            finally
            {
                Com.Release(downloader);
                Com.Release(collection);
            }
        }, cancellationToken);
    }

    /// <summary>Installs one update; <paramref name="progress"/> receives WUA's percentage while it runs.</summary>
    public Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        var handle = AsHandle(update);
        return RunAsync("install", () =>
        {
            if (!Com.GetBool(handle.Update, "EulaAccepted", fallback: true))
            {
                if (!acceptEula)
                {
                    // Policy forbids accepting the license; WUA would refuse to install anyway.
                    return new UpdateOperationResult(UpdateOperationResult.Failed, unchecked((int)0x80240FFF), false);
                }

                Com.Invoke(handle.Update, "AcceptEula");
            }

            var collection = Com.Create("Microsoft.Update.UpdateColl");
            Com.Invoke(collection, "Add", handle.Update);
            var installer = Com.Invoke(handle.Session, "CreateUpdateInstaller")!;
            try
            {
                Com.TrySet(installer, "ClientApplicationID", ClientApplicationId); // recorded in Windows Update history
                Com.TrySet(installer, "AllowSourcePrompts", false);
                Com.TrySet(installer, "ForceQuiet", true); // IUpdateInstaller2: suppress any UI
                Com.Set(installer, "Updates", collection);
                WaitUntilNotBusy(installer, cancellationToken);

                var result = WuaAsyncJob.Run(installer, "Install", progress, abortOnCancel: false, _logger, cancellationToken);
                var overall = ReadResult(result, out var overallHr);
                var rebootRequired = Com.GetBool(result, "RebootRequired");
                var perUpdate = Com.Invoke(result, "GetUpdateResult", 0)!;
                var code = ReadResult(perUpdate, out var updateHr);
                rebootRequired |= Com.GetBool(perUpdate, "RebootRequired");
                Com.Release(perUpdate);
                Com.Release(result);
                return new UpdateOperationResult(code != 0 ? code : overall, updateHr != 0 ? updateHr : overallHr, rebootRequired);
            }
            finally
            {
                Com.Release(installer);
                Com.Release(collection);
            }
        }, cancellationToken);
    }

    /// <summary>Uninstalls one installed update with Windows Update's own uninstall, when Windows Update lists it as installed and
    /// uninstallable. The search reads Windows Update's local records only (installed updates need no server).</summary>
    public Task<WuaUninstallResult> UninstallAsync(Guid updateGuid, CancellationToken cancellationToken) =>
        RunAsync("uninstall", () =>
        {
            var session = CreateSession();
            var searcher = Com.Invoke(session, "CreateUpdateSearcher")!;
            List<object> found;
            try
            {
                Com.TrySet(searcher, "ClientApplicationID", ClientApplicationId);
                Com.TrySet(searcher, "Online", false);
                found = Search(searcher, "IsInstalled=1 and UpdateID='" + updateGuid.ToString("D", CultureInfo.InvariantCulture) + "'");
            }
            finally
            {
                Com.Release(searcher);
            }

            if (found.Count == 0)
            {
                Com.Release(session);
                return new WuaUninstallResult(WuaUninstallStatus.NotInstalled);
            }

            foreach (var extra in found.Skip(1))
            {
                Com.Release(extra);
            }

            var update = found[0];
            var collection = Com.Create("Microsoft.Update.UpdateColl");
            object? installer = null;
            try
            {
                if (!Com.GetBool(update, "IsUninstallable"))
                {
                    return new WuaUninstallResult(WuaUninstallStatus.NotUninstallable);
                }

                Com.Invoke(collection, "Add", update);
                installer = Com.Invoke(session, "CreateUpdateInstaller")!;
                Com.TrySet(installer, "ClientApplicationID", ClientApplicationId); // recorded in Windows Update history
                Com.TrySet(installer, "AllowSourcePrompts", false);
                Com.TrySet(installer, "ForceQuiet", true);
                Com.Set(installer, "Updates", collection);
                WaitUntilNotBusy(installer, cancellationToken);

                var result = Com.Invoke(installer, "Uninstall")!;
                var overall = ReadResult(result, out var overallHr);
                var rebootRequired = Com.GetBool(result, "RebootRequired");
                var perUpdate = Com.Invoke(result, "GetUpdateResult", 0)!;
                var code = ReadResult(perUpdate, out var updateHr);
                rebootRequired |= Com.GetBool(perUpdate, "RebootRequired");
                Com.Release(perUpdate);
                Com.Release(result);
                return new WuaUninstallResult(WuaUninstallStatus.Attempted,
                    new UpdateOperationResult(code != 0 ? code : overall, updateHr != 0 ? updateHr : overallHr, rebootRequired));
            }
            finally
            {
                if (installer is not null)
                {
                    Com.Release(installer);
                }

                Com.Release(collection);
                Com.Release(update);
                Com.Release(session);
            }
        }, cancellationToken);

    public Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken) =>
        RunAsync<IReadOnlyList<HistoryEntryReport>>("history", () =>
        {
            var session = CreateSession();
            var searcher = Com.Invoke(session, "CreateUpdateSearcher")!;
            var entries = new List<HistoryEntryReport>();
            try
            {
                var total = Convert.ToInt32(Com.Invoke(searcher, "GetTotalHistoryCount"), CultureInfo.InvariantCulture);
                var count = Math.Min(total, Math.Max(1, maxEntries));
                if (count <= 0)
                {
                    return entries;
                }

                var history = Com.Invoke(searcher, "QueryHistory", 0, count);
                foreach (var entry in Com.Items(history))
                {
                    try
                    {
                        var mapped = MapHistory(entry);
                        if (mapped is not null && (since is null || mapped.Date > since))
                        {
                            entries.Add(mapped);
                        }
                    }
                    catch (COMException ex)
                    {
                        _logger.LogDebug(ex, "Skipping an unreadable Windows Update history entry.");
                    }
                    finally
                    {
                        Com.Release(entry);
                    }
                }

                Com.Release(history);
                return entries;
            }
            finally
            {
                Com.Release(searcher);
                Com.Release(session);
            }
        }, cancellationToken);

    /// <summary>WUA's own "reboot required" flag (Microsoft.Update.SystemInfo).</summary>
    public Task<bool> IsSystemRebootRequiredAsync(CancellationToken cancellationToken) =>
        RunAsync("system info", () =>
        {
            var info = Com.Create("Microsoft.Update.SystemInfo");
            try
            {
                return Com.GetBool(info, "RebootRequired");
            }
            finally
            {
                Com.Release(info);
            }
        }, cancellationToken);

    // ------------------------------------------------------------------ helpers

    private Task<T> RunAsync<T>(string operation, Func<T> work, CancellationToken cancellationToken) =>
        ComThread.RunAsync(() =>
        {
            try
            {
                return work();
            }
            catch (COMException ex)
            {
                var description = WindowsUpdateErrors.Describe(ex.HResult);
                _logger.LogWarning("Windows Update {Operation} failed with {Code}: {Description}", operation, WindowsUpdateErrors.Format(ex.HResult), description);
                throw new WindowsUpdateException($"Windows Update {operation} failed: {description}", ex.HResult, ex);
            }
            catch (InvalidComObjectException ex)
            {
                throw new WindowsUpdateException($"Windows Update {operation} failed: the update object is no longer valid.", unchecked((int)0x80240FFF), ex);
            }
        }, cancellationToken);

    private static object CreateSession()
    {
        var session = Com.Create("Microsoft.Update.Session");
        Com.TrySet(session, "ClientApplicationID", ClientApplicationId);

        // IUpdateSession2.UserLocale: request en-US metadata so the shared classifier's title rules work on every
        // display language. Failure (older WUA) just means localized titles.
        Com.TrySet(session, "UserLocale", EnUsLcid);
        return session;
    }

    private List<object> Search(object searcher, string criteria)
    {
        var result = Com.Invoke(searcher, "Search", criteria)!;
        try
        {
            var code = Com.GetInt(result, "ResultCode");
            if (code is UpdateOperationResult.Failed or UpdateOperationResult.Aborted)
            {
                throw new WindowsUpdateException($"Windows Update search '{criteria}' did not succeed (result code {code}).", unchecked((int)0x80240FFF));
            }

            if (code == UpdateOperationResult.SucceededWithErrors)
            {
                _logger.LogWarning("Windows Update search '{Criteria}' completed with errors; results may be incomplete.", criteria);
            }

            var updates = Com.Get(result, "Updates");
            var list = Com.Items(updates).ToList();
            return list;
        }
        finally
        {
            Com.Release(result);
        }
    }

    private static ReportedUpdate Map(object update)
    {
        var identity = Com.Get(update, "Identity")!;
        var updateId = Guid.Parse(Com.GetString(identity, "UpdateID")!);
        var revision = Com.GetInt(identity, "RevisionNumber");
        Com.Release(identity);

        var categories = new List<UpdateCategoryRef>();
        foreach (var category in Com.Items(Com.Get(update, "Categories")))
        {
            _ = Guid.TryParse(Com.GetString(category, "CategoryID"), out var categoryId);
            categories.Add(new UpdateCategoryRef
            {
                Id = categoryId,
                Name = Com.GetString(category, "Name") ?? string.Empty,
                Type = Com.GetString(category, "Type"),
            });
            Com.Release(category);
        }

        var behavior = Com.Get(update, "InstallationBehavior");
        var canRequestUserInput = behavior is not null && Com.GetBool(behavior, "CanRequestUserInput");
        var rebootBehavior = behavior is null ? null : Com.TryGetInt(behavior, "RebootBehavior");
        Com.Release(behavior);

        var superseded = Com.Strings(Com.Get(update, "SupersededUpdateIDs"))
            .Select(id => Guid.TryParse(id, out var g) ? g : Guid.Empty)
            .Where(g => g != Guid.Empty)
            .ToList();

        return new ReportedUpdate
        {
            UpdateGuid = updateId,
            RevisionNumber = revision,
            Title = Com.GetString(update, "Title") ?? updateId.ToString(),
            Description = Com.GetString(update, "Description"),
            KbNumbers = Com.Strings(Com.Get(update, "KBArticleIDs"))
                .Select(KbNumber.Normalize).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Categories = categories,
            IsDriver = Com.GetInt(update, "Type") == 2,
            BrowseOnly = Com.GetBool(update, "BrowseOnly"),
            IsMandatory = Com.GetBool(update, "IsMandatory"),
            IsDownloaded = Com.GetBool(update, "IsDownloaded"),
            IsInstalled = Com.GetBool(update, "IsInstalled"),
            RebootRequired = Com.GetBool(update, "RebootRequired"),
            EulaAccepted = Com.GetBool(update, "EulaAccepted", fallback: true),
            CanRequestUserInput = canRequestUserInput,
            RebootBehavior = rebootBehavior,
            MsrcSeverity = NullIfEmpty(Com.GetString(update, "MsrcSeverity")),
            LastDeploymentChangeTime = Com.TryGetDate(update, "LastDeploymentChangeTime"),
            MaxDownloadSize = Com.TryGetLong(update, "MaxDownloadSize"),
            SupportUrl = NullIfEmpty(Com.GetString(update, "SupportUrl")),
            SupersededUpdateGuids = superseded,
        };
    }

    private static HistoryEntryReport? MapHistory(object entry)
    {
        var title = Com.GetString(entry, "Title");
        var date = Com.TryGetDate(entry, "Date");
        if (string.IsNullOrWhiteSpace(title) || date is null)
        {
            return null;
        }

        Guid? updateId = null;
        int? revision = null;
        var identity = Com.Get(entry, "UpdateIdentity");
        if (identity is not null)
        {
            if (Guid.TryParse(Com.GetString(identity, "UpdateID"), out var id) && id != Guid.Empty)
            {
                updateId = id;
                revision = Com.TryGetInt(identity, "RevisionNumber");
            }

            Com.Release(identity);
        }

        var hresult = Com.GetInt(entry, "HResult");
        var kb = KbPattern().Match(title);
        return new HistoryEntryReport
        {
            UpdateGuid = updateId,
            RevisionNumber = revision,
            Title = title,
            KbNumber = kb.Success ? "KB" + kb.Groups[1].Value : null,
            Operation = Com.GetInt(entry, "Operation") switch
            {
                1 => "Installation",
                2 => "Uninstallation",
                _ => "Other",
            },
            ResultCode = Com.GetInt(entry, "ResultCode"),
            HResult = hresult == 0 ? null : WindowsUpdateErrors.Format(hresult),
            Date = date.Value,
            ClientApplicationId = NullIfEmpty(Com.GetString(entry, "ClientApplicationID")),
        };
    }

    private bool IsMicrosoftUpdateRegistered()
    {
        try
        {
            var manager = Com.Create("Microsoft.Update.ServiceManager");
            try
            {
                foreach (var service in Com.Items(Com.Get(manager, "Services")))
                {
                    var id = Com.GetString(service, "ServiceID");
                    Com.Release(service);
                    if (string.Equals(id, MicrosoftUpdateServiceId, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            finally
            {
                Com.Release(manager);
            }
        }
        catch (COMException ex)
        {
            _logger.LogDebug(ex, "Could not enumerate Windows Update services.");
        }

        return false;
    }

    private static int ReadResult(object result, out int hresult)
    {
        hresult = Com.GetInt(result, "HResult");
        return Com.GetInt(result, "ResultCode");
    }

    private void WaitUntilNotBusy(object installer, CancellationToken cancellationToken)
    {
        var waited = TimeSpan.Zero;
        while (Com.GetBool(installer, "IsBusy"))
        {
            if (waited >= BusyTimeout)
            {
                throw new WindowsUpdateException("Windows Update has been busy with another installation for 30 minutes.", unchecked((int)0x80240016));
            }

            if (waited == TimeSpan.Zero)
            {
                _logger.LogInformation("Windows Update is busy with another installation; waiting.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            Thread.Sleep(BusyPoll);
            waited += BusyPoll;
        }
    }

    private static WuaUpdateHandle AsHandle(IUpdateHandle handle) =>
        handle as WuaUpdateHandle ?? throw new ArgumentException("The update handle was not created by this service.", nameof(handle));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    [GeneratedRegex(@"\bKB(\d{6,8})\b", RegexOptions.IgnoreCase)]
    private static partial Regex KbPattern();

    /// <summary>Holds an IUpdate and the session that produced it (needed to create downloader/installer).</summary>
    private sealed class WuaUpdateHandle : IUpdateHandle
    {
        public WuaUpdateHandle(object update, object session)
        {
            Update = update;
            Session = session;
        }

        public object Update { get; private set; }

        public object Session { get; }

        public void Dispose()
        {
            if (Update is not null)
            {
                Com.Release(Update);
                Update = null!;
            }
        }
    }
}

/// <summary>Reboot detector based on WUA's own SystemInfo.RebootRequired flag.</summary>
public sealed class WuaRebootDetector : IRebootDetector
{
    private readonly WuaWindowsUpdateService _service;

    public WuaRebootDetector(WuaWindowsUpdateService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    public async Task<RebootStatus> DetectAsync(CancellationToken cancellationToken) =>
        await _service.IsSystemRebootRequiredAsync(cancellationToken)
            ? new RebootStatus(true, ["Windows Update (SystemInfo.RebootRequired)"])
            : RebootStatus.None;
}
