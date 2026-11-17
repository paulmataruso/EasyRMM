using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Applications;

/// <summary>Output of one winget run.</summary>
public sealed record WingetRunResult(int ExitCode, string Output);

/// <summary>winget could not be started (not installed, or the run timed out).</summary>
public sealed class WingetException : Exception
{
    public WingetException()
    {
    }

    public WingetException(string message)
        : base(message)
    {
    }

    public WingetException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Runs winget.exe with an argument vector (never through a shell). Implemented on Windows; faked in tests.</summary>
public interface IWingetRunner
{
    /// <summary>Path of the machine-wide winget.exe, or null when App Installer is not installed for all users.</summary>
    string? Locate();

    /// <exception cref="WingetException">winget is missing or did not finish within <paramref name="timeout"/>.</exception>
    Task<WingetRunResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Application updates through winget, limited to the community source (<c>winget</c>, never the Microsoft Store) and to
/// the approved package IDs. Every command line is fixed apart from an ID and a version that passed
/// <see cref="ApplicationIds"/> validation. Only applications that are already installed are upgraded, and an upgrade
/// counts as installed only when winget lists the target version afterwards.
/// </summary>
public sealed class WingetApplicationUpdateService(IWingetRunner runner, ILogger<WingetApplicationUpdateService> logger) : IApplicationUpdateService
{
    public static readonly Version MinimumVersion = new(1, 6);
    public static readonly TimeSpan VersionTimeout = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan ListTimeout = TimeSpan.FromMinutes(3);
    public static readonly TimeSpan InstallTimeout = TimeSpan.FromMinutes(60);

    private static readonly string[] CommonArguments = ["--source", ApplicationIds.Source, "--accept-source-agreements", "--disable-interactivity"];

    public static IReadOnlyList<string> ListArguments(string id) => ["list", "--id", id, "--exact", .. CommonArguments];

    public static IReadOnlyList<string> UpgradeArguments(string id, string version) =>
        ["upgrade", "--id", id, "--exact", "--version", version, "--silent", "--accept-package-agreements", .. CommonArguments];

    public async Task<ApplicationScanResult> ScanAsync(IReadOnlyList<string> approvedIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(approvedIds);
        if (runner.Locate() is null)
        {
            return Failed("winget_not_found",
                "winget (App Installer) is not installed for all users on this computer. Windows Server 2019 and 2022 do not include it.");
        }

        Version? version;
        try
        {
            version = WingetOutput.ParseWingetVersion((await runner.RunAsync(["--version"], VersionTimeout, cancellationToken)).Output);
        }
        catch (WingetException ex)
        {
            return Failed("winget_failed", ex.Message);
        }

        if (version is null || version < MinimumVersion)
        {
            return Failed("winget_too_old", $"winget {version?.ToString() ?? "(unknown version)"} is too old; EasyPatch needs {MinimumVersion} or later.",
                version?.ToString());
        }

        var missing = new List<UpdateCandidate>();
        var installed = new List<ReportedUpdate>();
        var errors = new List<string>();
        var checkedCount = 0;
        foreach (var id in approvedIds.Where(ApplicationIds.IsValid).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            checkedCount++;
            WingetRunResult result;
            try
            {
                result = await runner.RunAsync(ListArguments(id), ListTimeout, cancellationToken);
            }
            catch (WingetException ex)
            {
                errors.Add($"{id}: {ex.Message}");
                continue;
            }

            var row = WingetOutput.FindRow(result.Output, id);
            if (row is null)
            {
                if (result.ExitCode is not 0 and not WingetExitCodes.NoApplicationsFound)
                {
                    errors.Add($"{id}: winget exited with {WingetOutput.FormatExitCode(result.ExitCode)}. {WingetOutput.Tail(result.Output, 200)}".Trim());
                }

                continue; // not installed: EasyPatch never installs new applications
            }

            if (!ApplicationIds.IsValidVersion(row.InstalledVersion))
            {
                logger.LogInformation("{Id}: winget cannot tell the installed version ({Version}); skipped.", id, row.InstalledVersion);
                continue;
            }

            installed.Add(Describe(row, row.InstalledVersion, installed: true));
            if (row.AvailableVersion is { } available && ApplicationIds.IsValidVersion(available) &&
                !string.Equals(available, row.InstalledVersion, StringComparison.OrdinalIgnoreCase))
            {
                missing.Add(new UpdateCandidate(Describe(row, available, installed: false),
                    new ApplicationUpdateHandle(row.Id, available, row.InstalledVersion)));
            }
        }

        logger.LogInformation("Application check: {Checked} approved application(s), {Installed} installed, {Updates} update(s) available, {Errors} error(s).",
            checkedCount, installed.Count, missing.Count, errors.Count);
        var report = new ApplicationScanReport
        {
            Succeeded = errors.Count == 0,
            ErrorCode = errors.Count == 0 ? null : "winget_list_failed",
            ErrorMessage = errors.Count == 0 ? null : Truncate(string.Join(" ", errors.Take(3)), 1000),
            WingetVersion = version.ToString(),
            Checked = checkedCount,
        };
        return new ApplicationScanResult(missing, installed, report);
    }

    public async Task<UpdateOperationResult> InstallAsync(ApplicationUpdateHandle update, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (!ApplicationIds.IsValid(update.Id) || !ApplicationIds.IsValidVersion(update.Version))
        {
            return Failure("invalid_application", "The application ID or version is not valid.");
        }

        WingetRunResult result;
        try
        {
            logger.LogInformation("Upgrading {Id} from {Installed} to {Version} with winget.", update.Id, update.InstalledVersion, update.Version);
            result = await runner.RunAsync(UpgradeArguments(update.Id, update.Version), InstallTimeout, cancellationToken);
        }
        catch (WingetException ex)
        {
            return Failure("winget_failed", ex.Message);
        }

        // Never trust the exit code alone: the target version must be listed as installed.
        string? nowInstalled = null;
        try
        {
            var check = await runner.RunAsync(ListArguments(update.Id), ListTimeout, cancellationToken);
            nowInstalled = WingetOutput.FindRow(check.Output, update.Id)?.InstalledVersion;
        }
        catch (WingetException ex)
        {
            logger.LogWarning("Could not check the installed version of {Id}: {Message}", update.Id, ex.Message);
        }

        var rebootRequired = WingetExitCodes.IsRebootRequired(result.ExitCode);
        if (string.Equals(nowInstalled, update.Version, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation("Upgraded {Id} to {Version}{Restart}.", update.Id, update.Version, rebootRequired ? " (restart required)" : "");
            return new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, rebootRequired);
        }

        var code = WingetOutput.FormatExitCode(result.ExitCode);
        var reason = WingetExitCodes.Describe(result.ExitCode);
        var state = nowInstalled is null ? $"{update.Id} is not listed as installed" : $"{update.Id} {nowInstalled} is installed instead of {update.Version}";
        var message = result.ExitCode == 0
            ? $"winget reported success, but {state}."
            : $"winget exited with {code}{(reason is null ? "" : ": " + reason)} {state}. {WingetOutput.Tail(result.Output, 300)}";
        logger.LogWarning("Upgrade of {Id} to {Version} failed: {Message}", update.Id, update.Version, message);
        return Failure(result.ExitCode == 0 ? "not_verified" : "winget_" + code, message.Trim()) with { RebootRequired = rebootRequired };
    }

    private static ReportedUpdate Describe(WingetListRow row, string version, bool installed)
    {
        var name = row.Name.Length > 0 ? row.Name : row.Id;
        return new ReportedUpdate
        {
            UpdateGuid = ApplicationIds.UpdateGuidFor(row.Id, version),
            Title = Truncate($"{name} {version}", 300),
            Description = installed ? null : $"Upgrades {name} ({row.Id}) from {row.InstalledVersion} to {version} with winget.",
            IsInstalled = installed,
            IsDownloaded = true,
            EulaAccepted = true,
            Application = new ApplicationUpdateInfo { Id = row.Id, Version = version, InstalledVersion = row.InstalledVersion },
        };
    }

    private static ApplicationScanResult Failed(string code, string message, string? version = null) =>
        new([], [], new ApplicationScanReport { Succeeded = false, ErrorCode = code, ErrorMessage = message, WingetVersion = version });

    private static UpdateOperationResult Failure(string code, string message) =>
        new(UpdateOperationResult.Failed, 0, false) { ErrorCode = Truncate(code, 32), Message = Truncate(message, 1000) };

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}

/// <summary>
/// Windows Update plus application updates: the application part runs after a successful Windows Update scan and only
/// while the server's policy enables it, for the approved applications only. Installs are routed by handle type.
/// </summary>
public sealed class CompositeUpdateService(
    IUpdateService system,
    IApplicationUpdateService applications,
    Func<ApplicationUpdatesConfig?> config,
    ILogger<CompositeUpdateService> logger) : IUpdateService
{
    public string Name => system.Name;

    public (string Code, string Message) DescribeFailure(Exception exception) => system.DescribeFailure(exception);

    public async Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken)
    {
        var result = await system.ScanAsync(includeInstalled, cancellationToken);
        var settings = config();
        if (settings is not { Enabled: true } || settings.ApprovedApps.Count == 0)
        {
            return result;
        }

        var approved = settings.ApprovedApps.Where(ApplicationIds.IsValid).Distinct(StringComparer.OrdinalIgnoreCase).Take(ApplicationIds.MaxApproved).ToList();
        ApplicationScanResult apps;
        try
        {
            apps = await applications.ScanAsync(approved, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The application update check failed.");
            apps = new ApplicationScanResult([], [], new ApplicationScanReport
            {
                Succeeded = false, ErrorCode = "winget_failed", ErrorMessage = $"The application check failed ({ex.GetType().Name}).",
            });
        }

        return new UpdateScanResult(
            [.. result.Missing, .. apps.Missing],
            includeInstalled ? [.. result.Installed, .. apps.Installed] : result.Installed,
            result.MicrosoftUpdateRegistered)
        {
            Applications = apps.Report,
        };
    }

    public Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken) =>
        system.IsRebootRequiredBeforeInstallationAsync(cancellationToken);

    /// <summary>winget downloads during the upgrade.</summary>
    public Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken) =>
        update is ApplicationUpdateHandle
            ? Task.FromResult(new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, false))
            : system.DownloadAsync(update, progress, cancellationToken);

    /// <summary>Application upgrades report no percentage (winget only draws a progress bar on its console).</summary>
    public Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken) =>
        update is ApplicationUpdateHandle app
            ? applications.InstallAsync(app, cancellationToken)
            : system.InstallAsync(update, acceptEula, progress, cancellationToken);

    public Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken) =>
        system.GetHistoryAsync(since, maxEntries, cancellationToken);
}
