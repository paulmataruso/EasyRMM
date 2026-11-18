using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Removal;

/// <summary>
/// Removes an installed Windows update the way Windows itself allows it:
/// <list type="number">
/// <item>Windows Update's own uninstall, when Windows Update lists the update as installed and uninstallable.</item>
/// <item>Otherwise DISM: the servicing packages named for the KB (<c>Package_for_KB…</c>), or the cumulative update package whose
/// build matches the title or whose package information names the KB, are removed with
/// <c>dism /Online /Remove-Package /PackageName:… /NoRestart</c>, the method Microsoft documents for cumulative updates that
/// were installed together with a servicing stack update.</item>
/// </list>
/// The computer is never restarted. A removal counts only when DISM no longer lists the package as installed afterwards.
/// </summary>
public sealed class WindowsUpdateRemover(IWindowsUpdateUninstaller? windowsUpdate, IDismRunner dism, ILogger<WindowsUpdateRemover> logger) : IUpdateRemover
{
    public static readonly TimeSpan QueryTimeout = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan RemoveTimeout = TimeSpan.FromHours(2);

    /// <summary>Package information is read for at most this many cumulative update packages.</summary>
    private const int MaxInfoQueries = 6;

    public async Task<UpdateRemovalResult> RemoveAsync(UninstallUpdatePayload update, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(update);
        var label = update.KbNumber is { } number ? "KB" + number : update.Title;

        WuaUninstallStatus? wuaStatus = null;
        string? wuaError = null;
        if (windowsUpdate is not null)
        {
            try
            {
                var result = await windowsUpdate.UninstallAsync(update.UpdateGuid, cancellationToken);
                if (result is { Status: WuaUninstallStatus.Attempted, Result: { } outcome })
                {
                    return FromWindowsUpdate(label, outcome);
                }

                wuaStatus = result.Status;
            }
            catch (WindowsUpdateException ex)
            {
                wuaError = ex.Message;
                logger.LogWarning("Windows Update could not look up {Update} for removal ({Error}); trying DISM.", label, ex.Message);
            }
        }

        if (update.KbNumber is not { } kb)
        {
            return wuaStatus switch
            {
                WuaUninstallStatus.NotInstalled => new UpdateRemovalResult(UpdateRemovalStatus.NotInstalled,
                    $"Windows Update does not list {label} as installed.", Method: "Windows Update"),
                WuaUninstallStatus.NotUninstallable => new UpdateRemovalResult(UpdateRemovalStatus.NotRemovable,
                    $"Windows Update cannot uninstall {label}, and it has no KB number to find its servicing package.", ErrorCode: "update_not_removable",
                    Method: "Windows Update"),
                _ => new UpdateRemovalResult(UpdateRemovalStatus.Failed, $"{label} could not be removed: {wuaError ?? "Windows Update is not available."}",
                    ErrorCode: "update_removal_failed"),
            };
        }

        try
        {
            return await RemoveWithDismAsync(update, kb, wuaStatus, wuaError, cancellationToken);
        }
        catch (DismException ex)
        {
            return new UpdateRemovalResult(UpdateRemovalStatus.Failed, $"KB{kb} could not be removed: {ex.Message}", ErrorCode: "dism_failed", Method: "DISM");
        }
    }

    private static UpdateRemovalResult FromWindowsUpdate(string label, UpdateOperationResult outcome)
    {
        if (outcome.IsSuccess)
        {
            return new UpdateRemovalResult(UpdateRemovalStatus.Removed,
                $"Windows Update uninstalled {label}." + (outcome.RebootRequired ? " Restart the computer to finish removing it." : string.Empty),
                outcome.RebootRequired, outcome.ResultCode == UpdateOperationResult.SucceededWithErrors ? WindowsUpdateErrors.Format(outcome.HResult) : null,
                "Windows Update");
        }

        return new UpdateRemovalResult(UpdateRemovalStatus.Failed,
            $"Windows Update could not uninstall {label}: {WindowsUpdateErrors.Describe(outcome.HResult)}",
            ErrorCode: WindowsUpdateErrors.Format(outcome.HResult), Method: "Windows Update");
    }

    private async Task<UpdateRemovalResult> RemoveWithDismAsync(UninstallUpdatePayload update, string kb, WuaUninstallStatus? wuaStatus, string? wuaError,
        CancellationToken cancellationToken)
    {
        var packages = await GetPackagesAsync(cancellationToken);
        var matches = await FindPackagesAsync(packages, update.Title, kb, cancellationToken);
        var removable = matches.Where(DismPackages.IsRemovable).ToList();
        if (removable.Count == 0)
        {
            if (matches.Any(p => p.State == DismPackages.UninstallPending))
            {
                return new UpdateRemovalResult(UpdateRemovalStatus.Removed,
                    $"Windows has already queued KB{kb} for removal. Restart the computer to finish removing it.", RebootRequired: true, Method: "DISM");
            }

            return wuaStatus switch
            {
                WuaUninstallStatus.NotUninstallable => new UpdateRemovalResult(UpdateRemovalStatus.NotRemovable,
                    $"Windows Update cannot uninstall KB{kb}, and Windows has no removable servicing package for it.", ErrorCode: "update_not_removable",
                    Method: "DISM"),
                WuaUninstallStatus.NotInstalled => new UpdateRemovalResult(UpdateRemovalStatus.NotInstalled,
                    $"KB{kb} is not installed: neither Windows Update nor DISM lists it.", Method: "DISM"),
                _ => new UpdateRemovalResult(UpdateRemovalStatus.Failed,
                    $"DISM has no installed package for KB{kb}, and Windows Update could not be checked: {wuaError ?? "it is not available."}",
                    ErrorCode: "update_removal_failed", Method: "DISM"),
            };
        }

        var rebootRequired = false;
        foreach (var package in removable)
        {
            logger.LogInformation("Removing {Package} (KB{Kb}) with DISM.", package.Identity, kb);
            var result = await dism.RunAsync(
                ["/Online", "/Remove-Package", "/PackageName:" + package.Identity, "/Quiet", "/NoRestart", "/English", "/LogPath:" + dism.LogPath],
                RemoveTimeout, cancellationToken);
            if (result.ExitCode == DismPackages.PermanentPackage)
            {
                return new UpdateRemovalResult(UpdateRemovalStatus.NotRemovable,
                    $"Windows does not allow KB{kb} to be removed: {package.Identity} is a permanent package.", ErrorCode: "update_not_removable",
                    Method: "DISM");
            }

            if (result.ExitCode is not (0 or DismPackages.RestartRequired))
            {
                return new UpdateRemovalResult(UpdateRemovalStatus.Failed,
                    $"DISM could not remove {package.Identity} (KB{kb}), exit code {FormatExitCode(result.ExitCode)}: {DismPackages.Summarize(result.Output)} See {dism.LogPath}.",
                    ErrorCode: FormatExitCode(result.ExitCode), Method: "DISM");
            }

            rebootRequired |= result.ExitCode == DismPackages.RestartRequired;
        }

        // Confirm: DISM must no longer list the packages as installed.
        var after = await GetPackagesAsync(cancellationToken);
        foreach (var package in removable)
        {
            var now = after.FirstOrDefault(p => string.Equals(p.Identity, package.Identity, StringComparison.OrdinalIgnoreCase));
            if (now is not null && DismPackages.IsRemovable(now))
            {
                return new UpdateRemovalResult(UpdateRemovalStatus.Failed,
                    $"DISM finished, but {package.Identity} (KB{kb}) is still {now.State.ToLowerInvariant()}. See {dism.LogPath}.",
                    ErrorCode: "update_still_installed", Method: "DISM");
            }

            rebootRequired |= now?.State == DismPackages.UninstallPending;
        }

        var names = string.Join(", ", removable.Select(p => p.Identity));
        return new UpdateRemovalResult(UpdateRemovalStatus.Removed,
            $"Removed KB{kb} with DISM ({names})." + (rebootRequired ? " Restart the computer to finish removing it." : string.Empty),
            rebootRequired, Method: "DISM");
    }

    private async Task<IReadOnlyList<DismPackage>> GetPackagesAsync(CancellationToken cancellationToken)
    {
        var result = await dism.RunAsync(["/Online", "/Get-Packages", "/English", "/LogPath:" + dism.LogPath], QueryTimeout, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new DismException($"DISM could not list the installed packages (exit code {FormatExitCode(result.ExitCode)}): {DismPackages.Summarize(result.Output)}");
        }

        return DismPackages.Parse(result.Output);
    }

    /// <summary>The packages for the KB: those named for it, otherwise the cumulative update package for the title's build or
    /// whose package information names the KB.</summary>
    private async Task<IReadOnlyList<DismPackage>> FindPackagesAsync(IReadOnlyList<DismPackage> packages, string title, string kb,
        CancellationToken cancellationToken)
    {
        var named = DismPackages.NamedForKb(packages, kb);
        if (named.Count > 0)
        {
            return named;
        }

        var rollups = DismPackages.RollupCandidates(packages);
        if (DismPackages.BuildFromTitle(title) is { } build && rollups.Where(p => DismPackages.IsBuild(p, build)).ToList() is { Count: > 0 } byBuild)
        {
            return byBuild;
        }

        var confirmed = new List<DismPackage>();
        foreach (var candidate in rollups.Take(MaxInfoQueries))
        {
            var info = await dism.RunAsync(["/Online", "/Get-PackageInfo", "/PackageName:" + candidate.Identity, "/English", "/LogPath:" + dism.LogPath],
                QueryTimeout, cancellationToken);
            if (info.ExitCode == 0 && DismPackages.MentionsKb(info.Output, kb))
            {
                confirmed.Add(candidate);
            }
        }

        return confirmed;
    }

    private static string FormatExitCode(int code) =>
        code < 0 ? WindowsUpdateErrors.Format(code) : code.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
