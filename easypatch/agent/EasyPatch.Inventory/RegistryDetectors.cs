using System.Globalization;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Scanning;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Win32;

namespace EasyPatch.Inventory;

internal static class Reg
{
    public static RegistryKey? OpenLocalMachine(string path)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return root.OpenSubKey(path, writable: false);
    }

    public static bool KeyExists(string path)
    {
        using var key = OpenLocalMachine(path);
        return key is not null;
    }

    public static object? GetValue(string path, string name)
    {
        using var key = OpenLocalMachine(path);
        return key?.GetValue(name);
    }

    /// <summary>The value names and subkey names of a key (empty when it does not exist).</summary>
    public static IReadOnlyList<string> GetNames(string path)
    {
        using var key = OpenLocalMachine(path);
        return key is null ? [] : [.. key.GetValueNames(), .. key.GetSubKeyNames()];
    }

    public static string? GetString(string path, string name) =>
        GetValue(path, name) is { } value ? Convert.ToString(value, CultureInfo.InvariantCulture) : null;

    public static int? GetInt(string path, string name)
    {
        var value = GetValue(path, name);
        return value switch
        {
            int i => i,
            long l => (int)l,
            string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };
    }
}

/// <summary>
/// Detects pending restarts from the registry signals Windows itself uses. Read-only.
/// </summary>
public sealed class RegistryRebootDetector : IRebootDetector
{
    public Task<RebootStatus> DetectAsync(CancellationToken cancellationToken)
    {
        var reasons = new List<string>();
        IReadOnlyList<Guid> updateIds = [];
        var packages = new List<string>();
        IReadOnlyList<PendingFileOperation> fileOperations = [];

        const string WindowsUpdateKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
        if (Reg.KeyExists(WindowsUpdateKey))
        {
            reasons.Add("Windows Update (RebootRequired)");
            updateIds = WindowsRebootSignals.UpdateIds(Reg.GetNames(WindowsUpdateKey));
        }

        const string ServicingRebootKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
        if (Reg.KeyExists(ServicingRebootKey))
        {
            reasons.Add("Component Based Servicing (RebootPending)");
            packages.AddRange(WindowsRebootSignals.Packages(Reg.GetNames(ServicingRebootKey)));
        }

        const string ServicingPackagesKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending";
        if (Reg.KeyExists(ServicingPackagesKey))
        {
            reasons.Add("Component Based Servicing (PackagesPending)");
            packages.AddRange(WindowsRebootSignals.Packages(Reg.GetNames(ServicingPackagesKey)));
        }

        // Only files waiting to be replaced need the restart; files queued for deletion are cleanup (WindowsRebootSignals.NeedRestart).
        if (Reg.GetValue(@"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") is string[] { Length: > 0 } renames &&
            WindowsRebootSignals.FileOperations(renames) is var operations && WindowsRebootSignals.NeedRestart(operations))
        {
            reasons.Add("Pending file rename operations");
            fileOperations = operations;
        }

        if (Reg.GetInt(@"SOFTWARE\Microsoft\Updates", "UpdateExeVolatile") is { } volatileFlag && volatileFlag != 0)
        {
            reasons.Add("Update installer (UpdateExeVolatile)");
        }

        var activeName = Reg.GetString(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName");
        var pendingName = Reg.GetString(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName");
        if (!string.IsNullOrEmpty(activeName) && !string.IsNullOrEmpty(pendingName) &&
            !string.Equals(activeName, pendingName, StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("Pending computer rename");
        }

        if (reasons.Count == 0)
        {
            return Task.FromResult(RebootStatus.None);
        }

        var details = new RebootDetails
        {
            WindowsUpdateIds = updateIds,
            ServicingPackages = packages,
            FileOperations = fileOperations,
            FileOperationCount = fileOperations.Count,
        }.Sanitized();
        return Task.FromResult(new RebootStatus(true, reasons, details.IsEmpty ? null : details));
    }
}

/// <summary>
/// Reports how Windows Update is configured on the endpoint (WSUS, Windows Update for Business, MDM, Automatic
/// Updates mode). Strictly read-only: EasyPatch never changes customer update configuration.
/// </summary>
public sealed class RegistryUpdateSourceDetector : IUpdateSourceDetector
{
    private const string PolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
    private const string AuPolicyPath = PolicyPath + @"\AU";
    private const string MdmPath = @"SOFTWARE\Microsoft\PolicyManager\current\device\Update";

    public UpdateSourceInfo Detect()
    {
        var wsusServer = Reg.GetString(PolicyPath, "WUServer");
        var useWsus = Reg.GetInt(AuPolicyPath, "UseWUServer") == 1 && !string.IsNullOrWhiteSpace(wsusServer);

        var deferQualityDays = Reg.GetInt(PolicyPath, "DeferQualityUpdates") == 1
            ? Reg.GetInt(PolicyPath, "DeferQualityUpdatesPeriodInDays")
            : null;
        var deferFeatureDays = Reg.GetInt(PolicyPath, "DeferFeatureUpdates") == 1
            ? Reg.GetInt(PolicyPath, "DeferFeatureUpdatesPeriodInDays")
            : null;
        var targetRelease = Reg.GetInt(PolicyPath, "TargetReleaseVersion") == 1
            ? Reg.GetString(PolicyPath, "TargetReleaseVersionInfo")
            : null;

        // Intune / MDM-delivered Windows Update for Business policies.
        var mdmQuality = Reg.GetInt(MdmPath, "DeferQualityUpdatesPeriodInDays");
        var mdmFeature = Reg.GetInt(MdmPath, "DeferFeatureUpdatesPeriodInDays");
        var mdmTarget = Reg.GetString(MdmPath, "TargetReleaseVersion");
        bool managedByMdm;
        using (var mdm = Reg.OpenLocalMachine(MdmPath))
        {
            managedByMdm = mdm is not null && mdm.ValueCount > 0;
        }

        deferQualityDays ??= mdmQuality;
        deferFeatureDays ??= mdmFeature;
        targetRelease ??= string.IsNullOrWhiteSpace(mdmTarget) ? null : mdmTarget;

        var wufb = deferQualityDays is not null || deferFeatureDays is not null || targetRelease is not null ||
                   Reg.GetValue(PolicyPath, "BranchReadinessLevel") is not null ||
                   Reg.GetInt(PolicyPath, "DisableDualScan") is not null ||
                   Reg.GetValue(PolicyPath, "PauseQualityUpdatesStartTime") is not null ||
                   managedByMdm;

        return new UpdateSourceInfo
        {
            Type = useWsus ? UpdateSourceType.Wsus : UpdateSourceType.WindowsUpdate,
            WsusServer = useWsus ? wsusServer : null,
            WufbPoliciesConfigured = wufb,
            DeferQualityUpdatesDays = deferQualityDays,
            DeferFeatureUpdatesDays = deferFeatureDays,
            TargetReleaseVersion = targetRelease,
            AutomaticUpdatesMode = DetectAutomaticUpdatesMode(),
            ManagedByMdm = managedByMdm,
        };
    }

    private static string DetectAutomaticUpdatesMode()
    {
        if (Reg.GetInt(AuPolicyPath, "NoAutoUpdate") == 1)
        {
            return "Disabled";
        }

        return Reg.GetInt(AuPolicyPath, "AUOptions") switch
        {
            null => "NotConfigured",
            1 => "Disabled",
            2 => "NotifyDownload",
            3 => "AutoDownloadNotifyInstall",
            4 => "AutoDownloadScheduleInstall",
            5 => "LocalAdminChooses",
            7 => "AutoDownloadNotifyInstallNotifyRestart",
            _ => "Unknown",
        };
    }
}
