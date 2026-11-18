using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace EasyPatch.Contracts.Policy;

// Windows Update settings an administrator can choose to enforce on an endpoint. Each group is either not managed
// (null: EasyPatch leaves Windows' own configuration alone) or managed as a whole. The agent writes the matching
// Group Policy registry values, keeps the computer's original values, and restores them when the group stops being
// managed or the agent is uninstalled. WSUS settings (WUServer, UseWUServer) are never touched.

public enum WindowsUpdatePolicyGroup
{
    AutomaticUpdates,
    FeatureUpdates,
    QualityUpdates,
    RestartBehavior,
}

public enum AutoUpdateMode
{
    /// <summary>Windows does not install updates by itself; only EasyPatch installs them.</summary>
    Disabled,
    NotifyDownload,
    AutoDownloadNotifyInstall,
    AutoDownloadScheduleInstall,
}

public sealed record AutomaticUpdatesSettings
{
    public AutoUpdateMode Mode { get; init; }

    /// <summary>For <see cref="AutoUpdateMode.AutoDownloadScheduleInstall"/>: 0 every day, 1 Sunday … 7 Saturday.</summary>
    public int ScheduledInstallDay { get; init; }

    /// <summary>For <see cref="AutoUpdateMode.AutoDownloadScheduleInstall"/>: hour of day, 0-23.</summary>
    public int ScheduledInstallHour { get; init; } = 3;
}

public sealed record FeatureUpdateSettings
{
    /// <summary>Defer feature updates by this many days (0-365); null = no deferral.</summary>
    public int? DeferDays { get; init; }

    /// <summary>Pin the Windows version: "Windows 10" or "Windows 11". Set together with <see cref="TargetReleaseVersion"/>.</summary>
    public string? TargetProductVersion { get; init; }

    /// <summary>Pin the Windows version, e.g. "24H2".</summary>
    public string? TargetReleaseVersion { get; init; }
}

public sealed record QualityUpdateSettings
{
    /// <summary>Defer quality (monthly) updates by this many days (0-30); null = no deferral.</summary>
    public int? DeferDays { get; init; }

    /// <summary>Remove the user's ability to pause updates in Settings.</summary>
    public bool DisablePause { get; init; }
}

public sealed record RestartBehaviorSettings
{
    /// <summary>Windows does not restart by itself while a user is signed in.</summary>
    public bool NoAutoRestartWithSignedInUsers { get; init; }

    /// <summary>Active hours (0-23), during which Windows does not restart by itself. Both or neither.</summary>
    public int? ActiveHoursStart { get; init; }

    public int? ActiveHoursEnd { get; init; }
}

/// <summary>Effective Windows Update settings for one endpoint. A null group is not managed.</summary>
public sealed record WindowsUpdatePolicySettings
{
    public AutomaticUpdatesSettings? AutomaticUpdates { get; init; }
    public FeatureUpdateSettings? FeatureUpdates { get; init; }
    public QualityUpdateSettings? QualityUpdates { get; init; }
    public RestartBehaviorSettings? RestartBehavior { get; init; }

    public bool IsManaged(WindowsUpdatePolicyGroup group) => group switch
    {
        WindowsUpdatePolicyGroup.AutomaticUpdates => AutomaticUpdates is not null,
        WindowsUpdatePolicyGroup.FeatureUpdates => FeatureUpdates is not null,
        WindowsUpdatePolicyGroup.QualityUpdates => QualityUpdates is not null,
        WindowsUpdatePolicyGroup.RestartBehavior => RestartBehavior is not null,
        _ => false,
    };
}

/// <summary>The two registry keys EasyPatch may write, under HKLM.</summary>
public enum PolicyRegistryKey
{
    /// <summary>SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate</summary>
    WindowsUpdate,
    /// <summary>SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU</summary>
    AutomaticUpdates,
}

/// <summary>A registry value: a DWORD, a string, or absent (both null).</summary>
public sealed record PolicyRegistryValue(PolicyRegistryKey Key, string Name, int? DWord = null, string? Text = null)
{
    public bool IsAbsent => DWord is null && Text is null;

    public string Path => WindowsUpdatePolicyRegistry.KeyPath(Key);

    public string Display => IsAbsent ? "(not set)" : DWord is { } d ? d.ToString(CultureInfo.InvariantCulture) : $"\"{Text}\"";
}

public static partial class WindowsUpdatePolicyRegistry
{
    public const string WindowsUpdateKeyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
    public const string AutomaticUpdatesKeyPath = WindowsUpdateKeyPath + @"\AU";

    public static IReadOnlyList<string> ProductVersions { get; } = ["Windows 10", "Windows 11"];

    public static string KeyPath(PolicyRegistryKey key) => key == PolicyRegistryKey.AutomaticUpdates ? AutomaticUpdatesKeyPath : WindowsUpdateKeyPath;

    private static readonly Dictionary<WindowsUpdatePolicyGroup, (PolicyRegistryKey Key, string Name)[]> Owned = new()
    {
        [WindowsUpdatePolicyGroup.AutomaticUpdates] =
        [
            (PolicyRegistryKey.AutomaticUpdates, "NoAutoUpdate"),
            (PolicyRegistryKey.AutomaticUpdates, "AUOptions"),
            (PolicyRegistryKey.AutomaticUpdates, "ScheduledInstallDay"),
            (PolicyRegistryKey.AutomaticUpdates, "ScheduledInstallTime"),
        ],
        [WindowsUpdatePolicyGroup.FeatureUpdates] =
        [
            (PolicyRegistryKey.WindowsUpdate, "DeferFeatureUpdates"),
            (PolicyRegistryKey.WindowsUpdate, "DeferFeatureUpdatesPeriodInDays"),
            (PolicyRegistryKey.WindowsUpdate, "TargetReleaseVersion"),
            (PolicyRegistryKey.WindowsUpdate, "ProductVersion"),
            (PolicyRegistryKey.WindowsUpdate, "TargetReleaseVersionInfo"),
        ],
        [WindowsUpdatePolicyGroup.QualityUpdates] =
        [
            (PolicyRegistryKey.WindowsUpdate, "DeferQualityUpdates"),
            (PolicyRegistryKey.WindowsUpdate, "DeferQualityUpdatesPeriodInDays"),
            (PolicyRegistryKey.WindowsUpdate, "SetDisablePauseUXAccess"),
        ],
        [WindowsUpdatePolicyGroup.RestartBehavior] =
        [
            (PolicyRegistryKey.AutomaticUpdates, "NoAutoRebootWithLoggedOnUsers"),
            (PolicyRegistryKey.WindowsUpdate, "SetActiveHours"),
            (PolicyRegistryKey.WindowsUpdate, "ActiveHoursStart"),
            (PolicyRegistryKey.WindowsUpdate, "ActiveHoursEnd"),
        ],
    };

    /// <summary>Every registry value a group owns. Managing a group means EasyPatch decides all of them.</summary>
    public static IReadOnlyList<(PolicyRegistryKey Key, string Name)> OwnedValues(WindowsUpdatePolicyGroup group) => Owned[group];

    /// <summary>The desired state of every value the group owns (absent values are deleted). Null when the group is not managed.</summary>
    public static IReadOnlyList<PolicyRegistryValue>? DesiredValues(WindowsUpdatePolicySettings settings, WindowsUpdatePolicyGroup group)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var set = new Dictionary<string, PolicyRegistryValue>(StringComparer.OrdinalIgnoreCase);
        void Put(PolicyRegistryKey key, string name, int? dword = null, string? text = null) => set[name] = new PolicyRegistryValue(key, name, dword, text);

        switch (group)
        {
            case WindowsUpdatePolicyGroup.AutomaticUpdates when settings.AutomaticUpdates is { } au:
                Put(PolicyRegistryKey.AutomaticUpdates, "NoAutoUpdate", au.Mode == AutoUpdateMode.Disabled ? 1 : 0);
                if (au.Mode != AutoUpdateMode.Disabled)
                {
                    Put(PolicyRegistryKey.AutomaticUpdates, "AUOptions", au.Mode switch
                    {
                        AutoUpdateMode.NotifyDownload => 2,
                        AutoUpdateMode.AutoDownloadNotifyInstall => 3,
                        _ => 4,
                    });
                }

                if (au.Mode == AutoUpdateMode.AutoDownloadScheduleInstall)
                {
                    Put(PolicyRegistryKey.AutomaticUpdates, "ScheduledInstallDay", au.ScheduledInstallDay);
                    Put(PolicyRegistryKey.AutomaticUpdates, "ScheduledInstallTime", au.ScheduledInstallHour);
                }

                break;
            case WindowsUpdatePolicyGroup.FeatureUpdates when settings.FeatureUpdates is { } fu:
                if (fu.DeferDays is { } featureDays)
                {
                    Put(PolicyRegistryKey.WindowsUpdate, "DeferFeatureUpdates", 1);
                    Put(PolicyRegistryKey.WindowsUpdate, "DeferFeatureUpdatesPeriodInDays", featureDays);
                }

                if (!string.IsNullOrEmpty(fu.TargetReleaseVersion) && !string.IsNullOrEmpty(fu.TargetProductVersion))
                {
                    Put(PolicyRegistryKey.WindowsUpdate, "TargetReleaseVersion", 1);
                    Put(PolicyRegistryKey.WindowsUpdate, "ProductVersion", text: fu.TargetProductVersion);
                    Put(PolicyRegistryKey.WindowsUpdate, "TargetReleaseVersionInfo", text: fu.TargetReleaseVersion.ToUpperInvariant());
                }

                break;
            case WindowsUpdatePolicyGroup.QualityUpdates when settings.QualityUpdates is { } qu:
                if (qu.DeferDays is { } qualityDays)
                {
                    Put(PolicyRegistryKey.WindowsUpdate, "DeferQualityUpdates", 1);
                    Put(PolicyRegistryKey.WindowsUpdate, "DeferQualityUpdatesPeriodInDays", qualityDays);
                }

                if (qu.DisablePause)
                {
                    Put(PolicyRegistryKey.WindowsUpdate, "SetDisablePauseUXAccess", 1);
                }

                break;
            case WindowsUpdatePolicyGroup.RestartBehavior when settings.RestartBehavior is { } rb:
                if (rb.NoAutoRestartWithSignedInUsers)
                {
                    Put(PolicyRegistryKey.AutomaticUpdates, "NoAutoRebootWithLoggedOnUsers", 1);
                }

                if (rb is { ActiveHoursStart: { } start, ActiveHoursEnd: { } end })
                {
                    Put(PolicyRegistryKey.WindowsUpdate, "SetActiveHours", 1);
                    Put(PolicyRegistryKey.WindowsUpdate, "ActiveHoursStart", start);
                    Put(PolicyRegistryKey.WindowsUpdate, "ActiveHoursEnd", end);
                }

                break;
            default:
                return null;
        }

        return Owned[group].Select(o => set.TryGetValue(o.Name, out var v) ? v : new PolicyRegistryValue(o.Key, o.Name)).ToList();
    }

    public static IReadOnlyList<string> Validate(WindowsUpdatePolicySettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var errors = new List<string>();
        if (settings.AutomaticUpdates is { } au)
        {
            if (!Enum.IsDefined(au.Mode))
            {
                errors.Add("Unknown Automatic Updates mode.");
            }

            if (au.ScheduledInstallDay is < 0 or > 7)
            {
                errors.Add("The scheduled install day must be 0 (every day) or 1-7 (Sunday-Saturday).");
            }

            if (au.ScheduledInstallHour is < 0 or > 23)
            {
                errors.Add("The scheduled install hour must be between 0 and 23.");
            }
        }

        if (settings.FeatureUpdates is { } fu)
        {
            if (fu.DeferDays is < 0 or > 365)
            {
                errors.Add("Feature updates can be deferred by 0-365 days.");
            }

            var hasProduct = !string.IsNullOrEmpty(fu.TargetProductVersion);
            var hasRelease = !string.IsNullOrEmpty(fu.TargetReleaseVersion);
            if (hasProduct != hasRelease)
            {
                errors.Add("To pin the Windows version, set both the product (Windows 10 or Windows 11) and the version (for example 24H2).");
            }
            else if (hasProduct)
            {
                if (!ProductVersions.Contains(fu.TargetProductVersion!, StringComparer.Ordinal))
                {
                    errors.Add("The pinned product must be \"Windows 10\" or \"Windows 11\".");
                }

                if (!ReleaseVersionPattern().IsMatch(fu.TargetReleaseVersion!))
                {
                    errors.Add("The pinned version must look like 24H2.");
                }
            }
        }

        if (settings.QualityUpdates is { DeferDays: < 0 or > 30 })
        {
            errors.Add("Quality updates can be deferred by 0-30 days.");
        }

        if (settings.RestartBehavior is { } rb)
        {
            if (rb.ActiveHoursStart.HasValue != rb.ActiveHoursEnd.HasValue)
            {
                errors.Add("Set both the start and the end of active hours.");
            }
            else if (rb is { ActiveHoursStart: { } start, ActiveHoursEnd: { } end })
            {
                if (start is < 0 or > 23 || end is < 0 or > 23)
                {
                    errors.Add("Active hours must be between 0 and 23.");
                }
                else if (start == end || (end - start + 24) % 24 > 18)
                {
                    errors.Add("Active hours must span 1 to 18 hours.");
                }
            }
        }

        return errors;
    }

    [GeneratedRegex("^[0-9]{2}H[12]$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ReleaseVersionPattern();
}

public enum WindowsUpdatePolicyState
{
    NotManaged,
    Applied,
    /// <summary>Another policy source (domain Group Policy, MDM) changed a value EasyPatch set. EasyPatch stops re-applying it.</summary>
    Conflict,
    Error,
}

public sealed record WindowsUpdatePolicyGroupStatus
{
    public required WindowsUpdatePolicyGroup Group { get; init; }
    public required WindowsUpdatePolicyState State { get; init; }
    public string? Message { get; init; }
    public DateTimeOffset? AppliedAt { get; init; }

    /// <summary>Values changed by another policy source (for <see cref="WindowsUpdatePolicyState.Conflict"/>).</summary>
    public IReadOnlyList<string> ConflictingValues { get; init; } = [];
}

/// <summary>Sent in a check-in when the enforcement status changes.</summary>
public sealed record WindowsUpdatePolicyReport
{
    public IReadOnlyList<WindowsUpdatePolicyGroupStatus> Groups { get; init; } = [];

    /// <summary>MDM (Intune) Update policies are present; Windows may give them precedence over Group Policy values.</summary>
    public bool MdmUpdatePoliciesPresent { get; init; }

    /// <summary>Stable digest of the content, used to send the report only when it changes.</summary>
    public string ComputeHash()
    {
        var sb = new StringBuilder();
        sb.Append(MdmUpdatePoliciesPresent ? '1' : '0');
        foreach (var g in Groups.OrderBy(g => g.Group))
        {
            sb.Append('|').Append(g.Group).Append(':').Append(g.State).Append(':').Append(g.Message)
              .Append(':').Append(string.Join(',', g.ConflictingValues));
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())))[..32];
    }
}
