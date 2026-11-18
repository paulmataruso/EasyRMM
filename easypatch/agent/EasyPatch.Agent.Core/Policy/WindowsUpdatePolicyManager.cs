using System.Security;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts.Policy;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Policy;

/// <summary>
/// Enforces the Windows Update settings an administrator configured in EasyPatch policy, one settings group at a time.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Only the values listed in <see cref="WindowsUpdatePolicyRegistry"/> are ever written; WSUS settings
/// (WUServer, UseWUServer) are never touched.</item>
/// <item>Before a group is first changed, its original values are saved; they are put back when the group is no
/// longer managed, the agent is unenrolled or its credential is revoked.</item>
/// <item>If another policy source (for example domain Group Policy or a script) changes a value EasyPatch set, the
/// group is reported as a conflict and EasyPatch stops re-applying it until the administrator changes the settings,
/// so the two never fight over the registry.</item>
/// </list>
/// </remarks>
public sealed class WindowsUpdatePolicyManager
{
    /// <summary>The status is re-sent at least this often even when unchanged.</summary>
    public static readonly TimeSpan ReportRefreshInterval = TimeSpan.FromHours(24);

    private const string ConflictMessage =
        "Another policy source (for example domain Group Policy) changed values EasyPatch set. EasyPatch stopped re-applying this group; " +
        "remove the other policy or change the EasyPatch setting to apply it again.";

    private readonly IPolicyRegistry _registry;
    private readonly AgentStateStore _state;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Dictionary<WindowsUpdatePolicyGroup, string> _transientErrors = [];

    public WindowsUpdatePolicyManager(IPolicyRegistry registry, AgentStateStore state, TimeProvider time, ILogger<WindowsUpdatePolicyManager> logger)
    {
        _registry = registry;
        _state = state;
        _time = time;
        _logger = logger;
    }

    /// <summary>Applies the effective settings (null: manage nothing, restoring anything EasyPatch changed).</summary>
    public void Apply(WindowsUpdatePolicySettings? settings)
    {
        foreach (var group in Enum.GetValues<WindowsUpdatePolicyGroup>())
        {
            var desired = settings is null ? null : WindowsUpdatePolicyRegistry.DesiredValues(settings, group);
            ApplyGroup(group, desired);
        }
    }

    /// <summary>Restores every managed group (uninstall, revocation).</summary>
    public void RestoreAll() => Apply(null);

    public WindowsUpdatePolicyReport BuildReport()
    {
        var groups = _state.Read(s => s.WindowsUpdatePolicy.Groups.ToDictionary(g => g.Key, g => new WindowsUpdatePolicyGroupStatus
        {
            Group = g.Key,
            State = g.Value.State,
            Message = g.Value.Message,
            AppliedAt = g.Value.AppliedAt,
            ConflictingValues = g.Value.ConflictingValues.ToList(),
        }));

        var mdm = false;
        try
        {
            mdm = _registry.MdmUpdatePoliciesPresent();
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            _logger.LogDebug(ex, "Could not check for MDM update policies.");
        }

        return new WindowsUpdatePolicyReport
        {
            Groups = Enum.GetValues<WindowsUpdatePolicyGroup>().Select(group =>
                groups.TryGetValue(group, out var status) ? status
                : _transientErrors.TryGetValue(group, out var error) ? new WindowsUpdatePolicyGroupStatus { Group = group, State = WindowsUpdatePolicyState.Error, Message = error }
                : new WindowsUpdatePolicyGroupStatus { Group = group, State = WindowsUpdatePolicyState.NotManaged }).ToList(),
            MdmUpdatePoliciesPresent = mdm,
        };
    }

    /// <summary>The report to include in the next check-in: only when it changed or is due for a refresh.</summary>
    public WindowsUpdatePolicyReport? PendingReport()
    {
        var report = BuildReport();
        var (hash, at) = _state.Read(s => (s.WindowsUpdatePolicy.LastReportedHash, s.WindowsUpdatePolicy.LastReportedAt));
        return hash != report.ComputeHash() || at is not { } last || _time.GetUtcNow() - last >= ReportRefreshInterval ? report : null;
    }

    /// <summary>Records that the server accepted <paramref name="report"/>.</summary>
    public void MarkReported(WindowsUpdatePolicyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var hash = report.ComputeHash();
        var now = _time.GetUtcNow();
        _state.Update(s =>
        {
            s.WindowsUpdatePolicy.LastReportedHash = hash;
            s.WindowsUpdatePolicy.LastReportedAt = now;
        });
    }

    private void ApplyGroup(WindowsUpdatePolicyGroup group, IReadOnlyList<PolicyRegistryValue>? desired)
    {
        var entry = _state.Read(s => s.WindowsUpdatePolicy.Groups.TryGetValue(group, out var g) ? Copy(g) : null);
        var now = _time.GetUtcNow();
        try
        {
            if (desired is null)
            {
                if (entry is not null)
                {
                    Restore(group, entry);
                    _state.Update(s => s.WindowsUpdatePolicy.Groups.Remove(group));
                    _logger.LogInformation(AgentEventIds.WindowsUpdatePolicyChanged,
                        "Windows Update {Group} settings are no longer managed by EasyPatch; the original values were restored.", group);
                }

                _transientErrors.Remove(group);
                return;
            }

            if (entry is null)
            {
                // Save the original values before changing anything, so a crash part-way cannot lose them.
                entry = new ManagedPolicyGroup
                {
                    Original = WindowsUpdatePolicyRegistry.OwnedValues(group).Select(o => _registry.Read(o.Key, o.Name)).ToList(),
                };
                var saved = entry;
                _state.Update(s => s.WindowsUpdatePolicy.Groups[group] = saved);
                Write(group, desired, now, "applied");
                return;
            }

            if (!SameValues(entry.Applied, desired))
            {
                // The administrator changed the settings: apply them (this also ends a conflict).
                Write(group, desired, now, "updated");
                return;
            }

            if (entry.State == WindowsUpdatePolicyState.Conflict)
            {
                return; // stays until the settings change
            }

            var drift = desired
                .Select(v => (Desired: v, Actual: _registry.Read(v.Key, v.Name)))
                .Where(x => !Same(x.Desired, x.Actual))
                .ToList();
            if (drift.Count == 0)
            {
                if (entry.State == WindowsUpdatePolicyState.Error)
                {
                    Write(group, desired, now, "applied");
                }

                _transientErrors.Remove(group);
                return;
            }

            if (entry.State == WindowsUpdatePolicyState.Error)
            {
                Write(group, desired, now, "applied"); // a previous write failed part-way: finish it
                return;
            }

            var conflicting = drift.Select(x => $"{x.Desired.Name} = {x.Actual.Display} (EasyPatch: {x.Desired.Display})").ToList();
            Update(group, g =>
            {
                g.State = WindowsUpdatePolicyState.Conflict;
                g.Message = ConflictMessage;
                g.ConflictingValues = conflicting;
            });
            _logger.LogWarning(AgentEventIds.WindowsUpdatePolicyConflict,
                "Windows Update {Group} settings were changed by another policy source ({Values}). EasyPatch stopped re-applying them.",
                group, string.Join("; ", conflicting));
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            _logger.LogError(ex, "Could not apply Windows Update {Group} settings.", group);
            var message = $"Could not change the Windows Update settings: {ex.Message}";
            if (_state.Read(s => s.WindowsUpdatePolicy.Groups.ContainsKey(group)))
            {
                Update(group, g =>
                {
                    g.State = WindowsUpdatePolicyState.Error;
                    g.Message = message;
                });
            }
            else
            {
                _transientErrors[group] = message;
            }
        }
    }

    private void Write(WindowsUpdatePolicyGroup group, IReadOnlyList<PolicyRegistryValue> desired, DateTimeOffset now, string verb)
    {
        foreach (var value in desired)
        {
            if (!Same(_registry.Read(value.Key, value.Name), value))
            {
                _registry.Write(value);
            }
        }

        Update(group, g =>
        {
            g.Applied = desired.ToList();
            g.State = WindowsUpdatePolicyState.Applied;
            g.Message = null;
            g.AppliedAt = now;
            g.ConflictingValues = [];
        });
        _transientErrors.Remove(group);
        _logger.LogInformation(AgentEventIds.WindowsUpdatePolicyChanged, "Windows Update {Group} settings {Verb}: {Values}.", group, verb,
            string.Join(", ", desired.Select(v => $"{v.Name}={v.Display}")));
    }

    private void Restore(WindowsUpdatePolicyGroup group, ManagedPolicyGroup entry)
    {
        foreach (var original in entry.Original)
        {
            var applied = entry.Applied.Find(a => string.Equals(a.Name, original.Name, StringComparison.OrdinalIgnoreCase));
            var actual = _registry.Read(original.Key, original.Name);

            // Put back only what still holds EasyPatch's value; anything another source changed since is left alone.
            if (entry.Applied.Count == 0 || applied is null || Same(actual, applied))
            {
                if (!Same(actual, original))
                {
                    _registry.Write(original);
                }
            }
            else
            {
                _logger.LogInformation("Windows Update {Group}: {Name} was changed by another policy source and is left as it is.", group, original.Name);
            }
        }
    }

    private void Update(WindowsUpdatePolicyGroup group, Action<ManagedPolicyGroup> change) => _state.Update(s =>
    {
        if (s.WindowsUpdatePolicy.Groups.TryGetValue(group, out var g))
        {
            change(g);
        }
    });

    private static bool Same(PolicyRegistryValue a, PolicyRegistryValue b) => a.DWord == b.DWord && string.Equals(a.Text, b.Text, StringComparison.Ordinal);

    private static bool SameValues(IReadOnlyList<PolicyRegistryValue> a, IReadOnlyList<PolicyRegistryValue> b) =>
        a.Count == b.Count && a.All(x => b.Any(y => y.Key == x.Key && string.Equals(y.Name, x.Name, StringComparison.OrdinalIgnoreCase) && Same(x, y)));

    private static bool IsRegistryFailure(Exception ex) => ex is UnauthorizedAccessException or IOException or SecurityException or InvalidOperationException;

    private static ManagedPolicyGroup Copy(ManagedPolicyGroup g) => new()
    {
        Original = g.Original.ToList(),
        Applied = g.Applied.ToList(),
        State = g.State,
        Message = g.Message,
        AppliedAt = g.AppliedAt,
        ConflictingValues = g.ConflictingValues.ToList(),
    };
}
