using System.Text.Json.Serialization;

namespace EasyPatch.Agent.Core.Defender;

/// <summary>What Defender says of itself: its settings and its status (ADR-0070, section 5).</summary>
public sealed class DefenderPrefs
{
    /// <summary>Defender's PowerShell module is not on this computer (a Windows Server installed without Defender).</summary>
    public bool Missing { get; init; }

    /// <summary>Defender's own "N/A: ..." text in place of a list: it hides what it will not show. Never a guess from an empty list.</summary>
    public string? NotAvailable { get; init; }

    /// <summary>The four lists, by kind.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Lists { get; init; } = new Dictionary<string, IReadOnlyList<string>>();

    /// <summary><c>DisableLocalAdminMerge</c>: local exclusions are ignored in favour of the policy's (Intune, Group Policy, Configuration Manager).</summary>
    public bool DisableLocalAdminMerge { get; init; }

    /// <summary>Controlled Folder Access is on or only auditing.</summary>
    public bool ControlledFolderAccessOn { get; init; }

    /// <summary>The number of Attack Surface Reduction rules that are set.</summary>
    public int AsrRules { get; init; }

    /// <summary><c>AMRunningMode</c>: Normal, Passive, SxS Passive Mode, EDR Block Mode.</summary>
    public string RunningMode { get; init; } = "";

    public bool AntivirusOn { get; init; }

    public bool ServiceOn { get; init; }

    public bool RealTimeOn { get; init; }

    public bool TamperProtected { get; init; }

    public bool Listed(string kind, string path) =>
        Lists.TryGetValue(kind, out var list) && list.Any(e => DefenderRecord.Normalize(e) == DefenderRecord.Normalize(path));
}

/// <summary>Defender said no (Tamper Protection, a policy).</summary>
public sealed class DefenderRefusedException(string reason) : Exception(reason);

/// <summary>Reads and changes Defender's lists. Add and Remove throw <see cref="DefenderRefusedException"/> for Defender's own refusal.</summary>
public interface IDefenderBackend
{
    /// <summary>"powershell" or "wmi": which one the last call used.</summary>
    string Method { get; }

    Task<DefenderPrefs> ReadAsync(CancellationToken cancellationToken);

    Task AddAsync(string kind, string path, CancellationToken cancellationToken);

    Task RemoveAsync(string kind, string path, CancellationToken cancellationToken);
}

/// <summary>What the machine does to a folder (ADR-0070, section 2): lock it down to SYSTEM and Administrators, and verify that it, what
/// is above it and everything in it are administrators-only.</summary>
public interface IFolderGuard
{
    /// <summary>Creates the folder if it is missing, locks it down and verifies it; the reason it cannot be trusted, null when it can.</summary>
    string? Secure(string folder);

    /// <summary>Verifies only; changes nothing.</summary>
    string? Check(string folder);
}

public static class DefenderStates
{
    public const string Effective = "effective";
    public const string PresentNotEffective = "present_not_effective";
    public const string NotLocked = "not_locked";
    public const string Refused = "refused";
    public const string Unavailable = "unavailable";
    public const string NotApplicable = "not_applicable";

    /// <summary>For a kind only: Controlled Folder Access or Attack Surface Reduction is off, so there is nothing to allow.</summary>
    public const string NotNeeded = "not_needed";
}

public sealed record DefenderFolderReport(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("listed")] bool Listed,
    [property: JsonPropertyName("ours")] bool Ours,
    [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason);

public sealed record DefenderKindReport(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason);

/// <summary>The state of the agent's Defender exclusions: the shape of the EasyRMM agent's report, so the console shows both alike.</summary>
public sealed record DefenderReport(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason,
    [property: JsonPropertyName("kinds")] IReadOnlyList<DefenderKindReport> Kinds,
    [property: JsonPropertyName("folders")] IReadOnlyList<DefenderFolderReport> Folders,
    [property: JsonPropertyName("method"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Method,
    [property: JsonPropertyName("agentVersion")] string AgentVersion);

/// <summary>The fixed set the agent excludes: whole folders (as paths and as Attack Surface Reduction exclusions) and the full path of
/// each executable (as a process and as a Controlled Folder Access application). Every path is fixed in the agent's code.</summary>
public sealed class DefenderExclusionsOptions
{
    public required IReadOnlyList<string> Folders { get; init; }

    public required IReadOnlyList<string> Programs { get; init; }

    public required string RecordFile { get; init; }

    public required string AgentVersion { get; init; }
}

public sealed record DefenderRemoveResult(IReadOnlyList<string> Removed, IReadOnlyList<string> Left, bool RecordDeleted);
