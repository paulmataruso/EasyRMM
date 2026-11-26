using System.Text.Json;
using System.Text.Json.Serialization;

namespace EasyPatch.Agent.Core.Defender;

/// <summary>The four kinds of Microsoft Defender exclusion (ADR-0070, section 3). The names are the ones of the EasyRMM agent's record
/// and report, so both agents write the same format.</summary>
public static class DefenderKinds
{
    /// <summary><c>ExclusionPath</c>: a whole folder.</summary>
    public const string Path = "path";

    /// <summary><c>ExclusionProcess</c>: the full path of an executable.</summary>
    public const string Process = "process";

    /// <summary><c>AttackSurfaceReductionOnlyExclusions</c>: a folder.</summary>
    public const string Asr = "asr";

    /// <summary><c>ControlledFolderAccessAllowedApplications</c>: the full path of an executable.</summary>
    public const string Cfa = "cfa";

    public static readonly IReadOnlyList<string> All = [Path, Process, Asr, Cfa];

    /// <summary>The parameter of <c>Add-MpPreference</c> and <c>Remove-MpPreference</c> for a kind, null for an unknown kind.</summary>
    public static string? Parameter(string kind) => kind switch
    {
        Path => "ExclusionPath",
        Process => "ExclusionProcess",
        Asr => "AttackSurfaceReductionOnlyExclusions",
        Cfa => "ControlledFolderAccessAllowedApplications",
        _ => null,
    };
}

/// <summary>One exclusion the agent added: the kind, the path, when, and by which agent version.</summary>
public sealed class DefenderEntry
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    [JsonPropertyName("at")]
    public DateTimeOffset At { get; set; }

    [JsonPropertyName("agentVersion")]
    public string AgentVersion { get; set; } = "";
}

/// <summary>
/// Exactly what the agent added to Defender's lists, in <c>state\defender-exclusions.json</c> of the data folder (ADR-0070, section 4).
/// The same format as the EasyRMM agent's record: <c>{"version":1,"entries":[{"kind","path","at","agentVersion"}]}</c>.
/// </summary>
public sealed class DefenderRecord
{
    public const string FileName = "defender-exclusions.json";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("entries")]
    public List<DefenderEntry> Entries { get; set; } = [];

    /// <summary>The form in which paths are compared: slashes as backslashes, no trailing separator (except on a root), lower case.</summary>
    public static string Normalize(string path)
    {
        var p = path.Trim().Replace('/', '\\');
        while (p.Length > 3 && p.EndsWith('\\'))
        {
            p = p[..^1];
        }

        return p.ToLowerInvariant();
    }

    public bool Has(string kind, string path) => IndexOf(kind, path) >= 0;

    public void Put(DefenderEntry entry)
    {
        if (!Has(entry.Kind, entry.Path))
        {
            Entries.Add(entry);
        }
    }

    public void Drop(string kind, string path)
    {
        if (IndexOf(kind, path) is var i and >= 0)
        {
            Entries.RemoveAt(i);
        }
    }

    private int IndexOf(string kind, string path) =>
        Entries.FindIndex(e => e.Kind == kind && Normalize(e.Path) == Normalize(path));

    /// <summary>Reads the record. <paramref name="found"/> is false when there is none; a file that is not a record is
    /// <paramref name="corrupt"/>, and the record returned is then empty.</summary>
    public static DefenderRecord Load(string file, out bool found, out bool corrupt)
    {
        found = false;
        corrupt = false;
        if (!File.Exists(file))
        {
            return new DefenderRecord();
        }

        found = true;
        try
        {
            var record = JsonSerializer.Deserialize<DefenderRecord>(File.ReadAllText(file));
            if (record is { Version: 1, Entries: not null } && record.Entries.TrueForAll(e => DefenderKinds.Parameter(e.Kind) is not null && e.Path.Length > 0))
            {
                return record;
            }
        }
        catch (JsonException)
        {
        }

        corrupt = true;
        return new DefenderRecord();
    }

    /// <summary>Writes the record, replacing the file whole.</summary>
    public void Save(string file)
    {
        Version = 1;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(file))!);
        var temporary = file + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, Json));
        File.Move(temporary, file, overwrite: true);
    }
}
