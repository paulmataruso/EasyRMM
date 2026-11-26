using System.Text.Json;
using System.Text.RegularExpressions;

namespace EasyPatch.Agent.Core.Defender;

/// <summary>The fixed PowerShell texts that drive Defender's module, and how their answers are read (ADR-0070, section 4). The text is
/// fixed and built from no input: a path travels in an environment variable, never in the script.</summary>
public static partial class DefenderScripts
{
    private static readonly JsonSerializerOptions ReadOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>The environment variable that carries the path to a script.</summary>
    public const string PathVariable = "EASYPATCH_DEFENDER_PATH";

    /// <summary>Prints Defender's preference and status as one line of JSON.</summary>
    public const string ReadScript = """
        $ErrorActionPreference = 'Stop'
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { '{"missing":true}'; exit 0 }
        $p = Get-MpPreference
        $s = Get-MpComputerStatus
        [pscustomobject]@{
          missing = $false
          path = @($p.ExclusionPath | ForEach-Object { [string]$_ })
          process = @($p.ExclusionProcess | ForEach-Object { [string]$_ })
          asr = @($p.AttackSurfaceReductionOnlyExclusions | ForEach-Object { [string]$_ })
          cfa = @($p.ControlledFolderAccessAllowedApplications | ForEach-Object { [string]$_ })
          disableLocalAdminMerge = [bool]$p.DisableLocalAdminMerge
          cfaMode = [int]$p.EnableControlledFolderAccess
          asrRules = @($p.AttackSurfaceReductionRules_Ids).Count
          runningMode = [string]$s.AMRunningMode
          antivirusEnabled = [bool]$s.AntivirusEnabled
          serviceEnabled = [bool]$s.AMServiceEnabled
          realTimeEnabled = [bool]$s.RealTimeProtectionEnabled
          tamperProtected = [bool]$s.IsTamperProtected
        } | ConvertTo-Json -Compress
        """;

    /// <summary><c>Add-MpPreference</c> or <c>Remove-MpPreference</c> for one kind; null for an unknown kind.</summary>
    public static string? ChangeScript(string verb, string kind) =>
        DefenderKinds.Parameter(kind) is { } parameter && verb is "Add" or "Remove"
            ? $"$ErrorActionPreference = 'Stop'; {verb}-MpPreference -{parameter} $env:{PathVariable}"
            : null;

    /// <summary>The same change by the <c>MSFT_MpPreference</c> class, used once when the module cannot be used.</summary>
    public static string? WmiScript(string verb, string kind) =>
        DefenderKinds.Parameter(kind) is { } parameter && verb is "Add" or "Remove"
            ? $"$ErrorActionPreference = 'Stop'; $r = Invoke-CimMethod -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference -MethodName {verb} -Arguments @{{{parameter} = [string[]]@($env:{PathVariable})}}; if ($r -and $r.ReturnValue) {{ exit 1 }}"
            : null;

    /// <summary>Whether a cmdlet's error is Defender refusing (Tamper Protection, a policy) rather than the module failing.</summary>
    public static bool IsRefusal(string output) => RefusalPattern().IsMatch(output);

    [GeneratedRegex("access is denied|0x800106ba|tamper|0x80070005|managed by|group policy|blocked by", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RefusalPattern();

    /// <summary>Reads <see cref="ReadScript"/>'s output (its last line).</summary>
    public static DefenderPrefs ParsePrefs(string output)
    {
        var text = output.Trim();
        var line = text[(text.LastIndexOf('\n') + 1)..].Trim();
        ReadOut? read;
        try
        {
            read = JsonSerializer.Deserialize<ReadOut>(line, ReadOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The answer of Defender cannot be read: {ex.Message}", ex);
        }

        if (read is null)
        {
            throw new InvalidDataException("The answer of Defender is empty.");
        }

        if (read.Missing)
        {
            return new DefenderPrefs { Missing = true };
        }

        var lists = new Dictionary<string, IReadOnlyList<string>>
        {
            [DefenderKinds.Path] = read.Path ?? [],
            [DefenderKinds.Process] = read.Process ?? [],
            [DefenderKinds.Asr] = read.Asr ?? [],
            [DefenderKinds.Cfa] = read.Cfa ?? [],
        };

        // Defender hides what it will not show behind text such as "N/A: Must be an administrator or have Tamper Protection ...".
        var hidden = lists.Values.SelectMany(l => l).FirstOrDefault(e => e.TrimStart().StartsWith("N/A:", StringComparison.Ordinal));
        return new DefenderPrefs
        {
            Lists = lists,
            NotAvailable = hidden?.Trim(),
            DisableLocalAdminMerge = read.DisableLocalAdminMerge,
            ControlledFolderAccessOn = read.CfaMode is 1 or 2,
            AsrRules = read.AsrRules,
            RunningMode = read.RunningMode ?? "",
            AntivirusOn = read.AntivirusEnabled,
            ServiceOn = read.ServiceEnabled,
            RealTimeOn = read.RealTimeEnabled,
            TamperProtected = read.TamperProtected,
        };
    }

    private sealed class ReadOut
    {
        public bool Missing { get; set; }

        public List<string>? Path { get; set; }

        public List<string>? Process { get; set; }

        public List<string>? Asr { get; set; }

        public List<string>? Cfa { get; set; }

        public bool DisableLocalAdminMerge { get; set; }

        public int CfaMode { get; set; }

        public int AsrRules { get; set; }

        public string? RunningMode { get; set; }

        public bool AntivirusEnabled { get; set; }

        public bool ServiceEnabled { get; set; }

        public bool RealTimeEnabled { get; set; }

        public bool TamperProtected { get; set; }
    }
}
