using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace EasyPatch.MacOS.Platform;

/// <summary>The macOS release and hardware family, read once when the agent starts.</summary>
/// <param name="ProductVersion"><c>sw_vers -productVersion</c>, e.g. <c>15.7.2</c>.</param>
/// <param name="BuildVersion"><c>sw_vers -buildVersion</c>, e.g. <c>24G325</c>.</param>
/// <param name="AppleSilicon"><c>sysctl hw.optional.arm64</c> is 1 (also true for an Intel build of the agent running under Rosetta).</param>
public sealed partial record MacSystemInfo(string ProductVersion, string? BuildVersion, bool AppleSilicon)
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public int Major => int.TryParse(ProductVersion.Split('.')[0], NumberStyles.None, CultureInfo.InvariantCulture, out var major) ? major : 0;

    /// <summary>e.g. <c>macOS Sequoia 15.7.2</c>.</summary>
    public string Caption => MarketingName(Major) is { } name ? $"macOS {name} {ProductVersion}" : $"macOS {ProductVersion}";

    public static string? MarketingName(int major) => major switch
    {
        12 => "Monterey",
        13 => "Ventura",
        14 => "Sonoma",
        15 => "Sequoia",
        26 => "Tahoe",
        _ => null,
    };

    public static MacSystemInfo Read(ICommandRunner commands)
    {
        ArgumentNullException.ThrowIfNull(commands);
        var version = Run(commands, "sw_vers", ["-productVersion"]);
        if (string.IsNullOrWhiteSpace(version) || !VersionRegex().IsMatch(version))
        {
            throw new PlatformNotSupportedException("sw_vers did not report a macOS version.");
        }

        var build = Run(commands, "sw_vers", ["-buildVersion"]);
        var arm64 = Run(commands, "sysctl", ["-n", "hw.optional.arm64"]);
        return new MacSystemInfo(version, string.IsNullOrWhiteSpace(build) ? null : build, arm64 == "1");
    }

    /// <summary>Standard output of a system program, trimmed; null when it fails.</summary>
    internal static string? Run(ICommandRunner commands, string program, IReadOnlyList<string> arguments)
    {
        try
        {
            var result = commands.RunAsync(program, arguments, Timeout, CancellationToken.None).GetAwaiter().GetResult();
            return result.Succeeded ? result.StandardOutput.Trim() : null;
        }
        catch (CommandException)
        {
            return null;
        }
    }

    /// <summary><c>sysctl -n kern.boottime</c>: <c>{ sec = 1731700000, usec = 123456 } Sat Nov 16 04:00:00 2024</c>.</summary>
    public static DateTimeOffset? ParseBootTime(string? text)
    {
        var match = BootTimeRegex().Match(text ?? string.Empty);
        return match.Success && long.TryParse(match.Groups["sec"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    /// <summary>The processor's name: <c>sysctl -n machdep.cpu.brand_string</c> (Intel and Apple silicon), else
    /// <c>system_profiler</c>'s chip or CPU type, which can be "Unknown" (seen on an Intel virtual machine).</summary>
    public static string? ProcessorName(string? brandString, string? chip)
    {
        if (!string.IsNullOrWhiteSpace(brandString))
        {
            return brandString.Trim();
        }

        return string.IsNullOrWhiteSpace(chip) || chip.Trim().Equals("Unknown", StringComparison.OrdinalIgnoreCase) ? null : chip.Trim();
    }

    /// <summary>The fields EasyPatch uses from <c>system_profiler -json SPHardwareDataType</c>.</summary>
    public sealed record Hardware(string? ModelName, string? ModelIdentifier, string? Chip, string? SerialNumber, string? HardwareUuid);

    public static Hardware? ParseHardware(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("SPHardwareDataType", out var array) || array.ValueKind != JsonValueKind.Array ||
                array.GetArrayLength() == 0)
            {
                return null;
            }

            var item = array[0];
            string? Text(string name) => item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            return new Hardware(Text("machine_name"), Text("machine_model"), Text("chip_type") ?? Text("cpu_type"), Text("serial_number"),
                Text("platform_UUID"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    [GeneratedRegex(@"^\d{2}(\.\d+){0,2}$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionRegex();

    [GeneratedRegex(@"sec\s*=\s*(?<sec>\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex BootTimeRegex();
}
