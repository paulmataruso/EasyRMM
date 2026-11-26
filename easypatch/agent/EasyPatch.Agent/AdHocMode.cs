using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace EasyPatch.Agent;

/// <summary>
/// The ad-hoc mode of <c>run</c> (EasyRMM Quick Assist, ADR-0080): the agent runs as a console child of a runner for one
/// session, with a data directory, registry key and single-instance lock of its own, so it never touches
/// <c>C:\ProgramData\EasyPatch</c>, <c>HKLM\SOFTWARE\EasyPatch</c> or an installed agent's lock. It still needs an
/// elevated process, and it refuses to start when a real EasyPatch install is on the computer.
/// </summary>
internal static partial class AdHocMode
{
    public const string RegistryPrefix = @"SOFTWARE\EasyPatchAdHoc\";

    public static bool Active { get; private set; }

    public static string DataDirectory { get; private set; } = "";

    public static string RegistryKeyPath { get; private set; } = "";

    public static string LockName { get; private set; } = "agent.lock";

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$")]
    private static partial Regex Name();

    /// <summary>Reads <c>--adhoc --data-dir D --registry-key K --lock L</c>; null when the arguments do not ask for ad-hoc mode.</summary>
    public static (string DataDirectory, string Key, string Lock)? Parse(string[] arguments)
    {
        if (!arguments.Contains("--adhoc", StringComparer.Ordinal))
        {
            return null;
        }

        string? dir = null, key = null, lockName = null;
        for (var i = 0; i < arguments.Length; i++)
        {
            string Next() => i + 1 < arguments.Length ? arguments[++i] : throw new CliUsageException($"'{arguments[i]}' needs a value.");
            switch (arguments[i])
            {
                case "--adhoc":
                    break;
                case "--data-dir":
                    dir = Next();
                    break;
                case "--registry-key":
                    key = Next();
                    break;
                case "--lock":
                    lockName = Next();
                    break;
                default:
                    throw new CliUsageException($"'run --adhoc' does not take '{arguments[i]}'.");
            }
        }

        if (string.IsNullOrEmpty(dir) || !Path.IsPathFullyQualified(dir) || dir.Contains("..", StringComparison.Ordinal))
        {
            throw new CliUsageException("--data-dir must be a full path.");
        }

        if (key is null || !Name().IsMatch(key))
        {
            throw new CliUsageException("--registry-key must be a short name of letters, digits, dots and hyphens.");
        }

        if (lockName is null || !Name().IsMatch(lockName))
        {
            throw new CliUsageException("--lock must be a short name of letters, digits, dots and hyphens.");
        }

        return (Path.GetFullPath(dir), RegistryPrefix + key, lockName);
    }

    public static void Enable((string DataDirectory, string Key, string Lock) options)
    {
        DataDirectory = options.DataDirectory;
        RegistryKeyPath = options.Key;
        LockName = options.Lock;
        Active = true;
    }

    /// <summary>What shows a real EasyPatch install on this computer, or null: its service, its data directory or its registry key.</summary>
    public static string? ExistingInstall()
    {
        var real = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify), "EasyPatch");
        if (Directory.Exists(real))
        {
            return real;
        }

        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var path in new[] { @"SYSTEM\CurrentControlSet\Services\" + AgentComposition.ServiceName, @"SOFTWARE\EasyPatch" })
        {
            using var found = root.OpenSubKey(path, writable: false);
            if (found is not null)
            {
                return @"HKLM\" + path;
            }
        }

        return null;
    }
}
