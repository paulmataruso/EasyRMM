using System.Text;
using EasyPatch.Agent.Core.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Unix;

/// <summary>
/// Bootstrap settings in <c>agent.conf</c> (<c>/etc/easypatch/agent.conf</c> on Linux, <c>/Library/EasyPatch/agent.conf</c> on macOS;
/// <c>Key=value</c> lines; root-only, mode 0600). The installer or
/// <c>easypatch-agent enroll</c> writes it; the enrollment token and deployment code are removed from it as soon as they
/// have been used. Values are never logged.
/// </summary>
public sealed class ConfFileBootstrapSource : IBootstrapConfigSource
{
    /// <summary>The Linux location.</summary>
    public const string DefaultPath = "/etc/easypatch/agent.conf";

    private const UnixFileMode FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly string[] SecretKeys = ["EnrollmentToken", "DeploymentCode"];

    private readonly string _path;
    private readonly ILogger _logger;

    public ConfFileBootstrapSource(string path = DefaultPath, ILogger? logger = null)
    {
        _path = path;
        _logger = logger ?? NullLogger.Instance;
    }

    public BootstrapConfig Read()
    {
        var values = ReadValues(_path);
        if (values.Count > 0)
        {
            Restrict();
        }

        return new BootstrapConfig(values.GetValueOrDefault("ServerUrl"), values.GetValueOrDefault("EnrollmentToken"),
            values.GetValueOrDefault("DeploymentCode"), values.GetValueOrDefault("ProxyUrl"));
    }

    public string SetupHint => $"Run 'sudo easypatch-agent enroll' or the install script from the EasyPatch console (settings: {_path}).";

    public string? ReadValue(string key) => ReadValues(_path).GetValueOrDefault(key);

    public void ClearEnrollmentSecrets()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        var lines = File.ReadAllLines(_path);
        var kept = lines.Where(l => !SecretKeys.Any(k => KeyOf(l) == k)).ToList();
        if (kept.Count != lines.Length)
        {
            WriteLines(_path, kept);
            _logger.LogInformation("Removed the used enrollment secret from {Path}.", _path);
        }
    }

    /// <summary>Writes the settings (replacing the file). Empty values are left out.</summary>
    public static void Write(string path, BootstrapConfig config, string? logLevel = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        var lines = new List<string>
        {
            "# EasyPatch agent settings. Root-only: may contain an enrollment secret until the agent has used it.",
        };
        void Add(string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                if (value.Contains('\n', StringComparison.Ordinal) || value.Contains('\r', StringComparison.Ordinal))
                {
                    throw new ArgumentException($"{key} must be a single line.");
                }

                lines.Add($"{key}={value.Trim()}");
            }
        }

        Add("ServerUrl", config.ServerUrl);
        Add("EnrollmentToken", config.EnrollmentToken);
        Add("DeploymentCode", config.DeploymentCode);
        Add("ProxyUrl", config.ProxyUrl);
        Add("LogLevel", logLevel);
        WriteLines(path, lines);
    }

    public static void Delete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    internal static Dictionary<string, string> ReadValues(string path)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] lines;
        try
        {
            if (!File.Exists(path))
            {
                return values;
            }

            lines = File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return values;
        }

        foreach (var line in lines)
        {
            var key = KeyOf(line);
            if (key is null)
            {
                continue;
            }

            var value = line[(line.IndexOf('=', StringComparison.Ordinal) + 1)..].Trim();
            if (value.Length >= 2 && (value[0] == '"' || value[0] == '\'') && value[^1] == value[0])
            {
                value = value[1..^1];
            }

            if (value.Length > 0)
            {
                values[key] = value;
            }
        }

        return values;
    }

    private static string? KeyOf(string line)
    {
        var trimmed = line.TrimStart();
        if (trimmed.Length == 0 || trimmed[0] == '#')
        {
            return null;
        }

        var equals = trimmed.IndexOf('=', StringComparison.Ordinal);
        return equals > 0 ? trimmed[..equals].Trim() : null;
    }

    /// <summary>Makes sure only root can read the file (it may hold an enrollment secret).</summary>
    private void Restrict()
    {
        try
        {
            if ((File.GetUnixFileMode(_path) & ~FileMode) != 0)
            {
                File.SetUnixFileMode(_path, FileMode);
                _logger.LogWarning("{Path} was readable by other users; its mode was changed to 0600.", _path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void WriteLines(string path, IReadOnlyList<string> lines)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory, DirectoryMode);
        }

        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, new FileStreamOptions
                   {
                       Mode = System.IO.FileMode.CreateNew,
                       Access = FileAccess.Write,
                       Share = FileShare.None,
                       UnixCreateMode = FileMode,
                       Options = FileOptions.WriteThrough,
                   }))
            {
                var bytes = Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n");
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
