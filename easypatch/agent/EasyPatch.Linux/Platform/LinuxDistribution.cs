using System.Text;

namespace EasyPatch.Linux.Platform;

/// <summary>Package manager families the agent supports.</summary>
public enum PackageFamily
{
    Unsupported,

    /// <summary>Debian, Ubuntu and derivatives: apt and dpkg, .deb agent packages.</summary>
    Debian,

    /// <summary>Red Hat Enterprise Linux 8+ and rebuilds (Rocky, AlmaLinux, Oracle): dnf and rpm, .rpm agent packages.</summary>
    RedHat,
}

/// <summary>The distribution as described by <c>/etc/os-release</c>.</summary>
public sealed record LinuxDistribution
{
    public required string Id { get; init; }
    public IReadOnlyList<string> IdLike { get; init; } = [];
    public string? VersionId { get; init; }
    public string? PrettyName { get; init; }
    public string? Name { get; init; }
    public string? VersionCodename { get; init; }

    public PackageFamily Family
    {
        get
        {
            var ids = IdLike.Prepend(Id).ToList();
            if (ids.Any(i => i is "debian" or "ubuntu"))
            {
                return PackageFamily.Debian;
            }

            return ids.Any(i => i is "rhel" or "fedora" or "centos") ? PackageFamily.RedHat : PackageFamily.Unsupported;
        }
    }

    /// <summary>The release the update catalog is keyed on: Ubuntu's full VERSION_ID ("24.04"), otherwise the major version
    /// ("12", "9"), because minor releases of Debian and Enterprise Linux share one package stream.</summary>
    public string ReleaseKey
    {
        get
        {
            var version = VersionId ?? "unknown";
            if (Id == "ubuntu")
            {
                return version;
            }

            var dot = version.IndexOf('.', StringComparison.Ordinal);
            return dot > 0 ? version[..dot] : version;
        }
    }

    /// <summary>Product name used as the update's product category, e.g. "Debian 12", "Ubuntu 24.04", "Rocky Linux 9".</summary>
    public string ProductName
    {
        get
        {
            var name = Id switch
            {
                "debian" => "Debian",
                "ubuntu" => "Ubuntu",
                "rhel" => "Red Hat Enterprise Linux",
                "rocky" => "Rocky Linux",
                "almalinux" => "AlmaLinux",
                "ol" => "Oracle Linux",
                "centos" => "CentOS Stream",
                _ => string.IsNullOrWhiteSpace(Name) ? Id : Name,
            };
            return $"{name} {ReleaseKey}";
        }
    }

    public static LinuxDistribution? Read(string path = "/etc/os-release")
    {
        foreach (var candidate in new[] { path, "/usr/lib/os-release" })
        {
            try
            {
                if (File.Exists(candidate))
                {
                    return Parse(File.ReadAllText(candidate));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return null;
    }

    /// <summary>Parses os-release (shell-style KEY=value lines; values may be quoted).</summary>
    public static LinuxDistribution? Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            values[line[..equals]] = Unquote(line[(equals + 1)..]);
        }

        if (!values.TryGetValue("ID", out var id) || string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        return new LinuxDistribution
        {
            Id = id.ToLowerInvariant(),
            IdLike = values.TryGetValue("ID_LIKE", out var like)
                ? like.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : [],
            VersionId = values.GetValueOrDefault("VERSION_ID"),
            PrettyName = values.GetValueOrDefault("PRETTY_NAME"),
            Name = values.GetValueOrDefault("NAME"),
            VersionCodename = values.GetValueOrDefault("VERSION_CODENAME"),
        };
    }

    private static string Unquote(string value)
    {
        value = value.Trim();
        if (value.Length >= 2 && (value[0] == '"' || value[0] == '\'') && value[^1] == value[0])
        {
            var quote = value[0];
            value = value[1..^1];
            if (quote == '"')
            {
                var builder = new StringBuilder(value.Length);
                for (var i = 0; i < value.Length; i++)
                {
                    if (value[i] == '\\' && i + 1 < value.Length && value[i + 1] is '"' or '\\' or '$' or '`')
                    {
                        i++;
                    }

                    builder.Append(value[i]);
                }

                value = builder.ToString();
            }
        }

        return value;
    }
}
