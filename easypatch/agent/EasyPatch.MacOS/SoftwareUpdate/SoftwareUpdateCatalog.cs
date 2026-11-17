using System.Security.Cryptography;
using System.Text;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.MacOS.SoftwareUpdate;

/// <summary>How Apple's updates are reported to the server: identity, title, classification.</summary>
public static class SoftwareUpdateCatalog
{
    private const string ClassificationType = "UpdateClassification";
    private const string ProductType = "Product";

    /// <summary>Apple security releases (lists the security content of each update).</summary>
    public const string SecurityReleasesUrl = "https://support.apple.com/100100";

    /// <summary>The product without its version: <c>macOS Sequoia 15.7.2</c> → <c>macOS Sequoia</c>, <c>Safari</c> → <c>Safari</c>.</summary>
    public static string LineOf(string title, string version)
    {
        ArgumentNullException.ThrowIfNull(title);
        var line = title.Trim();
        if (!string.IsNullOrWhiteSpace(version))
        {
            var index = line.IndexOf(version.Trim(), StringComparison.Ordinal);
            if (index > 0)
            {
                line = line[..index];
            }
        }

        line = line.Trim().TrimEnd(',', '-').Trim();
        return line.Length == 0 ? title.Trim() : line;
    }

    /// <summary>Matches a listed update with its <c>softwareupdate --history</c> entry.</summary>
    public static string InstalledKey(string title, string version) => LineOf(title, version) + "|" + version.Trim();

    /// <summary>The same version of the same Apple product is the same update on every Mac.</summary>
    public static Guid UpdateGuidFor(string line, string version) => HashGuid($"easypatch-macos-update|{line}|{version.Trim()}");

    public static bool IsMacOS(string title) => title.StartsWith("macOS ", StringComparison.OrdinalIgnoreCase);

    /// <summary>Background Security Improvements (macOS 26) and Rapid Security Responses (macOS 13 to 15).</summary>
    public static bool IsSecurityResponse(string title, string version) =>
        title.Contains("Background Security", StringComparison.OrdinalIgnoreCase) ||
        title.Contains("Rapid Security Response", StringComparison.OrdinalIgnoreCase) ||
        version.TrimEnd().EndsWith(')');

    /// <summary>
    /// "Upgrades" for a newer major macOS release; "Security Updates" for security responses and macOS updates within the
    /// installed major release (Apple ships security fixes in nearly all of them, but <c>softwareupdate</c> does not say which);
    /// "Updates" for everything else (Safari, command line tools, …).
    /// </summary>
    public static string ClassificationOf(SoftwareUpdateItem item, int installedMajor)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (IsSecurityResponse(item.Title, item.Version))
        {
            return "Security Updates";
        }

        if (IsMacOS(item.Title))
        {
            return MajorOf(item.Version) is { } major && installedMajor > 0 && major > installedMajor ? "Upgrades" : "Security Updates";
        }

        return "Updates";
    }

    public static int? MajorOf(string? version)
    {
        var first = (version ?? string.Empty).Split('.', ' ')[0];
        return int.TryParse(first, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var major) ? major : null;
    }

    /// <summary>Builds the update reported to the server for one listed update.</summary>
    public static ReportedUpdate Describe(SoftwareUpdateItem item, int installedMajor)
    {
        ArgumentNullException.ThrowIfNull(item);
        var line = LineOf(item.Title, item.Version);
        var classification = ClassificationOf(item, installedMajor);
        var product = IsMacOS(item.Title) ? "macOS" : line;
        var title = item.Version.Length == 0 || item.Title.Contains(item.Version, StringComparison.Ordinal) ? item.Title : $"{item.Title} {item.Version}";
        var description = new StringBuilder($"{title} from Apple software update (softwareupdate label: {item.Label}).");
        if (item.RestartRequired)
        {
            description.Append(" It completes when the Mac restarts; on Macs with Apple silicon only a volume owner (in System Settings) or MDM can install it.");
        }

        if (classification == "Security Updates" && !IsSecurityResponse(item.Title, item.Version))
        {
            description.Append(" Apple includes security fixes in nearly all macOS updates; softwareupdate does not say which.");
        }

        return new ReportedUpdate
        {
            UpdateGuid = UpdateGuidFor(line, item.Version),
            RevisionNumber = 1,
            Title = title,
            Description = description.ToString(),
            Categories =
            [
                new UpdateCategoryRef { Id = CategoryGuid(ClassificationType, classification), Name = classification, Type = ClassificationType },
                new UpdateCategoryRef { Id = CategoryGuid(ProductType, product), Name = product, Type = ProductType },
            ],
            RebootBehavior = item.RestartRequired ? 1 : 0,
            MaxDownloadSize = item.SizeBytes,
            SupportUrl = IsMacOS(item.Title) ? SecurityReleasesUrl : null,
        };
    }

    private static Guid CategoryGuid(string type, string name) => HashGuid($"easypatch-macos-category|{type}|{name}");

    /// <summary>A name-based (UUIDv8) GUID from the SHA-256 of <paramref name="text"/>.</summary>
    private static Guid HashGuid(string text)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(text), hash);
        var bytes = hash[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes, bigEndian: true);
    }
}
