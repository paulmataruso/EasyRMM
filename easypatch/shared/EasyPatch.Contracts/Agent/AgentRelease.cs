using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace EasyPatch.Contracts.Agent;

/// <summary>What a release signature covers: one agent package (MSI, deb, rpm or pkg), identified by file name, version,
/// architecture, size and SHA-256. Changing any of them (or the file) invalidates the signature.</summary>
public sealed record AgentReleaseManifest
{
    /// <summary><c>EasyPatchAgent-&lt;version&gt;-&lt;architecture&gt;.&lt;msi|deb|rpm|pkg&gt;</c>; the extension is the
    /// package format.</summary>
    public required string FileName { get; init; }

    /// <summary>Three-part version, e.g. <c>1.2.0</c>.</summary>
    public required string Version { get; init; }

    /// <summary><c>x64</c> or <c>arm64</c>.</summary>
    public required string Architecture { get; init; }

    /// <summary>Lower-case hex SHA-256 of the package.</summary>
    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }
}

/// <summary>The detached signature file published next to a package (<c>EasyPatchAgent-1.2.0-x64.msi.sig</c>, JSON).</summary>
public sealed record AgentReleaseSignature
{
    public int Format { get; init; } = AgentRelease.SignatureFormat;

    /// <summary>The signing key (<see cref="AgentRelease.KeyId"/>).</summary>
    public required string KeyId { get; init; }

    public required AgentReleaseManifest Manifest { get; init; }

    /// <summary>Base64 ECDSA P-256 / SHA-256 signature (IEEE P1363) of <see cref="AgentRelease.CanonicalBytes"/>.</summary>
    public required string Signature { get; init; }
}

/// <summary>Payload of an <see cref="JobType.AgentUpdate"/> job: the package to install and its release signature. The
/// agent downloads the file named in the manifest from its own server and installs it only if the signature verifies
/// against a release key built into the agent and the download matches the manifest.</summary>
public sealed record AgentUpdatePayload
{
    public required AgentReleaseManifest Package { get; init; }
    public required string KeyId { get; init; }
    public required string Signature { get; init; }
}

/// <summary>
/// Release signing for agent updates. A release key is an ECDSA P-256 key pair: the private key stays with whoever
/// builds the agent (never on the EasyPatch server); the public key is built into the agent. The server only relays
/// packages and signatures, so it cannot make an agent install anything that was not signed with that private key.
/// </summary>
public static partial class AgentRelease
{
    public const int SignatureFormat = 1;

    /// <summary>Upper bound for a package download (the packages are about 55 MB).</summary>
    public const long MaxPackageBytes = 512L * 1024 * 1024;

    public const string SignatureExtension = ".sig";

    public static IReadOnlyList<string> Architectures { get; } = ["x64", "arm64"];

    /// <summary>Windows Installer package (Windows agents, and agents that do not report a format).</summary>
    public const string FormatMsi = "msi";

    /// <summary>Debian package (Debian, Ubuntu and derivatives).</summary>
    public const string FormatDeb = "deb";

    /// <summary>RPM package (Red Hat Enterprise Linux and rebuilds).</summary>
    public const string FormatRpm = "rpm";

    /// <summary>macOS installer package (the experimental macOS agent, 1.9.0 and later).</summary>
    public const string FormatPkg = "pkg";

    public static IReadOnlyList<string> PackageFormats { get; } = [FormatMsi, FormatDeb, FormatRpm, FormatPkg];

    private const string Domain = "easypatch-agent-release-v1";

    [GeneratedRegex(@"^EasyPatchAgent-(?<version>\d{1,5}\.\d{1,5}\.\d{1,5})-(?<arch>x64|arm64)\.(?<format>msi|deb|rpm|pkg)$", RegexOptions.CultureInvariant)]
    private static partial Regex FileNameRegex();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Regex();

    [GeneratedRegex("^[0-9a-f]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdRegex();

    /// <summary>The exact bytes that are signed. Every field is included and a domain prefix keeps the signature from
    /// being valid for anything else.</summary>
    public static byte[] CanonicalBytes(AgentReleaseManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        return Encoding.UTF8.GetBytes(string.Join('\n',
            Domain, manifest.FileName, manifest.Version, manifest.Architecture, manifest.Sha256,
            manifest.SizeBytes.ToString(CultureInfo.InvariantCulture), string.Empty));
    }

    /// <summary>First 16 hex characters of the SHA-256 of the public key's SubjectPublicKeyInfo.</summary>
    public static string KeyId(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))[..16];
    }

    public static bool IsKeyId(string? value) => value is not null && KeyIdRegex().IsMatch(value);

    public static string Sign(AgentReleaseManifest manifest, ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        RequireP256(privateKey);
        return Convert.ToBase64String(privateKey.SignData(CanonicalBytes(manifest), HashAlgorithmName.SHA256));
    }

    public static bool Verify(AgentReleaseManifest manifest, string? signature, ECDsa publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (string.IsNullOrEmpty(signature) || publicKey.KeySize != 256)
        {
            return false;
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(signature);
        }
        catch (FormatException)
        {
            return false;
        }

        return bytes.Length == 64 && publicKey.VerifyData(CanonicalBytes(manifest), bytes, HashAlgorithmName.SHA256);
    }

    /// <summary>Reads every <c>PUBLIC KEY</c> block in PEM text (several keys allow a key to be replaced). The caller
    /// disposes the keys.</summary>
    /// <exception cref="CryptographicException">A block is not an ECDSA P-256 public key.</exception>
    public static IReadOnlyList<ECDsa> ParsePublicKeys(string pemText)
    {
        ArgumentNullException.ThrowIfNull(pemText);
        var keys = new List<ECDsa>();
        var remaining = pemText.AsSpan();
        try
        {
            while (PemEncoding.TryFind(remaining, out var fields))
            {
                if (remaining[fields.Label].SequenceEqual("PUBLIC KEY"))
                {
                    var key = ECDsa.Create();
                    keys.Add(key);
                    key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(remaining[fields.Base64Data].ToString()), out _);
                    RequireP256(key);
                }

                remaining = remaining[fields.Location.End..];
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            foreach (var key in keys)
            {
                key.Dispose();
            }

            throw new CryptographicException("A release public key is not an ECDSA P-256 key.", ex);
        }
        catch
        {
            foreach (var key in keys)
            {
                key.Dispose();
            }

            throw;
        }

        return keys;
    }

    /// <summary>Builds the manifest for a package file (name, size and hash).</summary>
    public static AgentReleaseManifest Describe(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var name = Path.GetFileName(path);
        var match = FileNameRegex().Match(name);
        if (!match.Success)
        {
            throw new ArgumentException($"'{name}' is not an agent package name (EasyPatchAgent-<version>-<x64|arm64>.<msi|deb|rpm|pkg>).", nameof(path));
        }

        using var stream = File.OpenRead(path);
        return new AgentReleaseManifest
        {
            FileName = name,
            Version = match.Groups["version"].Value,
            Architecture = match.Groups["arch"].Value,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(stream)),
            SizeBytes = stream.Length,
        };
    }

    /// <summary>Problems with a manifest's fields (empty when it is well formed).</summary>
    public static IReadOnlyList<string> Validate(AgentReleaseManifest? manifest)
    {
        if (manifest is null)
        {
            return ["The package description is missing."];
        }

        var errors = new List<string>();
        var match = FileNameRegex().Match(manifest.FileName ?? string.Empty);
        if (!match.Success)
        {
            errors.Add("The package file name is not EasyPatchAgent-<version>-<x64|arm64>.<msi|deb|rpm|pkg>.");
        }
        else if (match.Groups["version"].Value != manifest.Version || match.Groups["arch"].Value != manifest.Architecture)
        {
            errors.Add("The package file name does not match its version and architecture.");
        }

        if (!Sha256Regex().IsMatch(manifest.Sha256 ?? string.Empty))
        {
            errors.Add("The package hash is not a lower-case hex SHA-256.");
        }

        if (manifest.SizeBytes is <= 0 or > MaxPackageBytes)
        {
            errors.Add("The package size is out of range.");
        }

        return errors;
    }

    /// <summary>Package format (<see cref="FormatMsi"/>, <see cref="FormatDeb"/>, <see cref="FormatRpm"/> or <see cref="FormatPkg"/>) of an agent
    /// package file name, or null when it is not one.</summary>
    public static string? FormatOf(string? fileName)
    {
        var match = FileNameRegex().Match(fileName ?? string.Empty);
        return match.Success ? match.Groups["format"].Value : null;
    }

    /// <summary>The package format an agent installs updates from: <see cref="FormatMsi"/> when it did not say (agents
    /// before 1.3.0 only ran on Windows), null when it named a format this server does not know.</summary>
    public static string? NormalizeFormat(string? format) =>
        format is null ? FormatMsi : PackageFormats.Contains(format) ? format : null;

    /// <summary>Parses the numeric part of an agent version (<c>1.2.0</c>, <c>1.2.0+abc</c> or <c>1.2.0-beta</c>).</summary>
    public static Version? ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var core = text.Split('+', '-')[0];
        return Version.TryParse(core, out var version) ? new Version(version.Major, version.Minor, Math.Max(version.Build, 0)) : null;
    }

    /// <summary>Package architecture for a process architecture, or null when there is no package for it.</summary>
    public static string? ArchitectureOf(Architecture architecture) => architecture switch
    {
        Architecture.X64 => "x64",
        Architecture.Arm64 => "arm64",
        _ => null,
    };

    private static void RequireP256(ECDsa key)
    {
        if (key.KeySize != 256)
        {
            throw new ArgumentException("Release keys are ECDSA P-256 keys.", nameof(key));
        }
    }
}
