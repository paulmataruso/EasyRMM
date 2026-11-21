using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Services;

public sealed class EasyPatchOptions
{
    public const string Section = "EasyPatch";

    /// <summary>Public HTTPS base URL agents and installers use, e.g. https://patches.example.com.</summary>
    public string PublicUrl { get; set; } = "https://localhost";

    /// <summary>Directory containing agent packages (EasyPatchAgent-&lt;version&gt;-&lt;arch&gt;.&lt;msi|deb|rpm|pkg&gt;), each
    /// optionally with its release signature (<c>.sig</c>).</summary>
    public string AgentPackagesPath { get; set; } = "/app/agent-packages";

    /// <summary>The worker's copy of the pinned winget release (writable by the worker, read-only for the API). Files an
    /// administrator places in <c>&lt;AgentPackagesPath&gt;/winget</c> are served too.</summary>
    public string WingetCachePath { get; set; } = "/app/winget";

    /// <summary>At most this many automatic agent updates run at the same time (spreads the downloads).</summary>
    public int AutomaticAgentUpdateConcurrency { get; set; } = 25;

    /// <summary>The host updater's status directory, mounted read-only into the worker (EasyRMM's ADR-0052). The worker reads
    /// <see cref="Maintenance.AgentUpdateHold.FileName"/> there.</summary>
    public string UpdaterStatusPath { get; set; } = "/run/easyrmm-updater";
}

/// <param name="Release">The release signature file, when present and describing exactly this file. The server never
/// checks the signature itself (it has no release key); agents do.</param>
/// <param name="SignatureProblem">Why a <c>.sig</c> file next to the package was ignored.</param>
/// <param name="Format">msi, deb, rpm or pkg (<see cref="AgentRelease.PackageFormats"/>).</param>
public sealed record AgentPackage(string FileName, string Version, string Architecture, long SizeBytes, string Sha256, DateTimeOffset ModifiedAt,
    AgentReleaseSignature? Release = null, string? SignatureProblem = null, string Format = AgentRelease.FormatMsi);

/// <summary>Lists agent packages (MSI, deb, rpm, and pkg for the experimental macOS agent) placed in the packages directory (mounted
/// read-only into the API container).</summary>
public sealed partial class AgentPackageService(IOptions<EasyPatchOptions> options, TimeProvider clock, ILogger<AgentPackageService> logger)
{
    private readonly ConcurrentDictionary<string, (long Length, DateTime Modified, string Sha256)> hashes = new();
    private readonly ConcurrentDictionary<string, string> reportedProblems = new(StringComparer.Ordinal);
    private IReadOnlyList<AgentPackage> cached = [];
    private DateTimeOffset cachedAt = DateTimeOffset.MinValue;
    private readonly Lock gate = new();

    [GeneratedRegex(@"^EasyPatchAgent-(?<version>\d+\.\d+\.\d+(?:\.\d+)?)-(?<arch>x64|arm64)\.(?<format>msi|deb|rpm|pkg)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FileNamePattern();

    public IReadOnlyList<AgentPackage> List()
    {
        lock (gate)
        {
            if (clock.GetUtcNow() - cachedAt < TimeSpan.FromSeconds(60))
            {
                return cached;
            }

            cached = Scan();
            cachedAt = clock.GetUtcNow();
            return cached;
        }
    }

    /// <summary>The newest package for an architecture and format (by default the x64 MSI).</summary>
    public AgentPackage? GetLatest(string architecture = "x64", string format = AgentRelease.FormatMsi) =>
        List().Where(p => p.Architecture.Equals(architecture, StringComparison.OrdinalIgnoreCase) &&
                          p.Format.Equals(format, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(p => Version.TryParse(p.Version, out var v) ? v : new Version(0, 0))
            .FirstOrDefault();

    /// <summary>The newest agent version among the packages of one format (the version agents of that kind should run).</summary>
    public string? GetLatestVersion(string format = AgentRelease.FormatMsi) =>
        List().Where(p => p.Format.Equals(format, StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Version)
            .OrderByDescending(v => Version.TryParse(v, out var parsed) ? parsed : new Version(0, 0))
            .FirstOrDefault();

    /// <summary>
    /// The listed package with this file name. A package file copied in after the last scan is found too: the worker keeps
    /// its own list and may already have offered it to agents, so a cache miss rescans the folder (at most once a second).
    /// </summary>
    public AgentPackage? Find(string fileName)
    {
        var package = FindIn(List(), fileName);
        if (package is not null || string.IsNullOrEmpty(fileName) || !FileNamePattern().IsMatch(fileName) ||
            !File.Exists(Path.Combine(options.Value.AgentPackagesPath, fileName)))
        {
            return package;
        }

        lock (gate)
        {
            if (clock.GetUtcNow() - cachedAt >= MinimumRescanInterval)
            {
                cached = Scan();
                cachedAt = clock.GetUtcNow();
            }

            return FindIn(cached, fileName);
        }
    }

    private static readonly TimeSpan MinimumRescanInterval = TimeSpan.FromSeconds(1);

    private static AgentPackage? FindIn(IReadOnlyList<AgentPackage> packages, string fileName) =>
        packages.FirstOrDefault(p => p.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase));

    /// <summary>Resolves a package file path, refusing anything that is not a listed package (no path traversal).</summary>
    public string? GetPath(string fileName)
    {
        var package = Find(fileName);
        return package is null ? null : Path.Combine(options.Value.AgentPackagesPath, package.FileName);
    }

    private List<AgentPackage> Scan()
    {
        var dir = options.Value.AgentPackagesPath;
        var result = new List<AgentPackage>();
        if (!Directory.Exists(dir))
        {
            return result;
        }

        foreach (var path in Directory.EnumerateFiles(dir, "EasyPatchAgent-*"))
        {
            var name = Path.GetFileName(path);
            if (name.EndsWith(AgentRelease.SignatureExtension, StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var match = FileNamePattern().Match(name);
            if (!match.Success)
            {
                logger.LogWarning("Ignoring agent package with unexpected name {FileName}", name);
                continue;
            }

            try
            {
                var info = new FileInfo(path);
                var key = info.FullName;
                if (!hashes.TryGetValue(key, out var entry) || entry.Length != info.Length || entry.Modified != info.LastWriteTimeUtc)
                {
                    using var stream = info.OpenRead();
                    entry = (info.Length, info.LastWriteTimeUtc, Convert.ToHexString(SHA256.HashData(stream)));
                    hashes[key] = entry;
                }

                var (release, problem) = ReadSignature(path, name, info.Length, entry.Sha256);
                result.Add(new AgentPackage(name, match.Groups["version"].Value, match.Groups["arch"].Value.ToLowerInvariant(),
                    info.Length, entry.Sha256, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), release, problem,
                    match.Groups["format"].Value.ToLowerInvariant()));
            }
            catch (IOException ex)
            {
                logger.LogWarning(ex, "Could not read agent package {FileName}", name);
            }
        }

        return result;
    }

    /// <summary>Reads <c>&lt;package&gt;.sig</c> and checks that it describes this exact file.</summary>
    private (AgentReleaseSignature? Release, string? Problem) ReadSignature(string packagePath, string fileName, long size, string sha256)
    {
        var path = packagePath + AgentRelease.SignatureExtension;
        if (!File.Exists(path))
        {
            return (null, null);
        }

        string? problem;
        try
        {
            var info = new FileInfo(path);
            if (info.Length > 16 * 1024)
            {
                problem = "The signature file is too large.";
            }
            else
            {
                var signature = JsonSerializer.Deserialize<AgentReleaseSignature>(File.ReadAllText(path), ContractJson.Options);
                problem = signature switch
                {
                    null => "The signature file is empty.",
                    { Format: not AgentRelease.SignatureFormat } => $"Unsupported signature format {signature.Format}.",
                    _ when !AgentRelease.IsKeyId(signature.KeyId) => "The signature file has no valid key ID.",
                    _ when AgentRelease.Validate(signature.Manifest) is [var error, ..] => error,
                    _ when signature.Manifest.FileName != fileName => "The signature file is for a different package.",
                    _ when signature.Manifest.SizeBytes != size || !signature.Manifest.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase) =>
                        "The package does not match its signature file (it was changed or rebuilt after signing).",
                    _ when string.IsNullOrEmpty(signature.Signature) => "The signature file has no signature.",
                    _ => null,
                };
                if (problem is null)
                {
                    return (signature, null);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            problem = "The signature file could not be read.";
        }

        if (!reportedProblems.TryGetValue(fileName, out var reported) || reported != problem)
        {
            reportedProblems[fileName] = problem;
            logger.LogWarning("Ignoring the release signature of agent package {FileName}: {Problem}", fileName, problem);
        }

        return (null, problem);
    }
}
