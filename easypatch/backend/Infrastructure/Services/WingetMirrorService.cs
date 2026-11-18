using System.Collections.Concurrent;
using System.Security.Cryptography;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Services;

/// <summary>The winget release files the server keeps for agents (by default the pinned <see cref="WingetDistribution"/>).</summary>
public sealed record WingetMirrorFiles(IReadOnlyList<WingetFile> Files, string ReleaseUrl)
{
    public static WingetMirrorFiles Pinned { get; } = new(WingetDistribution.Files, WingetDistribution.ReleaseUrl);
}

/// <summary>
/// The server's copy of the pinned winget release, for Windows agents that cannot download it from GitHub. The API serves a
/// file only when its size and SHA-256 match the pinned values. When an agent asks for a file the server does not have,
/// the API records the request and the worker (<see cref="Maintenance.WingetMirrorTask"/>) downloads the release from
/// GitHub. Agents check the pinned SHA-256 again themselves.
/// </summary>
public sealed class WingetMirrorService(IOptions<EasyPatchOptions> options, WingetMirrorFiles release, IHttpClientFactory httpClients,
    ILogger<WingetMirrorService> logger)
{
    public const string HttpClientName = "winget-mirror";
    private const string PartialSuffix = ".part";

    private readonly ConcurrentDictionary<string, (long Length, DateTime Modified, bool Valid)> _checked = new(StringComparer.Ordinal);

    public IReadOnlyList<WingetFile> Files => release.Files;

    /// <summary>The pinned file with exactly this name, or null (nothing else is ever served).</summary>
    public WingetFile? Find(string fileName) => release.Files.FirstOrDefault(f => string.Equals(f.Name, fileName, StringComparison.Ordinal));

    /// <summary>Path of a verified copy of <paramref name="file"/>: placed by an administrator, or downloaded by the worker.</summary>
    public string? GetPath(WingetFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        foreach (var path in new[] { Path.Combine(options.Value.AgentPackagesPath, "winget", file.Name), Path.Combine(options.Value.WingetCachePath, file.Name) })
        {
            if (IsValid(path, file))
            {
                return path;
            }
        }

        return null;
    }

    public bool IsComplete() => release.Files.All(f => GetPath(f) is not null);

    /// <summary>Records that an agent asked for a file the server does not have (at most every 10 minutes).</summary>
    public static Task RequestAsync(EasyPatchDbContext db, DateTimeOffset now, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(db);
        var name = Mirrors.Winget;
        var staleBefore = now.AddMinutes(-10);
        return db.Database.ExecuteSqlAsync(
            $"""
             INSERT INTO mirror_states (name, requested_at, failures) VALUES ({name}, {now}, 0)
             ON CONFLICT (name) DO UPDATE SET requested_at = EXCLUDED.requested_at
             WHERE mirror_states.requested_at IS NULL OR mirror_states.requested_at < {staleBefore}
             """, ct);
    }

    /// <summary>Downloads every file the server does not have yet from the GitHub release, keeping only verified files.</summary>
    /// <exception cref="InvalidOperationException">A download failed or did not match; the message says which.</exception>
    public async Task MirrorAsync(CancellationToken ct)
    {
        var directory = options.Value.WingetCachePath;
        Directory.CreateDirectory(directory);
        RemoveStaleFiles(directory);
        var http = httpClients.CreateClient(HttpClientName);
        foreach (var file in release.Files.Where(f => GetPath(f) is null))
        {
            var target = Path.Combine(directory, file.Name);
            var partial = target + PartialSuffix;
            try
            {
                using (var response = await http.GetAsync(new Uri(release.ReleaseUrl + Uri.EscapeDataString(file.Name)), HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new InvalidOperationException($"Downloading {file.Name} from GitHub failed with HTTP {(int)response.StatusCode}.");
                    }

                    if (response.RequestMessage?.RequestUri is { Scheme: not "https" })
                    {
                        throw new InvalidOperationException($"The download of {file.Name} was redirected away from HTTPS.");
                    }

                    await using var source = await response.Content.ReadAsStreamAsync(ct);
                    await using var destination = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None);
                    var buffer = new byte[81920];
                    long total = 0;
                    int read;
                    while ((read = await source.ReadAsync(buffer, ct)) > 0)
                    {
                        total += read;
                        if (total > file.Size)
                        {
                            throw new InvalidOperationException($"{file.Name} from GitHub is larger than the pinned release.");
                        }

                        await destination.WriteAsync(buffer.AsMemory(0, read), ct);
                    }
                }

                if (!await MatchesAsync(partial, file, ct))
                {
                    throw new InvalidOperationException($"{file.Name} from GitHub does not match the pinned size and SHA-256.");
                }

                File.Move(partial, target, overwrite: true);
                logger.LogInformation("Downloaded {File} of winget {Version} for agents.", file.Name, WingetDistribution.Version);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException($"Downloading {file.Name} from GitHub failed: {ex.Message}", ex);
            }
            finally
            {
                if (File.Exists(partial))
                {
                    File.Delete(partial);
                }
            }
        }
    }

    private bool IsValid(string path, WingetFile file)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length != file.Size)
        {
            return false;
        }

        var key = (info.Length, info.LastWriteTimeUtc);
        if (_checked.TryGetValue(path, out var cached) && (cached.Length, cached.Modified) == key)
        {
            return cached.Valid;
        }

        bool valid;
        using (var stream = File.OpenRead(path))
        {
            valid = string.Equals(Convert.ToHexStringLower(SHA256.HashData(stream)), file.Sha256, StringComparison.OrdinalIgnoreCase);
        }

        if (!valid)
        {
            logger.LogWarning("{Path} does not match the pinned winget release and is not served.", path);
        }

        _checked[path] = (key.Length, key.LastWriteTimeUtc, valid);
        return valid;
    }

    private static async Task<bool> MatchesAsync(string path, WingetFile file, CancellationToken ct)
    {
        if (new FileInfo(path).Length != file.Size)
        {
            return false;
        }

        await using var stream = File.OpenRead(path);
        return string.Equals(Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct)), file.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Files of an earlier pinned release (and interrupted downloads) are removed.</summary>
    private void RemoveStaleFiles(string directory)
    {
        foreach (var path in Directory.EnumerateFiles(directory))
        {
            if (Find(Path.GetFileName(path)) is null)
            {
                try
                {
                    File.Delete(path);
                }
                catch (IOException ex)
                {
                    logger.LogDebug(ex, "Could not delete {Path}.", path);
                }
            }
        }
    }
}
