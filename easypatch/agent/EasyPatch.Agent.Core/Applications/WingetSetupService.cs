using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Applications;

/// <summary>Installs App Installer (winget) for all users of the computer. Implemented on Windows; faked in tests.</summary>
public interface IWingetProvisioner
{
    /// <summary>The dependency folder to install from (<c>x64</c> or <c>arm64</c>).</summary>
    string Architecture { get; }

    /// <summary>Why winget cannot be installed on this computer (for example a Windows version that is too old), or null.</summary>
    string? UnsupportedReason { get; }

    /// <summary>Provisions the package with its dependencies and license.</summary>
    /// <exception cref="WingetException">The installation failed; the message says why.</exception>
    Task ProvisionAsync(string bundlePath, IReadOnlyList<string> dependencyPaths, string licensePath, CancellationToken cancellationToken);
}

/// <summary>Somewhere the winget release files can be downloaded from.</summary>
public interface IWingetFileSource
{
    /// <summary>Used in messages: "GitHub", "the EasyPatch server".</summary>
    string Name { get; }

    /// <summary>Writes the file to <paramref name="destination"/>; never more than <see cref="WingetFile.Size"/> bytes.</summary>
    Task DownloadAsync(WingetFile file, Stream destination, CancellationToken cancellationToken);
}

/// <summary>The winget release to install: its files and which of them is the bundle, the dependencies and the license.</summary>
public sealed record WingetRelease(string Version, IReadOnlyList<WingetFile> Files, string Bundle, string Dependencies, string License)
{
    public static WingetRelease Pinned { get; } = new(WingetDistribution.Version, WingetDistribution.Files, WingetDistribution.Bundle,
        WingetDistribution.Dependencies, WingetDistribution.License);
}

/// <summary>
/// Makes sure the computer has a machine-wide winget, so application updates work without preparation. When there is
/// none (or it is older than <see cref="WingetApplicationUpdateService.MinimumVersion"/>), it downloads the pinned
/// release (<see cref="WingetDistribution"/>) from GitHub, or from the EasyPatch server when GitHub fails, checks the size
/// and SHA-256 of every file, and provisions App Installer for all users. Nothing is installed from a file that does
/// not match. Failed attempts are retried after 30 minutes, 2 hours, 6 hours, then daily; a working winget is checked
/// again daily.
/// </summary>
public sealed partial class WingetSetupService
{
    public static readonly TimeSpan RecheckInterval = TimeSpan.FromHours(24);
    public static readonly TimeSpan ServerPreparingRetry = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan[] RetryDelays = [TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(6), TimeSpan.FromHours(24)];
    private static readonly TimeSpan BusyPoll = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxBusyWait = TimeSpan.FromHours(2);

    /// <summary>Downloads and the installed package need room; the release is about 315 MB.</summary>
    public const long RequiredFreeBytes = 1536L * 1024 * 1024;

    private readonly IWingetRunner _runner;
    private readonly IWingetProvisioner _provisioner;
    private readonly IReadOnlyList<IWingetFileSource> _sources;
    private readonly AgentStateStore _state;
    private readonly WingetRelease _release;
    private readonly string _workDirectory;
    private readonly Func<bool> _busy;
    private readonly Func<string, long?> _freeSpace;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private bool _serverPreparing;

    /// <param name="sources">Tried in order for each file (GitHub first, then the EasyPatch server).</param>
    /// <param name="workDirectory">Emptied before and deleted after each attempt.</param>
    /// <param name="busy">True while a job runs; the installation step waits for it (downloads do not).</param>
    /// <param name="freeSpace">Free bytes on the volume of a directory (null when unknown).</param>
    public WingetSetupService(IWingetRunner runner, IWingetProvisioner provisioner, IReadOnlyList<IWingetFileSource> sources, AgentStateStore state,
        string workDirectory, Func<bool> busy, TimeProvider time, ILogger<WingetSetupService> logger, WingetRelease? release = null,
        Func<string, long?>? freeSpace = null)
    {
        _runner = runner;
        _provisioner = provisioner;
        _sources = sources;
        _state = state;
        _workDirectory = workDirectory;
        _busy = busy;
        _time = time;
        _logger = logger;
        _release = release ?? WingetRelease.Pinned;
        _freeSpace = freeSpace ?? FreeSpace;
    }

    /// <summary>What the server is told at check-in; null until the first check.</summary>
    public WingetStatusReport? Report => _state.Read(s => s.Winget.CheckedAt is null
        ? null
        : new WingetStatusReport
        {
            Version = s.Winget.Version,
            InstalledByAgent = s.Winget.InstalledByAgent,
            SetupError = s.Winget.Error,
            CheckedAt = s.Winget.CheckedAt,
        });

    /// <summary>Checks a few minutes after start, then as <see cref="EnsureAsync"/> schedules, until cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var next = FirstCheck();
        while (!cancellationToken.IsCancellationRequested)
        {
            var wait = next - _time.GetUtcNow();
            if (wait > TimeSpan.Zero)
            {
                try
                {
                    await Task.Delay(wait, _time, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }

            try
            {
                var ready = await EnsureAsync(cancellationToken);
                next = _time.GetUtcNow() + (ready ? RecheckInterval : RetryDelay());
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The winget check failed.");
                next = _time.GetUtcNow() + RetryDelays[0];
            }
        }
    }

    /// <summary>Checks winget and installs it when it is missing or too old. True when a usable winget is present.</summary>
    public async Task<bool> EnsureAsync(CancellationToken cancellationToken)
    {
        _serverPreparing = false;
        var found = await FindAsync(cancellationToken);
        if (found is { } version && version >= WingetApplicationUpdateService.MinimumVersion)
        {
            Record(version.ToString(), error: null, attempted: false);
            return true;
        }

        if (_provisioner.UnsupportedReason is { } unsupported)
        {
            Record(found?.ToString(), unsupported, attempted: false);
            return false;
        }

        _logger.LogInformation("{State}; installing winget {Version} for all users.",
            found is null ? "winget is not installed for all users" : $"winget {found} is too old", _release.Version);
        string? error;
        try
        {
            error = await InstallAsync(cancellationToken);
        }
        finally
        {
            TryDelete(_workDirectory);
        }

        if (error is null)
        {
            var installed = await FindAsync(cancellationToken);
            if (installed is { } now && now >= WingetApplicationUpdateService.MinimumVersion)
            {
                _logger.LogInformation(AgentEventIds.WingetInstalled, "Installed winget {Version} for all users.", now);
                Record(now.ToString(), error: null, attempted: true, installedByAgent: true);
                return true;
            }

            error = installed is null
                ? "App Installer was installed, but its winget.exe was not found."
                : $"App Installer was installed, but winget reports version {installed}.";
        }

        _logger.LogWarning(AgentEventIds.WingetSetupFailed, "Could not install winget: {Error}", error);
        Record(found?.ToString(), error, attempted: true);
        return false;
    }

    /// <summary>Downloads, verifies, extracts and provisions. Returns why it failed, or null.</summary>
    private async Task<string?> InstallAsync(CancellationToken cancellationToken)
    {
        TryDelete(_workDirectory);
        Directory.CreateDirectory(_workDirectory);
        if (_freeSpace(_workDirectory) is { } free && free < RequiredFreeBytes)
        {
            return $"Not enough free disk space: installing winget needs {RequiredFreeBytes / (1024 * 1024)} MB, " +
                   $"{free / (1024 * 1024)} MB are free.";
        }

        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in _release.Files)
        {
            var (path, error) = await DownloadAsync(file, cancellationToken);
            if (path is null)
            {
                return error;
            }

            paths[file.Name] = path;
        }

        var dependencies = ExtractDependencies(paths[_release.Dependencies], Path.Combine(_workDirectory, "dependencies"));
        if (dependencies.Count == 0)
        {
            return $"The dependency archive has no packages for {_provisioner.Architecture}.";
        }

        var waited = TimeSpan.Zero;
        while (_busy() && waited < MaxBusyWait)
        {
            await Task.Delay(BusyPoll, _time, cancellationToken);
            waited += BusyPoll;
        }

        try
        {
            await _provisioner.ProvisionAsync(paths[_release.Bundle], dependencies, paths[_release.License], cancellationToken);
            return null;
        }
        catch (WingetException ex)
        {
            return ex.Message;
        }
    }

    /// <summary>The first source that delivers the file with the right size and SHA-256.</summary>
    private async Task<(string? Path, string Error)> DownloadAsync(WingetFile file, CancellationToken cancellationToken)
    {
        var path = Path.Combine(_workDirectory, file.Name);
        var problems = new List<string>();
        foreach (var source in _sources)
        {
            try
            {
                await using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await source.DownloadAsync(file, stream, cancellationToken);
                }

                var problem = await VerifyAsync(path, file, cancellationToken);
                if (problem is null)
                {
                    _logger.LogInformation("Downloaded {File} from {Source}.", file.Name, source.Name);
                    return (path, "");
                }

                problems.Add($"{source.Name}: {problem}");
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                if (ex is AgentTransientException { StatusCode: System.Net.HttpStatusCode.ServiceUnavailable })
                {
                    _serverPreparing = true; // the server is fetching its copy
                }

                problems.Add($"{source.Name}: {ex.Message}");
            }

            _logger.LogWarning("Could not download {File} from {Source}.", file.Name, source.Name);
            TryDeleteFile(path);
        }

        return (null, $"Could not download {file.Name}. " + string.Join(" ", problems));
    }

    internal static async Task<string?> VerifyAsync(string path, WingetFile file, CancellationToken cancellationToken)
    {
        var length = new FileInfo(path).Length;
        if (length != file.Size)
        {
            return $"the file has {length} bytes instead of {file.Size}.";
        }

        await using var stream = File.OpenRead(path);
        var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
        return string.Equals(hash, file.Sha256, StringComparison.OrdinalIgnoreCase) ? null : "the file's SHA-256 does not match the pinned release.";
    }

    /// <summary>Extracts the packages of this computer's architecture (<c>&lt;arch&gt;/name.appx</c>); nothing else.</summary>
    internal List<string> ExtractDependencies(string archivePath, string directory)
    {
        Directory.CreateDirectory(directory);
        var result = new List<string>();
        var prefix = _provisioner.Architecture + "/";
        using var archive = ZipFile.OpenRead(archivePath);
        foreach (var entry in archive.Entries)
        {
            var name = entry.FullName.Replace('\\', '/');
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fileName = name[prefix.Length..];
            if (!PackageFileName().IsMatch(fileName))
            {
                continue; // subfolders, unexpected names or types
            }

            var target = Path.Combine(directory, fileName);
            entry.ExtractToFile(target, overwrite: false);
            result.Add(target);
        }

        return result;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(appx|msix)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageFileName();

    private async Task<Version?> FindAsync(CancellationToken cancellationToken)
    {
        if (_runner.Locate() is null)
        {
            return null;
        }

        try
        {
            var result = await _runner.RunAsync(["--version"], WingetApplicationUpdateService.VersionTimeout, cancellationToken);
            return WingetOutput.ParseWingetVersion(result.Output);
        }
        catch (WingetException ex)
        {
            _logger.LogWarning("winget is installed but could not be run: {Error}", ex.Message);
            return null;
        }
    }

    private void Record(string? version, string? error, bool attempted, bool installedByAgent = false)
    {
        var now = _time.GetUtcNow();
        _state.Update(s =>
        {
            var w = s.Winget;
            w.InstalledByAgent = installedByAgent || (w.InstalledByAgent && version is not null && version == w.Version);
            w.Version = version;
            w.Error = error;
            w.CheckedAt = now;
            if (attempted)
            {
                w.LastAttemptAt = now;
            }

            w.Failures = error is null ? 0 : attempted ? w.Failures + 1 : w.Failures;
        });
    }

    private DateTimeOffset FirstCheck()
    {
        var now = _time.GetUtcNow();
        var winget = _state.Read(s => s.Winget);
        var soon = now + TimeSpan.FromMinutes(3) + TimeSpan.FromSeconds(Random.Shared.Next(0, 180));
        if (winget.Error is null || winget.LastAttemptAt is not { } attempt)
        {
            return soon; // check after every start; installation happens only when needed
        }

        var retry = attempt + RetryDelays[Math.Clamp(winget.Failures - 1, 0, RetryDelays.Length - 1)];
        return retry > soon ? retry : soon;
    }

    private TimeSpan RetryDelay()
    {
        if (_serverPreparing)
        {
            return ServerPreparingRetry;
        }

        var failures = _state.Read(s => s.Winget.Failures);
        return RetryDelays[Math.Clamp(failures - 1, 0, RetryDelays.Length - 1)];
    }

    private static long? FreeSpace(string directory)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(directory));
            return string.IsNullOrEmpty(root) ? null : new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not delete {Directory}.", directory);
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>Downloads the release files from a base URL over HTTPS (GitHub).</summary>
public sealed class HttpWingetFileSource(HttpClient http, string baseUrl, string name, TimeSpan timeout) : IWingetFileSource
{
    public string Name => name;

    public async Task DownloadAsync(WingetFile file, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(file);
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            using var response = await http.GetAsync(new Uri(baseUrl + Uri.EscapeDataString(file.Name)), HttpCompletionOption.ResponseHeadersRead,
                timeoutSource.Token);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"HTTP {(int)response.StatusCode}.", null, response.StatusCode);
            }

            if (response.RequestMessage?.RequestUri is { Scheme: not "https" })
            {
                throw new HttpRequestException("The download was redirected away from HTTPS.");
            }

            await using var source = await response.Content.ReadAsStreamAsync(timeoutSource.Token);
            await CopyLimitedAsync(source, destination, file.Size, timeoutSource.Token);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"The download took longer than {timeout.TotalMinutes:0} minutes.", ex);
        }
    }

    internal static async Task CopyLimitedAsync(Stream source, Stream destination, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException("The file is larger than the pinned release says.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }
}

/// <summary>Downloads the release files from the EasyPatch server's copy (used when GitHub cannot be reached).</summary>
public sealed class ServerWingetFileSource(Func<AgentApiClient?> client, TimeSpan timeout) : IWingetFileSource
{
    public string Name => "the EasyPatch server";

    public Task DownloadAsync(WingetFile file, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(file);
        var api = client() ?? throw new InvalidOperationException("The agent is not enrolled.");
        return api.DownloadWingetFileAsync(file.Name, destination, file.Size, timeout, cancellationToken);
    }
}
