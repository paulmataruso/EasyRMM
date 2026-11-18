using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Security;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Jobs;

/// <summary>
/// Agent update jobs. The agent installs a package only when
/// <list type="number">
/// <item>its release signature verifies against a release key built into this agent (the server cannot supply keys),</item>
/// <item>it is newer than this agent and for this agent's architecture, and</item>
/// <item>the downloaded file has exactly the size and SHA-256 the signature covers (checked again just before
/// the installer starts, with the file held open against changes).</item>
/// </list>
/// The installer (Windows Installer, or apt/dnf in a separate systemd unit on Linux) upgrades the agent, which stops this
/// service and starts the new version. The job completes only when the new version is running and picks the job up
/// again; if the old version comes back instead, it fails.
/// </summary>
public sealed partial class AgentUpdateHandler
{
    /// <summary>The previous version waits this long for a running installation before giving up.</summary>
    public static readonly TimeSpan InstallTimeout = TimeSpan.FromMinutes(30);

    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(30);

    private const int DownloadAttempts = 3;

    private readonly AgentPlatform _platform;
    private readonly AgentStateStore _state;
    private readonly JobReporter _reporter;
    private readonly ReleaseKeyRing _keys;
    private readonly Func<AgentApiClient?> _client;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public AgentUpdateHandler(AgentPlatform platform, AgentStateStore state, JobReporter reporter, ReleaseKeyRing keys, Func<AgentApiClient?> client,
        AgentRuntimeOptions options, TimeProvider time, ILogger<AgentUpdateHandler> logger)
    {
        _platform = platform;
        _state = state;
        _reporter = reporter;
        _keys = keys;
        _client = client;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>True when this agent can install updates: it has an installer for its package format, knows its package
    /// architecture and was built with at least one release key.</summary>
    public bool CanUpdate => _platform.AgentInstaller is not null && !_keys.IsEmpty && _options.PackageArchitecture is not null &&
                             AgentRelease.ParseVersion(_options.AgentVersion) is not null;

    public IReadOnlyList<string> TrustedKeyIds => CanUpdate ? _keys.KeyIds : [];

    public async Task<JobOutcome> ExecuteAsync(JobRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var jobId = record.Job.JobId;
        if (record.AgentUpdate is { } launched)
        {
            return await CompleteAfterInstallAsync(jobId, launched, cancellationToken);
        }

        var payload = record.Job.AgentUpdate ?? throw new InvalidOperationException("The agent update job has no payload.");
        if (Check(payload) is { } problem)
        {
            return Fail(jobId, problem.Code, problem.Message);
        }

        var package = payload.Package;
        _reporter.Report(jobId, JobStatus.Running, "Downloading", 10,
            $"Downloading EasyPatch Agent {package.Version} ({package.SizeBytes / (1024 * 1024)} MB).");
        string path;
        try
        {
            path = await DownloadAsync(package, cancellationToken);
        }
        catch (UpdateFailure failure)
        {
            return Fail(jobId, failure.Code, failure.Message);
        }

        if (_state.Read(s => s.FindJob(jobId)?.CancelRequested == true))
        {
            Delete(path);
            _reporter.Report(jobId, JobStatus.Cancelled, "Cancelled", null, "Agent update cancelled by an administrator before it was installed.");
            return JobOutcome.Finished;
        }

        return await InstallAsync(jobId, package, path, cancellationToken);
    }

    // ------------------------------------------------------------------ checks

    private (string Code, string Message)? Check(AgentUpdatePayload payload)
    {
        var package = payload.Package;
        if (AgentRelease.Validate(package) is [var invalid, ..])
        {
            return ("update_invalid", invalid);
        }

        var format = _platform.AgentInstaller?.PackageFormat ?? AgentRelease.FormatMsi;
        if (AgentRelease.FormatOf(package.FileName) != format)
        {
            return ("update_wrong_format", $"{package.FileName} is not a {format} package, which this agent installs updates from.");
        }

        if (package.Architecture != _options.PackageArchitecture)
        {
            return ("update_wrong_architecture", $"{package.FileName} is for {package.Architecture}; this agent is {_options.PackageArchitecture}.");
        }

        if (AgentRelease.ParseVersion(package.Version) <= AgentRelease.ParseVersion(_options.AgentVersion))
        {
            return ("update_not_newer", $"EasyPatch Agent {_options.AgentVersion} is installed and {package.Version} is not newer. Agents are never downgraded.");
        }

        if (!_keys.KeyIds.Contains(payload.KeyId))
        {
            return ("update_untrusted_key",
                $"{package.FileName} is signed with release key {payload.KeyId}, which this agent does not trust ({string.Join(", ", _keys.KeyIds)}). It was not installed.");
        }

        if (!_keys.Verify(payload))
        {
            return ("update_signature_invalid", $"The release signature of {package.FileName} is not valid. It was not installed.");
        }

        return null;
    }

    // ------------------------------------------------------------------ download

    private async Task<string> DownloadAsync(AgentReleaseManifest package, CancellationToken cancellationToken)
    {
        var directory = _options.UpdateDirectory;
        string partial;
        string final;
        try
        {
            Directory.CreateDirectory(directory);
            CleanUp(directory);
            final = Path.Combine(directory, package.FileName);
            partial = final + ".partial";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new UpdateFailure("update_download_failed", $"Could not prepare {directory}: {ex.Message}");
        }

        for (var attempt = 1; ; attempt++)
        {
            var client = _client() ?? throw new UpdateFailure("update_download_failed", "The agent is not connected to a server.");
            try
            {
                await using (var file = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await client.DownloadAgentPackageAsync(package.FileName, file, package.SizeBytes, DownloadTimeout, cancellationToken);
                }

                break;
            }
            catch (AgentTransientException ex) when (attempt < DownloadAttempts)
            {
                var delay = _options.BackoffBase * Math.Pow(3, attempt);
                _logger.LogWarning("Downloading {Package} failed; retrying in {Delay:g}: {Message}", package.FileName, delay, ex.Message);
                await Task.Delay(delay, cancellationToken);
            }
            catch (AgentApiException ex)
            {
                Delete(partial);
                throw new UpdateFailure("update_download_failed", ex.Message);
            }
            catch (InvalidDataException ex)
            {
                Delete(partial);
                throw new UpdateFailure("update_hash_mismatch", ex.Message + " It was not installed.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Delete(partial);
                throw new UpdateFailure("update_download_failed", $"Could not save {package.FileName}: {ex.Message}");
            }
        }

        string hash;
        long size;
        await using (var stream = new FileStream(partial, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            size = stream.Length;
            hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
        }

        if (size != package.SizeBytes || hash != package.Sha256)
        {
            Delete(partial);
            throw new UpdateFailure("update_hash_mismatch",
                $"The downloaded {package.FileName} does not match its release signature (SHA-256 {hash}, expected {package.Sha256}). It was not installed.");
        }

        File.Move(partial, final, overwrite: true);
        return final;
    }

    // ------------------------------------------------------------------ install

    private async Task<JobOutcome> InstallAsync(Guid jobId, AgentReleaseManifest package, string path, CancellationToken cancellationToken)
    {
        var installer = _platform.AgentInstaller!;
        var waitingSince = _time.GetUtcNow();
        var reportedWait = false;
        while (installer.IsInstallerBusy())
        {
            if (_time.GetUtcNow() - waitingSince > InstallTimeout)
            {
                Delete(path);
                return Fail(jobId, "update_installer_busy",
                    $"Another {installer.DisplayName} installation was still running after {InstallTimeout.TotalMinutes:0} minutes, so the agent was not updated.");
            }

            if (!reportedWait)
            {
                reportedWait = true;
                _reporter.Report(jobId, JobStatus.Running, "Waiting", 50, $"Waiting for another {installer.DisplayName} installation to finish.");
            }

            await Task.Delay(_options.InstallerPollInterval, cancellationToken);
        }

        var logPath = Path.Combine(_options.UpdateDirectory, $"install-{package.Version}.log");

        // Hold the package open without write sharing from the last hash check until the installer has finished with it.
        // The handle is closed before the package is deleted (Windows cannot delete an open file).
        int? exitCode = null;
        var changed = false;
        string? startFailure = null;
        await using (var hold = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(hold, cancellationToken));
            if (hold.Length != package.SizeBytes || hash != package.Sha256)
            {
                changed = true;
            }
            else
            {
                StartedInstalling(jobId, package, path, logPath);
                SuspendTrays(true);
                await WaitForTraysToCloseAsync(cancellationToken);
                try
                {
                    using var process = installer.Start(path, logPath);
                    exitCode = await process.WaitForExitAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    // The installer is stopping this service to replace it. The new version finishes the job.
                    throw;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    startFailure = ex.Message;
                }
            }
        }

        Delete(path);
        if (changed)
        {
            return Fail(jobId, "update_hash_mismatch", $"{package.FileName} changed on disk after it was verified. It was not installed.");
        }

        // The installer could not be started, or it finished while this process is still running: the upgrade did not replace it.
        SuspendTrays(false);
        ClearLaunch(jobId);
        if (exitCode is not { } code)
        {
            return Fail(jobId, "update_install_failed", $"{installer.DisplayName} could not be started: {startFailure}");
        }

        return Fail(jobId, "update_install_failed", installer.IsSuccess(code)
            ? $"{installer.DisplayName} reported success (exit code {code}) but did not replace the running agent {_options.AgentVersion}. Log: {logPath}"
            : $"{installer.DisplayName} failed with exit code {code}{installer.DescribeResult(code)}. EasyPatch Agent {_options.AgentVersion} is still installed. Log: {logPath}");
    }

    /// <summary>Records the launch in the job's state (the next version of the agent completes the job from it) and reports it.</summary>
    private void StartedInstalling(Guid jobId, AgentReleaseManifest package, string path, string logPath)
    {
        var now = _time.GetUtcNow();
        _state.Update(s =>
        {
            var record = s.FindJob(jobId);
            if (record is not null)
            {
                record.AgentUpdate = new AgentUpdateProgress
                {
                    FromVersion = _options.AgentVersion,
                    TargetVersion = package.Version,
                    PackagePath = path,
                    LogPath = logPath,
                    LaunchedAt = now,
                };
            }
        });
        _reporter.Report(jobId, JobStatus.Running, "Installing", 60,
            $"Installing EasyPatch Agent {package.Version}. The agent service restarts; the job completes when {package.Version} is running.");
        _logger.LogInformation(AgentEventIds.AgentUpdateStarted,
            "Installing EasyPatch Agent {Target} (release key verified, SHA-256 {Sha256}); this service ({Current}) will be restarted by {Installer}.",
            package.Version, package.Sha256, _options.AgentVersion, _platform.AgentInstaller?.DisplayName);
    }

    private async Task<JobOutcome> CompleteAfterInstallAsync(Guid jobId, AgentUpdateProgress progress, CancellationToken cancellationToken)
    {
        var current = AgentRelease.ParseVersion(_options.AgentVersion);
        if (current >= AgentRelease.ParseVersion(progress.TargetVersion))
        {
            Delete(progress.PackagePath);
            _reporter.Report(jobId, JobStatus.Completed, "Completed", 100,
                $"EasyPatch Agent updated from {progress.FromVersion} to {_options.AgentVersion}.");
            _logger.LogInformation(AgentEventIds.AgentUpdated, "EasyPatch Agent updated from {From} to {To}.", progress.FromVersion, _options.AgentVersion);
            return JobOutcome.Finished;
        }

        // The previous version is running: the installation is still going on, or it failed (Windows Installer rolled the
        // product back; apt/dnf left the old package installed).
        var installer = _platform.AgentInstaller;
        var name = installer?.DisplayName ?? "The installer";
        while (installer?.IsInstallerBusy() == true)
        {
            if (_time.GetUtcNow() - progress.LaunchedAt > InstallTimeout)
            {
                return Fail(jobId, "update_install_timeout",
                    $"{name} was still running {InstallTimeout.TotalMinutes:0} minutes after the update to {progress.TargetVersion} started. Log: {progress.LogPath}");
            }

            await Task.Delay(_options.InstallerPollInterval, cancellationToken);
        }

        Delete(progress.PackagePath);
        var error = installer?.ReadResult(progress.LogPath);
        return Fail(jobId, "update_install_failed",
            $"EasyPatch Agent {progress.TargetVersion} was not installed" +
            (error is { } code && installer is not null && !installer.IsSuccess(code) ? $": {name} error {code}{installer.DescribeResult(code)}" : string.Empty) +
            $". Version {_options.AgentVersion} is still running. Log: {progress.LogPath}");
    }

    // ------------------------------------------------------------------ helpers

    private JobOutcome Fail(Guid jobId, string code, string message)
    {
        _logger.LogWarning(AgentEventIds.AgentUpdateFailed, "Agent update job {JobId} failed ({Code}): {Message}", jobId, code, message);
        _reporter.Report(jobId, JobStatus.Failed, "Failed", null, message, errorCode: code, errorMessage: message);
        return JobOutcome.Finished;
    }

    private void ClearLaunch(Guid jobId) => _state.Update(s =>
    {
        if (s.FindJob(jobId) is { } record)
        {
            record.AgentUpdate = null;
        }
    });

    private void SuspendTrays(bool suspended)
    {
        try
        {
            _platform.Users.SuspendTrays(suspended);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not {Action} the trays.", suspended ? "close" : "reopen");
        }
    }

    private async Task WaitForTraysToCloseAsync(CancellationToken cancellationToken)
    {
        for (var i = 0; i < 20; i++)
        {
            int open;
            try
            {
                open = _platform.Users.GetSessions().TrayConnected;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not count the trays.");
                return;
            }

            if (open == 0)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
        }
    }

    /// <summary>Deletes leftover packages and partial downloads, and installer logs older than 30 days.</summary>
    private void CleanUp(string directory)
    {
        var cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-30);
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            var name = Path.GetFileName(file);
            var stale = AgentRelease.FormatOf(name) is not null || name.EndsWith(".partial", StringComparison.OrdinalIgnoreCase) ||
                        (name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) && File.GetLastWriteTimeUtc(file) < cutoff);
            if (stale)
            {
                Delete(file);
            }
        }
    }

    private void Delete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not delete {Path}.", path);
        }
    }

    [GeneratedRegex(@"(?:MainEngineThread is returning|Installation success or error status:) (\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex InstallerResultRegex();

    /// <summary>The final result code from a verbose Windows Installer log (ANSI or UTF-16), or null.</summary>
    public static int? ReadInstallerResult(string logPath)
    {
        try
        {
            if (!File.Exists(logPath))
            {
                return null;
            }

            using var stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var bom = new byte[2];
            var unicode = stream.Read(bom, 0, 2) == 2 && bom[0] == 0xFF && bom[1] == 0xFE;
            const int tail = 512 * 1024;
            if (stream.Length > tail)
            {
                stream.Seek(-tail, SeekOrigin.End);
            }
            else
            {
                stream.Seek(unicode ? 2 : 0, SeekOrigin.Begin);
            }

            using var reader = new StreamReader(stream, unicode ? Encoding.Unicode : Encoding.Latin1, detectEncodingFromByteOrderMarks: false);
            var matches = InstallerResultRegex().Matches(reader.ReadToEnd());
            for (var i = matches.Count - 1; i >= 0; i--)
            {
                if (int.TryParse(matches[i].Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var code) && code != 0)
                {
                    return code;
                }
            }

            return matches.Count > 0 ? 0 : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static string DescribeInstallerError(int code) => code switch
    {
        1601 => " (the Windows Installer service could not be accessed)",
        1602 => " (the installation was cancelled)",
        1603 => " (a fatal error occurred during installation)",
        1618 => " (another installation was already in progress)",
        1619 => " (the package could not be opened)",
        1620 => " (the package is not a valid Windows Installer package)",
        1625 => " (installation is prohibited by system policy)",
        1638 => " (another version of the product is already installed)",
        1639 => " (invalid command line)",
        1641 or 3010 => " (Windows must restart to finish the installation)",
        _ => string.Empty,
    };

    private sealed class UpdateFailure(string code, string message) : Exception(message)
    {
        public string Code { get; } = code;
    }
}
