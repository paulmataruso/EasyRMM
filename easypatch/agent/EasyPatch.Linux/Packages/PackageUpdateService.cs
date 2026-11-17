using System.Security.Cryptography;
using System.Text;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Linux.Platform;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Packages;

/// <summary>A package upgrade found by the latest scan.</summary>
internal sealed class PackageHandle(PackageUpgrade upgrade, Guid updateGuid, int rebootBehavior) : IUpdateHandle
{
    public PackageUpgrade Upgrade { get; } = upgrade;

    public Guid UpdateGuid { get; } = updateGuid;

    public int RebootBehavior { get; } = rebootBehavior;

    public void Dispose()
    {
    }
}

/// <summary>
/// Linux updates: one update per newer version of an installed package, found and installed with apt or dnf. An update
/// is reported installed only when the package database shows that version (or a newer one) installed afterwards.
/// </summary>
public sealed class PackageUpdateService : IUpdateService, IBatchUpdateService, IDisposable
{
    private const string ClassificationType = "UpdateClassification";
    private const string ProductType = "Product";

    private readonly PackageBackend _backend;
    private readonly LinuxDistribution _distribution;
    private readonly string _ledgerPath;
    private readonly IRebootDetector? _rebootDetector;
    private readonly TransientUnitRunner _units;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _ledgerLock = new(1, 1);

    public PackageUpdateService(PackageBackend backend, LinuxDistribution distribution, string ledgerPath, TransientUnitRunner units,
        IRebootDetector? rebootDetector, TimeProvider time, ILogger<PackageUpdateService> logger)
    {
        _backend = backend;
        _distribution = distribution;
        _ledgerPath = ledgerPath;
        _units = units;
        _rebootDetector = rebootDetector;
        _time = time;
        _logger = logger;
    }

    public string Name => _backend.Name;

    public void Dispose() => _ledgerLock.Dispose();

    public (string Code, string Message) DescribeFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return (_backend.FailureCode, OutputRedactor.Redact(exception.Message));
    }

    // ------------------------------------------------------------------ scan

    public async Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken)
    {
        // A transaction started by an earlier agent process (before a restart) finishes first.
        await _units.WaitWhileRunningAsync(PackageBackend.PackagesUnit, PackageBackend.TransactionTimeout, cancellationToken);

        var upgrades = await _backend.FindUpgradesAsync(cancellationToken);
        var installed = await _backend.GetInstalledAsync(cancellationToken);
        var native = await _backend.GetNativeArchitectureAsync(cancellationToken);
        var now = _time.GetUtcNow();

        var found = new List<(ReportedUpdate Update, string Key, string Version, PackageUpgrade Upgrade)>();
        foreach (var upgrade in upgrades)
        {
            var installedVersion = upgrade.InstalledVersion ?? installed.GetValueOrDefault(upgrade.Key);
            var withInstalled = upgrade with { InstalledVersion = installedVersion };
            found.Add((Describe(withInstalled, native), upgrade.Key, upgrade.Version, withInstalled));
        }

        await _ledgerLock.WaitAsync(cancellationToken);
        try
        {
            var ledger = PackageLedger.Load(_ledgerPath);
            ledger.Record(found.Select(f => (f.Update, f.Key, f.Version)).ToList(), installed, _backend.CompareVersions, now);

            var missing = found.Select(f =>
            {
                var superseded = ledger.SupersededBy(f.Update.UpdateGuid, f.Key, f.Version, _backend.CompareVersions);
                var update = superseded.Count == 0 ? f.Update : f.Update with { SupersededUpdateGuids = superseded };
                return new UpdateCandidate(update, new PackageHandle(f.Upgrade, update.UpdateGuid, update.RebootBehavior ?? 0));
            }).ToList();

            var installedReports = includeInstalled
                ? ledger.Installed.Select(e => e.Update with
                {
                    IsInstalled = true,
                    Package = e.Update.Package is { } package ? package with { InstalledVersion = installed.GetValueOrDefault(e.Key) } : null,
                }).ToList()
                : [];

            try
            {
                ledger.Save();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Could not save the package ledger: {Message}", ex.Message);
            }

            _logger.LogInformation("{Name} scan: {Missing} upgrade(s) available ({Security} security), {Installed} recently installed.",
                Name, missing.Count, missing.Count(c => c.Update.Package?.Security == true), installedReports.Count);
            return new UpdateScanResult(missing, installedReports, microsoftUpdateRegistered: false);
        }
        finally
        {
            _ledgerLock.Release();
        }
    }

    /// <summary>Linux never refuses installations until a restart.</summary>
    public Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken) => Task.FromResult(false);

    /// <summary>The package managers' own histories are not reported (see docs/linux-agent.md).</summary>
    public Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<HistoryEntryReport>>([]);

    /// <summary>Jobs use the batch methods below; single updates report no percentage.</summary>
    public async Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken) =>
        (await DownloadAsync([update], cancellationToken))[0];

    public async Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken) =>
        (await InstallAsync([update], null, cancellationToken))[0];

    // ------------------------------------------------------------------ download

    public async Task<IReadOnlyList<UpdateOperationResult>> DownloadAsync(IReadOnlyList<IUpdateHandle> updates, CancellationToken cancellationToken)
    {
        var handles = Handles(updates);
        var all = await _backend.DownloadAsync(handles.Select(h => h.Upgrade).ToList(), cancellationToken);
        if (all.Succeeded)
        {
            return handles.Select(_ => Success(false)).ToList();
        }

        if (handles.Count == 1)
        {
            return [Failure(all.Output, "The download failed")];
        }

        // Find out which ones fail.
        var results = new List<UpdateOperationResult>(handles.Count);
        foreach (var handle in handles)
        {
            var one = await _backend.DownloadAsync([handle.Upgrade], cancellationToken);
            results.Add(one.Succeeded ? Success(false) : Failure(one.Output, "The download failed"));
        }

        return results;
    }

    // ------------------------------------------------------------------ install

    public async Task<IReadOnlyList<UpdateOperationResult>> InstallAsync(IReadOnlyList<IUpdateHandle> updates, IProgress<BatchInstallProgress>? progress,
        CancellationToken cancellationToken)
    {
        var handles = Handles(updates);
        var names = handles.Select(h => h.Upgrade.Name).ToHashSet(StringComparer.Ordinal);
        var started = new HashSet<string>(StringComparer.Ordinal);
        void OnStarted(string name)
        {
            if (names.Contains(name) && started.Add(name))
            {
                progress?.Report(new BatchInstallProgress(started.Count, names.Count, name));
            }
        }

        var outputs = new Dictionary<Guid, string>();
        var marks = await _backend.BeforeInstallAsync(cancellationToken);
        IReadOnlyDictionary<string, string> installed;
        try
        {
            var upgrades = handles.Select(h => h.Upgrade).ToList();
            var transaction = await _backend.InstallAsync(upgrades, OnStarted, cancellationToken);
            if (!transaction.Succeeded && await _backend.TryRepairAsync(transaction.Output, cancellationToken))
            {
                transaction = await _backend.InstallAsync(upgrades, OnStarted, cancellationToken);
            }

            foreach (var handle in handles)
            {
                outputs[handle.UpdateGuid] = transaction.Output;
            }

            installed = await _backend.GetInstalledAsync(cancellationToken);
            var unconfirmed = handles.Where(h => !IsInstalled(h, installed)).ToList();
            if (!transaction.Succeeded && handles.Count > 1 && unconfirmed.Count > 0)
            {
                // One package can fail the whole transaction: install the rest one at a time.
                _logger.LogWarning("The {Name} transaction failed; installing the {Count} remaining update(s) one at a time.", Name, unconfirmed.Count);
                foreach (var handle in unconfirmed)
                {
                    var single = await _backend.InstallAsync([handle.Upgrade], OnStarted, cancellationToken);
                    outputs[handle.UpdateGuid] = single.Output;
                }

                installed = await _backend.GetInstalledAsync(cancellationToken);
            }
        }
        finally
        {
            await _backend.AfterInstallAsync(marks, CancellationToken.None);
        }

        var reboot = await DetectRebootAsync(cancellationToken);
        var results = new List<UpdateOperationResult>(handles.Count);
        foreach (var handle in handles)
        {
            if (IsInstalled(handle, installed))
            {
                var needsRestart = reboot.Pending && (handle.RebootBehavior > 0 || reboot.Packages.Contains(handle.Upgrade.Name));
                results.Add(Success(needsRestart));
                _logger.LogInformation("Installed {Package} {Version}{Restart}.", handle.Upgrade.Name, handle.Upgrade.Version,
                    needsRestart ? " (restart required)" : string.Empty);
                continue;
            }

            var now = installed.GetValueOrDefault(handle.Upgrade.Key);
            var reason = now is null
                ? $"{handle.Upgrade.Name} is not installed after the {Name} transaction"
                : $"{handle.Upgrade.Name} {now} is still installed instead of {handle.Upgrade.Version}";
            results.Add(Failure(outputs.GetValueOrDefault(handle.UpdateGuid), reason));
        }

        progress?.Report(new BatchInstallProgress(names.Count, names.Count, null));
        return results;
    }

    private bool IsInstalled(PackageHandle handle, IReadOnlyDictionary<string, string> installed) =>
        installed.TryGetValue(handle.Upgrade.Key, out var version) && _backend.CompareVersions(version, handle.Upgrade.Version) >= 0;

    private async Task<(bool Pending, HashSet<string> Packages)> DetectRebootAsync(CancellationToken cancellationToken)
    {
        var packages = LinuxRebootDetector.ReadRebootRequiredPackages();
        if (_rebootDetector is null)
        {
            return (packages.Count > 0, packages);
        }

        try
        {
            var status = await _rebootDetector.DetectAsync(cancellationToken);
            return (status.Pending, packages);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Restart detection after installation failed.");
            return (packages.Count > 0, packages);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static List<PackageHandle> Handles(IReadOnlyList<IUpdateHandle> updates)
    {
        ArgumentNullException.ThrowIfNull(updates);
        return updates.Select(u => u as PackageHandle ?? throw new ArgumentException("Not a package update handle.", nameof(updates))).ToList();
    }

    private static UpdateOperationResult Success(bool rebootRequired) => new(UpdateOperationResult.Succeeded, 0, rebootRequired);

    private UpdateOperationResult Failure(string? output, string reason)
    {
        var detail = OutputRedactor.Summarize(output, 900);
        return new UpdateOperationResult(UpdateOperationResult.Failed, 0, false)
        {
            ErrorCode = _backend.FailureCode,
            Message = detail.Length == 0 ? reason + "." : $"{reason}: {detail}",
        };
    }

    /// <summary>Builds the update reported to the server for one upgrade.</summary>
    internal ReportedUpdate Describe(PackageUpgrade upgrade, string nativeArchitecture)
    {
        var foreign = upgrade.Architecture != nativeArchitecture && upgrade.Architecture is not ("all" or "noarch");
        var classification = upgrade.Security ? "Security Updates" : "Updates";
        var product = _distribution.ProductName;
        var repository = upgrade.Origins.Count == 0 ? null : string.Join(", ", upgrade.Origins);
        if (repository is { Length: > 250 })
        {
            repository = repository[..250];
        }

        var description = new StringBuilder()
            .Append($"Upgrades {upgrade.Name} ({upgrade.Architecture}) from {upgrade.InstalledVersion ?? "the installed version"} to {upgrade.Version}.");
        if (repository is not null)
        {
            description.Append($" Source: {repository}.");
        }

        if (upgrade.Advisories.Count > 0)
        {
            description.Append($" Advisories: {string.Join(", ", upgrade.Advisories)}.");
        }

        return new ReportedUpdate
        {
            UpdateGuid = UpdateGuidFor(_distribution, upgrade.Name, upgrade.Architecture, upgrade.Version),
            RevisionNumber = 1,
            Title = foreign ? $"{upgrade.Name} {upgrade.Version} ({upgrade.Architecture})" : $"{upgrade.Name} {upgrade.Version}",
            Description = description.ToString(),
            Categories =
            [
                new UpdateCategoryRef { Id = CategoryGuid(ClassificationType, classification), Name = classification, Type = ClassificationType },
                new UpdateCategoryRef { Id = CategoryGuid(ProductType, product), Name = product, Type = ProductType },
            ],
            MsrcSeverity = upgrade.Severity,
            RebootBehavior = RebootBehaviorOf(upgrade.Name),
            Package = new PackageUpdateInfo
            {
                Name = upgrade.Name,
                Architecture = upgrade.Architecture,
                Version = upgrade.Version,
                InstalledVersion = upgrade.InstalledVersion,
                Repository = repository,
                Security = upgrade.Security,
                Advisories = upgrade.Advisories,
                Cves = upgrade.Cves,
                SourcePackage = upgrade.Source,
            },
        };
    }

    /// <summary>The same version of the same package on the same distribution release is the same update everywhere.</summary>
    public static Guid UpdateGuidFor(LinuxDistribution distribution, string name, string architecture, string version)
    {
        ArgumentNullException.ThrowIfNull(distribution);
        return HashGuid($"easypatch-linux-package|{distribution.Id}|{distribution.ReleaseKey}|{name}|{architecture}|{version}");
    }

    private static Guid CategoryGuid(string type, string name) => HashGuid($"easypatch-linux-category|{type}|{name}");

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

    private static readonly HashSet<string> MayRequireRestart = new(StringComparer.Ordinal)
    {
        "libc6", "glibc", "systemd", "udev", "dbus", "dbus-broker", "dbus-daemon", "linux-firmware", "intel-microcode", "amd64-microcode",
        "microcode_ctl", "openssl-libs", "libssl3", "libssl3t64", "gnutls", "libgnutls30", "libgnutls30t64",
    };

    /// <summary>0 never, 1 always (a new kernel), 2 may need a restart (core libraries, firmware, microcode).</summary>
    public static int RebootBehaviorOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name.StartsWith("linux-image-", StringComparison.Ordinal) || name is "kernel" or "kernel-core" or "kernel-rt" or "kernel-rt-core" ||
            name.StartsWith("kernel-uek", StringComparison.Ordinal) && !name.Contains("devel", StringComparison.Ordinal))
        {
            return 1;
        }

        return MayRequireRestart.Contains(name) || name.StartsWith("firmware-", StringComparison.Ordinal) ? 2 : 0;
    }
}
