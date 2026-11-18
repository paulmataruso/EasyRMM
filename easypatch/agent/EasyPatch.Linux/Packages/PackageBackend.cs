using System.Text.Json;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using System.Text.RegularExpressions;
using EasyPatch.Linux.Platform;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Packages;

/// <summary>Outcome of one package-manager transaction.</summary>
/// <param name="ExitCode">The command's exit code (-1 when it was killed or could not run).</param>
/// <param name="Output">Its combined output (not yet redacted).</param>
public sealed record TransactionResult(int ExitCode, string Output)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// apt or dnf. Every command line is built here from fixed templates; the only variable parts are package names,
/// architectures and versions that the package manager itself reported and that passed <see cref="PackageNames"/>.
/// Commands that change installed packages run in the transient unit <see cref="PackagesUnit"/>.
/// </summary>
public abstract class PackageBackend
{
    /// <summary>Transient unit for package transactions.</summary>
    public const string PackagesUnit = "easypatch-packages";

    /// <summary>Package transactions are given this long (the package manager also waits up to 30 minutes for locks).</summary>
    public static readonly TimeSpan TransactionTimeout = TimeSpan.FromHours(3);

    protected static readonly TimeSpan QueryTimeout = TimeSpan.FromMinutes(5);
    protected static readonly TimeSpan RefreshTimeout = TimeSpan.FromMinutes(30);

    protected PackageBackend(ICommandRunner commands, TransientUnitRunner units, string workDirectory, ILogger logger)
    {
        Commands = commands;
        Units = units;
        WorkDirectory = workDirectory;
        Logger = logger;
    }

    protected ICommandRunner Commands { get; }

    protected TransientUnitRunner Units { get; }

    /// <summary>Holds the transaction logs (inside the agent's data directory).</summary>
    protected string WorkDirectory { get; }

    protected ILogger Logger { get; }

    /// <summary><c>apt</c> or <c>dnf</c>.</summary>
    public abstract string Name { get; }

    /// <summary>Agent package format: <c>deb</c> or <c>rpm</c>.</summary>
    public abstract string PackageFormat { get; }

    /// <summary>Error code prefix, e.g. <c>apt_failed</c>.</summary>
    public string FailureCode => Name + "_failed";

    /// <summary>Compares two versions with the package manager's rules.</summary>
    public abstract int CompareVersions(string a, string b);

    /// <summary>The machine's own architecture as the package manager names it (amd64, x86_64, …).</summary>
    public abstract Task<string> GetNativeArchitectureAsync(CancellationToken cancellationToken);

    /// <summary>Refreshes repository metadata and lists the upgrades of installed packages, classified (security or not).
    /// Throws <see cref="CommandException"/> when the package sources cannot be read.</summary>
    public abstract Task<IReadOnlyList<PackageUpgrade>> FindUpgradesAsync(CancellationToken cancellationToken);

    /// <summary>Installed packages: <c>name:arch</c> → version (the newest one for install-only packages such as kernels).</summary>
    public abstract Task<IReadOnlyDictionary<string, string>> GetInstalledAsync(CancellationToken cancellationToken);

    /// <summary>Downloads the packages for these upgrades (and their new dependencies) without installing anything.</summary>
    public abstract Task<TransactionResult> DownloadAsync(IReadOnlyList<PackageUpgrade> upgrades, CancellationToken cancellationToken);

    /// <summary>Installs exactly these versions in one transaction. <paramref name="onStarted"/> is called with the name of
    /// each package the package manager starts configuring.</summary>
    public abstract Task<TransactionResult> InstallAsync(IReadOnlyList<PackageUpgrade> upgrades, Action<string>? onStarted, CancellationToken cancellationToken);

    /// <summary>Called once before a set of install transactions (apt: remembers which packages are marked automatic).</summary>
    public virtual Task<object?> BeforeInstallAsync(CancellationToken cancellationToken) => Task.FromResult<object?>(null);

    /// <summary>Called once after the install transactions with the value <see cref="BeforeInstallAsync"/> returned.</summary>
    public virtual Task AfterInstallAsync(object? state, CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Repairs an interrupted earlier transaction when <paramref name="output"/> says one is blocking this one
    /// (apt: <c>dpkg --configure -a</c>). Returns true when a repair ran.</summary>
    public virtual Task<bool> TryRepairAsync(string output, CancellationToken cancellationToken) => Task.FromResult(false);

    /// <summary>Runs a transaction in the packages unit and returns its exit code and output.</summary>
    protected async Task<TransactionResult> RunTransactionAsync(string program, IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string> environment, string description, Action<string>? onLine, CancellationToken cancellationToken)
    {
        await Units.WaitWhileRunningAsync(PackagesUnit, TransactionTimeout, cancellationToken);
        Directory.CreateDirectory(WorkDirectory);
        var logPath = Path.Combine(WorkDirectory, "transaction.log");
        var exitCode = await Units.RunAsync(PackagesUnit, program, arguments, environment, logPath, description, TransactionTimeout, onLine, cancellationToken);
        string output;
        try
        {
            output = File.Exists(logPath) ? await File.ReadAllTextAsync(logPath, cancellationToken) : string.Empty;
        }
        catch (IOException ex)
        {
            output = $"(the transaction log could not be read: {ex.Message})";
        }

        Logger.LogInformation("{Program} finished with exit code {ExitCode}.", program, exitCode);
        if (exitCode != 0)
        {
            Logger.LogWarning("{Program} output: {Output}", program, OutputRedactor.Summarize(output, 4000));
        }

        return new TransactionResult(exitCode, output);
    }

    /// <summary>Runs a read-only query and throws when it fails.</summary>
    protected async Task<CommandResult> QueryAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null, params int[] acceptedExitCodes)
    {
        var result = await Commands.RunAsync(program, arguments, timeout, cancellationToken, environment);
        if (result.ExitCode != 0 && !acceptedExitCodes.Contains(result.ExitCode))
        {
            throw new CommandException($"{program} {arguments.FirstOrDefault(a => !a.StartsWith('-'))} failed (exit code {result.ExitCode}): " +
                                       OutputRedactor.Summarize(result.Combined));
        }

        return result;
    }
}

/// <summary>Debian and Ubuntu: apt-get, apt-cache, apt-mark, dpkg.</summary>
public sealed partial class AptBackend : PackageBackend
{
    private static readonly IReadOnlyDictionary<string, string> Environment = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["DEBIAN_FRONTEND"] = "noninteractive",
        ["DEBCONF_NONINTERACTIVE_SEEN"] = "true",
        ["APT_LISTCHANGES_FRONTEND"] = "none",
        ["APT_LISTBUGS_FRONTEND"] = "none",
    };

    // Keep the configuration files the administrator changed (and take new defaults where they did not).
    private static readonly string[] DpkgOptions =
        ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "-o", "DPkg::Lock::Timeout=1800"];

    private string? _nativeArchitecture;

    public AptBackend(ICommandRunner commands, TransientUnitRunner units, string workDirectory, ILogger logger)
        : base(commands, units, workDirectory, logger)
    {
    }

    public override string Name => "apt";

    public override string PackageFormat => "deb";

    public override int CompareVersions(string a, string b) => DebianVersion.Compare(a, b);

    public override async Task<string> GetNativeArchitectureAsync(CancellationToken cancellationToken)
    {
        if (_nativeArchitecture is null)
        {
            var result = await QueryAsync("dpkg", ["--print-architecture"], QueryTimeout, cancellationToken);
            _nativeArchitecture = result.StandardOutput.Trim();
        }

        return _nativeArchitecture;
    }

    public override async Task<IReadOnlyList<PackageUpgrade>> FindUpgradesAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken);

        var simulation = await QueryAsync("apt-get",
            ["-s", "-q", "-o", "Debug::NoLocking=true", "--with-new-pkgs", "upgrade"], QueryTimeout, cancellationToken, Environment);
        var upgrades = AptParsers.ParseSimulation(simulation.StandardOutput).ToList();
        if (upgrades.Count > 0)
        {
            // The server looks up security tracker data by source package (agent 1.4.0 and later). Optional: a failure
            // only means no CVEs for these upgrades.
            try
            {
                var sources = await QueryAsync("dpkg-query", ["-W", "-f=${Package}\t${Architecture}\t${source:Package}\n"], QueryTimeout,
                    cancellationToken, Environment);
                var byKey = AptParsers.ParseSourcePackages(sources.StandardOutput);
                for (var i = 0; i < upgrades.Count; i++)
                {
                    if (byKey.TryGetValue(upgrades[i].Key, out var source) || byKey.TryGetValue(upgrades[i].Name + ":all", out source))
                    {
                        upgrades[i] = upgrades[i] with { Source = source };
                    }
                }
            }
            catch (CommandException ex)
            {
                Logger.LogWarning("Could not read the source packages; updates are reported without them (no CVE matching): {Message}", ex.Message);
            }
        }

        // A point-release version can include a fix first published in the security repository: the upgrade is a
        // security update when the security repository has a version newer than the installed one.
        var unclassified = upgrades.Where(u => !u.Security).Select(u => u.Name).Distinct(StringComparer.Ordinal).ToList();
        if (unclassified.Count > 0)
        {
            var entries = new List<AptParsers.MadisonEntry>();
            foreach (var chunk in unclassified.Chunk(100))
            {
                var madison = await QueryAsync("apt-cache", ["madison", .. chunk], QueryTimeout, cancellationToken, Environment);
                entries.AddRange(AptParsers.ParseMadison(madison.StandardOutput));
            }

            for (var i = 0; i < upgrades.Count; i++)
            {
                if (!upgrades[i].Security && AptParsers.HasNewerSecurityVersion(upgrades[i], entries))
                {
                    upgrades[i] = upgrades[i] with { Security = true };
                }
            }
        }

        return upgrades;
    }

    /// <summary><c>apt-get update</c>, retried while another apt process holds the lists lock. Fails when there are no
    /// package sources or none could be read.</summary>
    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + RefreshTimeout;
        while (true)
        {
            var result = await Commands.RunAsync("apt-get", ["update", "-q"], RefreshTimeout, cancellationToken, Environment);
            var output = result.Combined;
            if (result.ExitCode != 0 && output.Contains("Could not get lock", StringComparison.Ordinal) && DateTime.UtcNow < deadline)
            {
                Logger.LogInformation("Another apt process holds the package lists lock; retrying apt-get update in 15 seconds.");
                await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
                continue;
            }

            var lines = output.Split('\n');
            var reached = lines.Count(l => l.StartsWith("Hit:", StringComparison.Ordinal) || l.StartsWith("Get:", StringComparison.Ordinal) ||
                                           l.StartsWith("Ign:", StringComparison.Ordinal));
            var failed = lines.Count(l => l.StartsWith("Err:", StringComparison.Ordinal));
            if (reached == 0 && failed == 0)
            {
                throw new CommandException("No apt package sources are configured, so updates cannot be found.");
            }

            if (result.ExitCode != 0 || reached == 0)
            {
                throw new CommandException($"apt-get update failed (exit code {result.ExitCode}): {OutputRedactor.Summarize(output)}");
            }

            if (failed > 0 || output.Contains("\nW: ", StringComparison.Ordinal))
            {
                Logger.LogWarning("apt-get update reported problems: {Output}", OutputRedactor.Summarize(output));
            }

            return;
        }
    }

    public override async Task<IReadOnlyDictionary<string, string>> GetInstalledAsync(CancellationToken cancellationToken)
    {
        var result = await QueryAsync("dpkg-query",
            ["-W", "-f=${Package}\\t${Architecture}\\t${Version}\\t${db:Status-Abbrev}\\n"], QueryTimeout, cancellationToken);
        return AptParsers.ParseInstalled(result.StandardOutput);
    }

    public override async Task<TransactionResult> DownloadAsync(IReadOnlyList<PackageUpgrade> upgrades, CancellationToken cancellationToken)
    {
        var native = await GetNativeArchitectureAsync(cancellationToken);
        string[] args = ["install", "-y", "-q", "--download-only", "--only-upgrade", "--no-remove", "-o", "DPkg::Lock::Timeout=1800", "--", .. Specs(upgrades, native)];
        var result = await Commands.RunAsync("apt-get", args, TransactionTimeout, cancellationToken, Environment);
        return new TransactionResult(result.ExitCode, result.Combined);
    }

    public override async Task<TransactionResult> InstallAsync(IReadOnlyList<PackageUpgrade> upgrades, Action<string>? onStarted, CancellationToken cancellationToken)
    {
        var native = await GetNativeArchitectureAsync(cancellationToken);
        string[] args = ["install", "-y", "-q", "--only-upgrade", "--no-remove", .. DpkgOptions, "--", .. Specs(upgrades, native)];
        return await RunTransactionAsync("apt-get", args, Environment, "EasyPatch package installation (apt-get)", line =>
        {
            var match = SettingUpRegex().Match(line);
            if (match.Success)
            {
                onStarted?.Invoke(match.Groups["name"].Value);
            }
        }, cancellationToken);
    }

    public override async Task<object?> BeforeInstallAsync(CancellationToken cancellationToken) => await ShowAutoAsync(cancellationToken);

    /// <summary><c>apt-get install</c> marks the packages it is given as manually installed. Packages that were automatic
    /// before are marked automatic again, so <c>apt autoremove</c> keeps working as it did.</summary>
    public override async Task AfterInstallAsync(object? state, CancellationToken cancellationToken)
    {
        if (state is not HashSet<string> before || before.Count == 0)
        {
            return;
        }

        try
        {
            var after = await ShowAutoAsync(cancellationToken);
            var restore = before.Where(p => !after.Contains(p)).Where(PackageNameWithArch).ToList();
            foreach (var chunk in restore.Chunk(200))
            {
                await QueryAsync("apt-mark", ["auto", "--", .. chunk], QueryTimeout, cancellationToken, Environment);
            }

            if (restore.Count > 0)
            {
                Logger.LogInformation("Marked {Count} upgraded package(s) as automatically installed again.", restore.Count);
            }
        }
        catch (CommandException ex)
        {
            Logger.LogWarning("Could not restore the automatic-install marks: {Message}", ex.Message);
        }
    }

    public override async Task<bool> TryRepairAsync(string output, CancellationToken cancellationToken)
    {
        if (!output.Contains("dpkg --configure -a", StringComparison.Ordinal))
        {
            return false;
        }

        Logger.LogWarning("An earlier dpkg run was interrupted; running dpkg --configure -a before installing.");
        var result = await RunTransactionAsync("dpkg", ["--force-confdef", "--force-confold", "--configure", "-a"], Environment,
            "EasyPatch package repair (dpkg --configure -a)", null, cancellationToken);
        return result.Succeeded;
    }

    private async Task<HashSet<string>> ShowAutoAsync(CancellationToken cancellationToken)
    {
        var result = await QueryAsync("apt-mark", ["showauto"], QueryTimeout, cancellationToken, Environment);
        return result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.Ordinal);
    }

    private static bool PackageNameWithArch(string value)
    {
        var colon = value.IndexOf(':', StringComparison.Ordinal);
        return colon < 0
            ? PackageNames.IsDebianName(value)
            : PackageNames.IsDebianName(value[..colon]) && PackageNames.IsArchitecture(value[(colon + 1)..]);
    }

    /// <summary><c>name=version</c>, or <c>name:arch=version</c> for a foreign architecture; the exact version that was
    /// scanned (and approved) is installed, never a newer one published since.</summary>
    internal static IEnumerable<string> Specs(IEnumerable<PackageUpgrade> upgrades, string native) =>
        upgrades.Select(u => (u.Architecture == native || u.Architecture == "all" ? u.Name : u.Name + ":" + u.Architecture) + "=" + u.Version);

    [GeneratedRegex(@"^Setting up (?<name>[a-z0-9][a-z0-9+.\-]*)(?::[a-z0-9_]+)? \(", RegexOptions.CultureInvariant)]
    private static partial Regex SettingUpRegex();
}

/// <summary>Red Hat Enterprise Linux 8+ and rebuilds: dnf (4) and rpm.</summary>
public sealed class DnfBackend : PackageBackend
{
    private static readonly IReadOnlyDictionary<string, string> NoEnvironment = new Dictionary<string, string>(StringComparer.Ordinal);

    private string? _nativeArchitecture;

    public DnfBackend(ICommandRunner commands, TransientUnitRunner units, string workDirectory, ILogger logger)
        : base(commands, units, workDirectory, logger)
    {
    }

    public override string Name => "dnf";

    public override string PackageFormat => "rpm";

    public override int CompareVersions(string a, string b) => RpmVersion.Compare(a, b);

    public override async Task<string> GetNativeArchitectureAsync(CancellationToken cancellationToken)
    {
        if (_nativeArchitecture is null)
        {
            var result = await QueryAsync("uname", ["-m"], QueryTimeout, cancellationToken);
            _nativeArchitecture = result.StandardOutput.Trim();
        }

        return _nativeArchitecture;
    }

    public override async Task<IReadOnlyList<PackageUpgrade>> FindUpgradesAsync(CancellationToken cancellationToken)
    {
        await QueryAsync("dnf", ["-q", "-y", "makecache", "--refresh"], RefreshTimeout, cancellationToken);

        var repos = await QueryAsync("dnf", ["-q", "-C", "repolist", "--enabled"], QueryTimeout, cancellationToken);
        var repoCount = repos.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Count(l => !l.StartsWith("repo id", StringComparison.Ordinal));
        if (repoCount == 0)
        {
            throw new CommandException("No dnf repositories are enabled, so updates cannot be found.");
        }

        // check-update exits 100 when there are updates, 0 when there are none.
        var check = await QueryAsync("dnf", ["-q", "-C", "check-update"], QueryTimeout, cancellationToken, null, 100);
        var upgrades = DnfParsers.ParseCheckUpdate(check.StandardOutput);
        if (upgrades.Count == 0)
        {
            return upgrades;
        }

        var installed = await GetInstalledAsync(cancellationToken);
        var advisories = await GetAdvisoriesAsync(cancellationToken);
        var byPackage = advisories.ToLookup(a => a.Name + ":" + a.Architecture, StringComparer.Ordinal);
        var cves = await GetCvesAsync(cancellationToken);

        var result = new List<PackageUpgrade>(upgrades.Count);
        foreach (var upgrade in upgrades)
        {
            var installedVersion = installed.GetValueOrDefault(upgrade.Key);
            var applicable = byPackage[upgrade.Key]
                .Where(a => (installedVersion is null || RpmVersion.Compare(a.Version, installedVersion) > 0) && RpmVersion.Compare(a.Version, upgrade.Version) <= 0)
                .ToList();
            var security = applicable.Where(a => a.IsSecurity).ToList();
            var advisoryIds = applicable.Select(a => a.Id).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            result.Add(upgrade with
            {
                InstalledVersion = installedVersion,
                Security = security.Count > 0,
                Severity = security.Select(a => a.Severity).OrderByDescending(DnfParsers.SeverityRank).FirstOrDefault(),
                Advisories = advisoryIds,
                Cves = cves.For(upgrade, installedVersion, advisoryIds),
            });
        }

        return result;
    }

    /// <summary>The advisories (errata) for the available upgrades. dnf4 (RHEL 8 to 10) prints a fixed text format; dnf5 (Fedora 41
    /// and later) prints a different table, so its JSON output is used instead.</summary>
    private async Task<IReadOnlyList<DnfParsers.Advisory>> GetAdvisoriesAsync(CancellationToken cancellationToken)
    {
        if (!await IsDnf5Async(cancellationToken))
        {
            return DnfParsers.ParseUpdateInfo(
                (await QueryAsync("dnf", ["-q", "-C", "updateinfo", "list", "--updates"], QueryTimeout, cancellationToken)).StandardOutput);
        }

        var output = (await QueryAsync("dnf", ["-q", "-C", "advisory", "list", "--updates", "--json"], QueryTimeout, cancellationToken)).StandardOutput;
        try
        {
            return DnfParsers.ParseAdvisoryJson(output);
        }
        catch (JsonException ex)
        {
            // Without advisories every upgrade is classified as Other; the upgrades themselves are still reported.
            Logger.LogWarning("Could not read the dnf5 advisory list, so no update is classified as a security update: {Message}", ex.Message);
            return [];
        }
    }

    /// <summary>CVE IDs per upgrade. dnf4: <c>updateinfo list --with-cve</c> lists each reference of each advisory per
    /// package (CVE IDs among other references). dnf5: <c>advisory info --json</c> gives the references per advisory. A
    /// failure only means no CVEs are reported; the scan itself goes on.</summary>
    private async Task<DnfCves> GetCvesAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!await IsDnf5Async(cancellationToken))
            {
                var output = (await QueryAsync("dnf", ["-q", "-C", "updateinfo", "list", "--updates", "--with-cve"], QueryTimeout, cancellationToken))
                    .StandardOutput;
                return new DnfCves(DnfParsers.ParseUpdateInfo(output).Where(a => DnfParsers.IsCve(a.Id)).ToList(), null);
            }

            var json = (await QueryAsync("dnf", ["-q", "-C", "advisory", "info", "--updates", "--json"], QueryTimeout, cancellationToken)).StandardOutput;
            return new DnfCves([], DnfParsers.ParseAdvisoryCves(json));
        }
        catch (Exception ex) when (ex is CommandException or JsonException)
        {
            Logger.LogWarning("Could not read the CVE references of the available updates; updates are reported without CVE IDs: {Message}", ex.Message);
            return new DnfCves([], null);
        }
    }

    /// <summary>CVE lookup for one scan: dnf4 rows are per package version, dnf5 rows per advisory.</summary>
    private sealed class DnfCves(IReadOnlyList<DnfParsers.Advisory> perPackage, IReadOnlyDictionary<string, IReadOnlyList<string>>? perAdvisory)
    {
        private readonly ILookup<string, DnfParsers.Advisory> byPackage = perPackage.ToLookup(a => a.Name + ":" + a.Architecture, StringComparer.Ordinal);

        public IReadOnlyList<string> For(PackageUpgrade upgrade, string? installedVersion, IReadOnlyList<string> advisories)
        {
            var cves = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var row in byPackage[upgrade.Key])
            {
                if ((installedVersion is null || RpmVersion.Compare(row.Version, installedVersion) > 0) && RpmVersion.Compare(row.Version, upgrade.Version) <= 0)
                {
                    cves.Add(row.Id);
                }
            }

            if (perAdvisory is not null)
            {
                foreach (var advisory in advisories)
                {
                    if (perAdvisory.TryGetValue(advisory, out var list))
                    {
                        cves.UnionWith(list);
                    }
                }
            }

            return cves.Take(PackageUpdateInfo.MaxCves).ToList();
        }
    }

    private async Task<bool> IsDnf5Async(CancellationToken cancellationToken)
    {
        var version = await QueryAsync("dnf", ["--version"], QueryTimeout, cancellationToken);
        return version.StandardOutput.TrimStart().StartsWith("dnf5", StringComparison.Ordinal);
    }

    public override async Task<IReadOnlyDictionary<string, string>> GetInstalledAsync(CancellationToken cancellationToken)
    {
        var result = await QueryAsync("rpm", ["-qa", "--qf", "%{NAME}\\t%{ARCH}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"], QueryTimeout, cancellationToken);
        return DnfParsers.ParseInstalled(result.StandardOutput);
    }

    public override async Task<TransactionResult> DownloadAsync(IReadOnlyList<PackageUpgrade> upgrades, CancellationToken cancellationToken)
    {
        string[] args = ["-y", "upgrade", "--downloadonly", "--", .. Specs(upgrades)];
        var result = await Commands.RunAsync("dnf", args, TransactionTimeout, cancellationToken);
        return new TransactionResult(result.ExitCode, result.Combined);
    }

    public override Task<TransactionResult> InstallAsync(IReadOnlyList<PackageUpgrade> upgrades, Action<string>? onStarted, CancellationToken cancellationToken)
    {
        string[] args = ["-y", "upgrade", "--", .. Specs(upgrades)];
        var names = upgrades.Select(u => u.Name).ToHashSet(StringComparer.Ordinal);
        return RunTransactionAsync("dnf", args, NoEnvironment, "EasyPatch package installation (dnf)", line =>
        {
            if (DnfParsers.ParseProgressPackage(line) is { } name && names.Contains(name))
            {
                onStarted?.Invoke(name);
            }
        }, cancellationToken);
    }

    /// <summary><c>name-[epoch:]version-release.arch</c>: the exact version that was scanned (and approved).</summary>
    internal static IEnumerable<string> Specs(IEnumerable<PackageUpgrade> upgrades) =>
        upgrades.Select(u => $"{u.Name}-{u.Version}.{u.Architecture}");
}
