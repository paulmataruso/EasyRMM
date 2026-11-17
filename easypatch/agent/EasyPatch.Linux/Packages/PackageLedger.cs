using System.Text.Json;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;

namespace EasyPatch.Linux.Packages;

/// <summary>
/// The package upgrades this agent has reported as missing. A package manager only lists what is missing, so the ledger
/// is how an upgrade that was reported missing is later reported as installed (once that version or a newer one is
/// installed), and how an older upgrade is reported as superseded by a newer version of the same package.
/// </summary>
public sealed class PackageLedger
{
    /// <summary>Installed upgrades are reported for this long, then forgotten (the server keeps them as installed).</summary>
    public static readonly TimeSpan InstalledRetention = TimeSpan.FromDays(30);

    /// <summary>Upgrades that are neither missing nor installed any more (removed packages) are forgotten after this.</summary>
    public static readonly TimeSpan StaleRetention = TimeSpan.FromDays(30);

    private const int MaxEntries = 20_000;

    private readonly string _path;
    private Dictionary<Guid, Entry> _entries;

    private PackageLedger(string path, Dictionary<Guid, Entry> entries)
    {
        _path = path;
        _entries = entries;
    }

    public sealed record Entry
    {
        public required ReportedUpdate Update { get; init; }

        /// <summary><c>name:arch</c>.</summary>
        public required string Key { get; init; }
        public required string Version { get; init; }
        public DateTimeOffset LastMissingAt { get; set; }
        public DateTimeOffset? InstalledAt { get; set; }
    }

    public IReadOnlyCollection<Entry> Entries => _entries.Values;

    public static PackageLedger Load(string path)
    {
        try
        {
            var bytes = AtomicFile.TryReadAllBytes(path);
            if (bytes is not null && JsonSerializer.Deserialize<List<Entry>>(bytes, ContractJson.Options) is { } list)
            {
                return new PackageLedger(path, list.Where(e => e.Update is not null).GroupBy(e => e.Update.UpdateGuid).ToDictionary(g => g.Key, g => g.Last()));
            }
        }
        catch (JsonException)
        {
            // A damaged ledger only means installed upgrades are not reported as such; start over.
        }

        return new PackageLedger(path, []);
    }

    /// <summary>Records a scan: <paramref name="missing"/> are the upgrades found now; <paramref name="installed"/> maps
    /// <c>name:arch</c> to the installed version.</summary>
    public void Record(IReadOnlyList<(ReportedUpdate Update, string Key, string Version)> missing, IReadOnlyDictionary<string, string> installed,
        Func<string, string, int> compare, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(missing);
        ArgumentNullException.ThrowIfNull(installed);
        var current = new HashSet<Guid>();
        foreach (var (update, key, version) in missing)
        {
            current.Add(update.UpdateGuid);
            _entries[update.UpdateGuid] = new Entry
            {
                Update = update with { SupersededUpdateGuids = [], IsInstalled = false },
                Key = key,
                Version = version,
                LastMissingAt = now,
            };
        }

        foreach (var entry in _entries.Values.Where(e => !current.Contains(e.Update.UpdateGuid)))
        {
            var isInstalled = installed.TryGetValue(entry.Key, out var installedVersion) && compare(installedVersion, entry.Version) >= 0;
            if (isInstalled)
            {
                entry.InstalledAt ??= now;
            }
            else
            {
                entry.InstalledAt = null;
            }
        }

        _entries = _entries.Values
            .Where(e => current.Contains(e.Update.UpdateGuid) ||
                        (e.InstalledAt is { } at ? now - at < InstalledRetention : now - e.LastMissingAt < StaleRetention))
            .OrderByDescending(e => e.LastMissingAt)
            .Take(MaxEntries)
            .ToDictionary(e => e.Update.UpdateGuid);
    }

    /// <summary>Earlier upgrades of the same package that were never installed and are older than <paramref name="version"/>.</summary>
    public IReadOnlyList<Guid> SupersededBy(Guid updateGuid, string key, string version, Func<string, string, int> compare) =>
        _entries.Values
            .Where(e => e.Key == key && e.Update.UpdateGuid != updateGuid && e.InstalledAt is null && compare(e.Version, version) < 0)
            .Select(e => e.Update.UpdateGuid)
            .ToList();

    /// <summary>Upgrades reported missing earlier that are now installed.</summary>
    public IEnumerable<Entry> Installed => _entries.Values.Where(e => e.InstalledAt is not null);

    public void Save() => AtomicFile.WriteAllBytes(_path, JsonSerializer.SerializeToUtf8Bytes(_entries.Values.ToList(), ContractJson.Options));
}
