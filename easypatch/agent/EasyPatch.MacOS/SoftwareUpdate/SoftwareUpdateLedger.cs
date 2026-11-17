using System.Text.Json;
using EasyPatch.Agent.Core.State;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;

namespace EasyPatch.MacOS.SoftwareUpdate;

/// <summary>
/// What this agent has seen of Apple's updates. <c>softwareupdate --list</c> only shows what is missing, so an update that
/// was listed and then disappears is reported installed only when <c>softwareupdate --history</c> records that version, and
/// an older version of the same product that is no longer listed is reported superseded by the newer one. The ledger also
/// remembers which updates EasyPatch installed that complete at the next restart.
/// </summary>
public sealed class SoftwareUpdateLedger
{
    /// <summary>Installed updates are reported for this long, then forgotten (the server keeps them as installed).</summary>
    public static readonly TimeSpan InstalledRetention = TimeSpan.FromDays(30);

    /// <summary>Updates that are neither listed nor in the history any more are forgotten after this.</summary>
    public static readonly TimeSpan StaleRetention = TimeSpan.FromDays(30);

    private const int MaxEntries = 2_000;

    private readonly string _path;
    private readonly Data _data;

    private SoftwareUpdateLedger(string path, Data data)
    {
        _path = path;
        _data = data;
    }

    public sealed record Entry
    {
        public required ReportedUpdate Update { get; init; }

        /// <summary>The product without the version (<see cref="SoftwareUpdateCatalog.LineOf"/>).</summary>
        public required string Line { get; init; }
        public required string Version { get; init; }
        public DateTimeOffset LastListedAt { get; set; }
        public DateTimeOffset? InstalledAt { get; set; }
    }

    /// <summary>An update EasyPatch installed that completes when the Mac restarts.</summary>
    public sealed record PendingRestart
    {
        public required Guid UpdateGuid { get; init; }
        public required string Title { get; init; }

        /// <summary>The Mac's boot time when the update was installed; a different boot time means it has restarted since.</summary>
        public required DateTimeOffset BootTime { get; init; }
    }

    private sealed class Data
    {
        public List<Entry> Entries { get; set; } = [];
        public List<PendingRestart> PendingRestarts { get; set; } = [];
    }

    public IReadOnlyList<Entry> Entries => _data.Entries;

    public static SoftwareUpdateLedger Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Data? data = null;
        try
        {
            var bytes = AtomicFile.TryReadAllBytes(path);
            if (bytes is not null)
            {
                data = JsonSerializer.Deserialize<Data>(bytes, ContractJson.Options);
            }
        }
        catch (JsonException)
        {
            // A damaged ledger only loses installed/superseded reporting for updates seen before; start again.
        }

        data ??= new Data();
        data.Entries ??= [];
        data.PendingRestarts ??= [];
        return new SoftwareUpdateLedger(path, data);
    }

    public void Save() => AtomicFile.WriteAllBytes(_path, JsonSerializer.SerializeToUtf8Bytes(_data, ContractJson.Options));

    /// <summary>Records a scan: the updates listed now, and the installation history.</summary>
    public void Record(IReadOnlyList<(ReportedUpdate Update, string Line, string Version)> listed, IReadOnlyList<SoftwareUpdateHistoryEntry> history,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(listed);
        ArgumentNullException.ThrowIfNull(history);
        var byGuid = _data.Entries.ToDictionary(e => e.Update.UpdateGuid);
        foreach (var (update, line, version) in listed)
        {
            byGuid[update.UpdateGuid] = new Entry { Update = update, Line = line, Version = version, LastListedAt = now };
        }

        var listedGuids = listed.Select(l => l.Update.UpdateGuid).ToHashSet();
        var installed = history.Select(h => SoftwareUpdateCatalog.InstalledKey(h.Title, h.Version)).ToHashSet(StringComparer.Ordinal);
        foreach (var entry in byGuid.Values.Where(e => !listedGuids.Contains(e.Update.UpdateGuid) && e.InstalledAt is null))
        {
            if (installed.Contains(SoftwareUpdateCatalog.InstalledKey(entry.Line, entry.Version)))
            {
                entry.InstalledAt = now;
            }
        }

        _data.Entries = byGuid.Values
            .Where(e => listedGuids.Contains(e.Update.UpdateGuid) ||
                        (e.InstalledAt is { } at ? now - at < InstalledRetention : now - e.LastListedAt < StaleRetention))
            .OrderByDescending(e => e.LastListedAt)
            .Take(MaxEntries)
            .ToList();
    }

    /// <summary>Updates that were listed before and are recorded in the installation history since.</summary>
    public IEnumerable<Entry> Installed => _data.Entries.Where(e => e.InstalledAt is not null);

    /// <summary>Older versions of the same product, seen before and neither listed nor installed now: a listed update
    /// replaces them, like a superseding Windows update.</summary>
    public IReadOnlyList<Guid> SupersededBy(Guid updateGuid, string line, string version, IReadOnlySet<Guid> listed) =>
        _data.Entries
            .Where(e => e.Update.UpdateGuid != updateGuid && !listed.Contains(e.Update.UpdateGuid) && e.InstalledAt is null &&
                        string.Equals(e.Line, line, StringComparison.Ordinal) && SoftwareUpdateParser.CompareVersions(e.Version, version) < 0)
            .Select(e => e.Update.UpdateGuid)
            .ToList();

    /// <summary>Updates EasyPatch installed since the last restart that complete at the next one.</summary>
    public IReadOnlyList<PendingRestart> PendingRestarts(DateTimeOffset bootTime) =>
        _data.PendingRestarts.Where(p => SameBoot(p.BootTime, bootTime)).ToList();

    public void AddPendingRestart(Guid updateGuid, string title, DateTimeOffset bootTime)
    {
        _data.PendingRestarts.RemoveAll(p => p.UpdateGuid == updateGuid || !SameBoot(p.BootTime, bootTime));
        _data.PendingRestarts.Add(new PendingRestart { UpdateGuid = updateGuid, Title = title, BootTime = bootTime });
    }

    /// <summary>Forgets restarts that have happened.</summary>
    public void PrunePendingRestarts(DateTimeOffset bootTime) => _data.PendingRestarts.RemoveAll(p => !SameBoot(p.BootTime, bootTime));

    private static bool SameBoot(DateTimeOffset a, DateTimeOffset b) => (a - b).Duration() <= TimeSpan.FromSeconds(5);
}
