using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Defender;

/// <summary>
/// The EasyPatch agent's Microsoft Defender exclusions (ADR-0070, slice B). For each working folder: lock it down, verify it, and only
/// then exclude it (as a path and as an Attack Surface Reduction exclusion); for each executable inside a verified folder: exclude it as
/// a process and allow it through Controlled Folder Access. Everything added is written to a record first, and only what is recorded is
/// ever removed. A Defender that is not the active antivirus is <c>not_applicable</c>, never a failure. The logic is here, apart from the
/// Windows calls (<see cref="IDefenderBackend"/>, <see cref="IFolderGuard"/>), so it is tested on every system.
/// </summary>
public sealed class DefenderExclusions(DefenderExclusionsOptions options, IDefenderBackend backend, IFolderGuard guard, ILogger logger, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>Whether Defender is the active antivirus with real-time protection on, or why not (null when it is).</summary>
    public static string? NotApplicableReason(DefenderPrefs prefs)
    {
        if (prefs.Missing)
        {
            return "Microsoft Defender is not installed on this computer.";
        }

        if (prefs.RunningMode.Length > 0 && !string.Equals(prefs.RunningMode, "Normal", StringComparison.OrdinalIgnoreCase))
        {
            return $"Microsoft Defender is not the active antivirus (running mode {prefs.RunningMode}).";
        }

        if (!prefs.AntivirusOn || !prefs.ServiceOn)
        {
            return "Microsoft Defender antivirus is off.";
        }

        return prefs.RealTimeOn ? null : "Microsoft Defender real-time protection is off.";
    }

    /// <summary>Locks down, verifies and excludes what qualifies, removes what no longer does, and reports. Never throws for a
    /// Defender failure: it is reported as <c>unavailable</c> or <c>refused</c>.</summary>
    public async Task<DefenderReport> ReconcileAsync(CancellationToken cancellationToken)
    {
        var record = DefenderRecord.Load(options.RecordFile, out _, out var corrupt);
        if (corrupt)
        {
            logger.LogWarning("The Defender record {File} cannot be read; exclusions already in Defender are treated as not ours.", options.RecordFile);
        }

        var reasons = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in options.Folders)
        {
            if (guard.Secure(folder) is { } reason)
            {
                reasons[folder] = reason;
                logger.LogWarning("Not excluding {Folder}: not_locked: {Reason}", folder, reason);
            }
        }

        DefenderPrefs prefs;
        try
        {
            prefs = await backend.ReadAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Microsoft Defender could not be read.");
            return Report(null, record, reasons, new Dictionary<(string, string), string>(), $"Microsoft Defender could not be read: {Brief(ex)}", unavailable: true);
        }

        if (NotApplicableReason(prefs) is { } notApplicable)
        {
            logger.LogInformation("Defender exclusions: not_applicable: {Reason}", notApplicable);
            return Report(prefs, record, reasons, new Dictionary<(string, string), string>(), notApplicable, unavailable: false, notApplicable: true);
        }

        if (prefs.NotAvailable is { } hidden)
        {
            return Report(prefs, record, reasons, new Dictionary<(string, string), string>(), hidden, unavailable: true);
        }

        var refusals = new Dictionary<(string Kind, string Path), string>();
        string? failure = null;

        // What no longer qualifies: a folder that is not locked down loses what the agent added for it.
        foreach (var entry in record.Entries.ToList())
        {
            var unqualified = reasons.Keys.Any(f => Under(entry.Path, f));
            if (unqualified && prefs.Listed(entry.Kind, entry.Path))
            {
                failure ??= await TryRemoveAsync(record, entry, cancellationToken);
            }
            else if (unqualified)
            {
                record.Drop(entry.Kind, entry.Path);
                record.Save(options.RecordFile);
            }
        }

        foreach (var (kind, path) in Wanted(reasons))
        {
            if (prefs.Listed(kind, path) && !record.Has(kind, path))
            {
                continue; // somebody else's: not recorded, not added again, never removed
            }

            if (prefs.Listed(kind, path))
            {
                continue; // ours and still there
            }

            // The record first, so a crash between the two never leaves an exclusion nothing will remove.
            record.Put(new DefenderEntry { Kind = kind, Path = path, At = _clock.GetUtcNow(), AgentVersion = options.AgentVersion });
            record.Save(options.RecordFile);
            try
            {
                await backend.AddAsync(kind, path, cancellationToken);
                logger.LogInformation("Defender exclusion added: {Kind} {Path} (by {Method})", kind, path, backend.Method);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                record.Drop(kind, path);
                record.Save(options.RecordFile);
                if (ex is DefenderRefusedException refused)
                {
                    refusals[(kind, path)] = refused.Message + (prefs.TamperProtected ? " (Tamper Protection is on)" : "");
                    logger.LogWarning("Defender refused the {Kind} exclusion {Path}: {Reason}", kind, path, refused.Message);
                }
                else
                {
                    failure ??= $"Defender could not be changed: {Brief(ex)}";
                    logger.LogWarning(ex, "Defender exclusion {Kind} {Path} could not be added.", kind, path);
                }
            }
        }

        DefenderPrefs after;
        try
        {
            after = await backend.ReadAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Report(prefs, record, reasons, refusals, $"Microsoft Defender could not be read back: {Brief(ex)}", unavailable: true);
        }

        return Report(after, record, reasons, refusals, failure, unavailable: failure is not null);
    }

    /// <summary>What is excluded now, without changing anything.</summary>
    public async Task<DefenderReport> StatusAsync(CancellationToken cancellationToken)
    {
        var record = DefenderRecord.Load(options.RecordFile, out _, out _);
        var reasons = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in options.Folders)
        {
            if (guard.Check(folder) is { } reason)
            {
                reasons[folder] = reason;
            }
        }

        try
        {
            var prefs = await backend.ReadAsync(cancellationToken);
            var notApplicable = NotApplicableReason(prefs);
            if (notApplicable is null && prefs.NotAvailable is { } hidden)
            {
                return Report(prefs, record, reasons, new Dictionary<(string, string), string>(), hidden, unavailable: true);
            }

            return Report(prefs, record, reasons, new Dictionary<(string, string), string>(), notApplicable, unavailable: false, notApplicable: notApplicable is not null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Report(null, record, reasons, new Dictionary<(string, string), string>(), $"Microsoft Defender could not be read: {Brief(ex)}", unavailable: true);
        }
    }

    /// <summary>Removes exactly the recorded entries, one call each, then deletes the record. With no readable record, removes only what
    /// matches the fixed set and only for folders that still verify. A failed removal keeps its entry in the record for a retry.</summary>
    public async Task<DefenderRemoveResult> RemoveAsync(CancellationToken cancellationToken)
    {
        var record = DefenderRecord.Load(options.RecordFile, out var found, out var corrupt);
        var removed = new List<string>();
        var left = new List<string>();

        DefenderPrefs prefs;
        try
        {
            prefs = await backend.ReadAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Defender could not be read; the exclusions stay and the record is kept for a retry.");
            return new DefenderRemoveResult(removed, record.Entries.Select(e => $"{e.Kind} {e.Path}").ToList(), RecordDeleted: false);
        }

        if (prefs.Missing)
        {
            // No Defender, so nothing of ours can be in it.
            DeleteRecord();
            return new DefenderRemoveResult(removed, left, RecordDeleted: true);
        }

        var targets = new List<DefenderEntry>();
        if (found && !corrupt)
        {
            targets.AddRange(record.Entries);
        }
        else
        {
            logger.LogWarning("The Defender record is {State}: removing only what matches the fixed set, for folders that verify.", found ? "corrupt" : "missing");
            foreach (var (kind, path) in Wanted(new Dictionary<string, string>(), verify: true))
            {
                if (prefs.Listed(kind, path))
                {
                    targets.Add(new DefenderEntry { Kind = kind, Path = path });
                }
                else
                {
                    left.Add($"{kind} {path} (not listed)");
                }
            }
        }

        var allRemoved = true;
        foreach (var entry in targets)
        {
            if (!prefs.Listed(entry.Kind, entry.Path))
            {
                record.Drop(entry.Kind, entry.Path); // already gone
                continue;
            }

            try
            {
                await backend.RemoveAsync(entry.Kind, entry.Path, cancellationToken);
                removed.Add($"{entry.Kind} {entry.Path}");
                record.Drop(entry.Kind, entry.Path);
                logger.LogInformation("Defender exclusion removed: {Kind} {Path}", entry.Kind, entry.Path);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                allRemoved = false;
                left.Add($"{entry.Kind} {entry.Path}");
                logger.LogWarning(ex, "Defender exclusion {Kind} {Path} could not be removed.", entry.Kind, entry.Path);
            }
        }

        if (allRemoved)
        {
            DeleteRecord();
            return new DefenderRemoveResult(removed, left, RecordDeleted: true);
        }

        if (found && !corrupt)
        {
            record.Save(options.RecordFile);
        }

        return new DefenderRemoveResult(removed, left, RecordDeleted: false);
    }

    private void DeleteRecord()
    {
        try
        {
            File.Delete(options.RecordFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "The Defender record {File} could not be deleted.", options.RecordFile);
        }
    }

    private async Task<string?> TryRemoveAsync(DefenderRecord record, DefenderEntry entry, CancellationToken cancellationToken)
    {
        try
        {
            await backend.RemoveAsync(entry.Kind, entry.Path, cancellationToken);
            record.Drop(entry.Kind, entry.Path);
            record.Save(options.RecordFile);
            logger.LogWarning("Defender exclusion removed because its folder is no longer locked down: {Kind} {Path}", entry.Kind, entry.Path);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Defender exclusion {Kind} {Path} could not be removed.", entry.Kind, entry.Path);
            return $"Defender could not be changed: {Brief(ex)}";
        }
    }

    /// <summary>Every (kind, path) the agent wants: the folders that are locked down as paths and ASR exclusions, and the programs inside
    /// them as processes and Controlled Folder Access applications. With <paramref name="verify"/>, the folders are checked here.</summary>
    private List<(string Kind, string Path)> Wanted(IReadOnlyDictionary<string, string> reasons, bool verify = false)
    {
        var good = options.Folders.Where(f => verify ? guard.Check(f) is null : !reasons.ContainsKey(f)).ToList();
        var wanted = new List<(string, string)>();
        foreach (var folder in good)
        {
            wanted.Add((DefenderKinds.Path, folder));
            wanted.Add((DefenderKinds.Asr, folder));
        }

        foreach (var program in options.Programs.Where(p => good.Exists(f => Under(p, f))))
        {
            wanted.Add((DefenderKinds.Process, program));
            wanted.Add((DefenderKinds.Cfa, program));
        }

        return wanted;
    }

    private static bool Under(string path, string folder)
    {
        var p = DefenderRecord.Normalize(path);
        var f = DefenderRecord.Normalize(folder);
        return p == f || p.StartsWith(f.TrimEnd('\\') + "\\", StringComparison.Ordinal);
    }

    private DefenderReport Report(
        DefenderPrefs? prefs, DefenderRecord record, Dictionary<string, string> reasons, Dictionary<(string Kind, string Path), string> refusals,
        string? reason, bool unavailable, bool notApplicable = false)
    {
        var folders = options.Folders
            .Select(f => new DefenderFolderReport(f, prefs?.Listed(DefenderKinds.Path, f) ?? false, record.Has(DefenderKinds.Path, f), reasons.GetValueOrDefault(f)))
            .ToList();
        var kinds = DefenderKinds.All.Select(k => KindState(k, prefs, record, reasons, refusals, notApplicable, unavailable, reason)).ToList();
        var (state, why) = Decide(prefs, reasons, kinds, reason, unavailable, notApplicable);
        return new DefenderReport(state, why, kinds, folders, backend.Method.Length > 0 ? backend.Method : null, options.AgentVersion);
    }

    private DefenderKindReport KindState(
        string kind, DefenderPrefs? prefs, DefenderRecord record, Dictionary<string, string> reasons, Dictionary<(string Kind, string Path), string> refusals,
        bool notApplicable, bool unavailable, string? reason)
    {
        if (notApplicable)
        {
            return new DefenderKindReport(kind, DefenderStates.NotApplicable, reason);
        }

        if (unavailable || prefs is null)
        {
            return new DefenderKindReport(kind, DefenderStates.Unavailable, reason);
        }

        var wanted = Wanted(reasons).Where(w => w.Kind == kind).Select(w => w.Path).ToList();
        if (wanted.Count == 0)
        {
            return new DefenderKindReport(kind, DefenderStates.NotLocked, "no folder of this agent could be locked down");
        }

        if (kind == DefenderKinds.Asr && prefs.AsrRules == 0)
        {
            return new DefenderKindReport(kind, DefenderStates.NotNeeded, "no Attack Surface Reduction rule is set");
        }

        if (kind == DefenderKinds.Cfa && !prefs.ControlledFolderAccessOn)
        {
            return new DefenderKindReport(kind, DefenderStates.NotNeeded, "Controlled Folder Access is off");
        }

        foreach (var path in wanted)
        {
            if (refusals.TryGetValue((kind, path), out var refused))
            {
                return new DefenderKindReport(kind, DefenderStates.Refused, refused);
            }

            if (!prefs.Listed(kind, path))
            {
                return new DefenderKindReport(kind, DefenderStates.Refused, $"{path} is not in Defender's list");
            }
        }

        return prefs.DisableLocalAdminMerge
            ? new DefenderKindReport(kind, DefenderStates.PresentNotEffective, "local exclusions are ignored (DisableLocalAdminMerge)")
            : new DefenderKindReport(kind, DefenderStates.Effective, null);
    }

    private static (string State, string? Reason) Decide(
        DefenderPrefs? prefs, Dictionary<string, string> reasons, List<DefenderKindReport> kinds, string? reason, bool unavailable, bool notApplicable)
    {
        if (notApplicable)
        {
            return (DefenderStates.NotApplicable, reason);
        }

        if (unavailable || prefs is null)
        {
            return (DefenderStates.Unavailable, reason ?? "Microsoft Defender cannot be read.");
        }

        if (reasons.Count > 0)
        {
            var first = reasons.First();
            return (DefenderStates.NotLocked, $"{first.Key}: {first.Value}");
        }

        if (kinds.Find(k => k.State == DefenderStates.Refused) is { } refused)
        {
            return (DefenderStates.Refused, refused.Reason);
        }

        if (kinds.Find(k => k.State == DefenderStates.PresentNotEffective) is { } ignored)
        {
            return (DefenderStates.PresentNotEffective, ignored.Reason);
        }

        return (DefenderStates.Effective, null);
    }

    private static string Brief(Exception ex)
    {
        var text = string.Join(' ', ex.Message.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return text.Length > 200 ? text[^200..] : text;
    }
}
