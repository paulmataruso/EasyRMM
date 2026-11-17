using System.Globalization;
using System.Net;
using System.Text.Json;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Agent.Core.Outbox;

public enum OutboxKind
{
    JobStatus,
    ScanResults,
    Inventory,
    History,
}

/// <summary>One persisted report waiting to be delivered.</summary>
public sealed record OutboxEnvelope
{
    public required long Sequence { get; init; }
    public required OutboxKind Kind { get; init; }
    public required string Route { get; init; }
    public Guid? JobId { get; init; }
    public long? JobSequence { get; init; }
    public ScanTrigger? ScanTrigger { get; init; }
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>The exact JSON body that will be signed and sent.</summary>
    public required string Body { get; init; }
}

public enum FlushResult
{
    /// <summary>Everything was delivered (or nothing was pending).</summary>
    Drained,

    /// <summary>A transient failure stopped the flush; retry after backoff.</summary>
    Retry,
}

/// <summary>
/// Durable, ordered queue of reports. Items are written to &lt;data&gt;/outbox before any send is attempted and
/// deleted only after the server returns 2xx, so reports survive network outages, service restarts and reboots.
/// Delivery is strictly in enqueue order, which keeps job status reports in sequence order.
/// </summary>
public sealed class ReportOutbox : IDisposable
{
    private const string Extension = ".json";

    private readonly string _directory;
    private readonly int _maxItems;
    private readonly long _maxBytes;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly SemaphoreSlim _flushGate = new(1, 1);
    private long _nextSequence;

    public ReportOutbox(string dataDirectory, int maxItems = 500, long maxBytes = 256L * 1024 * 1024, TimeProvider? timeProvider = null, ILogger<ReportOutbox>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        _directory = Path.Combine(dataDirectory, "outbox");
        Directory.CreateDirectory(_directory);
        AtomicFile.CleanupTemporaryFiles(_directory);
        _maxItems = Math.Max(10, maxItems);
        _maxBytes = Math.Max(1024 * 1024, maxBytes);
        _time = timeProvider ?? TimeProvider.System;
        _logger = (ILogger?)logger ?? NullLogger.Instance;
        _nextSequence = ListFiles().Select(f => f.Sequence).DefaultIfEmpty(0).Max() + 1;
    }

    /// <summary>Raised after an item is enqueued (the communication loop uses it to flush immediately).</summary>
    public event EventHandler? ItemEnqueued;

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return ListFiles().Count;
            }
        }
    }

    public void EnqueueJobStatus(Guid jobId, JobStatusReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        Enqueue(OutboxKind.JobStatus, AgentRoutes.JobStatus(jobId), report, jobId, report.Sequence, null);
    }

    public void EnqueueScanResults(ScanResultReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        Enqueue(OutboxKind.ScanResults, AgentRoutes.ScanResults, report, report.JobId, null, report.Trigger);
    }

    public void EnqueueInventory(InventoryReport report) =>
        Enqueue(OutboxKind.Inventory, AgentRoutes.Inventory, report, null, null, null);

    public void EnqueueHistory(HistoryReport report) =>
        Enqueue(OutboxKind.History, AgentRoutes.History, report, null, null, null);

    /// <summary>Job IDs that still have undelivered status reports (reported to the server as "held").</summary>
    public IReadOnlyCollection<Guid> PendingJobIds()
    {
        lock (_lock)
        {
            var ids = new HashSet<Guid>();
            foreach (var file in ListFiles().Where(f => f.Kind == OutboxKind.JobStatus))
            {
                var envelope = TryRead(file.Path);
                if (envelope?.JobId is { } id)
                {
                    ids.Add(id);
                }
            }

            return ids;
        }
    }

    public IReadOnlyList<OutboxEnvelope> Peek()
    {
        lock (_lock)
        {
            return ListFiles().Select(f => TryRead(f.Path)).OfType<OutboxEnvelope>().ToList();
        }
    }

    /// <summary>Delivers queued items in order. Auth failures propagate; transient failures stop the flush.</summary>
    public async Task<FlushResult> FlushAsync(AgentApiClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        await _flushGate.WaitAsync(cancellationToken);
        try
        {
            while (true)
            {
                OutboxFile? next;
                lock (_lock)
                {
                    next = ListFiles().FirstOrDefault();
                }

                if (next is null)
                {
                    return FlushResult.Drained;
                }

                var envelope = TryRead(next.Path);
                if (envelope is null)
                {
                    _logger.LogError("Discarding unreadable outbox item {File}.", Path.GetFileName(next.Path));
                    Delete(next.Path);
                    continue;
                }

                try
                {
                    await client.PostRawAsync(envelope.Route, System.Text.Encoding.UTF8.GetBytes(envelope.Body), cancellationToken);
                    Delete(next.Path);
                    _logger.LogDebug("Delivered {Kind} report #{Sequence}.", envelope.Kind, envelope.Sequence);
                }
                catch (AgentTransientException ex)
                {
                    _logger.LogInformation("Outbox delivery paused ({Count} pending): {Message}", Count, ex.Message);
                    return FlushResult.Retry;
                }
                catch (AgentRejectedException ex) when (IsPermanent(ex))
                {
                    // The server will never accept this report (e.g. the job no longer exists or the payload is
                    // invalid). Dropping it is the only way to unblock later reports; it is logged for diagnosis.
                    _logger.LogError("The server permanently rejected {Kind} report #{Sequence} (HTTP {Status}, {Code}); discarding it. {Message}",
                        envelope.Kind, envelope.Sequence, (int?)ex.StatusCode, ex.ErrorCode, ex.Message);
                    Delete(next.Path);
                }
            }
        }
        finally
        {
            _flushGate.Release();
        }
    }

    /// <summary>Deletes every queued item (used when identity is reset).</summary>
    public void Clear()
    {
        lock (_lock)
        {
            foreach (var file in ListFiles())
            {
                Delete(file.Path);
            }
        }
    }

    private static bool IsPermanent(AgentRejectedException ex) =>
        ex.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound or HttpStatusCode.Conflict
            or HttpStatusCode.Gone or HttpStatusCode.UnprocessableEntity or HttpStatusCode.RequestEntityTooLarge;

    private void Enqueue<T>(OutboxKind kind, string route, T payload, Guid? jobId, long? jobSequence, ScanTrigger? trigger)
    {
        var body = JsonSerializer.Serialize(payload, ContractJson.Options);
        lock (_lock)
        {
            var envelope = new OutboxEnvelope
            {
                Sequence = _nextSequence++,
                Kind = kind,
                Route = route,
                JobId = jobId,
                JobSequence = jobSequence,
                ScanTrigger = trigger,
                CreatedAt = _time.GetUtcNow(),
                Body = body,
            };
            var path = Path.Combine(_directory, FileName(envelope.Sequence, kind));
            AtomicFile.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(envelope, ContractJson.Options));
            EnforceBounds();
        }

        ItemEnqueued?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Keeps the outbox bounded. Order of sacrifice: older scheduled/startup scans that a newer scan has superseded,
    /// then older inventory, then older history. Job status and job-linked scans are never dropped.
    /// </summary>
    private void EnforceBounds()
    {
        var files = ListFiles();
        long totalBytes = files.Sum(f => f.Length);
        if (files.Count <= _maxItems && totalBytes <= _maxBytes)
        {
            return;
        }

        var droppable = new List<OutboxFile>();
        var scans = files.Where(f => f.Kind == OutboxKind.ScanResults).ToList();
        var latestScan = scans.LastOrDefault();
        foreach (var scan in scans)
        {
            if (scan == latestScan)
            {
                continue;
            }

            var envelope = TryRead(scan.Path);
            if (envelope is { JobId: null })
            {
                droppable.Add(scan);
            }
        }

        var inventories = files.Where(f => f.Kind == OutboxKind.Inventory).ToList();
        droppable.AddRange(inventories.Take(Math.Max(0, inventories.Count - 1)));
        var history = files.Where(f => f.Kind == OutboxKind.History).ToList();
        droppable.AddRange(history.Take(Math.Max(0, history.Count - 1)));

        var count = files.Count;
        foreach (var victim in droppable.OrderBy(f => f.Sequence))
        {
            if (count <= _maxItems && totalBytes <= _maxBytes)
            {
                break;
            }

            _logger.LogWarning("Outbox is full; dropping superseded {Kind} report #{Sequence}.", victim.Kind, victim.Sequence);
            Delete(victim.Path);
            count--;
            totalBytes -= victim.Length;
        }

        if (count > _maxItems || totalBytes > _maxBytes)
        {
            _logger.LogWarning("Outbox exceeds its limits ({Count} items) but holds only reports that must not be dropped.", count);
        }
    }

    private static string FileName(long sequence, OutboxKind kind) =>
        sequence.ToString("D12", CultureInfo.InvariantCulture) + "_" + kind + Extension;

    private List<OutboxFile> ListFiles()
    {
        var result = new List<OutboxFile>();
        foreach (var path in Directory.EnumerateFiles(_directory, "*" + Extension))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            var separator = name.IndexOf('_', StringComparison.Ordinal);
            if (separator <= 0 ||
                !long.TryParse(name.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var sequence) ||
                !Enum.TryParse<OutboxKind>(name.AsSpan(separator + 1), out var kind))
            {
                continue;
            }

            long length;
            try
            {
                length = new FileInfo(path).Length;
            }
            catch (IOException)
            {
                continue;
            }

            result.Add(new OutboxFile(path, sequence, kind, length));
        }

        result.Sort((a, b) => a.Sequence.CompareTo(b.Sequence));
        return result;
    }

    private OutboxEnvelope? TryRead(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            return JsonSerializer.Deserialize<OutboxEnvelope>(bytes, ContractJson.Options);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not read outbox item {File}.", Path.GetFileName(path));
            return null;
        }
    }

    private void Delete(string path)
    {
        lock (_lock)
        {
            AtomicFile.TryDelete(path);
        }
    }

    public void Dispose() => _flushGate.Dispose();

    private sealed record OutboxFile(string Path, long Sequence, OutboxKind Kind, long Length);
}
