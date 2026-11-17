namespace EasyPatch.Communication;

/// <summary>
/// Tracks the difference between the server's clock and the local clock so signed requests stay inside the
/// server's ±5 minute window even when the endpoint's clock is wrong. TLS still authenticates the server;
/// the offset only shifts the timestamp the agent signs.
/// </summary>
public sealed class ServerClock
{
    /// <summary>Offsets smaller than this are treated as noise (HTTP Date has 1 s resolution plus latency).</summary>
    private static readonly TimeSpan NoiseThreshold = TimeSpan.FromSeconds(5);

    private readonly TimeProvider _timeProvider;
    private readonly Lock _lock = new();
    private TimeSpan _offset;

    public ServerClock(TimeProvider? timeProvider = null, TimeSpan initialOffset = default)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _offset = initialOffset;
    }

    /// <summary>Raised when the offset changes materially (so it can be persisted).</summary>
    public event EventHandler<TimeSpan>? OffsetChanged;

    public TimeSpan Offset
    {
        get
        {
            lock (_lock)
            {
                return _offset;
            }
        }
    }

    /// <summary>Best estimate of the server's current time.</summary>
    public DateTimeOffset Now => _timeProvider.GetUtcNow() + Offset;

    public DateTimeOffset LocalNow => _timeProvider.GetUtcNow();

    /// <summary>Records a server timestamp observation (HTTP Date header or a serverTime field).</summary>
    public void Observe(DateTimeOffset serverTime)
    {
        var measured = serverTime - _timeProvider.GetUtcNow();
        TimeSpan updated;
        lock (_lock)
        {
            // Ignore jitter when we are already close; this keeps the offset stable for accurate clocks.
            if ((measured - _offset).Duration() < NoiseThreshold)
            {
                return;
            }

            _offset = measured.Duration() < NoiseThreshold ? TimeSpan.Zero : measured;
            updated = _offset;
        }

        OffsetChanged?.Invoke(this, updated);
    }
}
