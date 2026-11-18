namespace EasyPatch.Agent.Core.Util;

/// <summary>Exponential backoff with full jitter: delay = random(0, min(cap, base * 2^attempt)).</summary>
public sealed class ExponentialBackoff
{
    private readonly TimeSpan _base;
    private readonly TimeSpan _cap;
    private readonly Random _random;
    private int _attempt;

    public ExponentialBackoff(TimeSpan baseDelay, TimeSpan maxDelay, Random? random = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(baseDelay, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxDelay, baseDelay);

        _base = baseDelay;
        _cap = maxDelay;
        _random = random ?? Random.Shared;
    }

    public int Attempt => _attempt;

    /// <summary>Upper bound of the next delay (before jitter).</summary>
    public TimeSpan CurrentCeiling
    {
        get
        {
            var exponent = Math.Min(_attempt, 30);
            var ceilingTicks = Math.Min(_cap.Ticks, _base.Ticks * (1L << Math.Min(exponent, 20)));
            return TimeSpan.FromTicks(ceilingTicks);
        }
    }

    /// <summary>Returns the next delay and advances the attempt counter. Never below <paramref name="minimum"/>.</summary>
    public TimeSpan NextDelay(TimeSpan? minimum = null)
    {
        var ceiling = CurrentCeiling;
        _attempt++;
        var delay = TimeSpan.FromTicks((long)(_random.NextDouble() * ceiling.Ticks));
        if (delay < TimeSpan.FromSeconds(1))
        {
            delay = TimeSpan.FromSeconds(1);
        }

        if (minimum is { } min && delay < min)
        {
            delay = min > _cap ? _cap : min;
        }

        return delay;
    }

    public void Reset() => _attempt = 0;
}

public static class Jitter
{
    /// <summary>Applies ±<paramref name="percent"/>% random jitter to an interval (minimum 1 second).</summary>
    public static TimeSpan Apply(TimeSpan interval, int percent, Random? random = null)
    {
        random ??= Random.Shared;
        percent = Math.Clamp(percent, 0, 50);
        var factor = 1 + ((random.NextDouble() * 2) - 1) * (percent / 100.0);
        var ticks = (long)(interval.Ticks * factor);
        return TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerSecond, ticks));
    }

    /// <summary>Random delay in [min, max].</summary>
    public static TimeSpan Between(TimeSpan min, TimeSpan max, Random? random = null)
    {
        random ??= Random.Shared;
        if (max <= min)
        {
            return min;
        }

        return min + TimeSpan.FromTicks((long)(random.NextDouble() * (max - min).Ticks));
    }
}
