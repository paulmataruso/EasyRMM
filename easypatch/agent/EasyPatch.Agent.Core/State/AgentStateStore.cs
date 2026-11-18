using System.Text.Json;
using EasyPatch.Contracts.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Agent.Core.State;

/// <summary>
/// Thread-safe owner of <see cref="AgentState"/>. Every mutation is persisted atomically before
/// <see cref="Update{T}"/> returns, so the on-disk state is never behind what the agent has acted on.
/// </summary>
public sealed class AgentStateStore
{
    private readonly string _path;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private AgentState _state;

    public AgentStateStore(string dataDirectory, ILogger<AgentStateStore>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        var stateDirectory = Path.Combine(dataDirectory, "state");
        Directory.CreateDirectory(stateDirectory);
        AtomicFile.CleanupTemporaryFiles(stateDirectory);
        _path = Path.Combine(stateDirectory, "agent-state.json");
        _logger = (ILogger?)logger ?? NullLogger.Instance;
        _state = Load();
    }

    public string FilePath => _path;

    /// <summary>Returns a deep copy of the current state (safe to read without locking).</summary>
    public AgentState Snapshot()
    {
        lock (_lock)
        {
            return Clone(_state);
        }
    }

    /// <summary>Reads a value under the lock without copying the whole state.</summary>
    public T Read<T>(Func<AgentState, T> selector)
    {
        ArgumentNullException.ThrowIfNull(selector);
        lock (_lock)
        {
            return selector(_state);
        }
    }

    /// <summary>Applies a mutation and persists it atomically.</summary>
    public void Update(Action<AgentState> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        Update(state =>
        {
            mutate(state);
            return true;
        });
    }

    /// <summary>Applies a mutation; persists only when the delegate returns true. Returns that value.</summary>
    public bool Update(Func<AgentState, bool> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (_lock)
        {
            var working = Clone(_state);
            if (!mutate(working))
            {
                return false;
            }

            Persist(working);
            _state = working;
            return true;
        }
    }

    /// <summary>Applies a mutation that produces a result and persists it.</summary>
    public T Update<T>(Func<AgentState, T> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (_lock)
        {
            var working = Clone(_state);
            var result = mutate(working);
            Persist(working);
            _state = working;
            return result;
        }
    }

    /// <summary>Deletes all persisted identity/state (used by unenroll and forced re-enrollment).</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _state = new AgentState();
            AtomicFile.TryDelete(_path);
        }
    }

    private AgentState Load()
    {
        var bytes = AtomicFile.TryReadAllBytes(_path);
        if (bytes is null)
        {
            return new AgentState();
        }

        try
        {
            return JsonSerializer.Deserialize<AgentState>(bytes, ContractJson.Options) ?? new AgentState();
        }
        catch (JsonException ex)
        {
            // Never silently continue with a half-read identity: keep the corrupt file for diagnosis.
            var quarantine = _path + $".corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}";
            File.Copy(_path, quarantine, overwrite: true);
            _logger.LogError(ex, "Agent state file was unreadable and has been moved to {Quarantine}; starting with empty state.", quarantine);
            return new AgentState();
        }
    }

    private void Persist(AgentState state)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, ContractJson.Options);
        AtomicFile.WriteAllBytes(_path, bytes);
    }

    private static AgentState Clone(AgentState state) =>
        JsonSerializer.Deserialize<AgentState>(JsonSerializer.SerializeToUtf8Bytes(state, ContractJson.Options), ContractJson.Options)!;
}
