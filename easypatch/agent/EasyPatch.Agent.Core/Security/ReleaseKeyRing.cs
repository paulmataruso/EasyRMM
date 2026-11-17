using System.Security.Cryptography;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Core.Security;

/// <summary>The release public keys built into the agent. An agent update is installed only if its signature verifies
/// against one of them; the server cannot add or replace keys.</summary>
public sealed class ReleaseKeyRing : IDisposable
{
    private readonly Dictionary<string, ECDsa> _keys = new(StringComparer.Ordinal);

    /// <exception cref="CryptographicException">The PEM text contains something other than ECDSA P-256 public keys.</exception>
    public ReleaseKeyRing(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            return;
        }

        foreach (var key in AgentRelease.ParsePublicKeys(pem))
        {
            var id = AgentRelease.KeyId(key);
            if (!_keys.TryAdd(id, key))
            {
                key.Dispose();
            }
        }
    }

    public static ReleaseKeyRing Empty => new(null);

    public IReadOnlyList<string> KeyIds => _keys.Keys.Order(StringComparer.Ordinal).ToList();

    public bool IsEmpty => _keys.Count == 0;

    public bool Verify(AgentUpdatePayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return _keys.TryGetValue(payload.KeyId, out var key) && AgentRelease.Verify(payload.Package, payload.Signature, key);
    }

    public void Dispose()
    {
        foreach (var key in _keys.Values)
        {
            key.Dispose();
        }

        _keys.Clear();
    }
}
