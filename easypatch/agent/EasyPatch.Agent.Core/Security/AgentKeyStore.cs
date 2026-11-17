using System.Security.Cryptography;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Agent.Core.Security;

/// <summary>
/// Owns the agent's ECDSA P-256 private key. The key is generated on the device, stored as PKCS#8 protected by
/// <see cref="ISecretProtector"/> (DPAPI LocalMachine on Windows) and never transmitted. A second "pending" key
/// supports idempotent credential rotation.
/// </summary>
public sealed class AgentKeyStore : IDisposable
{
    private readonly string _keyPath;
    private readonly string _pendingPath;
    private readonly ISecretProtector _protector;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private ECDsa? _current;
    private ECDsa? _pending;

    public AgentKeyStore(string dataDirectory, ISecretProtector protector, ILogger<AgentKeyStore>? logger = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataDirectory);
        Directory.CreateDirectory(dataDirectory);
        _keyPath = Path.Combine(dataDirectory, "agent.key");
        _pendingPath = Path.Combine(dataDirectory, "agent.key.pending");
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    /// <summary>Returns the persisted key, generating and persisting one first if none exists.</summary>
    public ECDsa GetOrCreate()
    {
        lock (_lock)
        {
            if (_current is not null)
            {
                return _current;
            }

            _current = LoadKey(_keyPath);
            if (_current is null)
            {
                _current = AgentKeys.Generate();
                SaveKey(_keyPath, _current);
                _logger.LogInformation("Generated a new agent key with fingerprint {Fingerprint}.", Fingerprint(_current));
            }

            return _current;
        }
    }

    /// <summary>Returns the current key if one exists on disk.</summary>
    public ECDsa? TryGetCurrent()
    {
        lock (_lock)
        {
            return _current ??= LoadKey(_keyPath);
        }
    }

    /// <summary>Returns the pending rotation key, creating and persisting it if needed (so retries reuse it).</summary>
    public ECDsa GetOrCreatePending()
    {
        lock (_lock)
        {
            if (_pending is not null)
            {
                return _pending;
            }

            _pending = LoadKey(_pendingPath);
            if (_pending is null)
            {
                _pending = AgentKeys.Generate();
                SaveKey(_pendingPath, _pending);
            }

            return _pending;
        }
    }

    /// <summary>Makes the pending key the current key.</summary>
    public void PromotePending()
    {
        lock (_lock)
        {
            if (!File.Exists(_pendingPath))
            {
                return;
            }

            File.Move(_pendingPath, _keyPath, overwrite: true);
            _current?.Dispose();
            _current = _pending ?? LoadKey(_keyPath);
            _pending = null;
        }
    }

    /// <summary>
    /// Reconciles key files with the fingerprint recorded in state (finishes a rotation interrupted between
    /// saving the new credential and promoting the key). Returns false when no key matches.
    /// </summary>
    public bool EnsureMatches(string? expectedFingerprint)
    {
        if (string.IsNullOrEmpty(expectedFingerprint))
        {
            return TryGetCurrent() is not null;
        }

        lock (_lock)
        {
            _current ??= LoadKey(_keyPath);
            if (_current is not null && Fingerprint(_current) == expectedFingerprint)
            {
                return true;
            }

            _pending ??= LoadKey(_pendingPath);
            if (_pending is not null && Fingerprint(_pending) == expectedFingerprint)
            {
                _logger.LogWarning("Completing an interrupted credential rotation (promoting the pending key).");
                File.Move(_pendingPath, _keyPath, overwrite: true);
                _current?.Dispose();
                _current = _pending;
                _pending = null;
                return true;
            }

            return false;
        }
    }

    /// <summary>Deletes all key material (unenroll / forced re-enrollment / expired request).</summary>
    public void DeleteAll()
    {
        lock (_lock)
        {
            _current?.Dispose();
            _pending?.Dispose();
            _current = null;
            _pending = null;
            AtomicFile.TryDelete(_keyPath);
            AtomicFile.TryDelete(_pendingPath);
        }
    }

    public static string Fingerprint(ECDsa key) => AgentKeys.Fingerprint(AgentKeys.ExportPublicKey(key));

    public static string PublicKeyBase64(ECDsa key) => Convert.ToBase64String(AgentKeys.ExportPublicKey(key));

    public void Dispose()
    {
        lock (_lock)
        {
            _current?.Dispose();
            _pending?.Dispose();
            _current = null;
            _pending = null;
        }
    }

    private ECDsa? LoadKey(string path)
    {
        var bytes = AtomicFile.TryReadAllBytes(path);
        if (bytes is null)
        {
            return null;
        }

        byte[]? pkcs8 = null;
        try
        {
            pkcs8 = _protector.Unprotect(bytes);
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            if (key.KeySize != 256)
            {
                key.Dispose();
                throw new CryptographicException("Stored agent key is not a P-256 key.");
            }

            return key;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "The agent key at {Path} could not be read; it will not be used.", path);
            return null;
        }
        finally
        {
            if (pkcs8 is not null)
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
    }

    private void SaveKey(string path, ECDsa key)
    {
        var pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            AtomicFile.WriteAllBytes(path, _protector.Protect(pkcs8));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }
}

/// <summary>Signs with c_… once active and with r_… while waiting for approval.</summary>
public sealed class StateSigningCredentialProvider : ISigningCredentialProvider
{
    private readonly AgentStateStore _state;
    private readonly AgentKeyStore _keys;

    public StateSigningCredentialProvider(AgentStateStore state, AgentKeyStore keys)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
    }

    public SigningCredential? GetSigningCredential()
    {
        var (status, credentialId, requestId) = _state.Read(s => (s.Status, s.CredentialId, s.PendingEnrollmentRequestId));
        var id = status switch
        {
            AgentEnrollmentStatus.Active => credentialId,
            AgentEnrollmentStatus.PendingApproval => requestId,
            _ => null,
        };
        if (string.IsNullOrEmpty(id))
        {
            return null;
        }

        var key = _keys.TryGetCurrent();
        return key is null ? null : new SigningCredential(id, key);
    }
}
