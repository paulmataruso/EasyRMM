using System.Security.Cryptography;
using System.Text;
using EasyPatch.Agent.Core.Abstractions;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Protects the agent's private key with DPAPI in machine scope. Machine scope is required because the service runs
/// as LocalSystem and the key must survive profile changes; access to the key file itself is restricted to SYSTEM and
/// Administrators by the data directory ACL (<see cref="SecureStorage"/>). The entropy value binds the blob to
/// EasyPatch so other DPAPI consumers cannot be tricked into decrypting it by accident.
/// </summary>
internal sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("EasyPatch.Agent/agent-key/v1");

    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.LocalMachine);
    }

    public byte[] Unprotect(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        return ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.LocalMachine);
    }
}
