using System.Security.Cryptography;
using System.Text;
using EasyPatch.Contracts.Security;

namespace EasyPatch.Infrastructure.Security;

/// <summary>High-entropy random tokens. Only SHA-256 hashes are stored (tokens carry 256 bits of entropy,
/// so a fast hash is appropriate and enables indexed lookup).</summary>
public static class SecureTokens
{
    public static string Create(string prefix, int bytes = 32) =>
        prefix + RequestSigner.Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static string NewCredentialId() => "c_" + RequestSigner.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    public static string Fingerprint(params string?[] parts) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts))));
}
