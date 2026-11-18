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

    /// <summary>Human-friendly code (Crockford-like base32, no ambiguous characters).</summary>
    public static string CreateCode(string prefix, int length)
    {
        const string alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
        var chars = new char[length];
        for (var i = 0; i < length; i++)
        {
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return prefix + new string(chars);
    }

    public static string NewCredentialId() => "c_" + RequestSigner.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    public static string NewEnrollmentRequestId() => "r_" + RequestSigner.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    public static string Fingerprint(params string?[] parts) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', parts))));
}
