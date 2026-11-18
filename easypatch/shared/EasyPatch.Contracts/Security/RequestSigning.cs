using System.Security.Cryptography;
using System.Text;

namespace EasyPatch.Contracts.Security;

public static class AgentAuthHeaders
{
    public const string Credential = "X-EasyPatch-Credential";
    public const string Timestamp = "X-EasyPatch-Timestamp";
    public const string Nonce = "X-EasyPatch-Nonce";
    public const string ContentSha256 = "X-EasyPatch-Content-SHA256";
    public const string Signature = "X-EasyPatch-Signature";
}

/// <summary>Headers produced for one signed request.</summary>
public sealed record SignedRequestHeaders(
    string CredentialId,
    long Timestamp,
    string Nonce,
    string ContentSha256,
    string Signature);

/// <summary>
/// ECDSA P-256 / SHA-256 request signing used by every authenticated agent request.
/// The canonical string binds method, exact request target, time, a single-use nonce, the body hash
/// and the credential identifier, so a captured request cannot be replayed or altered.
/// </summary>
public static class RequestSigner
{
    public const string Scheme = "EASYPATCH-ECDSA-P256-SHA256";

    /// <summary>Maximum accepted clock difference between agent and server.</summary>
    public static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(5);

    public static string BuildCanonicalString(
        string method, string pathAndQuery, long timestamp, string nonce, string contentSha256, string credentialId)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(pathAndQuery);
        return string.Join('\n',
            Scheme,
            method.ToUpperInvariant(),
            pathAndQuery,
            timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            nonce,
            contentSha256,
            credentialId);
    }

    public static string ComputeContentHash(ReadOnlySpan<byte> body) =>
        Convert.ToHexStringLower(SHA256.HashData(body));

    public static string NewNonce() =>
        Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    public static SignedRequestHeaders Sign(
        ECDsa privateKey, string credentialId, string method, string pathAndQuery, ReadOnlySpan<byte> body, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var timestamp = now.ToUnixTimeSeconds();
        var nonce = NewNonce();
        var hash = ComputeContentHash(body);
        var canonical = BuildCanonicalString(method, pathAndQuery, timestamp, nonce, hash, credentialId);
        var signature = privateKey.SignData(
            Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedRequestHeaders(credentialId, timestamp, nonce, hash, Convert.ToBase64String(signature));
    }

    public static bool Verify(ECDsa publicKey, string canonical, string signatureBase64)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        Span<byte> signature = stackalloc byte[128];
        if (!Convert.TryFromBase64String(signatureBase64, signature, out var written) || written != 64)
        {
            return false;
        }

        return publicKey.VerifyData(
            Encoding.UTF8.GetBytes(canonical), signature[..written], HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>Validates a nonce's shape: base64url, 16–64 characters.</summary>
    public static bool IsValidNonce(string? nonce) =>
        nonce is { Length: >= 16 and <= 64 } && nonce.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    public static string Base64UrlEncode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Agent key helpers. Only NIST P-256 keys are accepted.</summary>
public static class AgentKeys
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

    public static ECDsa Generate() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static byte[] ExportPublicKey(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Imports a SubjectPublicKeyInfo and verifies it is a P-256 key. Throws <see cref="CryptographicException"/> otherwise.</summary>
    public static ECDsa ImportPublicKey(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var read);
            if (read != subjectPublicKeyInfo.Length)
            {
                throw new CryptographicException("Trailing data after public key.");
            }

            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid?.Value != P256Oid && parameters.Curve.Oid?.FriendlyName is not ("nistP256" or "ECDSA_P256"))
            {
                throw new CryptographicException("Only ECDSA P-256 keys are accepted.");
            }

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>Tries to decode and validate a base64 SubjectPublicKeyInfo.</summary>
    public static bool TryParsePublicKey(string? base64, out byte[] spki)
    {
        spki = [];
        if (string.IsNullOrWhiteSpace(base64) || base64.Length > 512)
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(base64);
            using var key = ImportPublicKey(bytes);
            spki = bytes;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Short human-comparable fingerprint, e.g. "3F2A-91C0-7B11-E4D2" (first 64 bits of SHA-256 of the SPKI).</summary>
    public static string Fingerprint(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var hex = Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo).AsSpan(0, 8));
        return $"{hex[..4]}-{hex[4..8]}-{hex[8..12]}-{hex[12..16]}";
    }
}
