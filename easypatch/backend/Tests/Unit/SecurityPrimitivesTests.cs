using System.Security.Cryptography;
using System.Text;
using EasyPatch.Api.Endpoints;
using EasyPatch.Contracts.Security;
using EasyPatch.Infrastructure.Security;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class RequestSigningTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Signature_round_trips_with_the_registered_public_key()
    {
        using var key = AgentKeys.Generate();
        var body = Encoding.UTF8.GetBytes("""{"agentVersion":"1.0.0"}""");
        var headers = RequestSigner.Sign(key, "c_abc", "POST", "/api/v1/agents/check-in", body, Now);

        using var publicKey = AgentKeys.ImportPublicKey(AgentKeys.ExportPublicKey(key));
        var canonical = RequestSigner.BuildCanonicalString("POST", "/api/v1/agents/check-in", headers.Timestamp, headers.Nonce,
            RequestSigner.ComputeContentHash(body), "c_abc");
        Assert.True(RequestSigner.Verify(publicKey, canonical, headers.Signature));
    }

    [Theory]
    [InlineData("GET", "/api/v1/agents/check-in", "c_abc", 0)] // method changed
    [InlineData("POST", "/api/v1/agents/inventory", "c_abc", 0)] // path changed
    [InlineData("POST", "/api/v1/agents/check-in", "c_other", 0)] // credential changed
    [InlineData("POST", "/api/v1/agents/check-in", "c_abc", 1)] // timestamp changed
    public void Any_change_to_the_signed_request_invalidates_the_signature(string method, string path, string credential, int timestampDelta)
    {
        using var key = AgentKeys.Generate();
        var body = "{}"u8.ToArray();
        var headers = RequestSigner.Sign(key, "c_abc", "POST", "/api/v1/agents/check-in", body, Now);
        var canonical = RequestSigner.BuildCanonicalString(method, path, headers.Timestamp + timestampDelta, headers.Nonce,
            RequestSigner.ComputeContentHash(body), credential);
        Assert.False(RequestSigner.Verify(key, canonical, headers.Signature));
    }

    [Fact]
    public void Body_tampering_changes_the_content_hash()
    {
        Assert.NotEqual(RequestSigner.ComputeContentHash("{\"a\":1}"u8), RequestSigner.ComputeContentHash("{\"a\":2}"u8));
        Assert.Equal(64, RequestSigner.ComputeContentHash([]).Length);
    }

    [Fact]
    public void Signature_from_a_different_key_is_rejected()
    {
        using var key = AgentKeys.Generate();
        using var attacker = AgentKeys.Generate();
        var headers = RequestSigner.Sign(attacker, "c_abc", "POST", "/x", [], Now);
        var canonical = RequestSigner.BuildCanonicalString("POST", "/x", headers.Timestamp, headers.Nonce, headers.ContentSha256, "c_abc");
        Assert.False(RequestSigner.Verify(key, canonical, headers.Signature));
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("short", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAA", true)]
    [InlineData("has spaces in it 123456", false)]
    [InlineData("abc_def-ghi_jkl-mno_pq", true)]
    public void Nonce_shape_is_validated(string? nonce, bool valid) => Assert.Equal(valid, RequestSigner.IsValidNonce(nonce));

    [Fact]
    public void Public_key_import_rejects_non_P256_keys()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var spki = p384.ExportSubjectPublicKeyInfo();
        Assert.ThrowsAny<CryptographicException>(() => AgentKeys.ImportPublicKey(spki));
        Assert.False(AgentKeys.TryParsePublicKey(Convert.ToBase64String(spki), out _));
        Assert.False(AgentKeys.TryParsePublicKey("not base64!", out _));
    }

    [Fact]
    public void Fingerprint_is_stable_and_formatted_for_humans()
    {
        using var key = AgentKeys.Generate();
        var spki = AgentKeys.ExportPublicKey(key);
        var fingerprint = AgentKeys.Fingerprint(spki);
        Assert.Matches("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", fingerprint);
        Assert.Equal(fingerprint, AgentKeys.Fingerprint(spki));
    }
}

public sealed class TotpTests
{
    // RFC 6238 appendix B test secret (SHA-1).
    private static readonly byte[] Secret = "12345678901234567890"u8.ToArray();

    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    public void Matches_rfc6238_vectors(long unixSeconds, string expected) =>
        Assert.Equal(expected, Totp.Compute(Secret, Totp.CurrentStep(DateTimeOffset.FromUnixTimeSeconds(unixSeconds))));

    [Fact]
    public void Accepts_adjacent_steps_and_blocks_reuse()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.CurrentStep(now);
        Assert.Equal(step, Totp.Verify(Secret, Totp.Compute(Secret, step), now, null));
        Assert.Equal(step - 1, Totp.Verify(Secret, Totp.Compute(Secret, step - 1), now, null));
        Assert.Equal(step + 1, Totp.Verify(Secret, Totp.Compute(Secret, step + 1), now, null));
        Assert.Null(Totp.Verify(Secret, Totp.Compute(Secret, step - 2), now, null));
        Assert.Null(Totp.Verify(Secret, Totp.Compute(Secret, step), now, lastUsedStep: step)); // replay
        Assert.Null(Totp.Verify(Secret, "abc123", now, null));
        Assert.Null(Totp.Verify(Secret, null, now, null));
    }

    [Fact]
    public void Base32_round_trips()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        Assert.Equal(bytes, Totp.Base32Decode(Totp.Base32Encode(bytes)));
    }
}

public sealed class PasswordHasherTests
{
    private readonly Argon2PasswordHasher hasher = new();

    [Fact]
    public void Hash_is_argon2id_phc_and_verifies()
    {
        var hash = hasher.Hash("Correct-Horse-Battery-9");
        Assert.StartsWith("$argon2id$", hash, StringComparison.Ordinal);
        Assert.NotEqual(hash, hasher.Hash("Correct-Horse-Battery-9")); // salted
        Assert.NotEqual(PasswordVerification.Failed, hasher.Verify("Correct-Horse-Battery-9", hash));
        Assert.Equal(PasswordVerification.Failed, hasher.Verify("correct-horse-battery-9", hash));
        Assert.Equal(PasswordVerification.Failed, hasher.Verify("anything", "!")); // unusable hash
    }

    [Theory]
    [InlineData("short", "admin", false)]
    [InlineData("aaaaaaaaaaaaaaaa", "admin", false)] // too few distinct characters
    [InlineData("admin-password-2026", "admin", false)] // contains the username
    [InlineData("Correct-Horse-Battery-9", "admin", true)]
    public void Policy_rejects_weak_passwords(string password, string username, bool ok) =>
        Assert.Equal(ok, PasswordPolicy.Validate(password, username) is null);
}

public sealed class CsvWriterTests
{
    [Theory]
    [InlineData("=HYPERLINK(\"http://evil\")", "\"'=HYPERLINK(\"\"http://evil\"\")\"")]
    [InlineData("+SUM(A1)", "'+SUM(A1)")]
    [InlineData("@cmd", "'@cmd")]
    [InlineData("-1+1", "'-1+1")]
    [InlineData("PC-01, Floor 2", "\"PC-01, Floor 2\"")]
    [InlineData("plain", "plain")]
    public void Escapes_formulas_and_delimiters(string input, string expected) => Assert.Equal(expected, CsvWriter.Escape(input));

    [Fact]
    public void Numbers_and_dates_are_not_prefixed()
    {
        Assert.Equal("-5", CsvWriter.Escape(-5));
        Assert.Equal("2026-11-13 12:00:00", CsvWriter.Escape(new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero)));
        Assert.Equal("Yes", CsvWriter.Escape(true));
        Assert.Equal(string.Empty, CsvWriter.Escape(null));
    }
}

public sealed class SecureTokenTests
{
    [Fact]
    public void Tokens_are_prefixed_random_and_stored_only_as_hashes()
    {
        var a = SecureTokens.Create("ept_");
        var b = SecureTokens.Create("ept_");
        Assert.StartsWith("ept_", a, StringComparison.Ordinal);
        Assert.NotEqual(a, b);
        Assert.Equal(64, SecureTokens.Hash(a).Length);
        Assert.DoesNotContain(a[4..], SecureTokens.Hash(a), StringComparison.Ordinal);
        Assert.Equal(SecureTokens.Hash(a), SecureTokens.Hash(a));
    }
}
