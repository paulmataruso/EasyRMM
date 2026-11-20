using System.Security.Cryptography;
using System.Text;
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
