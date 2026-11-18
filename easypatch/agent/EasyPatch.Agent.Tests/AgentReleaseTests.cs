using System.Security.Cryptography;
using EasyPatch.Agent.Core.Security;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Release signatures: what they cover and which keys are accepted.</summary>
public sealed class AgentReleaseTests
{
    private static readonly AgentReleaseManifest Manifest = new()
    {
        FileName = "EasyPatchAgent-1.2.0-x64.msi",
        Version = "1.2.0",
        Architecture = "x64",
        Sha256 = Convert.ToHexStringLower(SHA256.HashData("package"u8)),
        SizeBytes = 7,
    };

    public static TheoryData<string> Fields => ["FileName", "Version", "Architecture", "Sha256", "SizeBytes"];

    [Fact]
    public void A_signature_verifies_against_the_signing_key_only()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var signature = AgentRelease.Sign(Manifest, key);

        Assert.Equal(64, Convert.FromBase64String(signature).Length);
        Assert.True(AgentRelease.Verify(Manifest, signature, key));
        Assert.False(AgentRelease.Verify(Manifest, signature, other));
    }

    [Theory]
    [MemberData(nameof(Fields))]
    public void Changing_any_field_invalidates_the_signature(string field)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = AgentRelease.Sign(Manifest, key);

        var changed = field switch
        {
            "FileName" => Manifest with { FileName = "EasyPatchAgent-1.2.1-x64.msi" },
            "Version" => Manifest with { Version = "1.2.1" },
            "Architecture" => Manifest with { Architecture = "arm64" },
            "Sha256" => Manifest with { Sha256 = new string('0', 64) },
            _ => Manifest with { SizeBytes = 8 },
        };

        Assert.False(AgentRelease.Verify(changed, signature, key));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not base64!")]
    [InlineData("AAAA")]
    public void Malformed_signatures_do_not_verify(string? signature)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(AgentRelease.Verify(Manifest, signature, key));
    }

    [Fact]
    public void The_key_id_is_derived_from_the_public_key()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicOnly = ECDsa.Create();
        publicOnly.ImportFromPem(key.ExportSubjectPublicKeyInfoPem());

        var id = AgentRelease.KeyId(key);

        Assert.True(AgentRelease.IsKeyId(id));
        Assert.Equal(id, AgentRelease.KeyId(publicOnly));
    }

    [Fact]
    public void A_key_ring_holds_every_public_key_in_the_pem_and_ignores_other_blocks()
    {
        using var first = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = "# EasyPatch release keys\n" + first.ExportSubjectPublicKeyInfoPem() + "\n" +
                  "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + second.ExportSubjectPublicKeyInfoPem() + "\n" +
                  first.ExportSubjectPublicKeyInfoPem();

        using var ring = new ReleaseKeyRing(pem);

        Assert.Equal(new[] { AgentRelease.KeyId(first), AgentRelease.KeyId(second) }.Order(StringComparer.Ordinal), ring.KeyIds);
        var payload = new AgentUpdatePayload { Package = Manifest, KeyId = AgentRelease.KeyId(second), Signature = AgentRelease.Sign(Manifest, second) };
        Assert.True(ring.Verify(payload));
        Assert.False(ring.Verify(payload with { KeyId = AgentRelease.KeyId(first) }));
    }

    [Fact]
    public void Only_P256_public_keys_are_accepted()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var rsa = RSA.Create(2048);

        Assert.ThrowsAny<CryptographicException>(() => new ReleaseKeyRing(p384.ExportSubjectPublicKeyInfoPem()));
        Assert.ThrowsAny<CryptographicException>(() => new ReleaseKeyRing(rsa.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public void Manifests_are_validated()
    {
        Assert.Empty(AgentRelease.Validate(Manifest));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { FileName = "setup.msi" }));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { Version = "1.2.1" })); // name and version disagree
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { Architecture = "arm64" }));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { Sha256 = Manifest.Sha256.ToUpperInvariant() }));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { SizeBytes = 0 }));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { SizeBytes = AgentRelease.MaxPackageBytes + 1 }));
        Assert.NotEmpty(AgentRelease.Validate(Manifest with { FileName = "EasyPatchAgent-1.2.0-x64.msi/../evil.msi" }));
    }

    [Theory]
    [InlineData("1.2.0", "1.2.0")]
    [InlineData("1.2.0+abcdef", "1.2.0")]
    [InlineData("1.2.0-beta.1", "1.2.0")]
    [InlineData("1.2", "1.2.0")]
    [InlineData("unknown", null)]
    [InlineData(null, null)]
    public void Versions_are_compared_on_their_numeric_part(string? text, string? expected)
    {
        Assert.Equal(expected is null ? null : Version.Parse(expected), AgentRelease.ParseVersion(text));
    }
}
