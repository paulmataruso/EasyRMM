using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EasyPatch.Agent.Core.Security;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>The certificate authority recorded by the install script's "Skip certificate check" option (SERVERCACERT).</summary>
public sealed class ServerCertificateAuthorityTests : IDisposable
{
    private readonly Pki _lab = new("Caddy Local Authority - 2026 ECC Root");
    private readonly Pki _other = new("Someone Else's Root");

    public void Dispose()
    {
        _lab.Dispose();
        _other.Dispose();
    }

    [Fact]
    public void A_server_certificate_issued_by_the_recorded_authority_through_its_intermediate_is_accepted()
    {
        var authority = ServerCertificateAuthority.Parse(Convert.ToBase64String(_lab.Root.RawData));
        using var leaf = _lab.Issue("172.16.0.45");
        using var chain = _lab.HandshakeChain();

        Assert.True(authority.Validate(leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.Equal(_lab.Root.Subject, authority.Subject);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(_lab.Root.RawData)), authority.Sha256);
    }

    [Fact]
    public void Certificates_from_another_authority_a_wrong_host_name_or_an_expired_certificate_are_refused()
    {
        var authority = ServerCertificateAuthority.Parse(_lab.RootPem);

        using var foreign = _other.Issue("172.16.0.45");
        using var foreignChain = _other.HandshakeChain();
        Assert.False(authority.Validate(foreign, foreignChain, SslPolicyErrors.RemoteCertificateChainErrors));

        using var leaf = _lab.Issue("172.16.0.45");
        using var chain = _lab.HandshakeChain();
        Assert.False(authority.Validate(leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(authority.Validate(leaf, chain, SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(authority.Validate(null, chain, SslPolicyErrors.RemoteCertificateNotAvailable));

        using var expired = _lab.Issue("172.16.0.45", DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(-1));
        Assert.False(authority.Validate(expired, chain, SslPolicyErrors.RemoteCertificateChainErrors));

        // Without the intermediate the server sent, the chain cannot be built.
        using var leafOnly = new X509Chain();
        Assert.False(authority.Validate(leaf, leafOnly, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void Certificates_the_operating_system_trusts_are_still_accepted()
    {
        var authority = ServerCertificateAuthority.Parse(Convert.ToBase64String(_lab.Root.RawData));
        using var publicCertificate = _other.Issue("patch.example.com");

        Assert.True(authority.Validate(publicCertificate, null, SslPolicyErrors.None));
    }

    [Fact]
    public void Only_a_certificate_authority_certificate_can_be_recorded()
    {
        using var leaf = _lab.Issue("172.16.0.45");

        Assert.Throws<ArgumentException>(() => ServerCertificateAuthority.Parse(Convert.ToBase64String(leaf.RawData)));
        Assert.Throws<ArgumentException>(() => ServerCertificateAuthority.Parse("not a certificate"));
        Assert.Throws<ArgumentException>(() => ServerCertificateAuthority.Parse("<!doctype html><html></html>"));
        Assert.Throws<ArgumentException>(() => ServerCertificateAuthority.Parse(" "));
    }

    /// <summary>A root, an intermediate and server certificates, shaped like Caddy's internal CA.</summary>
    private sealed class Pki : IDisposable
    {
        private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public Pki(string rootName)
        {
            var now = DateTimeOffset.UtcNow;
            using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootRequest = new CertificateRequest($"CN={rootName}", rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            Root = rootRequest.CreateSelfSigned(now.AddDays(-30), now.AddYears(10));

            var intermediateRequest = new CertificateRequest($"CN={rootName} Intermediate", _intermediateKey, HashAlgorithmName.SHA256);
            intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
            intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));
            using var intermediatePublic = intermediateRequest.Create(Root, now.AddDays(-10), now.AddDays(7), RandomNumberGenerator.GetBytes(16));
            Intermediate = intermediatePublic.CopyWithPrivateKey(_intermediateKey);
        }

        public X509Certificate2 Root { get; }

        public X509Certificate2 Intermediate { get; }

        public string RootPem => Root.ExportCertificatePem();

        public X509Certificate2 Issue(string host, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest(string.Empty, key, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build(true));
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Intermediate, true, false));
            var from = notBefore ?? DateTimeOffset.UtcNow.AddHours(-1);
            return request.Create(Intermediate, from, notAfter ?? from.AddHours(13), RandomNumberGenerator.GetBytes(16));
        }

        /// <summary>What SslStream hands the callback: the intermediate the server sent is in the chain's extra store.</summary>
        public X509Chain HandshakeChain()
        {
            var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(Intermediate.RawData));
            return chain;
        }

        public void Dispose()
        {
            Root.Dispose();
            Intermediate.Dispose();
            _intermediateKey.Dispose();
        }
    }
}
