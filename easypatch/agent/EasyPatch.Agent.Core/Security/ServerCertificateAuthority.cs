using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EasyPatch.Agent.Core.Security;

/// <summary>
/// A certificate authority the agent trusts for its own connection to the EasyPatch server, and for nothing else on the
/// computer (MSI property SERVERCACERT, recorded by the install script's <i>Skip certificate check</i> option for servers
/// with a private CA such as Caddy's internal one). A certificate the operating system trusts is accepted as always; one
/// that fails only because its issuer is unknown is accepted when it chains to this authority, is valid now and is meant
/// for server authentication. A host-name mismatch or a missing certificate is never accepted.
/// </summary>
public sealed class ServerCertificateAuthority
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private readonly X509Certificate2 _root;

    private ServerCertificateAuthority(X509Certificate2 root)
    {
        _root = root;
    }

    public string Subject => _root.Subject;

    /// <summary>SHA-256 of the certificate, as shown by the install script.</summary>
    public string Sha256 => _root.GetCertHashString(HashAlgorithmName.SHA256);

    /// <summary>Reads a base64 DER (as the MSI stores it) or PEM certificate authority certificate.</summary>
    /// <exception cref="ArgumentException">The value is not a certificate, or not a certificate authority's.</exception>
    public static ServerCertificateAuthority Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        X509Certificate2 certificate;
        try
        {
            var text = value.Trim();
            certificate = text.StartsWith("-----BEGIN", StringComparison.Ordinal)
                ? X509Certificate2.CreateFromPem(text)
                : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(text));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new ArgumentException("The server certificate authority (SERVERCACERT) is not a base64 or PEM certificate.", ex);
        }

        if (certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true })
        {
            certificate.Dispose();
            throw new ArgumentException("The server certificate authority (SERVERCACERT) is not a certificate authority certificate.");
        }

        return new ServerCertificateAuthority(certificate);
    }

    /// <summary>Certificate validation for the connection to the EasyPatch server (an SslStream callback).</summary>
    public bool Validate(X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null)
        {
            return false;
        }

        var leaf = certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        try
        {
            using var pinned = new X509Chain();
            pinned.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            pinned.ChainPolicy.CustomTrustStore.Add(_root);
            pinned.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
            pinned.ChainPolicy.DisableCertificateDownloads = true;
            // Private CAs (Caddy's among them) publish no revocation information; the default client check is off too.
            pinned.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (chain is not null)
            {
                // The intermediates the server sent.
                pinned.ChainPolicy.ExtraStore.AddRange(chain.ChainPolicy.ExtraStore);
                foreach (var element in chain.ChainElements)
                {
                    pinned.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }

            return pinned.Build(leaf);
        }
        finally
        {
            if (!ReferenceEquals(leaf, certificate))
            {
                leaf.Dispose();
            }
        }
    }
}
