using System.Net;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Security;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Production HTTP stack. TLS certificates are validated against the Windows trust store; validation cannot be disabled.
/// When the installer recorded a server certificate authority (SERVERCACERT), certificates issued by it are accepted too,
/// for this connection only (<see cref="ServerCertificateAuthority"/>). Redirects are not followed (a signed request must
/// reach exactly the URL it was signed for).
/// The proxy is the explicit PROXYURL when configured, otherwise .NET's system default (HTTPS_PROXY / HTTP_PROXY
/// environment variables, then the service account's WinINET settings). WinHTTP (<c>netsh winhttp</c>) proxy settings
/// are not used, so set PROXYURL on networks that require a proxy.
/// </summary>
internal sealed class AgentHttpClientFactory : IAgentHttpClientFactory
{
    private readonly IBootstrapConfigSource _bootstrap;

    public AgentHttpClientFactory(IBootstrapConfigSource bootstrap)
    {
        _bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
    }

    public HttpClient Create(Uri serverUrl)
    {
        ArgumentNullException.ThrowIfNull(serverUrl);
        if (serverUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The EasyPatch server URL must use HTTPS.", nameof(serverUrl));
        }

        var bootstrap = _bootstrap.Read();
        var proxy = CreateProxy(bootstrap.ProxyUrl);
        var authority = string.IsNullOrWhiteSpace(bootstrap.ServerCaCertificate) ? null : ServerCertificateAuthority.Parse(bootstrap.ServerCaCertificate);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            UseCookies = false,
            UseProxy = true,
            Proxy = proxy,
        };
        if (authority is not null)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) => authority.Validate(certificate, chain, errors);
        }

        return new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = serverUrl,
            Timeout = TimeSpan.FromMinutes(2),
        };
    }

    internal static IWebProxy CreateProxy(string? proxyUrl)
    {
        if (string.IsNullOrWhiteSpace(proxyUrl))
        {
            return HttpClient.DefaultProxy;
        }

        if (!Uri.TryCreate(proxyUrl.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("PROXYURL must be an absolute http:// or https:// URL without credentials.");
        }

        // Authenticating proxies use the machine account (the service runs as LocalSystem).
        return new WebProxy(uri, BypassOnLocal: false) { UseDefaultCredentials = true };
    }
}
