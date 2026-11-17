using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Communication;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Runtime;

/// <summary>Creates (and caches per server URL) the <see cref="AgentApiClient"/>.</summary>
public sealed class ApiClientAccessor
{
    private readonly IAgentHttpClientFactory _factory;
    private readonly ISigningCredentialProvider _credentials;
    private readonly ServerClock _clock;
    private readonly string _agentVersion;
    private readonly bool _requireHttps;
    private readonly ILoggerFactory _loggerFactory;
    private readonly Lock _lock = new();
    private AgentApiClient? _client;
    private Uri? _serverUrl;

    public ApiClientAccessor(
        IAgentHttpClientFactory factory,
        ISigningCredentialProvider credentials,
        ServerClock clock,
        string agentVersion,
        bool requireHttps,
        ILoggerFactory loggerFactory)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _agentVersion = agentVersion;
        _requireHttps = requireHttps;
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    public ServerClock Clock => _clock;

    public AgentApiClient Get(string serverUrl)
    {
        var uri = NormalizeServerUrl(serverUrl, _requireHttps);
        lock (_lock)
        {
            if (_client is not null && _serverUrl == uri)
            {
                return _client;
            }

            var http = _factory.Create(uri);
            if (http.BaseAddress is null)
            {
                http.BaseAddress = uri;
            }

            _client = new AgentApiClient(http, _credentials, _clock, _agentVersion, _loggerFactory.CreateLogger<AgentApiClient>());
            _serverUrl = uri;
            return _client;
        }
    }

    /// <summary>Validates and normalizes the server URL (absolute, http(s), trailing slash, no query/fragment).</summary>
    public static Uri NormalizeServerUrl(string? serverUrl, bool requireHttps)
    {
        if (string.IsNullOrWhiteSpace(serverUrl) || !Uri.TryCreate(serverUrl.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("The server URL is not a valid absolute URL (expected https://host[:port][/path]).", nameof(serverUrl));
        }

        if (uri.Scheme != Uri.UriSchemeHttps && (requireHttps || uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("The server URL must use HTTPS.", nameof(serverUrl));
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("The server URL must not contain credentials, a query string or a fragment.", nameof(serverUrl));
        }

        var builder = new UriBuilder(uri);
        if (!builder.Path.EndsWith('/'))
        {
            builder.Path += "/";
        }

        return builder.Uri;
    }
}
