using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace EasyPatch.Infrastructure.Services;

/// <summary>Reads discovery documents and key sets over HTTPS only, through the <see cref="OidcService.HttpClientName"/> client and with
/// a size limit.</summary>
public sealed class OidcDocumentRetriever(IHttpClientFactory httpFactory) : IDocumentRetriever
{
    public const int MaxDocumentBytes = 1 << 20;

    public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("OpenID Connect documents are only read over HTTPS.");
        }

        using var client = httpFactory.CreateClient(OidcService.HttpClientName);
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancel);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"The identity provider answered {(int)response.StatusCode}.", null, response.StatusCode);
        }

        return await OidcService.ReadLimitedAsync(response.Content, MaxDocumentBytes, cancel);
    }
}

/// <summary>Each issuer's discovery document and signing keys, cached (refreshed every 12 hours, or when a token names an unknown key).</summary>
public sealed class OidcConfigurationCache(IHttpClientFactory httpFactory)
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> managers = new(StringComparer.Ordinal);

    public ConfigurationManager<OpenIdConnectConfiguration> For(string issuer) =>
        managers.GetOrAdd(issuer, i => new ConfigurationManager<OpenIdConnectConfiguration>(
            OidcService.DiscoveryAddress(i), new OpenIdConnectConfigurationRetriever(), new OidcDocumentRetriever(httpFactory)));

    public void Forget(string issuer) => managers.TryRemove(issuer, out _);
}

/// <param name="Redirect">Where to send the browser: the provider's authorization endpoint, or the sign-in page with an error.</param>
/// <param name="Binding">The value for the browser-binding cookie (null on failure).</param>
public sealed record OidcStart(string Redirect, string? Binding);

/// <param name="Redirect">A console path: where the user was going, or the sign-in page with <c>?sso_error=</c>.</param>
public sealed record OidcCompletion(string Redirect, UserSession? Session, string? SessionToken);

/// <summary>The result of checking a provider's discovery document.</summary>
public sealed record OidcProbe(bool Ok, string? Issuer, string? AuthorizationEndpoint, string? TokenEndpoint, int SigningKeys, string Message);

/// <summary>
/// Single sign-on with OpenID Connect: the authorization code flow with PKCE (S256), <c>state</c> and <c>nonce</c>. The pending sign-in
/// is kept on the server, used once, expires after 10 minutes and is bound to the browser by a cookie. The ID token's signature (keys
/// from the provider's JWKS), issuer, audience, lifetime and nonce are checked. Tokens, codes, secrets and claims are never logged.
/// </summary>
public sealed class OidcService(
    EasyPatchDbContext db,
    AuthService auth,
    AuditService audit,
    NotificationSecrets secrets,
    OidcConfigurationCache cache,
    IHttpClientFactory httpFactory,
    IOptions<EasyPatchOptions> options,
    TimeProvider clock,
    ILogger<OidcService> logger)
{
    public const string HttpClientName = "oidc";
    public const string CallbackPath = "/api/v1/auth/sso/callback";
    public const string DefaultScopes = "openid email profile";
    public static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
    private const int MaxTokenResponseBytes = 256 * 1024;

    private static readonly string[] Algorithms =
        [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512, SecurityAlgorithms.RsaSsaPssSha256,
         SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512, SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384,
         SecurityAlgorithms.EcdsaSha512];

    /// <summary>The single redirect URI to register at every provider.</summary>
    public string RedirectUri => options.Value.PublicUrl.TrimEnd('/') + CallbackPath;

    public static string DiscoveryAddress(string issuer) => issuer.TrimEnd('/') + "/.well-known/openid-configuration";

    // -------------------------------------------------------------------------------------------
    // Sign-in
    // -------------------------------------------------------------------------------------------

    public async Task<OidcStart> StartAsync(Guid providerId, string? returnTo, CancellationToken ct)
    {
        var provider = await db.OidcProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Id == providerId && p.Enabled, ct);
        if (provider is null)
        {
            return new OidcStart(LoginError("unavailable"), null);
        }

        OpenIdConnectConfiguration config;
        try
        {
            config = await GetConfigurationAsync(provider, ct);
        }
        catch (Exception ex) when (ex is SsoFailure || IsProviderFailure(ex, ct))
        {
            logger.LogWarning("Single sign-on with provider {ProviderId} is unavailable: {Error}", provider.Id,
                ex is SsoFailure f ? f.Reason : Describe(ex));
            return new OidcStart(LoginError("unavailable"), null);
        }

        var now = clock.GetUtcNow();
        await db.OidcLoginStates.Where(s => s.ExpiresAt <= now).ExecuteDeleteAsync(ct);
        var state = SecureTokens.Create(string.Empty);
        var binding = SecureTokens.Create(string.Empty);
        var nonce = SecureTokens.Create(string.Empty);
        var verifier = SecureTokens.Create(string.Empty);
        db.OidcLoginStates.Add(new OidcLoginState
        {
            Id = Guid.CreateVersion7(now),
            ProviderId = provider.Id,
            StateHash = SecureTokens.Hash(state),
            BindingHash = SecureTokens.Hash(binding),
            Nonce = nonce,
            CodeVerifier = verifier,
            ReturnTo = SafeReturnTo(returnTo),
            CreatedAt = now,
            ExpiresAt = now + StateLifetime,
        });
        await db.SaveChangesAsync(ct);

        var query = new[]
        {
            ("response_type", "code"),
            ("client_id", provider.ClientId),
            ("redirect_uri", RedirectUri),
            ("scope", provider.Scopes),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", System.Buffers.Text.Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))),
            ("code_challenge_method", "S256"),
        };
        var endpoint = config.AuthorizationEndpoint;
        var url = endpoint + (endpoint.Contains('?', StringComparison.Ordinal) ? '&' : '?') +
                  string.Join('&', query.Select(q => $"{Uri.EscapeDataString(q.Item1)}={Uri.EscapeDataString(q.Item2)}"));
        return new OidcStart(url, binding);
    }

    /// <summary>Handles the provider's redirect back. Never throws for a failed sign-in: the result sends the browser to the sign-in page
    /// with a generic error code (<c>expired</c>, <c>denied</c>, <c>no_account</c>, <c>unavailable</c> or <c>failed</c>).</summary>
    public async Task<OidcCompletion> CompleteAsync(string? state, string? code, string? error, string? binding, string? ip, string? userAgent,
        CancellationToken ct)
    {
        OidcProvider? provider = null;
        Guid? userId = null;
        try
        {
            if (string.IsNullOrEmpty(state) || state.Length > 256)
            {
                throw new SsoFailure("expired", "state_missing");
            }

            var stateHash = SecureTokens.Hash(state);
            var pending = await db.OidcLoginStates.AsNoTracking().FirstOrDefaultAsync(s => s.StateHash == stateHash, ct);
            // Single use: only the request that deletes the row may continue, right or wrong.
            if (pending is null || await db.OidcLoginStates.Where(s => s.Id == pending.Id).ExecuteDeleteAsync(ct) != 1)
            {
                throw new SsoFailure("expired", "state_unknown");
            }

            if (pending.ExpiresAt <= clock.GetUtcNow())
            {
                throw new SsoFailure("expired", "state_expired");
            }

            if (string.IsNullOrEmpty(binding) || binding.Length > 256 ||
                !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(SecureTokens.Hash(binding)), Encoding.ASCII.GetBytes(pending.BindingHash)))
            {
                throw new SsoFailure("expired", "other_browser");
            }

            provider = await db.OidcProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Id == pending.ProviderId && p.Enabled, ct)
                       ?? throw new SsoFailure("unavailable", "provider_disabled");
            if (!string.IsNullOrEmpty(error))
            {
                throw new SsoFailure("denied", "provider_error"); // error_description is the provider's text: not logged
            }

            if (string.IsNullOrEmpty(code) || code.Length > 4096)
            {
                throw new SsoFailure("failed", "code_missing");
            }

            var config = await GetConfigurationAsync(provider, ct);
            var idToken = await RedeemCodeAsync(provider, config, code, pending.CodeVerifier, ct);
            var token = await ValidateIdTokenAsync(provider, config, idToken, pending.Nonce, ct);
            var (user, link) = await FindOrLinkUserAsync(provider, token, ct);
            userId = user.Id;

            var now = clock.GetUtcNow();
            var hasMfa = await auth.HasSecondFactorAsync(user, ct);
            var mfaCompleted = provider.ProviderEnforcesMfa || !hasMfa;
            var (session, sessionToken) = await auth.NewSessionAsync(user, mfaCompleted, ip, userAgent, ct);
            session.MfaByProvider = provider.ProviderEnforcesMfa;
            link.LastUsedAt = now;
            if (mfaCompleted)
            {
                user.LastLoginAt = now;
            }

            // Like a password sign-in, "auth.login" is recorded once no further step (EasyPatch MFA) remains.
            audit.Record(mfaCompleted ? "auth.login" : "auth.sso_verified", "User", user.Id.ToString(),
                details: new { method = "sso", provider = provider.DisplayName, mfaByProvider = provider.ProviderEnforcesMfa });
            await db.SaveChangesAsync(ct);
            return new OidcCompletion(pending.ReturnTo, session, sessionToken);
        }
        catch (Exception ex) when (ex is SsoFailure || IsProviderFailure(ex, ct))
        {
            var failure = ex as SsoFailure ?? new SsoFailure("failed", Describe(ex));
            db.ChangeTracker.Clear();
            logger.LogWarning("Single sign-on failed ({Reason}) for provider {ProviderId}", failure.Reason, provider?.Id);
            audit.Record("auth.sso_failed", userId is null ? "OidcProvider" : "User", (userId?.ToString() ?? provider?.Id.ToString()),
                details: new { provider = provider?.DisplayName, reason = failure.Reason });
            await db.SaveChangesAsync(CancellationToken.None);
            return new OidcCompletion(LoginError(failure.Code), null, null);
        }
    }

    private async Task<OpenIdConnectConfiguration> GetConfigurationAsync(OidcProvider provider, CancellationToken ct)
    {
        var config = await cache.For(provider.Issuer).GetConfigurationAsync(ct);
        CheckConfiguration(provider.Issuer, config);
        return config;
    }

    /// <summary>The discovery document must be the configured issuer's (OpenID Connect Discovery 1.0, 4.3), with HTTPS endpoints.</summary>
    private static void CheckConfiguration(string issuer, OpenIdConnectConfiguration config)
    {
        if (!string.Equals(config.Issuer?.TrimEnd('/'), issuer.TrimEnd('/'), StringComparison.Ordinal))
        {
            throw new SsoFailure("unavailable", "issuer_mismatch");
        }

        if (!IsHttps(config.AuthorizationEndpoint) || !IsHttps(config.TokenEndpoint))
        {
            throw new SsoFailure("unavailable", "endpoint_not_https");
        }
    }

    private async Task<string> RedeemCodeAsync(OidcProvider provider, OpenIdConnectConfiguration config, string code, string verifier,
        CancellationToken ct)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", RedirectUri),
            new("code_verifier", verifier),
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint);
        var secret = provider.ClientSecretProtected is null ? null : secrets.Unprotect(provider.ClientSecretProtected);
        // client_secret_post when the provider lists it (Entra ID, Google and Keycloak do); otherwise the default, client_secret_basic.
        if (secret is null || config.TokenEndpointAuthMethodsSupported.Contains("client_secret_post"))
        {
            form.Add(new("client_id", provider.ClientId));
            if (secret is not null)
            {
                form.Add(new("client_secret", secret));
            }
        }
        else
        {
            // client_secret_basic (RFC 6749, 2.3.1): both parts form-encoded.
            var basic = $"{Uri.EscapeDataString(provider.ClientId)}:{Uri.EscapeDataString(secret)}";
            request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(basic)));
        }

        request.Content = new FormUrlEncodedContent(form);
        request.Headers.Accept.ParseAdd("application/json");
        using var client = httpFactory.CreateClient(HttpClientName);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new SsoFailure("failed", $"token_request_{(int)response.StatusCode}"); // the body may echo the code: not logged
        }

        using var json = JsonDocument.Parse(await ReadLimitedAsync(response.Content, MaxTokenResponseBytes, ct));
        return json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.TryGetProperty("id_token", out var idToken) &&
               idToken.ValueKind == JsonValueKind.String && idToken.GetString() is { Length: > 0 } value
            ? value
            : throw new SsoFailure("failed", "no_id_token");
    }

    private async Task<JsonWebToken> ValidateIdTokenAsync(OidcProvider provider, OpenIdConnectConfiguration config, string idToken, string nonce,
        CancellationToken ct)
    {
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = config.Issuer,
            ValidAudience = provider.ClientId,
            IssuerSigningKeys = config.SigningKeys,
            ValidAlgorithms = Algorithms,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            RequireAudience = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            LifetimeValidator = (notBefore, expires, _, _) =>
            {
                var now = clock.GetUtcNow().UtcDateTime;
                return expires is { } exp && now < exp + ClockSkew && (notBefore is not { } nbf || now >= nbf - ClockSkew);
            },
        };
        var result = await handler.ValidateTokenAsync(idToken, parameters);
        if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            // The provider may have rotated its keys: read the key set again (at most every 5 minutes) and retry once.
            var manager = cache.For(provider.Issuer);
            manager.RequestRefresh();
            parameters.IssuerSigningKeys = (await manager.GetConfigurationAsync(ct)).SigningKeys;
            result = await handler.ValidateTokenAsync(idToken, parameters);
        }

        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
        {
            throw new SsoFailure("failed", "invalid_token:" + (result.Exception?.GetType().Name ?? "unknown"));
        }

        if (!jwt.TryGetPayloadValue<string>("nonce", out var tokenNonce) || tokenNonce is null ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(tokenNonce), Encoding.UTF8.GetBytes(nonce)))
        {
            throw new SsoFailure("failed", "nonce_mismatch");
        }

        if (string.IsNullOrEmpty(jwt.Subject) || jwt.Subject.Length > 255)
        {
            throw new SsoFailure("failed", "no_subject");
        }

        // OpenID Connect Core 3.1.3.7: with several audiences, the authorized party must be this client.
        if (jwt.Audiences.Count() > 1 && (!jwt.TryGetPayloadValue<string>("azp", out var azp) || azp != provider.ClientId))
        {
            throw new SsoFailure("failed", "azp_mismatch");
        }

        return jwt;
    }

    /// <summary>The user linked to the token's issuer and subject; otherwise an existing active user with the token's (verified) email
    /// address, linked now; otherwise, when the provider allows it, a new account for an address in an allowed domain.</summary>
    private async Task<(User User, ExternalLogin Link)> FindOrLinkUserAsync(OidcProvider provider, JsonWebToken token, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var link = await db.ExternalLogins.Include(l => l.User)
            .FirstOrDefaultAsync(l => l.Issuer == token.Issuer && l.Subject == token.Subject, ct);
        if (link is not null)
        {
            CheckCanSignIn(link.User!, now);
            return (link.User!, link);
        }

        var email = token.TryGetPayloadValue<string>("email", out var claim) && claim is not null ? AuthService.NormalizeEmail(claim) : null;
        if (email is null || !AuthService.IsValidEmail(email))
        {
            throw new SsoFailure("no_account", "no_email");
        }

        if (!provider.TrustEmailClaim && !EmailVerified(token))
        {
            throw new SsoFailure("no_account", "email_not_verified");
        }

        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        var method = "email";
        if (user is null)
        {
            var domain = email[(email.LastIndexOf('@') + 1)..];
            if (!provider.AutoProvision)
            {
                throw new SsoFailure("no_account", "no_matching_user");
            }

            if (!provider.AllowedDomains.Contains(domain, StringComparer.Ordinal))
            {
                throw new SsoFailure("no_account", "domain_not_allowed");
            }

            if (provider.DefaultRole == UserRole.SuperAdmin || !Enum.IsDefined(provider.DefaultRole))
            {
                throw new SsoFailure("failed", "invalid_default_role"); // never: the settings refuse it
            }

            user = await auth.CreateUserAsync(await UniqueUsernameAsync(email, ct), email, provider.DefaultRole, password: null, ct);
            method = "created";
        }
        else
        {
            CheckCanSignIn(user, now);
            // A user already linked to another account at this provider is not re-linked by email address.
            if (await db.ExternalLogins.AnyAsync(l => l.UserId == user.Id && l.ProviderId == provider.Id, ct))
            {
                throw new SsoFailure("no_account", "linked_to_other_account");
            }
        }

        link = new ExternalLogin
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            User = user,
            ProviderId = provider.Id,
            Issuer = token.Issuer,
            Subject = token.Subject,
            Email = email,
            CreatedAt = now,
        };
        db.ExternalLogins.Add(link);
        audit.Record("auth.sso_linked", "User", user.Id.ToString(), details: new { provider = provider.DisplayName, method, role = user.Role });
        return (user, link);
    }

    private static void CheckCanSignIn(User user, DateTimeOffset now)
    {
        if (!user.IsActive)
        {
            throw new SsoFailure("no_account", "inactive");
        }

        if (user.LockoutUntil is { } until && until > now)
        {
            throw new SsoFailure("failed", "locked_out");
        }
    }

    private static bool EmailVerified(JsonWebToken token) =>
        token.TryGetClaim("email_verified", out var claim) && string.Equals(claim.Value, "true", StringComparison.OrdinalIgnoreCase);

    private async Task<string> UniqueUsernameAsync(string email, CancellationToken ct)
    {
        var name = new string(email.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '@' ? c : '-').ToArray());
        name = name.Length > 60 ? name[..60] : name;
        for (var i = 1; i < 100; i++)
        {
            var candidate = i == 1 ? name : $"{name}-{i}";
            if (!await db.Users.AnyAsync(u => u.Username == candidate, ct))
            {
                return candidate;
            }
        }

        throw new SsoFailure("failed", "username_taken");
    }

    // -------------------------------------------------------------------------------------------
    // Administration
    // -------------------------------------------------------------------------------------------

    /// <summary>Reads the provider's discovery document and key set now (not from the cache), for the settings page.</summary>
    public async Task<OidcProbe> ProbeAsync(string issuer, CancellationToken ct)
    {
        cache.Forget(issuer);
        try
        {
            var config = await OpenIdConnectConfigurationRetriever.GetAsync(DiscoveryAddress(issuer), new OidcDocumentRetriever(httpFactory), ct);
            try
            {
                CheckConfiguration(issuer, config);
            }
            catch (SsoFailure f)
            {
                return new OidcProbe(false, config.Issuer, config.AuthorizationEndpoint, config.TokenEndpoint, config.SigningKeys.Count,
                    f.Reason == "issuer_mismatch"
                        ? $"The discovery document names the issuer \"{config.Issuer}\". Enter exactly that issuer."
                        : "The provider's authorization and token endpoints must use HTTPS.");
            }

            return config.SigningKeys.Count == 0
                ? new OidcProbe(false, config.Issuer, config.AuthorizationEndpoint, config.TokenEndpoint, 0, "The provider publishes no signing keys.")
                : new OidcProbe(true, config.Issuer, config.AuthorizationEndpoint, config.TokenEndpoint, config.SigningKeys.Count,
                    "The discovery document and signing keys were read.");
        }
        catch (Exception ex) when (IsProviderFailure(ex, ct))
        {
            logger.LogInformation("Reading the discovery document of {Issuer} failed: {Error}", issuer, Describe(ex));
            return new OidcProbe(false, null, null, null, 0, $"Could not read {DiscoveryAddress(issuer)} ({Describe(ex)}).");
        }
    }

    /// <summary>Drops the cached discovery document of an issuer whose settings changed.</summary>
    public void Forget(string issuer) => cache.Forget(issuer);

    // -------------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------------

    internal static async Task<string> ReadLimitedAsync(HttpContent content, int maxBytes, CancellationToken ct)
    {
        if (content.Headers.ContentLength > maxBytes)
        {
            throw new IOException("The identity provider's response is too large.");
        }

        await using var stream = await content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                throw new IOException("The identity provider's response is too large.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    /// <summary>A path in the console, never another site: <c>/</c> unless the value is a plain absolute path.</summary>
    public static string SafeReturnTo(string? returnTo) =>
        returnTo is { Length: > 0 and <= 2048 } r && r[0] == '/' && !r.StartsWith("//", StringComparison.Ordinal) &&
        !r.Contains('\\', StringComparison.Ordinal) && !r.Any(char.IsControl) && !r.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
            ? r
            : "/";

    private static string LoginError(string code) => $"/login?sso_error={code}";

    private static bool IsHttps(string? url) => Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;

    private static bool IsProviderFailure(Exception ex, CancellationToken ct) => ex switch
    {
        OperationCanceledException => !ct.IsCancellationRequested, // an HttpClient timeout
        HttpRequestException or IOException or InvalidOperationException or JsonException or SecurityTokenException or ArgumentException
            or FormatException or CryptographicException or DbUpdateException => true,
        _ => false,
    };

    /// <summary>Only the exception type and HTTP status: messages can contain URLs with codes or provider text.</summary>
    private static string Describe(Exception ex) => ex switch
    {
        HttpRequestException { StatusCode: { } status } => $"HTTP {(int)status}",
        OperationCanceledException => "timeout",
        InvalidOperationException { InnerException: { } inner } => Describe(inner),
        _ => ex.GetType().Name,
    };

    private sealed class SsoFailure(string code, string reason) : Exception(reason)
    {
        public string Code { get; } = code;
        public string Reason { get; } = reason;
    }
}
