using EasyPatch.Core.Entities;

namespace EasyPatch.Api.Contracts;

// Single sign-on (OpenID Connect).

/// <summary>An enabled provider, for the sign-in page's "Sign in with …" buttons.</summary>
/// <param name="IsEasyRmm">The provider is EasyRMM: listed first, and the console signs in through it on its own when it came from EasyRMM
/// or last signed in that way.</param>
public sealed record SsoProviderSummaryDto(Guid Id, string DisplayName, bool IsEasyRmm = false);

/// <param name="ClientSecretConfigured">The secret itself is never returned.</param>
/// <param name="LinkedUsers">Users linked to an account at this provider.</param>
public sealed record SsoProviderDto(
    Guid Id,
    string DisplayName,
    string Issuer,
    string ClientId,
    bool ClientSecretConfigured,
    string Scopes,
    bool Enabled,
    bool TrustEmailClaim,
    bool ProviderEnforcesMfa,
    bool AutoProvision,
    UserRole DefaultRole,
    IReadOnlyList<string> AllowedDomains,
    int LinkedUsers,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    bool IsEasyRmm = false);

/// <param name="RedirectUri">The redirect URI to register at every provider.</param>
public sealed record SsoSettingsDto(string RedirectUri, IReadOnlyList<SsoProviderDto> Providers);

/// <param name="ClientSecret">Write-only: null keeps the stored secret, an empty string removes it (a public client).</param>
/// <param name="Scopes">Space-separated; must include <c>openid</c>. Default <c>openid email profile</c>.</param>
/// <param name="AllowedDomains">Email domains for which <paramref name="AutoProvision"/> may create accounts (required when it is on).</param>
/// <param name="IsEasyRmm">The provider is EasyRMM (see <see cref="OidcProvider.IsEasyRmm"/>). It cannot change while users are linked.
/// It requires <paramref name="TrustEmailClaim"/>, <paramref name="ProviderEnforcesMfa"/> and <paramref name="AutoProvision"/> off.</param>
public sealed record SsoProviderRequest(
    string DisplayName,
    string Issuer,
    string ClientId,
    string? ClientSecret,
    string? Scopes,
    bool Enabled,
    bool TrustEmailClaim,
    bool ProviderEnforcesMfa,
    bool AutoProvision,
    UserRole DefaultRole,
    IReadOnlyList<string>? AllowedDomains,
    bool IsEasyRmm = false);

/// <param name="Password">The current password, unless the account has none or signed in within the last 10 minutes.</param>
public sealed record LinkEasyRmmRequest(string? Password);

/// <param name="Redirect">EasyRMM's sign-in page: the console goes there with a full page load.</param>
public sealed record LinkEasyRmmResponse(string Redirect);

public sealed record SsoProbeRequest(string Issuer);

public sealed record SsoProbeDto(bool Ok, string? Issuer, string? AuthorizationEndpoint, string? TokenEndpoint, int SigningKeys, string Message);

/// <summary>A user's link to an account at a provider (issuer and subject).</summary>
public sealed record ExternalLoginDto(Guid Id, Guid ProviderId, string ProviderName, string Issuer, string Subject, string? Email,
    DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);
