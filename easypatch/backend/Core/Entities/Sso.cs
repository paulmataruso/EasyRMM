namespace EasyPatch.Core.Entities;

/// <summary>An OpenID Connect identity provider users can sign in with. Configured by a super administrator.</summary>
public sealed class OidcProvider
{
    public Guid Id { get; set; }

    /// <summary>Shown on the sign-in button: "Sign in with {DisplayName}".</summary>
    public required string DisplayName { get; set; }

    /// <summary>The issuer identifier. Discovery is read from <c>{Issuer}/.well-known/openid-configuration</c>.</summary>
    public required string Issuer { get; set; }

    public required string ClientId { get; set; }

    /// <summary>The client secret, protected with ASP.NET Data Protection like the SMTP password. Null for a public client.</summary>
    public string? ClientSecretProtected { get; set; }

    /// <summary>Space-separated scopes; must include <c>openid</c>.</summary>
    public string Scopes { get; set; } = "openid email profile";

    public bool Enabled { get; set; } = true;

    /// <summary>Link an account by its email address even when the ID token does not say <c>email_verified: true</c>.</summary>
    public bool TrustEmailClaim { get; set; }

    /// <summary>The provider enforces MFA, so a sign-in through it does not ask for EasyPatch's second factor.</summary>
    public bool ProviderEnforcesMfa { get; set; }

    /// <summary>Create an account on first sign-in for an address in <see cref="AllowedDomains"/>.</summary>
    public bool AutoProvision { get; set; }

    /// <summary>The role of created accounts; never <see cref="UserRole.SuperAdmin"/>.</summary>
    public UserRole DefaultRole { get; set; } = UserRole.ReadOnly;

    /// <summary>Lower-case email domains for which accounts may be created.</summary>
    public List<string> AllowedDomains { get; set; } = [];

    /// <summary>
    /// This provider is EasyRMM, which owns EasyPatch (at most one provider is). Its accounts are managed by EasyRMM: matched by issuer
    /// and subject only, never by email; their role and organizations come from the ID token's <c>easypatch</c> claim at every sign-in;
    /// they sign in only through EasyRMM. Its second factor counts only when the token's <c>amr</c> contains <c>mfa</c>, and its sessions
    /// last at most <see cref="EasyRmmSessionLifetime"/>. <see cref="TrustEmailClaim"/>, <see cref="ProviderEnforcesMfa"/> and
    /// <see cref="AutoProvision"/> are off.
    /// </summary>
    public bool IsEasyRmm { get; set; }

    /// <summary>The longest session a sign-in through EasyRMM gives: a role taken away in EasyRMM lasts at most this long here.</summary>
    public static readonly TimeSpan EasyRmmSessionLifetime = TimeSpan.FromHours(1);

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Links a user to an account at an OpenID Connect provider, identified by the token's issuer and subject.</summary>
public sealed class ExternalLogin
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public Guid ProviderId { get; set; }
    public OidcProvider? Provider { get; set; }
    public required string Issuer { get; set; }
    public required string Subject { get; set; }

    /// <summary>The address the provider reported when the link was made, for administrators.</summary>
    public string? Email { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}

/// <summary>A sign-in in progress at a provider: single use, valid for 10 minutes and bound to the browser that started it.</summary>
public sealed class OidcLoginState
{
    public Guid Id { get; set; }
    public Guid ProviderId { get; set; }

    /// <summary>SHA-256 of the <c>state</c> parameter.</summary>
    public required string StateHash { get; set; }

    /// <summary>SHA-256 of the random value in the browser's binding cookie.</summary>
    public required string BindingHash { get; set; }

    public required string Nonce { get; set; }

    /// <summary>The PKCE code verifier (S256).</summary>
    public required string CodeVerifier { get; set; }

    public required string ReturnTo { get; set; }

    /// <summary>The signed-in user who started this sign-in to link their account to EasyRMM (My account → Link EasyRMM); null for a
    /// sign-in.</summary>
    public Guid? LinkUserId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
