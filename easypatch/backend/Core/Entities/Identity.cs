namespace EasyPatch.Core.Entities;

/// <summary>An account of a standalone EasyPatch (up to 1.10.0). Nobody signs in with one any more: people sign in to EasyRMM.
/// The account tables stay so an imported database keeps its history, and <c>prepare-import</c> disables what it brings;
/// sessions, passkeys, single sign-on and password resets are kept the same way, unused.</summary>
public sealed class User
{
    public Guid Id { get; set; }
    public required string Username { get; set; }
    public required string Email { get; set; }
    public required string PasswordHash { get; set; }
    public UserRole Role { get; set; }
    public bool IsActive { get; set; } = true;

    /// <summary>An authenticator app (TOTP) is set up. Security keys and passkeys are the other second factor
    /// (<see cref="WebAuthnCredential"/>): a user has MFA when either is present.</summary>
    public bool MfaEnabled { get; set; }

    /// <summary>TOTP secret protected with ASP.NET Data Protection.</summary>
    public string? MfaSecretProtected { get; set; }

    /// <summary>Pending (not yet confirmed) TOTP secret during MFA setup.</summary>
    public string? MfaPendingSecretProtected { get; set; }
    public long? MfaLastUsedStep { get; set; }
    public List<string> RecoveryCodeHashes { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public int FailedLoginCount { get; set; }
    public int LockoutCount { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }
    public DateTimeOffset PasswordChangedAt { get; set; }
    public bool MustChangePassword { get; set; }

    /// <summary>When the user last answered "Not now" to the offer to set up a passkey.</summary>
    public DateTimeOffset? PasskeyPromptDismissedAt { get; set; }

    /// <summary>
    /// Whether the user reaches every organization. When false they reach only those in <see cref="OrganizationAccess"/>, which
    /// can be none, for example after their organizations were deleted. An empty list never widens access. Super administrators
    /// reach every organization whatever this says.
    /// </summary>
    public bool AllOrganizations { get; set; } = true;

    public List<UserOrganizationAccess> OrganizationAccess { get; set; } = [];
    public List<WebAuthnCredential> WebAuthnCredentials { get; set; } = [];
    public List<ExternalLogin> ExternalLogins { get; set; } = [];
}

public sealed class UserSession
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public required string TokenHash { get; set; }
    public bool MfaCompleted { get; set; }

    /// <summary>Signed in through an identity provider that enforces MFA: EasyPatch does not require its own second factor.</summary>
    public bool MfaByProvider { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>Restricts a non-SuperAdmin user to specific organizations (customer-scoped admins).</summary>
public sealed class UserOrganizationAccess
{
    public Guid UserId { get; set; }
    public Guid OrganizationId { get; set; }
}

/// <summary>
/// An API token of a standalone EasyPatch (up to 1.10.0): a long-lived credential for scripts and integrations, stored as a SHA-256
/// hash. The patching engine no longer accepts any (it takes only EasyRMM's statements). The table stays, as the account tables do,
/// so the upgrade needs no migration; <c>prepare-import</c> deletes the tokens of an imported database.
/// </summary>
public sealed class ApiToken
{
    public Guid Id { get; set; }
    public required string Name { get; set; }

    /// <summary>The first characters of the secret (e.g. <c>ept_AbC12xYz</c>), to recognize a token without revealing it.</summary>
    public required string Prefix { get; set; }

    public required string TokenHash { get; set; }

    /// <summary><see cref="UserRole.ReadOnly"/> or <see cref="UserRole.Admin"/>.</summary>
    public UserRole Role { get; set; }

    public bool AllOrganizations { get; set; }

    /// <summary>The organizations a scoped token can access (ignored when <see cref="AllOrganizations"/> is set).</summary>
    public List<Guid> OrganizationIds { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public string? LastUsedIp { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
}

public sealed class PasswordResetToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required string TokenHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
}

public sealed class AuditLog
{
    public long Id { get; set; }
    public Guid? UserId { get; set; }
    public string? Username { get; set; }
    public Guid? OrganizationId { get; set; }
    public Guid? EndpointId { get; set; }
    public required string Action { get; set; }
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }

    /// <summary>JSON document with action-specific details.</summary>
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public string? CorrelationId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
