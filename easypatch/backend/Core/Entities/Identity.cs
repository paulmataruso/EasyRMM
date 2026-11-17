namespace EasyPatch.Core.Entities;

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
/// A long-lived credential for scripts and integrations (PSA, RMM, reporting). Only a SHA-256 hash of the secret is stored; the
/// secret is shown once when the token is created. A token acts with a fixed role (never SuperAdmin) and organization scope.
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
