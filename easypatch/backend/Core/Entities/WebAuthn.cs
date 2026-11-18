namespace EasyPatch.Core.Entities;

/// <summary>
/// A WebAuthn credential (security key or passkey) registered by a user. Only the public key is stored; the private key never
/// leaves the authenticator.
/// </summary>
public sealed class WebAuthnCredential
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public User? User { get; set; }

    /// <summary>The credential ID the authenticator chose (unique across all users).</summary>
    public required byte[] CredentialId { get; set; }

    /// <summary>The COSE-encoded public key.</summary>
    public required byte[] PublicKey { get; set; }

    /// <summary>The authenticator's signature counter at the last use (0 for authenticators that do not count).</summary>
    public long SignCount { get; set; }

    /// <summary>The authenticator model (all zeros when the authenticator does not say).</summary>
    public Guid Aaguid { get; set; }

    /// <summary>How the browser can reach the authenticator (usb, nfc, ble, internal, hybrid), as reported at registration.</summary>
    public List<string> Transports { get; set; } = [];

    /// <summary>A name the user chose, e.g. "YubiKey 5C" or "MacBook".</summary>
    public required string Name { get; set; }

    /// <summary>A passkey: a discoverable credential that signs the user in without an email address or password. A security key
    /// registered only as a second factor is not one.</summary>
    public bool IsPasskey { get; set; }

    /// <summary>The credential can be synced to other devices (backup eligible).</summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>The credential is currently synced (backed up).</summary>
    public bool IsBackedUp { get; set; }

    /// <summary>The attestation statement format at registration (EasyPatch asks for none).</summary>
    public string? AttestationFormat { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}

/// <summary>What a WebAuthn challenge is for.</summary>
public enum WebAuthnPurpose
{
    /// <summary>Registering a security key or passkey for the signed-in user.</summary>
    Register,

    /// <summary>A security key or passkey as the second factor after the password.</summary>
    SecondFactor,

    /// <summary>Signing in with a passkey alone.</summary>
    PasskeySignIn,
}

/// <summary>
/// A pending WebAuthn ceremony: the options sent to the browser (they contain the random challenge), bound to the session or, for a
/// passkey sign-in, to a random value in a browser cookie. Used once, and only within a few minutes.
/// </summary>
public sealed class WebAuthnChallenge
{
    public Guid Id { get; set; }
    public WebAuthnPurpose Purpose { get; set; }
    public Guid? UserId { get; set; }
    public Guid? SessionId { get; set; }

    /// <summary>SHA-256 (hex) of the random value in the passkey sign-in cookie.</summary>
    public string? BindingHash { get; set; }

    /// <summary>The credential creation or request options as JSON.</summary>
    public required string OptionsJson { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
