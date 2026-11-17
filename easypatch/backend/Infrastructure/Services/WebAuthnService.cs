using System.Security.Cryptography;
using System.Text.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Services;

/// <summary>Whether this server can offer passkeys and security keys, and if not, why.</summary>
/// <param name="RpId">The WebAuthn relying party ID: the console's host name.</param>
/// <param name="Origin">The only origin WebAuthn responses are accepted from: <c>https://host[:port]</c>.</param>
public sealed record WebAuthnAvailability(bool Available, string? RpId, string? Origin, string? Reason, string? Message)
{
    /// <summary>Browsers accept WebAuthn only on a secure origin whose host is a domain name: the console's public URL must be
    /// <c>https://</c> with a DNS name (<c>localhost</c> is allowed for development), not an IP address.</summary>
    public static WebAuthnAvailability FromPublicUrl(string? publicUrl)
    {
        if (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var uri))
        {
            return new(false, null, null, "invalid_public_url", "The server's public URL (EASYPATCH_DOMAIN) is not a valid URL.");
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return new(false, null, null, "not_https", "Passkeys and security keys need the console to be served over HTTPS.");
        }

        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            return new(false, null, null, "ip_address",
                $"Passkeys and security keys need the console to be reached by a DNS name, not an IP address ({uri.Host}). Set EASYPATCH_DOMAIN to a name that resolves to this server and has a certificate browsers trust.");
        }

        var host = uri.IdnHost.ToLowerInvariant();
        return new(true, host, uri.IsDefaultPort ? $"https://{host}" : $"https://{host}:{uri.Port}", null, null);
    }
}

/// <summary>What a registration produced: the credential and, for a user's first second factor, new recovery codes.</summary>
public sealed record WebAuthnRegistration(WebAuthnCredential Credential, IReadOnlyList<string>? RecoveryCodes);

/// <summary>
/// WebAuthn (FIDO2) security keys and passkeys, verified with the passwordless-lib Fido2 library: registration for the signed-in user,
/// a key as the second factor after the password, and passkey sign-in. Each ceremony's options (with its random challenge) are kept
/// on the server, bound to the session or to a browser cookie, and used at most once within five minutes. Challenges, public keys and
/// assertions are never logged.
/// </summary>
public sealed class WebAuthnService(
    EasyPatchDbContext db,
    AuthService auth,
    IOptions<EasyPatchOptions> options,
    AuditService audit,
    TimeProvider clock,
    ILogger<WebAuthnService> logger)
{
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(5);
    public const int MaxCredentialsPerUser = 20;
    public const int MaxNameLength = 64;

    /// <summary>A user who dismissed the passkey prompt sees it again after this long.</summary>
    public static readonly TimeSpan PasskeyPromptInterval = TimeSpan.FromDays(30);

    private static readonly JsonSerializerOptions ResponseJson = new() { PropertyNameCaseInsensitive = true };

    public WebAuthnAvailability Availability => WebAuthnAvailability.FromPublicUrl(options.Value.PublicUrl);

    // -------------------------------------------------------------------------------------------
    // Registration (signed-in user)
    // -------------------------------------------------------------------------------------------

    /// <summary>Starts registering a passkey (<paramref name="passkey"/>, discoverable, with user verification) or a security key
    /// used only as a second factor. A user who already has a second factor confirms with their password first.</summary>
    public async Task<string> BeginRegistrationAsync(Guid userId, Guid sessionId, bool passkey, string? password, CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        var session = await db.UserSessions.FirstAsync(s => s.Id == sessionId, ct);
        var existing = await db.WebAuthnCredentials.Where(c => c.UserId == userId).Select(c => new { c.CredentialId, c.Transports }).ToListAsync(ct);
        if (user.MfaEnabled || existing.Count > 0)
        {
            auth.RequireReauthentication(user, session, password);
        }

        if (existing.Count >= MaxCredentialsPerUser)
        {
            throw AppException.Conflict($"An account can have at most {MaxCredentialsPerUser} security keys and passkeys. Remove one first.", "too_many_keys");
        }

        var createOptions = Fido(availability).RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = userId.ToByteArray(), Name = user.Email, DisplayName = user.Username },
            ExcludeCredentials = existing.Select(c => new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, c.CredentialId, Transports(c.Transports)))
                .ToList(),
            AuthenticatorSelection = passkey
                ? new AuthenticatorSelection { ResidentKey = ResidentKeyRequirement.Required, UserVerification = UserVerificationRequirement.Required }
                : new AuthenticatorSelection { ResidentKey = ResidentKeyRequirement.Discouraged, UserVerification = UserVerificationRequirement.Discouraged },
            AttestationPreference = AttestationConveyancePreference.None,
            Extensions = new AuthenticationExtensionsClientInputs { CredProps = true },
        });
        var json = createOptions.ToJson();
        await StoreChallengeAsync(WebAuthnPurpose.Register, userId, sessionId, null, json, ct);
        return json;
    }

    public async Task<WebAuthnRegistration> CompleteRegistrationAsync(Guid userId, Guid sessionId, string? name, string credentialJson,
        CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        var challenge = await ConsumeAsync(c => c.Purpose == WebAuthnPurpose.Register && c.SessionId == sessionId && c.UserId == userId, ct);
        var original = CredentialCreateOptions.FromJson(challenge.OptionsJson);
        var response = Parse<AuthenticatorAttestationRawResponse>(credentialJson);
        RegisteredPublicKeyCredential registered;
        try
        {
            registered = await Fido(availability).MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = response,
                OriginalOptions = original,
                IsCredentialIdUniqueToUserCallback = async (args, token) =>
                    !await db.WebAuthnCredentials.AnyAsync(c => c.CredentialId == args.CredentialId, token),
            }, ct);
        }
        catch (Exception ex) when (IsVerificationFailure(ex))
        {
            logger.LogInformation("Registering a security key for user {UserId} failed verification: {Reason}", userId, Reason(ex));
            audit.Record("auth.webauthn_add_failed", "User", userId.ToString());
            await db.SaveChangesAsync(ct);
            throw AppException.BadRequest("The security key or passkey could not be registered. Try again.", "webauthn_failed");
        }

        var requestedPasskey = original.AuthenticatorSelection?.ResidentKey == ResidentKeyRequirement.Required;
        var isPasskey = response.ClientExtensionResults?.CredProps?.Rk ?? requestedPasskey;
        var now = clock.GetUtcNow();
        var credential = new WebAuthnCredential
        {
            Id = Guid.CreateVersion7(now),
            UserId = userId,
            CredentialId = registered.Id,
            PublicKey = registered.PublicKey,
            SignCount = registered.SignCount,
            Aaguid = registered.AaGuid,
            Transports = registered.Transports?.Select(t => t.ToString().ToLowerInvariant()).Distinct().ToList() ?? [],
            Name = CleanName(name) ?? (isPasskey ? "Passkey" : "Security key"),
            IsPasskey = isPasskey,
            IsBackupEligible = registered.IsBackupEligible,
            IsBackedUp = registered.IsBackedUp,
            AttestationFormat = ScanIngestionService.Truncate(registered.AttestationFormat, 32),
            CreatedAt = now,
        };
        db.WebAuthnCredentials.Add(credential);

        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        var hadSecondFactor = user.MfaEnabled || await db.WebAuthnCredentials.AnyAsync(c => c.UserId == userId, ct);
        IReadOnlyList<string>? codes = null;
        if (!hadSecondFactor)
        {
            // The first second factor: recovery codes sign the user in if the key is lost, as with an authenticator app.
            codes = AuthService.GenerateRecoveryCodes(user);
        }

        audit.Record("auth.webauthn_added", "User", userId.ToString(), details: new
        {
            credential = credential.Id, credential.Name, kind = isPasskey ? "passkey" : "security_key", aaguid = credential.Aaguid,
        });
        await db.SaveChangesAsync(ct);
        return new WebAuthnRegistration(credential, codes);
    }

    public async Task<WebAuthnCredential> RenameAsync(Guid userId, Guid credentialId, string? name, CancellationToken ct = default)
    {
        var credential = await db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.Id == credentialId && c.UserId == userId, ct)
                         ?? throw AppException.NotFound("Security key");
        credential.Name = CleanName(name) ?? throw AppException.BadRequest($"Enter a name of 1 to {MaxNameLength} characters.", "validation_failed");
        audit.Record("auth.webauthn_renamed", "User", userId.ToString(), details: new { credential = credential.Id, credential.Name });
        await db.SaveChangesAsync(ct);
        return credential;
    }

    /// <summary>Removes a key after the password (or a recent sign-in) confirms it. The last second factor cannot be removed while
    /// the server requires MFA.</summary>
    public async Task RemoveAsync(Guid userId, Guid sessionId, Guid credentialId, string? password, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        var session = await db.UserSessions.FirstAsync(s => s.Id == sessionId, ct);
        var credential = await db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.Id == credentialId && c.UserId == userId, ct)
                         ?? throw AppException.NotFound("Security key");
        auth.RequireReauthentication(user, session, password);
        var others = await db.WebAuthnCredentials.CountAsync(c => c.UserId == userId && c.Id != credentialId, ct);
        var last = !user.MfaEnabled && others == 0;
        if (last && (await auth.RequireMfaAsync(ct)))
        {
            throw AppException.Conflict(
                "This is your only second factor and the server requires one. Add another security key, passkey or authenticator app first.",
                "mfa_required");
        }

        db.WebAuthnCredentials.Remove(credential);
        if (last)
        {
            user.RecoveryCodeHashes = []; // no second factor is left for them to replace
        }

        audit.Record("auth.webauthn_removed", "User", userId.ToString(), details: new { credential = credential.Id, credential.Name });
        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // Second factor after the password
    // -------------------------------------------------------------------------------------------

    public async Task<string> BeginSecondFactorAsync(Guid sessionId, CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        var session = await PendingSessionAsync(sessionId, ct);
        var credentials = await db.WebAuthnCredentials.Where(c => c.UserId == session.UserId).Select(c => new { c.CredentialId, c.Transports })
            .ToListAsync(ct);
        if (credentials.Count == 0)
        {
            throw AppException.BadRequest("This account has no security key or passkey.", "no_security_key");
        }

        var assertionOptions = Fido(availability).GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = credentials
                .Select(c => new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, c.CredentialId, Transports(c.Transports))).ToList(),
            UserVerification = UserVerificationRequirement.Discouraged,
        });
        var json = assertionOptions.ToJson();
        await StoreChallengeAsync(WebAuthnPurpose.SecondFactor, session.UserId, sessionId, null, json, ct);
        return json;
    }

    public async Task CompleteSecondFactorAsync(Guid sessionId, string credentialJson, CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        var session = await PendingSessionAsync(sessionId, ct);
        var user = await db.Users.FirstAsync(u => u.Id == session.UserId, ct);
        var challenge = await ConsumeAsync(c => c.Purpose == WebAuthnPurpose.SecondFactor && c.SessionId == sessionId, ct);
        var response = Parse<AuthenticatorAssertionRawResponse>(credentialJson);
        var credential = await db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.UserId == user.Id && c.CredentialId == response.RawId, ct);
        var now = clock.GetUtcNow();
        if (credential is null || !await VerifyAsync(availability, challenge, response, credential, user.Id, ct))
        {
            auth.RegisterFailure(user, now);
            if (user.LockoutUntil is not null)
            {
                session.RevokedAt = now;
            }

            audit.Record("auth.mfa_failed", "User", user.Id.ToString(), details: new { method = "security_key", reason = credential is null ? "unknown_credential" : "invalid" });
            await db.SaveChangesAsync(ct);
            throw AppException.Unauthorized("invalid_security_key", "The security key could not be verified.");
        }

        user.FailedLoginCount = 0;
        user.LastLoginAt = now;
        session.MfaCompleted = true;
        audit.Record("auth.login", "User", user.Id.ToString(), details: new { mfa = credential.IsPasskey ? "passkey" : "security_key", credential = credential.Id });
        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // Passkey sign-in (no email address or password)
    // -------------------------------------------------------------------------------------------

    /// <summary>Starts a passkey sign-in. <paramref name="browserBinding"/> is a random value the caller puts in a cookie; the
    /// sign-in completes only in the browser that has it.</summary>
    public async Task<string> BeginPasskeySignInAsync(string browserBinding, CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        var assertionOptions = Fido(availability).GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = UserVerificationRequirement.Required,
        });
        var json = assertionOptions.ToJson();
        await StoreChallengeAsync(WebAuthnPurpose.PasskeySignIn, null, null, SecureTokens.Hash(browserBinding), json, ct);
        return json;
    }

    /// <summary>Signs in with a passkey: user verification on the authenticator (PIN or biometrics) plus possession of the key count as
    /// both factors, so the session needs no further MFA step.</summary>
    public async Task<LoginResult> CompletePasskeySignInAsync(string? browserBinding, string credentialJson, string? ip, string? userAgent,
        CancellationToken ct = default)
    {
        var availability = RequireAvailable();
        if (string.IsNullOrEmpty(browserBinding) || browserBinding.Length > 100)
        {
            throw ChallengeExpired();
        }

        var binding = SecureTokens.Hash(browserBinding);
        var challenge = await ConsumeAsync(c => c.Purpose == WebAuthnPurpose.PasskeySignIn && c.BindingHash == binding, ct);
        var response = Parse<AuthenticatorAssertionRawResponse>(credentialJson);
        var credential = await db.WebAuthnCredentials.Include(c => c.User).FirstOrDefaultAsync(c => c.CredentialId == response.RawId, ct);
        var now = clock.GetUtcNow();
        if (credential?.User is not { } user)
        {
            audit.Record("auth.login_failed", "User", null, details: new { method = "passkey", reason = "unknown_credential" });
            await db.SaveChangesAsync(ct);
            throw InvalidPasskey();
        }

        if (!user.IsActive || user.LockoutUntil is { } until && until > now)
        {
            audit.Record("auth.login_failed", "User", user.Id.ToString(), details: new { method = "passkey", reason = user.IsActive ? "locked_out" : "inactive" });
            await db.SaveChangesAsync(ct);
            throw InvalidPasskey();
        }

        if (!await VerifyAsync(availability, challenge, response, credential, user.Id, ct))
        {
            auth.RegisterFailure(user, now);
            audit.Record("auth.login_failed", "User", user.Id.ToString(), details: new { method = "passkey", reason = "invalid" });
            await db.SaveChangesAsync(ct);
            throw InvalidPasskey();
        }

        credential.IsPasskey = true; // it answered a request without an allow list, so it is discoverable
        user.FailedLoginCount = 0;
        user.LastLoginAt = now;
        var (session, token) = await auth.NewSessionAsync(user, mfaCompleted: true, ip, userAgent, ct);
        audit.Record("auth.login", "User", user.Id.ToString(), details: new { method = "passkey", credential = credential.Id });
        await db.SaveChangesAsync(ct);
        return new LoginResult(user, session, token, MfaRequired: false, MfaSetupRequired: false);
    }

    // -------------------------------------------------------------------------------------------
    // Passkey prompt
    // -------------------------------------------------------------------------------------------

    /// <summary>Whether to offer a passkey after sign-in: WebAuthn works on this server, the user has no passkey (a security key used
    /// only as a second factor does not count), and they have not answered "Not now" within <see cref="PasskeyPromptInterval"/>.</summary>
    public bool ShouldPromptForPasskey(User user, int passkeyCount) =>
        passkeyCount == 0 && Availability.Available &&
        (user.PasskeyPromptDismissedAt is not { } dismissed || clock.GetUtcNow() - dismissed >= PasskeyPromptInterval);

    public async Task DismissPasskeyPromptAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        user.PasskeyPromptDismissedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------------

    private async Task<bool> VerifyAsync(WebAuthnAvailability availability, WebAuthnChallenge challenge, AuthenticatorAssertionRawResponse response,
        WebAuthnCredential credential, Guid userId, CancellationToken ct)
    {
        try
        {
            var userHandle = userId.ToByteArray();
            var result = await Fido(availability).MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = AssertionOptions.FromJson(challenge.OptionsJson),
                StoredPublicKey = credential.PublicKey,
                StoredSignatureCounter = (uint)credential.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
                    Task.FromResult(args.UserHandle is null || CryptographicOperations.FixedTimeEquals(args.UserHandle, userHandle)),
            }, ct);
            credential.SignCount = result.SignCount;
            credential.IsBackedUp = result.IsBackedUp;
            credential.LastUsedAt = clock.GetUtcNow();
            return true;
        }
        catch (Exception ex) when (IsVerificationFailure(ex))
        {
            logger.LogInformation("A security key or passkey of user {UserId} failed verification: {Reason}", userId, Reason(ex));
            return false;
        }
    }

    /// <summary>A response the library rejected, including one too malformed to parse (not a server fault).</summary>
    private static bool IsVerificationFailure(Exception ex) =>
        ex is Fido2VerificationException or System.Formats.Cbor.CborContentException or FormatException or ArgumentException
            or InvalidOperationException or NotSupportedException or CryptographicException or JsonException;

    /// <summary>Only the library's error code or the exception type: never the message, which may quote the response.</summary>
    private static string Reason(Exception ex) => ex is Fido2VerificationException f ? f.Code.ToString() : ex.GetType().Name;

    private async Task<UserSession> PendingSessionAsync(Guid sessionId, CancellationToken ct)
    {
        var session = await db.UserSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct)
                      ?? throw AppException.Unauthorized("session_invalid", "Your session has expired. Sign in again.");
        if (session.MfaCompleted)
        {
            throw AppException.BadRequest("This sign-in is already complete.", "mfa_completed");
        }

        return session;
    }

    private async Task StoreChallengeAsync(WebAuthnPurpose purpose, Guid? userId, Guid? sessionId, string? bindingHash, string optionsJson,
        CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        // One pending ceremony per session (or browser) and purpose; expired ones of anybody are removed on the way.
        await db.WebAuthnChallenges
            .Where(c => c.ExpiresAt <= now || (c.Purpose == purpose &&
                                               ((sessionId != null && c.SessionId == sessionId) || (bindingHash != null && c.BindingHash == bindingHash))))
            .ExecuteDeleteAsync(ct);
        db.WebAuthnChallenges.Add(new WebAuthnChallenge
        {
            Id = Guid.CreateVersion7(now),
            Purpose = purpose,
            UserId = userId,
            SessionId = sessionId,
            BindingHash = bindingHash,
            OptionsJson = optionsJson,
            CreatedAt = now,
            ExpiresAt = now + ChallengeLifetime,
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Takes the pending challenge out of the database. Only one caller can: a replayed response finds nothing.</summary>
    private async Task<WebAuthnChallenge> ConsumeAsync(System.Linq.Expressions.Expression<Func<WebAuthnChallenge, bool>> match, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var challenge = await db.WebAuthnChallenges.AsNoTracking().Where(match).OrderByDescending(c => c.CreatedAt).FirstOrDefaultAsync(ct);
        if (challenge is null || await db.WebAuthnChallenges.Where(c => c.Id == challenge.Id).ExecuteDeleteAsync(ct) == 0 || challenge.ExpiresAt <= now)
        {
            throw ChallengeExpired();
        }

        return challenge;
    }

    private WebAuthnAvailability RequireAvailable()
    {
        var availability = Availability;
        return availability.Available
            ? availability
            : throw AppException.Conflict(availability.Message ?? "Passkeys and security keys are not available on this server.", "webauthn_unavailable");
    }

    private static Fido2 Fido(WebAuthnAvailability availability) => new(new Fido2Configuration
    {
        RPID = availability.RpId!,
        RPName = "EasyPatch",
        Origins = new HashSet<string>(StringComparer.Ordinal) { availability.Origin! },
        Timeout = (uint)ChallengeLifetime.TotalMilliseconds,
    });

    private static T Parse<T>(string json) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, ResponseJson) ?? throw new JsonException();
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException or NotSupportedException)
        {
            throw AppException.BadRequest("The browser's WebAuthn response is not valid.", "validation_failed");
        }
    }

    private static AuthenticatorTransport[]? Transports(List<string> values)
    {
        var parsed = values.Select(v => Enum.TryParse<AuthenticatorTransport>(v, ignoreCase: true, out var t) ? t : (AuthenticatorTransport?)null)
            .Where(t => t is not null).Select(t => t!.Value).ToArray();
        return parsed.Length == 0 ? null : parsed;
    }

    private static string? CleanName(string? name)
    {
        var trimmed = name?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed.Length > MaxNameLength ? trimmed[..MaxNameLength] : trimmed;
    }

    private static AppException ChallengeExpired() =>
        AppException.BadRequest("The security key request expired or was already used. Try again.", "webauthn_challenge_expired");

    private static AppException InvalidPasskey() => AppException.Unauthorized("invalid_passkey", "The passkey could not be verified.");
}
