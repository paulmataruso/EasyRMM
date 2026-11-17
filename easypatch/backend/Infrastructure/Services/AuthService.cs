using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using QRCoder;

namespace EasyPatch.Infrastructure.Services;

public sealed record LoginResult(User User, UserSession Session, string SessionToken, bool MfaRequired, bool MfaSetupRequired);

public sealed record SessionValidation(UserSession Session, User User, bool MfaSetupRequired);

public sealed record MfaSetup(string Secret, string OtpAuthUri, string QrCodeDataUri);

/// <summary>Administrator authentication: Argon2id passwords, lockout, server-side sessions, TOTP MFA, recovery codes,
/// administrator-issued password reset links.</summary>
public sealed class AuthService(
    EasyPatchDbContext db,
    IPasswordHasher hasher,
    IDataProtectionProvider dataProtection,
    SettingsService settingsService,
    AuditService audit,
    TimeProvider clock,
    ILogger<AuthService> logger)
{
    public const int MaxFailedAttempts = 5;
    private const string SessionPrefix = "eps_";
    private const string ResetPrefix = "epr_";
    private static readonly TimeSpan BaseLockout = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan MaxLockout = TimeSpan.FromHours(24);
    private static readonly string DummyHash = new Argon2PasswordHasher().Hash("dummy-password-for-timing");

    private IDataProtector MfaProtector => dataProtection.CreateProtector("EasyPatch.Mfa.v1");

    public static string NormalizeUsername(string username) => username.Trim().ToLowerInvariant();

    /// <summary>The form in which email addresses are stored and looked up: sign-in uses the email address, ignoring case.</summary>
    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    /// <summary>A plain address (<c>name@domain</c>, no display name or angle brackets) of at most 256 characters.</summary>
    public static bool IsValidEmail(string normalized) =>
        normalized.Length is >= 3 and <= 256 && !normalized.Any(char.IsWhiteSpace) &&
        System.Net.Mail.MailAddress.TryCreate(normalized, out var address) && address.Address == normalized &&
        address.User.Length > 0 && address.Host.Length > 0;

    // -------------------------------------------------------------------------------------------
    // Login / sessions
    // -------------------------------------------------------------------------------------------

    /// <summary>Signs in with the account's email address (the only sign-in name) and password.</summary>
    public async Task<LoginResult> LoginAsync(string email, string password, string? ip, string? userAgent, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var normalized = NormalizeEmail(email ?? string.Empty);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == normalized, ct);
        if (user is null || !user.IsActive)
        {
            hasher.Verify(password ?? string.Empty, DummyHash); // equalize timing
            audit.Record("auth.login_failed", "User", null, details: new { email = normalized, reason = "unknown_or_inactive" });
            await db.SaveChangesAsync(ct);
            throw InvalidCredentials();
        }

        if (user.LockoutUntil is { } until && until > now)
        {
            audit.Record("auth.login_blocked", "User", user.Id.ToString(), details: new { until });
            await db.SaveChangesAsync(ct);
            throw InvalidCredentials();
        }

        var result = hasher.Verify(password ?? string.Empty, user.PasswordHash);
        if (result == PasswordVerification.Failed)
        {
            RegisterFailure(user, now);
            audit.Record("auth.login_failed", "User", user.Id.ToString(), details: new { reason = "bad_password", user.FailedLoginCount });
            await db.SaveChangesAsync(ct);
            throw InvalidCredentials();
        }

        if (result == PasswordVerification.SuccessRehashNeeded)
        {
            user.PasswordHash = hasher.Hash(password!);
        }

        user.FailedLoginCount = 0;
        var settings = await settingsService.GetAsync(ct);
        var hasMfa = await HasSecondFactorAsync(user, ct);
        var (session, token) = NewSession(user, mfaCompleted: !hasMfa, ip, userAgent, settings, now);
        if (!hasMfa)
        {
            user.LastLoginAt = now;
            audit.Record("auth.login", "User", user.Id.ToString());
        }

        await db.SaveChangesAsync(ct);
        return new LoginResult(user, session, token, hasMfa, !hasMfa && settings.RequireMfa);
    }

    /// <summary>An authenticator app or at least one security key or passkey.</summary>
    public async Task<bool> HasSecondFactorAsync(User user, CancellationToken ct = default) =>
        user.MfaEnabled || await db.WebAuthnCredentials.AnyAsync(c => c.UserId == user.Id, ct);

    public async Task<SessionValidation?> ValidateSessionAsync(string? token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token) || !token.StartsWith(SessionPrefix, StringComparison.Ordinal) || token.Length > 100)
        {
            return null;
        }

        var now = clock.GetUtcNow();
        var hash = SecureTokens.Hash(token);
        var session = await db.UserSessions.Include(s => s.User).ThenInclude(u => u!.OrganizationAccess)
            .FirstOrDefaultAsync(s => s.TokenHash == hash, ct);
        if (session?.User is null || session.RevokedAt is not null || session.ExpiresAt <= now || !session.User.IsActive)
        {
            return null;
        }

        var settings = await settingsService.GetAsync(ct);
        if (now - session.LastSeenAt > TimeSpan.FromMinutes(settings.SessionIdleMinutes))
        {
            session.RevokedAt = now;
            await db.SaveChangesAsync(ct);
            return null;
        }

        if (now - session.LastSeenAt > TimeSpan.FromMinutes(1))
        {
            session.LastSeenAt = now;
            await db.SaveChangesAsync(ct);
        }

        // Only users without an authenticator app need the (cheap) security key lookup.
        // A session from an identity provider that enforces MFA needs no EasyPatch second factor.
        var setupRequired = settings.RequireMfa && !session.MfaByProvider && !await HasSecondFactorAsync(session.User, ct);
        return new SessionValidation(session, session.User, setupRequired);
    }

    public async Task VerifyMfaAsync(Guid sessionId, string code, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var session = await db.UserSessions.Include(s => s.User).FirstOrDefaultAsync(s => s.Id == sessionId, ct)
                      ?? throw AppException.Unauthorized("session_invalid", "Your session has expired. Sign in again.");
        var user = session.User!;
        if (!await HasSecondFactorAsync(user, ct))
        {
            throw AppException.BadRequest("Multi-factor authentication is not enabled for this account.");
        }

        if (session.MfaCompleted)
        {
            return;
        }

        // An authenticator code, or a recovery code (also for users whose only second factor is a security key).
        var step = user.MfaEnabled && user.MfaSecretProtected is not null
            ? Totp.Verify(Totp.Base32Decode(MfaProtector.Unprotect(user.MfaSecretProtected)), code, now, user.MfaLastUsedStep)
            : null;
        var usedRecovery = false;
        if (step is null)
        {
            usedRecovery = TryConsumeRecoveryCode(user, code);
        }

        if (step is null && !usedRecovery)
        {
            RegisterFailure(user, now);
            if (user.LockoutUntil is not null)
            {
                session.RevokedAt = now;
            }

            audit.Record("auth.mfa_failed", "User", user.Id.ToString());
            await db.SaveChangesAsync(ct);
            throw AppException.Unauthorized("invalid_mfa_code", "The verification code is not valid.");
        }

        if (step is { } s)
        {
            user.MfaLastUsedStep = s;
        }

        user.FailedLoginCount = 0;
        user.LastLoginAt = now;
        session.MfaCompleted = true;
        audit.Record("auth.login", "User", user.Id.ToString(), details: new { mfa = usedRecovery ? "recovery_code" : "totp" });
        await db.SaveChangesAsync(ct);
    }

    public async Task LogoutAsync(Guid sessionId, CancellationToken ct = default)
    {
        var session = await db.UserSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is not null && session.RevokedAt is null)
        {
            session.RevokedAt = clock.GetUtcNow();
            audit.Record("auth.logout", "User", session.UserId.ToString());
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<int> RevokeSessionsAsync(Guid userId, Guid? exceptSessionId, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        return await db.UserSessions
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != exceptSessionId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
    }

    // -------------------------------------------------------------------------------------------
    // MFA enrollment
    // -------------------------------------------------------------------------------------------

    public async Task<MfaSetup> BeginMfaSetupAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (user.MfaEnabled)
        {
            throw AppException.Conflict("Multi-factor authentication is already enabled.", "mfa_enabled");
        }

        var secret = Totp.Base32Encode(Totp.GenerateSecret());
        user.MfaPendingSecretProtected = MfaProtector.Protect(secret);
        await db.SaveChangesAsync(ct);
        var uri = Totp.BuildUri("EasyPatch", user.Username, Totp.Base32Decode(secret));
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(6);
        return new MfaSetup(secret, uri, "data:image/png;base64," + Convert.ToBase64String(png));
    }

    public async Task<IReadOnlyList<string>> EnableMfaAsync(Guid userId, Guid sessionId, string code, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (user.MfaPendingSecretProtected is null)
        {
            throw AppException.BadRequest("Start multi-factor setup first.");
        }

        var secretText = MfaProtector.Unprotect(user.MfaPendingSecretProtected);
        var step = Totp.Verify(Totp.Base32Decode(secretText), code, now, null)
                   ?? throw AppException.BadRequest("The verification code is not valid. Check the time on your device.", "invalid_mfa_code");
        user.MfaSecretProtected = user.MfaPendingSecretProtected;
        user.MfaPendingSecretProtected = null;
        user.MfaEnabled = true;
        user.MfaLastUsedStep = step;
        var codes = GenerateRecoveryCodes(user);
        var session = await db.UserSessions.FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is not null)
        {
            session.MfaCompleted = true;
        }

        audit.Record("auth.mfa_enabled", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
        return codes;
    }

    /// <summary>Removes the authenticator app. While the server requires MFA this is allowed only if a security key or passkey
    /// remains.</summary>
    public async Task DisableMfaAsync(Guid userId, Guid sessionId, string password, string code, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        var keys = await db.WebAuthnCredentials.AnyAsync(c => c.UserId == userId, ct);
        if (!keys && await RequireMfaAsync(ct))
        {
            throw AppException.Conflict("Multi-factor authentication is required by server policy and cannot be disabled.", "mfa_required");
        }

        await ConfirmAsync(user, sessionId, password, ct);
        if (user.MfaSecretProtected is null ||
            (Totp.Verify(Totp.Base32Decode(MfaProtector.Unprotect(user.MfaSecretProtected)), code, clock.GetUtcNow(), user.MfaLastUsedStep) is null
             && !TryConsumeRecoveryCode(user, code)))
        {
            throw AppException.BadRequest("The verification code is not valid.", "invalid_mfa_code");
        }

        ClearTotp(user);
        if (!keys)
        {
            user.RecoveryCodeHashes = [];
        }

        audit.Record("auth.mfa_disabled", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(Guid userId, Guid sessionId, string password, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        await ConfirmAsync(user, sessionId, password, ct);
        if (!await HasSecondFactorAsync(user, ct))
        {
            throw AppException.BadRequest("Multi-factor authentication is not enabled.");
        }

        var codes = GenerateRecoveryCodes(user);
        audit.Record("auth.recovery_codes_regenerated", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
        return codes;
    }

    // -------------------------------------------------------------------------------------------
    // Passwords
    // -------------------------------------------------------------------------------------------

    public async Task ChangePasswordAsync(Guid userId, Guid currentSessionId, string currentPassword, string newPassword, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        RequirePassword(user, currentPassword);
        SetPassword(user, newPassword);
        await RevokeSessionsAsync(user.Id, currentSessionId, ct);
        audit.Record("auth.password_changed", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Changes the user's own email address (the address they sign in with) after checking the current password, or
    /// for an account without one, a recent sign-in. Sessions stay signed in; linked single sign-on accounts stay linked.</summary>
    public async Task ChangeEmailAsync(Guid userId, Guid sessionId, string currentPassword, string newEmail, CancellationToken ct = default)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        await ConfirmAsync(user, sessionId, currentPassword, ct);
        var normalized = NormalizeEmail(newEmail ?? string.Empty);
        if (!IsValidEmail(normalized))
        {
            throw AppException.BadRequest("Enter a valid email address.", "validation_failed");
        }

        if (normalized == user.Email)
        {
            return;
        }

        if (await db.Users.AnyAsync(u => u.Email == normalized && u.Id != userId, ct))
        {
            throw AppException.Conflict("Another user already has that email address.", "email_in_use");
        }

        var previous = user.Email;
        user.Email = normalized;
        audit.Record("auth.email_changed", "User", user.Id.ToString(), details: new { from = previous, to = normalized });
        await db.SaveChangesAsync(ct);
    }

    public async Task<string> CreateResetTokenAsync(Guid userId, Guid? createdBy, CancellationToken ct = default)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw AppException.NotFound("User");
        var now = clock.GetUtcNow();
        await db.PasswordResetTokens.Where(t => t.UserId == userId && t.UsedAt == null).ExecuteUpdateAsync(s => s.SetProperty(t => t.UsedAt, now), ct);
        var token = SecureTokens.Create(ResetPrefix);
        db.PasswordResetTokens.Add(new PasswordResetToken
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            TokenHash = SecureTokens.Hash(token),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(60),
            CreatedByUserId = createdBy,
        });
        audit.Record("user.reset_link_created", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
        return token;
    }

    public async Task ResetPasswordAsync(string token, string newPassword, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var hash = SecureTokens.Hash(token ?? string.Empty);
        var reset = await db.PasswordResetTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (reset is null || reset.UsedAt is not null || reset.ExpiresAt <= now)
        {
            throw AppException.BadRequest("This password reset link is invalid or has expired.", "invalid_reset_token");
        }

        var user = await db.Users.FirstAsync(u => u.Id == reset.UserId, ct);
        SetPassword(user, newPassword);
        reset.UsedAt = now;
        user.LockoutUntil = null;
        user.FailedLoginCount = 0;
        await RevokeSessionsAsync(user.Id, null, ct);
        audit.Record("auth.password_reset", "User", user.Id.ToString());
        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // User administration
    // -------------------------------------------------------------------------------------------

    public async Task<User> CreateUserAsync(string username, string email, UserRole role, string? password, CancellationToken ct = default)
    {
        var normalized = NormalizeUsername(username ?? string.Empty);
        if (normalized.Length is < 3 or > 64 || !normalized.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '@'))
        {
            throw AppException.BadRequest("Usernames must be 3–64 characters: letters, digits, '.', '-', '_' or '@'.", "validation_failed");
        }

        var emailNormalized = NormalizeEmail(email ?? string.Empty);
        if (!IsValidEmail(emailNormalized))
        {
            throw AppException.BadRequest("A valid email address is required.", "validation_failed");
        }

        if (await db.Users.AnyAsync(u => u.Email == emailNormalized, ct))
        {
            throw AppException.Conflict("Another user already has that email address.", "email_in_use");
        }

        if (await db.Users.AnyAsync(u => u.Username == normalized, ct))
        {
            throw AppException.Conflict("Another user already has that username.", "username_in_use");
        }

        var now = clock.GetUtcNow();
        var user = new User
        {
            Id = Guid.CreateVersion7(now),
            Username = normalized,
            Email = emailNormalized,
            Role = role,
            PasswordHash = "!", // unusable until set
            CreatedAt = now,
            PasswordChangedAt = now,
        };
        if (password is not null)
        {
            SetPassword(user, password);
        }

        db.Users.Add(user);
        audit.Record("user.create", "User", user.Id.ToString(), details: new { user.Username, user.Email, role });
        await db.SaveChangesAsync(ct);
        return user;
    }

    public async Task<User> UpdateUserAsync(Guid userId, string? email, UserRole? role, bool? isActive, CancellationToken ct = default)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw AppException.NotFound("User");
        var demoting = (role is { } r && r != UserRole.SuperAdmin) || isActive == false;
        if (user.Role == UserRole.SuperAdmin && demoting &&
            await db.Users.CountAsync(u => u.Role == UserRole.SuperAdmin && u.IsActive && u.Id != userId, ct) == 0)
        {
            throw AppException.Conflict("At least one active Super Administrator must remain.", "last_super_admin");
        }

        if (email is not null)
        {
            var normalized = NormalizeEmail(email);
            if (!IsValidEmail(normalized))
            {
                throw AppException.BadRequest("A valid email address is required.", "validation_failed");
            }

            if (await db.Users.AnyAsync(u => u.Email == normalized && u.Id != userId, ct))
            {
                throw AppException.Conflict("Another user already has that email address.", "email_in_use");
            }

            user.Email = normalized;
        }

        if (role is { } newRole)
        {
            user.Role = newRole;
        }

        if (isActive is { } active)
        {
            user.IsActive = active;
            if (!active)
            {
                await RevokeSessionsAsync(user.Id, null, ct);
            }
        }

        audit.Record("user.update", "User", user.Id.ToString(), details: new { email, role, isActive });
        await db.SaveChangesAsync(ct);
        return user;
    }

    /// <summary>Removes every second factor (authenticator app, security keys and passkeys, recovery codes) and signs the user out.</summary>
    public async Task ResetMfaAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw AppException.NotFound("User");
        ClearMfa(user);
        var keys = await db.WebAuthnCredentials.Where(c => c.UserId == userId).ExecuteDeleteAsync(ct);
        await RevokeSessionsAsync(user.Id, null, ct);
        audit.Record("user.mfa_reset", "User", user.Id.ToString(), details: new { securityKeysRemoved = keys });
        await db.SaveChangesAsync(ct);
    }

    public async Task SetOrganizationAccessAsync(Guid userId, IReadOnlyCollection<Guid> organizationIds, CancellationToken ct = default)
    {
        var user = await db.Users.Include(u => u.OrganizationAccess).FirstOrDefaultAsync(u => u.Id == userId, ct) ?? throw AppException.NotFound("User");
        var valid = await db.Organizations.Where(o => organizationIds.Contains(o.Id)).Select(o => o.Id).ToListAsync(ct);
        if (valid.Count != organizationIds.Distinct().Count())
        {
            throw AppException.BadRequest("One or more organizations do not exist.", "validation_failed");
        }

        user.OrganizationAccess.Clear();
        user.OrganizationAccess.AddRange(valid.Select(id => new UserOrganizationAccess { UserId = userId, OrganizationId = id }));
        await RevokeSessionsAsync(user.Id, null, ct);
        audit.Record("user.organizations_set", "User", user.Id.ToString(), details: new { organizationIds = valid });
        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------------

    private void SetPassword(User user, string password)
    {
        var problem = PasswordPolicy.Validate(password, user.Username);
        if (problem is not null)
        {
            throw AppException.BadRequest(problem, "weak_password");
        }

        user.PasswordHash = hasher.Hash(password);
        user.PasswordChangedAt = clock.GetUtcNow();
        user.MustChangePassword = false;
    }

    private void RequirePassword(User user, string password)
    {
        // An empty password never matches (and Argon2 refuses an empty input).
        if (string.IsNullOrEmpty(password) || hasher.Verify(password, user.PasswordHash) == PasswordVerification.Failed)
        {
            throw AppException.BadRequest("The current password is incorrect.", "invalid_password");
        }
    }

    /// <summary>A sign-in this recent confirms a change to the user's sign-in methods without asking for the password again.</summary>
    public static readonly TimeSpan RecentSignIn = TimeSpan.FromMinutes(10);

    /// <summary>The account has a password it can sign in with (accounts created by single sign-on may not).</summary>
    public static bool HasUsablePassword(User user) => user.PasswordHash.StartsWith('$');

    /// <summary>Confirms a change to the user's sign-in methods: the current password when one is given, otherwise a sign-in (with
    /// MFA) within <see cref="RecentSignIn"/>.</summary>
    internal void RequireReauthentication(User user, UserSession session, string? password)
    {
        if (!string.IsNullOrEmpty(password))
        {
            RequirePassword(user, password);
        }
        else if (clock.GetUtcNow() - session.CreatedAt > RecentSignIn)
        {
            throw HasUsablePassword(user)
                ? AppException.BadRequest("Enter your current password to confirm.", "invalid_password")
                : new AppException(403, "reauthentication_required", "Sign out and sign in again, then retry within 10 minutes.");
        }
    }

    /// <summary>The current password; for an account without one (created by single sign-on), a sign-in within <see cref="RecentSignIn"/>.</summary>
    private async Task ConfirmAsync(User user, Guid sessionId, string password, CancellationToken ct)
    {
        if (HasUsablePassword(user))
        {
            RequirePassword(user, password);
            return;
        }

        RequireReauthentication(user, await db.UserSessions.AsNoTracking().FirstAsync(s => s.Id == sessionId, ct), null);
    }

    internal async Task<bool> RequireMfaAsync(CancellationToken ct) => (await settingsService.GetAsync(ct)).RequireMfa;

    internal async Task<(UserSession Session, string Token)> NewSessionAsync(User user, bool mfaCompleted, string? ip, string? userAgent,
        CancellationToken ct)
    {
        var settings = await settingsService.GetAsync(ct);
        return NewSession(user, mfaCompleted, ip, userAgent, settings, clock.GetUtcNow());
    }

    internal void RegisterFailure(User user, DateTimeOffset now)
    {
        user.FailedLoginCount++;
        if (user.FailedLoginCount >= MaxFailedAttempts)
        {
            user.LockoutCount++;
            var duration = TimeSpan.FromTicks(Math.Min(MaxLockout.Ticks, BaseLockout.Ticks * (1L << Math.Min(user.LockoutCount - 1, 10))));
            user.LockoutUntil = now + duration;
            user.FailedLoginCount = 0;
            logger.LogWarning("User {UserId} locked out until {Until} after repeated failures", user.Id, user.LockoutUntil);
            audit.Record("auth.locked_out", "User", user.Id.ToString(), details: new { until = user.LockoutUntil });
        }
    }

    private (UserSession Session, string Token) NewSession(User user, bool mfaCompleted, string? ip, string? userAgent, Core.Domain.ServerSettings settings, DateTimeOffset now)
    {
        var token = SecureTokens.Create(SessionPrefix);
        var session = new UserSession
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            TokenHash = SecureTokens.Hash(token),
            MfaCompleted = mfaCompleted,
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now.AddHours(settings.SessionAbsoluteHours),
            IpAddress = ScanIngestionService.Truncate(ip, 64),
            UserAgent = ScanIngestionService.Truncate(userAgent, 512),
        };
        db.UserSessions.Add(session);
        return (session, token);
    }

    internal static List<string> GenerateRecoveryCodes(User user)
    {
        var codes = Enumerable.Range(0, 10).Select(_ => SecureTokens.CreateCode(string.Empty, 10)).ToList();
        user.RecoveryCodeHashes = codes.Select(c => SecureTokens.Hash(NormalizeRecovery(c))).ToList();
        return codes.Select(c => $"{c[..5]}-{c[5..]}").ToList();
    }

    private static bool TryConsumeRecoveryCode(User user, string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var hash = SecureTokens.Hash(NormalizeRecovery(code));
        var index = user.RecoveryCodeHashes.IndexOf(hash);
        if (index < 0)
        {
            return false;
        }

        user.RecoveryCodeHashes = user.RecoveryCodeHashes.Where((_, i) => i != index).ToList();
        return true;
    }

    private static string NormalizeRecovery(string code) =>
        code.Replace("-", string.Empty, StringComparison.Ordinal).Replace(" ", string.Empty, StringComparison.Ordinal).Trim().ToUpperInvariant();

    private static void ClearMfa(User user)
    {
        ClearTotp(user);
        user.RecoveryCodeHashes = [];
    }

    private static void ClearTotp(User user)
    {
        user.MfaEnabled = false;
        user.MfaSecretProtected = null;
        user.MfaPendingSecretProtected = null;
        user.MfaLastUsedStep = null;
    }

    private static AppException InvalidCredentials() =>
        AppException.Unauthorized("invalid_credentials", "Email or password is incorrect, or the account is temporarily locked.");
}
