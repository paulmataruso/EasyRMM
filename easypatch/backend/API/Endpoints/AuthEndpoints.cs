using System.Security.Claims;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/auth").WithTags("Authentication");

        g.MapPost("/login", async (LoginRequest request, AuthService auth, CsrfProtection csrf, HttpContext http, EasyPatchDbContext db,
            WebAuthnService webauthn, CancellationToken ct) =>
        {
            new Validator().Required("email", request.Email, 256).Required("password", request.Password, 1024).ThrowIfInvalid();
            var result = await auth.LoginAsync(request.Email, request.Password, http.Connection.RemoteIpAddress?.ToString(),
                http.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua[..Math.Min(ua.Length, 512)] : null, ct);
            SessionCookies.Issue(http, result.SessionToken, result.Session.ExpiresAt);
            csrf.IssueCookie(http, result.Session.Id);
            return TypedResults.Ok(new LoginResponse(result.MfaRequired, result.MfaSetupRequired,
                await CurrentUserAsync(result.User, result.Session.MfaCompleted, result.MfaSetupRequired, db, webauthn, ct)));
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);

        g.MapPost("/mfa/verify", async (MfaCodeRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            new Validator().Required("code", request.Code, 64).ThrowIfInvalid();
            await auth.VerifyMfaAsync(user.GetSessionId(), request.Code.Trim(), ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SessionAny).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/logout", async (ClaimsPrincipal user, AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            await auth.LogoutAsync(user.GetSessionId(), ct);
            SessionCookies.Clear(http);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SessionAny);

        g.MapGet("/me", async (ClaimsPrincipal principal, EasyPatchDbContext db, WebAuthnService webauthn, CsrfProtection csrf, HttpContext http,
            CancellationToken ct) =>
        {
            var userId = principal.GetUserId();
            var user = await db.Users.AsNoTracking().Include(u => u.OrganizationAccess).FirstAsync(u => u.Id == userId, ct);
            csrf.IssueCookie(http, principal.GetSessionId());
            return TypedResults.Ok(await CurrentUserAsync(user, principal.FindFirstValue(EasyPatchClaims.MfaCompleted) == "true",
                principal.FindFirstValue(EasyPatchClaims.MfaSetupRequired) == "true", db, webauthn, ct));
        }).RequireAuthorization(Policies.SessionAny);

        g.MapPost("/mfa/setup", async (ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            var setup = await auth.BeginMfaSetupAsync(user.GetUserId(), ct);
            return TypedResults.Ok(new MfaSetupResponse(setup.Secret, setup.OtpAuthUri, setup.QrCodeDataUri));
        }).RequireAuthorization(Policies.SessionMfaPassed);

        g.MapPost("/mfa/enable", async (MfaCodeRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            new Validator().Required("code", request.Code, 16).ThrowIfInvalid();
            var codes = await auth.EnableMfaAsync(user.GetUserId(), user.GetSessionId(), request.Code.Trim(), ct);
            return TypedResults.Ok(new RecoveryCodesResponse(codes));
        }).RequireAuthorization(Policies.SessionMfaPassed).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/mfa/disable", async (MfaDisableRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            await auth.DisableMfaAsync(user.GetUserId(), user.GetSessionId(), request.Password ?? string.Empty, request.Code ?? string.Empty, ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Account).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/mfa/recovery-codes", async (PasswordConfirmRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
            TypedResults.Ok(new RecoveryCodesResponse(await auth.RegenerateRecoveryCodesAsync(user.GetUserId(), user.GetSessionId(), request.Password ?? string.Empty, ct))))
            .RequireAuthorization(Policies.Account).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/password/change", async (ChangePasswordRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            await auth.ChangePasswordAsync(user.GetUserId(), user.GetSessionId(), request.CurrentPassword ?? string.Empty,
                request.NewPassword ?? string.Empty, ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SessionMfaPassed).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/email/change", async (ChangeEmailRequest request, ClaimsPrincipal user, AuthService auth, CancellationToken ct) =>
        {
            await auth.ChangeEmailAsync(user.GetUserId(), user.GetSessionId(), request.CurrentPassword ?? string.Empty, request.NewEmail ?? string.Empty, ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SessionMfaPassed).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/password/reset", async (ResetPasswordRequest request, AuthService auth, CancellationToken ct) =>
        {
            await auth.ResetPasswordAsync(request.Token ?? string.Empty, request.NewPassword ?? string.Empty, ct);
            return TypedResults.NoContent();
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);

        g.MapGet("/sessions", async (ClaimsPrincipal user, EasyPatchDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var userId = user.GetUserId();
            var current = user.GetSessionId();
            var now = clock.GetUtcNow();
            var sessions = await db.UserSessions.AsNoTracking()
                .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
                .OrderByDescending(s => s.LastSeenAt)
                .Select(s => new SessionDto(s.Id, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.IpAddress, s.UserAgent, s.Id == current))
                .ToListAsync(ct);
            return TypedResults.Ok(sessions);
        }).RequireAuthorization(Policies.Account);

        g.MapDelete("/sessions/{id:guid}", async (Guid id, ClaimsPrincipal user, EasyPatchDbContext db, TimeProvider clock, AuditService audit,
            CancellationToken ct) =>
        {
            var userId = user.GetUserId();
            var session = await db.UserSessions.FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId, ct) ?? throw AppException.NotFound("Session");
            session.RevokedAt ??= clock.GetUtcNow();
            audit.Record("auth.session_revoked", "UserSession", id.ToString());
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Account);
    }

    internal static async Task<CurrentUserDto> CurrentUserAsync(User user, bool mfaCompleted, bool mfaSetupRequired, EasyPatchDbContext db,
        WebAuthnService webauthn, CancellationToken ct)
    {
        var kinds = await db.WebAuthnCredentials.AsNoTracking().Where(c => c.UserId == user.Id).Select(c => c.IsPasskey).ToListAsync(ct);
        var passkeys = kinds.Count(k => k);
        // Offer a passkey only once the user is fully signed in, not while they still have to finish MFA or change their password.
        var prompt = mfaCompleted && !mfaSetupRequired && !user.MustChangePassword && webauthn.ShouldPromptForPasskey(user, passkeys);
        return new CurrentUserDto(user.Id, user.Username, user.Email, user.Role, user.MfaEnabled || kinds.Count > 0, mfaCompleted, mfaSetupRequired,
            user.MustChangePassword, user.OrganizationAccess.Select(a => a.OrganizationId).ToList(), user.LastLoginAt,
            TotpEnabled: user.MfaEnabled, SecurityKeyCount: kinds.Count, PasskeyCount: passkeys, PasskeyPrompt: prompt,
            HasPassword: AuthService.HasUsablePassword(user));
    }
}

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/users").WithTags("Users").RequireAuthorization(Policies.SuperAdmin);

        g.MapGet("/", async (EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.Users.AsNoTracking().OrderBy(u => u.Username).Select(ToDto).ToListAsync(ct)));

        g.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.Users.AsNoTracking().Where(u => u.Id == id).Select(ToDto).FirstOrDefaultAsync(ct) ?? throw AppException.NotFound("User")));

        g.MapPost("/", async (CreateUserRequest request, AuthService auth, EasyPatchDbContext db, ClaimsPrincipal principal,
            IOptions<EasyPatchOptions> options, TimeProvider clock, CancellationToken ct) =>
        {
            var user = await auth.CreateUserAsync(request.Username, request.Email, request.Role, string.IsNullOrEmpty(request.Password) ? null : request.Password, ct);
            if (request.OrganizationIds is { Count: > 0 } orgs)
            {
                await auth.SetOrganizationAccessAsync(user.Id, orgs, ct);
            }

            ResetLinkResponse? link = null;
            if (string.IsNullOrEmpty(request.Password))
            {
                var token = await auth.CreateResetTokenAsync(user.Id, principal.GetUserId(), ct);
                link = new ResetLinkResponse(ResetUrl(options.Value, token), clock.GetUtcNow().AddMinutes(60));
            }

            var dto = await db.Users.AsNoTracking().Where(u => u.Id == user.Id).Select(ToDto).FirstAsync(ct);
            return TypedResults.Created($"/api/v1/users/{user.Id}", new CreateUserResponse(dto, link));
        });

        g.MapPut("/{id:guid}", async (Guid id, UpdateUserRequest request, AuthService auth, EasyPatchDbContext db, CancellationToken ct) =>
        {
            await auth.UpdateUserAsync(id, request.Email, request.Role, request.IsActive, ct);
            return TypedResults.Ok(await db.Users.AsNoTracking().Where(u => u.Id == id).Select(ToDto).FirstAsync(ct));
        });

        g.MapPost("/{id:guid}/reset-link", async (Guid id, AuthService auth, ClaimsPrincipal principal, IOptions<EasyPatchOptions> options, TimeProvider clock,
            CancellationToken ct) =>
        {
            var token = await auth.CreateResetTokenAsync(id, principal.GetUserId(), ct);
            return TypedResults.Ok(new ResetLinkResponse(ResetUrl(options.Value, token), clock.GetUtcNow().AddMinutes(60)));
        });

        g.MapPost("/{id:guid}/mfa/reset", async (Guid id, AuthService auth, CancellationToken ct) =>
        {
            await auth.ResetMfaAsync(id, ct);
            await auth.RevokeSessionsAsync(id, null, ct);
            return TypedResults.NoContent();
        });

        g.MapPost("/{id:guid}/sessions/revoke", async (Guid id, AuthService auth, AuditService audit, EasyPatchDbContext db, CancellationToken ct) =>
        {
            var count = await auth.RevokeSessionsAsync(id, null, ct);
            audit.Record("user.sessions_revoked", "User", id.ToString(), details: new { count });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(new { revoked = count });
        });

        g.MapPut("/{id:guid}/organizations", async (Guid id, OrganizationAccessRequest request, AuthService auth, EasyPatchDbContext db, CancellationToken ct) =>
        {
            await auth.SetOrganizationAccessAsync(id, request.OrganizationIds ?? [], ct); // takes effect on the user's next request
            return TypedResults.Ok(await db.Users.AsNoTracking().Where(u => u.Id == id).Select(ToDto).FirstAsync(ct));
        });

        // Single sign-on links (accounts at OpenID Connect providers).
        g.MapGet("/{id:guid}/external-logins", async (Guid id, EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.ExternalLogins.AsNoTracking().Where(l => l.UserId == id).OrderBy(l => l.CreatedAt)
                .Select(l => new ExternalLoginDto(l.Id, l.ProviderId, l.Provider!.DisplayName, l.Issuer, l.Subject, l.Email, l.CreatedAt, l.LastUsedAt))
                .ToListAsync(ct)));

        g.MapDelete("/{id:guid}/external-logins/{linkId:guid}", async (Guid id, Guid linkId, EasyPatchDbContext db, AuditService audit,
            CancellationToken ct) =>
        {
            var link = await db.ExternalLogins.Include(l => l.Provider).FirstOrDefaultAsync(l => l.Id == linkId && l.UserId == id, ct)
                       ?? throw AppException.NotFound("Linked sign-in");
            db.ExternalLogins.Remove(link);
            audit.Record("user.sso_unlinked", "User", id.ToString(), details: new { provider = link.Provider?.DisplayName });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        });
    }

    private static string ResetUrl(EasyPatchOptions options, string token) => $"{options.PublicUrl.TrimEnd('/')}/reset-password#token={token}";

    private static readonly System.Linq.Expressions.Expression<Func<User, UserDto>> ToDto = u => new UserDto(
        u.Id, u.Username, u.Email, u.Role, u.IsActive, u.MfaEnabled || u.WebAuthnCredentials.Any(), u.CreatedAt, u.LastLoginAt, u.LockoutUntil,
        u.OrganizationAccess.Select(a => a.OrganizationId).ToList(), u.MfaEnabled, u.WebAuthnCredentials.Count(), u.ExternalLogins.Count());
}
