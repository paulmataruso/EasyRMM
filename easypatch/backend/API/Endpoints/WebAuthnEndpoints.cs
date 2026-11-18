using System.Security.Claims;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>
/// Security keys and passkeys (WebAuthn). The options endpoints return the library's <c>PublicKeyCredentialCreationOptions</c> /
/// <c>PublicKeyCredentialRequestOptions</c> JSON (binary fields base64url-encoded) for <c>navigator.credentials</c>; the browser's
/// answer comes back as <c>{ credential }</c> in the same encoding.
/// </summary>
public static class WebAuthnEndpoints
{
    /// <summary>Binds a passkey sign-in to the browser that started it (a random value; the server keeps only its hash).</summary>
    public const string PasskeyCookie = "__Host-easypatch-webauthn";

    public static void MapWebAuthnEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/auth").WithTags("Authentication");

        g.MapGet("/webauthn", (WebAuthnService webauthn) =>
        {
            var a = webauthn.Availability;
            return TypedResults.Ok(new WebAuthnStatusDto(a.Available, a.RpId, a.Reason, a.Message));
        }).AllowAnonymous();

        // ---- Registration (the signed-in user's own keys) ----

        g.MapPost("/webauthn/register/options", async (WebAuthnRegisterOptionsRequest request, ClaimsPrincipal user, WebAuthnService webauthn,
            CancellationToken ct) =>
            Json(await webauthn.BeginRegistrationAsync(user.GetUserId(), user.GetSessionId(), request.Passkey, request.Password, ct)))
            .RequireAuthorization(Policies.SessionMfaPassed).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/webauthn/register", async (WebAuthnRegisterRequest request, ClaimsPrincipal user, WebAuthnService webauthn, CancellationToken ct) =>
        {
            new Validator().Optional("name", request.Name, WebAuthnService.MaxNameLength).ThrowIfInvalid();
            var result = await webauthn.CompleteRegistrationAsync(user.GetUserId(), user.GetSessionId(), request.Name, Credential(request.Credential), ct);
            return TypedResults.Ok(new WebAuthnRegisterResponse(ToDto(result.Credential), result.RecoveryCodes));
        }).RequireAuthorization(Policies.SessionMfaPassed).RequireRateLimiting(RateLimits.Login);

        g.MapGet("/webauthn/credentials", async (ClaimsPrincipal user, EasyPatchDbContext db, CancellationToken ct) =>
        {
            var userId = user.GetUserId();
            var credentials = await db.WebAuthnCredentials.AsNoTracking().Where(c => c.UserId == userId).OrderBy(c => c.CreatedAt).ToListAsync(ct);
            return TypedResults.Ok(credentials.Select(ToDto).ToList());
        }).RequireAuthorization(Policies.Account);

        g.MapPut("/webauthn/credentials/{id:guid}", async (Guid id, WebAuthnRenameRequest request, ClaimsPrincipal user, WebAuthnService webauthn,
            CancellationToken ct) =>
        {
            new Validator().Required("name", request.Name, WebAuthnService.MaxNameLength).ThrowIfInvalid();
            return TypedResults.Ok(ToDto(await webauthn.RenameAsync(user.GetUserId(), id, request.Name, ct)));
        }).RequireAuthorization(Policies.Account);

        g.MapPost("/webauthn/credentials/{id:guid}/remove", async (Guid id, PasswordConfirmRequest request, ClaimsPrincipal user,
            WebAuthnService webauthn, CancellationToken ct) =>
        {
            await webauthn.RemoveAsync(user.GetUserId(), user.GetSessionId(), id, request.Password, ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Account).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/passkey-prompt/dismiss", async (ClaimsPrincipal user, WebAuthnService webauthn, CancellationToken ct) =>
        {
            await webauthn.DismissPasskeyPromptAsync(user.GetUserId(), ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Account);

        // ---- A security key or passkey as the second factor after the password ----

        g.MapPost("/mfa/webauthn/options", async (ClaimsPrincipal user, WebAuthnService webauthn, CancellationToken ct) =>
            Json(await webauthn.BeginSecondFactorAsync(user.GetSessionId(), ct)))
            .RequireAuthorization(Policies.SessionAny).RequireRateLimiting(RateLimits.Login);

        g.MapPost("/mfa/webauthn", async (WebAuthnAssertionRequest request, ClaimsPrincipal user, WebAuthnService webauthn, CancellationToken ct) =>
        {
            await webauthn.CompleteSecondFactorAsync(user.GetSessionId(), Credential(request.Credential), ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SessionAny).RequireRateLimiting(RateLimits.Login);

        // ---- Passkey sign-in (no email address or password) ----

        g.MapPost("/passkey/options", async (WebAuthnService webauthn, HttpContext http, TimeProvider clock, CancellationToken ct) =>
        {
            var binding = SecureTokens.Create("pk_");
            var json = await webauthn.BeginPasskeySignInAsync(binding, ct);
            http.Response.Cookies.Append(PasskeyCookie, binding, BindingCookie(clock.GetUtcNow() + WebAuthnService.ChallengeLifetime));
            return Json(json);
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);

        g.MapPost("/passkey", async (WebAuthnAssertionRequest request, WebAuthnService webauthn, EasyPatchDbContext db, CsrfProtection csrf,
            HttpContext http, CancellationToken ct) =>
        {
            var binding = http.Request.Cookies[PasskeyCookie];
            http.Response.Cookies.Delete(PasskeyCookie, BindingCookie(null));
            var result = await webauthn.CompletePasskeySignInAsync(binding, Credential(request.Credential), http.Connection.RemoteIpAddress?.ToString(),
                http.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua[..Math.Min(ua.Length, 512)] : null, ct);
            SessionCookies.Issue(http, result.SessionToken, result.Session.ExpiresAt);
            csrf.IssueCookie(http, result.Session.Id);
            var user = await db.Users.AsNoTracking().Include(u => u.OrganizationAccess).FirstAsync(u => u.Id == result.User.Id, ct);
            return TypedResults.Ok(new LoginResponse(false, false,
                await AuthEndpoints.CurrentUserAsync(user, mfaCompleted: true, mfaSetupRequired: false, db, webauthn, ct)));
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);
    }

    internal static WebAuthnCredentialDto ToDto(WebAuthnCredential c) =>
        new(c.Id, c.Name, c.IsPasskey, c.IsBackedUp, c.Transports, c.CreatedAt, c.LastUsedAt);

    private static CookieOptions BindingCookie(DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };

    /// <summary>The options exactly as the library serialized them.</summary>
    private static IResult Json(string json) => TypedResults.Content(json, "application/json");

    private static string Credential(JsonElement credential) =>
        credential.ValueKind == JsonValueKind.Object && credential.GetRawText() is { Length: <= 64 * 1024 } raw
            ? raw
            : throw AppException.BadRequest("Send the browser's WebAuthn response as 'credential'.", "validation_failed");
}
