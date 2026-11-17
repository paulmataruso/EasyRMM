using System.Security.Claims;
using System.Text.Encodings.Web;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Security;

public static class EasyPatchClaims
{
    public const string UserId = ClaimTypes.NameIdentifier;
    public const string Username = ClaimTypes.Name;
    public const string Role = ClaimTypes.Role;
    public const string SessionId = "easypatch:sid";
    public const string MfaCompleted = "easypatch:mfa";
    public const string MfaSetupRequired = "easypatch:mfa_setup";
    public const string MustChangePassword = "easypatch:pwd_change";
    public const string Organization = "easypatch:org";
    public const string ApiTokenId = "easypatch:api_token";
    public const string AllOrganizations = "easypatch:all_orgs";

    public const string CredentialId = "easypatch:credential";
    public const string CredentialDbId = "easypatch:credential_db";
    public const string EndpointId = "easypatch:endpoint";
    public const string OrganizationId = "easypatch:organization";
    public const string AgentKind = "easypatch:agent_kind";

    public static Guid GetUserId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(UserId) ?? throw AppException.Unauthorized("unauthenticated", "Sign in to continue."));

    /// <summary>The signed-in user, or null for an API token.</summary>
    public static Guid? FindUserId(this ClaimsPrincipal principal) =>
        Guid.TryParse(principal.FindFirstValue(UserId), out var id) ? id : null;

    public static Guid GetSessionId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(SessionId) ?? throw AppException.Unauthorized("unauthenticated", "Sign in to continue."));

    public static UserRole GetRole(this ClaimsPrincipal principal) =>
        Enum.TryParse<UserRole>(principal.FindFirstValue(Role), out var role) ? role : UserRole.ReadOnly;

    public static Guid GetEndpointId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(EndpointId) ?? throw AppException.Unauthorized("unauthenticated", "Agent credential required."));
}

public sealed class SessionAuthenticationOptions : AuthenticationSchemeOptions;

/// <summary>Validates the opaque session cookie against the database (only a SHA-256 hash of the token is stored).</summary>
public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<SessionAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AuthService auth) : AuthenticationHandler<SessionAuthenticationOptions>(options, logger, encoder)
{
    public const string SchemeName = "Session";
    public const string CookieName = "__Host-easypatch-session";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(CookieName, out var token) || string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        var validation = await auth.ValidateSessionAsync(token, Context.RequestAborted);
        if (validation is null)
        {
            Response.Cookies.Delete(CookieName, SessionCookies.Options(Request, null));
            return AuthenticateResult.Fail("Session is invalid or expired.");
        }

        var user = validation.User;
        var claims = new List<Claim>
        {
            new(EasyPatchClaims.UserId, user.Id.ToString()),
            new(EasyPatchClaims.Username, user.Username),
            new(EasyPatchClaims.Role, user.Role.ToString()),
            new(EasyPatchClaims.SessionId, validation.Session.Id.ToString()),
            new(EasyPatchClaims.MfaCompleted, validation.Session.MfaCompleted ? "true" : "false"),
            new(EasyPatchClaims.MfaSetupRequired, validation.MfaSetupRequired ? "true" : "false"),
            new(EasyPatchClaims.MustChangePassword, user.MustChangePassword ? "true" : "false"),
        };
        claims.AddRange(user.OrganizationAccess.Select(a => new Claim(EasyPatchClaims.Organization, a.OrganizationId.ToString())));
        var identity = new ClaimsIdentity(claims, SchemeName, EasyPatchClaims.Username, EasyPatchClaims.Role);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status403Forbidden, "forbidden", "You do not have permission to perform this action.");
}

public static class SessionCookies
{
    public static CookieOptions Options(HttpRequest request, DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };

    public static void Issue(HttpContext context, string token, DateTimeOffset expires) =>
        context.Response.Cookies.Append(SessionAuthenticationHandler.CookieName, token, Options(context.Request, expires));

    public static void Clear(HttpContext context)
    {
        context.Response.Cookies.Delete(SessionAuthenticationHandler.CookieName, Options(context.Request, null));
        context.Response.Cookies.Delete(CsrfProtection.CookieName, CsrfProtection.CookieOptions());
    }
}
