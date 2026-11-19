using System.Security.Claims;
using System.Text.Encodings.Web;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Security;

public sealed class ApiTokenAuthenticationOptions : AuthenticationSchemeOptions;

/// <summary>
/// Authenticates <c>Authorization: Bearer ept_…</c> requests with an API token (made with <c>create-api-token</c>). The secret is
/// hashed and looked up; it is never logged.
/// </summary>
public sealed class ApiTokenAuthenticationHandler(
    IOptionsMonitor<ApiTokenAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiTokenService tokens) : AuthenticationHandler<ApiTokenAuthenticationOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiToken";
    private const string BearerPrefix = "Bearer ";

    /// <summary>True when the request carries a bearer credential in the Authorization header.</summary>
    public static bool HasBearer(HttpRequest request) =>
        request.Headers.Authorization.ToString().StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase);

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!HasBearer(Request))
        {
            return AuthenticateResult.NoResult();
        }

        var secret = Request.Headers.Authorization.ToString()[BearerPrefix.Length..].Trim();
        var token = await tokens.ValidateAsync(secret, Context.Connection.RemoteIpAddress?.ToString(), Context.RequestAborted);
        if (token is null)
        {
            return AuthenticateResult.Fail("The API token is invalid, expired or revoked.");
        }

        var claims = new List<Claim>
        {
            new(EasyPatchClaims.ApiTokenId, token.Id.ToString()),
            new(EasyPatchClaims.Username, ActorContextExtensions.ApiTokenPrefix + token.Name),
            new(EasyPatchClaims.Role, token.Role.ToString()),
            new(EasyPatchClaims.AllOrganizations, token.AllOrganizations ? "true" : "false"),
        };
        if (!token.AllOrganizations)
        {
            claims.AddRange(token.OrganizationIds.Select(id => new Claim(EasyPatchClaims.Organization, id.ToString())));
        }

        var identity = new ClaimsIdentity(claims, SchemeName, EasyPatchClaims.Username, EasyPatchClaims.Role);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status401Unauthorized, "unauthenticated", HasBearer(Request)
            ? "The API token is invalid, expired or revoked."
            : "Send an API token, or call through EasyRMM.");

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status403Forbidden, "forbidden", "This API token does not have permission to perform this action.");
}

/// <summary>
/// The administrator API's scheme: a statement from EasyRMM when the request carries one (EasyPatch as EasyRMM's patching engine),
/// otherwise a bearer API token. A request is authenticated by exactly one of them, so they are never combined: a request with a
/// statement that is not valid is refused, whatever else it has. EasyPatch has no sign-in, session or cookie of its own.
/// </summary>
public static class ConsoleAuthentication
{
    public const string SchemeName = "Console";

    public static string Select(HttpContext context) =>
        EasyRmmAuthenticationHandler.HasAssertion(context.Request)
            ? EasyRmmAuthenticationHandler.SchemeName
            : ApiTokenAuthenticationHandler.SchemeName;

    public static bool IsApiToken(this ClaimsPrincipal principal) =>
        principal.Identity is { IsAuthenticated: true, AuthenticationType: ApiTokenAuthenticationHandler.SchemeName };

    public static bool IsEasyRmm(this ClaimsPrincipal principal) =>
        principal.Identity is { IsAuthenticated: true, AuthenticationType: EasyRmmAuthenticationHandler.SchemeName };
}
