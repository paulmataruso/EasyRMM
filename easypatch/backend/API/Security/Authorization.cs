using System.Security.Claims;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Security;

public static class Policies
{
    /// <summary>A statement from EasyRMM or an API token, any role (read access).</summary>
    public const string Viewer = "Viewer";

    /// <summary>A statement from EasyRMM with the Admin or SuperAdmin role, or an Admin API token (operations).</summary>
    public const string Operator = "Operator";

    /// <summary>A statement from EasyRMM with the SuperAdmin role (server settings, global policy, tags, alert rules, notifications,
    /// lifecycle). API tokens are never SuperAdmin, so they are refused.</summary>
    public const string SuperAdmin = "SuperAdmin";

    /// <summary>Active agent credential.</summary>
    public const string Agent = "Agent";

    /// <summary>Pending enrollment request credential (<c>r_</c>).</summary>
    public const string AgentPending = "AgentPending";

    public static IServiceCollection AddEasyPatchAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(Viewer, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser())
            .AddPolicy(Operator, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser()
                .RequireRole(nameof(UserRole.Admin), nameof(UserRole.SuperAdmin)))
            .AddPolicy(SuperAdmin, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser()
                .RequireRole(nameof(UserRole.SuperAdmin)))
            .AddPolicy(Agent, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindActive))
            .AddPolicy(AgentPending, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindPending));
        return services;
    }
}

/// <summary>Request-scoped tenant (organization) visibility derived from the API token or the statement from EasyRMM.</summary>
public sealed class HttpTenantContext : ITenantContext
{
    public HttpTenantContext(IHttpContextAccessor accessor)
    {
        var user = accessor.HttpContext?.User;
        var scheme = user?.Identity?.IsAuthenticated == true ? user.Identity.AuthenticationType : null;
        if (user is null || scheme is not (ApiTokenAuthenticationHandler.SchemeName or EasyRmmAuthenticationHandler.SchemeName))
        {
            IsUnrestricted = false;
            AllowedOrganizationIds = new HashSet<Guid>();
            return;
        }

        // Only the explicit flag means "all", whatever the role: a token or statement for organizations that were all deleted sees
        // nothing. A statement from EasyRMM sees every organization only when it says so ("orgs": "*").
        IsUnrestricted = user.FindFirstValue(EasyPatchClaims.AllOrganizations) == "true";
        AllowedOrganizationIds = user.FindAll(EasyPatchClaims.Organization).Select(c => Guid.Parse(c.Value)).ToHashSet();
    }

    public bool IsUnrestricted { get; }
    public IReadOnlySet<Guid> AllowedOrganizationIds { get; }
}

public sealed class HttpActorContext(IHttpContextAccessor accessor) : IActorContext
{
    private HttpContext? Context => accessor.HttpContext;

    /// <summary>Always null: EasyPatch has no accounts of its own. Statements and tokens are named in <see cref="Username"/>.</summary>
    public Guid? UserId => null;

    public string? Username => Context?.User.FindFirstValue(EasyPatchClaims.Username)
                               ?? (Context?.User.FindFirstValue(EasyPatchClaims.CredentialId) is { } c ? "agent:" + c : null);

    public string? IpAddress => Context?.Connection.RemoteIpAddress?.ToString();

    public string? CorrelationId => Context?.TraceIdentifier;

    public string? OnBehalfOf => Context is { } context && context.User.IsApiToken()
        ? OnBehalfOfHeader.Parse(context.Request.Headers[OnBehalfOfHeader.Name])
        : null;
}

/// <summary>
/// <c>X-EasyPatch-On-Behalf-Of</c>: the person an integration's API token request is for, such as the signed-in user of the system that
/// calls EasyPatch. Only API token requests use it; a value that is not one line of printable text up to 254 characters is ignored.
/// </summary>
public static class OnBehalfOfHeader
{
    public const string Name = "X-EasyPatch-On-Behalf-Of";
    public const int MaxLength = 254;

    public static string? Parse(Microsoft.Extensions.Primitives.StringValues values)
    {
        if (values.Count != 1 || values[0]?.Trim() is not { Length: > 0 and <= MaxLength } value || value.Any(char.IsControl))
        {
            return null;
        }

        return value;
    }
}
