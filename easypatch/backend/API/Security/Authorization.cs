using System.Security.Claims;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Security;

public static class Policies
{
    /// <summary>A statement from EasyRMM, any role (read access).</summary>
    public const string Viewer = "Viewer";

    /// <summary>A statement from EasyRMM with the Admin or SuperAdmin role (operations).</summary>
    public const string Operator = "Operator";

    /// <summary>A statement from EasyRMM with the SuperAdmin role (server settings, global policy, tags, alert rules, notifications,
    /// lifecycle).</summary>
    public const string SuperAdmin = "SuperAdmin";

    /// <summary>Active agent credential.</summary>
    public const string Agent = "Agent";

    /// <summary>Pending enrollment request credential (<c>r_</c>).</summary>
    public const string AgentPending = "AgentPending";

    public static IServiceCollection AddEasyPatchAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(Viewer, p => p.AddAuthenticationSchemes(EasyRmmAuthenticationHandler.SchemeName).RequireAuthenticatedUser())
            .AddPolicy(Operator, p => p.AddAuthenticationSchemes(EasyRmmAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireRole(nameof(UserRole.Admin), nameof(UserRole.SuperAdmin)))
            .AddPolicy(SuperAdmin, p => p.AddAuthenticationSchemes(EasyRmmAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireRole(nameof(UserRole.SuperAdmin)))
            .AddPolicy(Agent, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindActive))
            .AddPolicy(AgentPending, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindPending));
        return services;
    }
}

/// <summary>Request-scoped tenant (organization) visibility derived from the statement from EasyRMM.</summary>
public sealed class HttpTenantContext : ITenantContext
{
    public HttpTenantContext(IHttpContextAccessor accessor)
    {
        var user = accessor.HttpContext?.User;
        var scheme = user?.Identity?.IsAuthenticated == true ? user.Identity.AuthenticationType : null;
        if (user is null || scheme != EasyRmmAuthenticationHandler.SchemeName)
        {
            IsUnrestricted = false;
            AllowedOrganizationIds = new HashSet<Guid>();
            return;
        }

        // Only the explicit flag means "all", whatever the role: a statement sees every organization only when it says so
        // ("orgs": "*"), and a statement for organizations that were all deleted sees nothing.
        IsUnrestricted = user.FindFirstValue(EasyPatchClaims.AllOrganizations) == "true";
        AllowedOrganizationIds = user.FindAll(EasyPatchClaims.Organization).Select(c => Guid.Parse(c.Value)).ToHashSet();
    }

    public bool IsUnrestricted { get; }
    public IReadOnlySet<Guid> AllowedOrganizationIds { get; }
}

public sealed class HttpActorContext(IHttpContextAccessor accessor) : IActorContext
{
    private HttpContext? Context => accessor.HttpContext;

    /// <summary>Always null: EasyPatch has no accounts of its own. Statements are named in <see cref="Username"/>.</summary>
    public Guid? UserId => null;

    public string? Username => Context?.User.FindFirstValue(EasyPatchClaims.Username)
                               ?? (Context?.User.FindFirstValue(EasyPatchClaims.CredentialId) is { } c ? "agent:" + c : null);

    public string? IpAddress => Context?.Connection.RemoteIpAddress?.ToString();

    public string? CorrelationId => Context?.TraceIdentifier;
}
