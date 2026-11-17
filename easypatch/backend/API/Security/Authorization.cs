using System.Security.Claims;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace EasyPatch.Api.Security;

public static class Policies
{
    /// <summary>Signed in with a session, MFA possibly still pending (MFA verification, logout, /me).</summary>
    public const string SessionAny = "SessionAny";

    /// <summary>Signed in and past the MFA step, but MFA enrollment or a password change may still be required.</summary>
    public const string SessionMfaPassed = "SessionMfaPassed";

    /// <summary>Fully signed in with a session, any role: the user's own account (MFA, recovery codes, sessions). Not API tokens.</summary>
    public const string Account = "Account";

    /// <summary>Fully authenticated session or API token, any role (read access).</summary>
    public const string Viewer = "Viewer";

    /// <summary>Fully authenticated Admin or SuperAdmin session, or an Admin API token (operations).</summary>
    public const string Operator = "Operator";

    /// <summary>Fully authenticated SuperAdmin (users, API tokens, server settings, global policy, lifecycle). API tokens are never
    /// SuperAdmin, so they are refused.</summary>
    public const string SuperAdmin = "SuperAdmin";

    /// <summary>Active agent credential.</summary>
    public const string Agent = "Agent";

    /// <summary>Pending enrollment request credential (<c>r_</c>).</summary>
    public const string AgentPending = "AgentPending";

    public static IServiceCollection AddEasyPatchAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationHandler, SessionStateHandler>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, ProblemAuthorizationResultHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(SessionAny, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName).RequireAuthenticatedUser())
            .AddPolicy(SessionMfaPassed, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .AddRequirements(new SessionStateRequirement(requireMfaSetup: false, requirePasswordCurrent: false)))
            .AddPolicy(Account, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .AddRequirements(new SessionStateRequirement(true, true)))
            .AddPolicy(Viewer, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser()
                .AddRequirements(new SessionStateRequirement(true, true)))
            .AddPolicy(Operator, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser()
                .AddRequirements(new SessionStateRequirement(true, true))
                .RequireRole(nameof(UserRole.Admin), nameof(UserRole.SuperAdmin)))
            .AddPolicy(SuperAdmin, p => p.AddAuthenticationSchemes(ConsoleAuthentication.SchemeName).RequireAuthenticatedUser()
                .AddRequirements(new SessionStateRequirement(true, true))
                .RequireRole(nameof(UserRole.SuperAdmin)))
            .AddPolicy(Agent, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindActive))
            .AddPolicy(AgentPending, p => p.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName).RequireAuthenticatedUser()
                .RequireClaim(EasyPatchClaims.AgentKind, AgentAuthenticationHandler.KindPending));
        return services;
    }
}

public sealed class SessionStateRequirement(bool requireMfaSetup, bool requirePasswordCurrent) : IAuthorizationRequirement
{
    public bool RequireMfaSetup { get; } = requireMfaSetup;
    public bool RequirePasswordCurrent { get; } = requirePasswordCurrent;
}

public sealed class SessionStateHandler : AuthorizationHandler<SessionStateRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SessionStateRequirement requirement)
    {
        var user = context.User;
        if (user.IsApiToken())
        {
            // API tokens have no MFA or password state; their role and organizations are checked like a user's.
            context.Succeed(requirement);
        }
        else if (user.FindFirstValue(EasyPatchClaims.MfaCompleted) != "true")
        {
            context.Fail(new AuthorizationFailureReason(this, "mfa_required"));
        }
        else if (requirement.RequireMfaSetup && user.FindFirstValue(EasyPatchClaims.MfaSetupRequired) == "true")
        {
            context.Fail(new AuthorizationFailureReason(this, "mfa_setup_required"));
        }
        else if (requirement.RequirePasswordCurrent && user.FindFirstValue(EasyPatchClaims.MustChangePassword) == "true")
        {
            context.Fail(new AuthorizationFailureReason(this, "password_change_required"));
        }
        else
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

/// <summary>Turns authorization failures into problem+json with a machine-readable code.</summary>
public sealed class ProblemAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler fallback = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden && authorizeResult.AuthorizationFailure?.FailureReasons.FirstOrDefault(r => r.Handler is SessionStateHandler) is { } reason)
        {
            var message = reason.Message switch
            {
                "mfa_required" => "Enter your verification code to finish signing in.",
                "mfa_setup_required" => "Set up multi-factor authentication to continue.",
                "password_change_required" => "You must change your password before continuing.",
                _ => "You do not have permission to perform this action.",
            };
            await ProblemResults.WriteAsync(context, StatusCodes.Status403Forbidden, reason.Message, message);
            return;
        }

        await fallback.HandleAsync(next, context, policy, authorizeResult);
    }
}

/// <summary>Request-scoped tenant (organization) visibility derived from the session or API token.</summary>
public sealed class HttpTenantContext : ITenantContext
{
    public HttpTenantContext(IHttpContextAccessor accessor)
    {
        var user = accessor.HttpContext?.User;
        var scheme = user?.Identity?.IsAuthenticated == true ? user.Identity.AuthenticationType : null;
        if (user is null || scheme is not (SessionAuthenticationHandler.SchemeName or ApiTokenAuthenticationHandler.SchemeName))
        {
            IsUnrestricted = false;
            AllowedOrganizationIds = new HashSet<Guid>();
            return;
        }

        var orgs = user.FindAll(EasyPatchClaims.Organization).Select(c => Guid.Parse(c.Value)).ToHashSet();
        IsUnrestricted = scheme == ApiTokenAuthenticationHandler.SchemeName
            ? user.FindFirstValue(EasyPatchClaims.AllOrganizations) == "true" // a scoped token whose organizations were deleted sees nothing
            : user.GetRole() == UserRole.SuperAdmin || orgs.Count == 0;
        AllowedOrganizationIds = orgs;
    }

    public bool IsUnrestricted { get; }
    public IReadOnlySet<Guid> AllowedOrganizationIds { get; }
}

public sealed class HttpActorContext(IHttpContextAccessor accessor) : IActorContext
{
    private HttpContext? Context => accessor.HttpContext;

    public Guid? UserId => Guid.TryParse(Context?.User.FindFirstValue(EasyPatchClaims.UserId), out var id) ? id : null;

    public string? Username => Context?.User.FindFirstValue(EasyPatchClaims.Username)
                               ?? (Context?.User.FindFirstValue(EasyPatchClaims.CredentialId) is { } c ? "agent:" + c : null);

    public string? IpAddress => Context?.Connection.RemoteIpAddress?.ToString();

    public string? CorrelationId => Context?.TraceIdentifier;
}
