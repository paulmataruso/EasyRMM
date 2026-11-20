using System.Security.Claims;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Security;

/// <summary>
/// The claims EasyPatch's authentication handlers put on a request: a statement from EasyRMM (EasyRmmAuthenticationHandler) or an
/// agent credential (AgentAuthenticationHandler).
/// </summary>
public static class EasyPatchClaims
{
    /// <summary>Who acted, as the audit log names it: <c>easyrmm:&lt;name&gt;</c>.</summary>
    public const string Username = ClaimTypes.Name;
    public const string Role = ClaimTypes.Role;
    public const string Organization = "easypatch:org";
    public const string AllOrganizations = "easypatch:all_orgs";
    /// <summary>Who a statement from EasyRMM acts for: an EasyRMM user's id, or "service" (EasyRmmAuthenticationHandler).</summary>
    public const string EasyRmmSubject = "easypatch:easyrmm_sub";

    public const string CredentialId = "easypatch:credential";
    public const string CredentialDbId = "easypatch:credential_db";
    public const string EndpointId = "easypatch:endpoint";
    public const string OrganizationId = "easypatch:organization";
    public const string AgentKind = "easypatch:agent_kind";

    public static UserRole GetRole(this ClaimsPrincipal principal) =>
        Enum.TryParse<UserRole>(principal.FindFirstValue(Role), out var role) ? role : UserRole.ReadOnly;

    public static Guid GetEndpointId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(EndpointId) ?? throw AppException.Unauthorized("unauthenticated", "Agent credential required."));
}
