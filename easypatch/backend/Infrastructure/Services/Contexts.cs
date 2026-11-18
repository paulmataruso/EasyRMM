namespace EasyPatch.Infrastructure.Services;

/// <summary>Which organizations the current caller may access. Every admin query is filtered through this.</summary>
public interface ITenantContext
{
    /// <summary>True for SuperAdmins, users without org restrictions, and background services.</summary>
    bool IsUnrestricted { get; }

    IReadOnlySet<Guid> AllowedOrganizationIds { get; }

    bool CanAccess(Guid organizationId) => IsUnrestricted || AllowedOrganizationIds.Contains(organizationId);

    void EnsureAccess(Guid organizationId)
    {
        if (!CanAccess(organizationId))
        {
            // Do not reveal existence of other tenants' data.
            throw AppException.NotFound("The requested resource");
        }
    }
}

/// <summary>Who is acting, for auditing.</summary>
public interface IActorContext
{
    Guid? UserId { get; }
    string? Username { get; }
    string? IpAddress { get; }
    string? CorrelationId { get; }

    /// <summary>
    /// For an API token, the person an integration says it acts for (<c>X-EasyPatch-On-Behalf-Of</c>). Informational: the token's role
    /// and organizations decide what the request may do.
    /// </summary>
    string? OnBehalfOf => null;
}

public static class ActorContextExtensions
{
    /// <summary>The actor name of requests made with an API token (<c>token:&lt;name&gt;</c>).</summary>
    public const string ApiTokenPrefix = "token:";

    /// <summary>The actor name of requests EasyRMM makes as its patching engine's console (<c>easyrmm:&lt;name&gt;</c>).</summary>
    public const string EasyRmmPrefix = "easyrmm:";

    /// <summary>True for a signed-in administrator, an API token or EasyRMM (not the system or an agent).</summary>
    public static bool IsAdministrator(this IActorContext actor) =>
        actor.UserId is not null || actor.Username?.StartsWith(ApiTokenPrefix, StringComparison.Ordinal) == true ||
        actor.Username?.StartsWith(EasyRmmPrefix, StringComparison.Ordinal) == true;
}

public sealed class SystemTenantContext : ITenantContext
{
    public bool IsUnrestricted => true;
    public IReadOnlySet<Guid> AllowedOrganizationIds { get; } = new HashSet<Guid>();
}

public sealed class SystemActorContext : IActorContext
{
    public Guid? UserId => null;
    public string? Username => "system";
    public string? IpAddress => null;
    public string? CorrelationId => null;
}

public static class TenantQueryExtensions
{
    public static IQueryable<T> ForTenant<T>(this IQueryable<T> query, ITenantContext tenant, System.Linq.Expressions.Expression<Func<T, Guid>> orgSelector)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        if (tenant.IsUnrestricted)
        {
            return query;
        }

        var allowed = tenant.AllowedOrganizationIds.ToArray();
        var param = orgSelector.Parameters[0];
        var contains = System.Linq.Expressions.Expression.Call(
            typeof(Enumerable), nameof(Enumerable.Contains), [typeof(Guid)],
            System.Linq.Expressions.Expression.Constant(allowed), orgSelector.Body);
        return query.Where(System.Linq.Expressions.Expression.Lambda<Func<T, bool>>(contains, param));
    }
}
