using System.Text.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;

namespace EasyPatch.Infrastructure.Services;

public sealed class AuditService(EasyPatchDbContext db, IActorContext actor, TimeProvider clock)
{
    private static readonly JsonSerializerOptions Json = Contracts.Json.ContractJson.Options;

    /// <summary>Adds an audit record to the current unit of work (saved with the caller's SaveChanges).</summary>
    public void Record(string action, string? targetType = null, string? targetId = null, Guid? organizationId = null,
        Guid? endpointId = null, object? details = null)
    {
        db.AuditLogs.Add(new AuditLog
        {
            UserId = actor.UserId,
            Username = actor.Username,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            OrganizationId = organizationId,
            EndpointId = endpointId,
            Details = details is null ? null : JsonSerializer.Serialize(details, Json),
            IpAddress = actor.IpAddress,
            CorrelationId = actor.CorrelationId,
            CreatedAt = clock.GetUtcNow(),
        });
    }
}

public static class EndpointEvents
{
    public static void Add(EasyPatchDbContext db, Endpoint endpoint, string type, string message, DateTimeOffset now,
        EventSeverity severity = EventSeverity.Info, Guid? jobId = null, object? details = null)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(endpoint);
        db.EndpointEvents.Add(new EndpointEvent
        {
            EndpointId = endpoint.Id,
            OrganizationId = endpoint.OrganizationId,
            Type = type,
            Severity = severity,
            Message = message.Length > 2000 ? message[..2000] : message,
            JobId = jobId,
            Details = details is null ? null : JsonSerializer.Serialize(details, Contracts.Json.ContractJson.Options),
            CreatedAt = now,
        });
    }
}
