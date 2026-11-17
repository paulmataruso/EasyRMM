using System.Security.Claims;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Endpoints;

/// <summary>Agent protocol. Every route except <c>/enroll</c> requires a signed request; the endpoint identity always
/// comes from the verified credential, never from the request body.</summary>
public static class AgentEndpoints
{
    public static void MapAgentEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/" + AgentRoutes.Prefix).WithTags("Agent protocol");

        g.MapPost("/enroll", async (EnrollRequest request, EnrollmentService enrollment, HttpContext http, CancellationToken ct) =>
                TypedResults.Ok(await enrollment.EnrollAsync(request, http.Connection.RemoteIpAddress, ct)))
            .AllowAnonymous()
            .RequireRateLimiting(RateLimits.Enroll);

        g.MapPost("/enrollment/status", async (ClaimsPrincipal user, EnrollmentService enrollment, CancellationToken ct) =>
                TypedResults.Ok(await enrollment.GetPendingStatusAsync(user.FindFirstValue(EasyPatchClaims.CredentialId)!, ct)))
            .RequireAuthorization(Policies.AgentPending)
            .RequireRateLimiting(RateLimits.Agent);

        var signed = g.MapGroup(string.Empty).RequireAuthorization(Policies.Agent).RequireRateLimiting(RateLimits.Agent);

        signed.MapPost("/check-in", async (CheckInRequest request, CheckInService checkIn, HttpContext http, CancellationToken ct) =>
        {
            var credential = (AgentCredentialInfo)http.Items[typeof(AgentCredentialInfo)]!;
            return TypedResults.Ok(await checkIn.CheckInAsync(credential, request, http.Connection.RemoteIpAddress?.ToString(), ct));
        });

        signed.MapPost("/inventory", async (InventoryReport report, ClaimsPrincipal user, ScanIngestionService ingestion, CancellationToken ct) =>
        {
            await ingestion.IngestInventoryAsync(user.GetEndpointId(), report, ct);
            return TypedResults.NoContent();
        });

        signed.MapPost("/updates/scan-results", async (ScanResultReport report, ClaimsPrincipal user, ScanIngestionService ingestion, CancellationToken ct) =>
        {
            await ingestion.IngestScanAsync(user.GetEndpointId(), report, ct);
            return TypedResults.NoContent();
        });

        signed.MapPost("/updates/history", async (HistoryReport report, ClaimsPrincipal user, ScanIngestionService ingestion, CancellationToken ct) =>
        {
            await ingestion.IngestHistoryAsync(user.GetEndpointId(), report, ct);
            return TypedResults.NoContent();
        });

        signed.MapPost("/jobs/{jobId:guid}/ack", async (Guid jobId, ClaimsPrincipal user, JobService jobs, CancellationToken ct) =>
            TypedResults.Ok(await jobs.AcknowledgeAsync(user.GetEndpointId(), jobId, ct)));

        signed.MapPost("/jobs/{jobId:guid}/status", async (Guid jobId, JobStatusReport report, ClaimsPrincipal user, JobService jobs, CancellationToken ct) =>
        {
            await jobs.ReportStatusAsync(user.GetEndpointId(), jobId, report, ct);
            return TypedResults.NoContent();
        });

        signed.MapPost("/credentials/rotate", async (RotateCredentialRequest request, ClaimsPrincipal user, EnrollmentService enrollment,
                CredentialCache cache, CancellationToken ct) =>
        {
            var current = user.FindFirstValue(EasyPatchClaims.CredentialId)!;
            var response = await enrollment.RotateAsync(user.GetEndpointId(), current, request, ct);
            cache.Invalidate(current);
            return TypedResults.Ok(response);
        });

        signed.MapPost("/unenroll", async (UnenrollRequest request, ClaimsPrincipal user, EnrollmentService enrollment, CredentialCache cache,
            CancellationToken ct) =>
        {
            await enrollment.UnenrollAsync(user.GetEndpointId(), Validator.Clean(request.Reason) ?? "Agent uninstalled", ct);
            cache.Invalidate(user.FindFirstValue(EasyPatchClaims.CredentialId)!);
            return TypedResults.NoContent();
        });
    }
}
