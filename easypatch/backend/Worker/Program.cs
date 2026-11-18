using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.Extensions.Diagnostics.HealthChecks;

// Background worker: job lease recovery and expiry, presence (online/offline), maintenance-window scheduling,
// rollout delays, alerts and notifications, compliance snapshots and retention. Each task runs under a PostgreSQL
// advisory lock.
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);
if (!builder.Environment.IsDevelopment() && builder.Configuration["Logging:Format"] != "text")
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o => o.IncludeScopes = true);
}

builder.Services.AddEasyPatchCore(builder.Configuration);
builder.Services.AddEasyPatchDataProtection(builder.Configuration, generateKeys: false); // decrypts notification secrets
builder.Services.AddEasyPatchMaintenance();
builder.Services.AddHealthChecks()
    .AddDbContextCheck<EasyPatchDbContext>("database")
    .AddCheck<MaintenanceHeartbeatCheck>("maintenance-loops");

var app = builder.Build();
app.MapHealthChecks("/health");
await app.RunAsync();

/// <summary>Unhealthy when a maintenance loop has not completed an iteration for several intervals.</summary>
internal sealed class MaintenanceHeartbeatCheck(MaintenanceHeartbeat heartbeat) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var stalled = heartbeat.Stalled();
        return Task.FromResult(stalled.Count == 0
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy($"Maintenance loops not progressing: {string.Join(", ", stalled)}"));
    }
}

/// <summary>Entry point marker for tests.</summary>
public partial class Program;
