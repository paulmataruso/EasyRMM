using System.Net;
using System.Text.Json.Serialization;
using EasyPatch.Api;
using EasyPatch.Api.Cli;
using EasyPatch.Api.Endpoints;
using EasyPatch.Api.Security;
using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;

if (args.Length > 0 && AdminCli.Commands.Contains(args[0]))
{
    return await AdminCli.RunAsync(args);
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 16 * 1024 * 1024;
});

if (!builder.Environment.IsDevelopment() && builder.Configuration["Logging:Format"] != "text")
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o => o.IncludeScopes = true);
}

builder.Services.AddEasyPatchCore(builder.Configuration);
builder.Services.AddEasyPatchDataProtection(builder.Configuration);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ITenantContext, HttpTenantContext>();
builder.Services.AddScoped<IActorContext, HttpActorContext>();
builder.Services.AddSingleton<EasyRmmGateway>();
builder.Services.AddHostedService<PresenceFlushService>();

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.MaxDepth = 32;
});
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<EasyPatchExceptionHandler>();

// The administrator API takes EasyRMM's statements and nothing else; agents sign their requests. EasyPatch has no sign-in, session,
// cookie or API token of its own.
builder.Services.AddAuthentication(EasyRmmAuthenticationHandler.SchemeName)
    .AddScheme<EasyRmmAuthenticationOptions, EasyRmmAuthenticationHandler>(EasyRmmAuthenticationHandler.SchemeName, null)
    .AddScheme<AgentAuthenticationOptions, AgentAuthenticationHandler>(AgentAuthenticationHandler.SchemeName, null);
builder.Services.AddEasyPatchAuthorization();
builder.Services.AddEasyPatchRateLimits(builder.Configuration);

builder.Services.AddOpenApi("v1", o => o.AddDocumentTransformer((document, _, _) =>
{
    document.Info.Title = "EasyPatch API";
    document.Info.Version = "v1";
    document.Info.Description = "EasyPatch, EasyRMM's patching engine: the administrator API EasyRMM calls, and the agent API.";
    return Task.CompletedTask;
}));

builder.Services.AddHealthChecks().AddDbContextCheck<EasyPatchDbContext>("database", tags: ["ready"]);

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    // Only a trusted proxy may set the client address: loopback (EasyRMM's edge, on the same host) and the networks in
    // ForwardedHeaders:KnownNetworks.
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1;
    foreach (var cidr in (builder.Configuration["ForwardedHeaders:KnownNetworks"] ?? string.Empty)
                 .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
    }
});

var app = builder.Build();
// An unusable gateway key stops the server now rather than at EasyRMM's first call.
_ = app.Services.GetRequiredService<EasyRmmGateway>();

app.UseForwardedHeaders();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseExceptionHandler();
app.Use((context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.Headers.CacheControl = "no-store";
    }

    return next(context);
});

app.UseRouting();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.MapOpenApi("/api/openapi/{documentName}.json").RequireAuthorization(Policies.Viewer);
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") }).AllowAnonymous();

app.MapAgentEndpoints();
app.MapOrganizationEndpoints();
app.MapEndpointEndpoints();
app.MapRestartPendingEndpoints();
app.MapTagEndpoints();
app.MapNotificationEndpoints();
app.MapJobEndpoints();
app.MapFleetUpdateEndpoints();
app.MapUpdateHoldEndpoints();
app.MapAgentManagementEndpoints();
app.MapDownloadEndpoints();
app.MapReportingEndpoints();
app.MapMonthlyReportEndpoints();
app.MapSettingsEndpoints();

app.MapFallback("/api/{**path}", (HttpContext ctx) =>
    ProblemResults.WriteAsync(ctx, StatusCodes.Status404NotFound, "not_found", "No API route matches this request."));

await app.RunAsync();
return 0;

/// <summary>Entry point marker for WebApplicationFactory in integration tests.</summary>
public partial class Program;
