using System.Net;
using System.Text.Json.Serialization;
using EasyPatch.Api;
using EasyPatch.Api.Cli;
using EasyPatch.Api.Endpoints;
using EasyPatch.Api.Security;
using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
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
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<WebAuthnService>();
builder.Services.AddScoped<OidcService>();
builder.Services.AddSingleton<OidcConfigurationCache>();
// Single sign-on: discovery, key sets and the token endpoint. No redirects or cookies, a short timeout, and no request logging.
builder.Services.AddHttpClient(OidcService.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(15))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    .RemoveAllLoggers();
builder.Services.AddSingleton<CsrfProtection>();
builder.Services.AddHostedService<PresenceFlushService>();

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.MaxDepth = 32;
});
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<EasyPatchExceptionHandler>();

builder.Services.AddAuthentication(ConsoleAuthentication.SchemeName)
    .AddPolicyScheme(ConsoleAuthentication.SchemeName, null, o => o.ForwardDefaultSelector = ConsoleAuthentication.Select)
    .AddScheme<SessionAuthenticationOptions, SessionAuthenticationHandler>(SessionAuthenticationHandler.SchemeName, null)
    .AddScheme<ApiTokenAuthenticationOptions, ApiTokenAuthenticationHandler>(ApiTokenAuthenticationHandler.SchemeName, null)
    .AddScheme<AgentAuthenticationOptions, AgentAuthenticationHandler>(AgentAuthenticationHandler.SchemeName, null);
builder.Services.AddEasyPatchAuthorization();
builder.Services.AddEasyPatchRateLimits(builder.Configuration);

builder.Services.AddOpenApi("v1", o => o.AddDocumentTransformer((document, _, _) =>
{
    document.Info.Title = "EasyPatch API";
    document.Info.Version = "v1";
    document.Info.Description = "Administrator and agent API for the EasyPatch Windows patch management platform.";
    return Task.CompletedTask;
}));

builder.Services.AddHealthChecks().AddDbContextCheck<EasyPatchDbContext>("database", tags: ["ready"]);

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    // Only the reverse proxy may set the client address. Trusted networks come from configuration (the Docker edge network).
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.ForwardLimit = 1;
    foreach (var cidr in (builder.Configuration["ForwardedHeaders:KnownNetworks"] ?? string.Empty)
                 .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
    }
});

var app = builder.Build();

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
app.UseMiddleware<CsrfMiddleware>();
app.UseRateLimiter();
app.UseAuthorization();

// Swagger UI is only served to signed-in administrators.
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/api/docs"), branch => branch.Use(async (ctx, next) =>
{
    var result = await ctx.AuthenticateAsync(SessionAuthenticationHandler.SchemeName);
    if (!result.Succeeded || result.Principal.FindFirst(EasyPatchClaims.MfaCompleted)?.Value != "true")
    {
        await ProblemResults.WriteAsync(ctx, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to view the API documentation.");
        return;
    }

    await next(ctx);
}));
app.UseSwaggerUI(o =>
{
    o.RoutePrefix = "api/docs";
    o.SwaggerEndpoint("/api/openapi/v1.json", "EasyPatch API v1");
    o.DocumentTitle = "EasyPatch API";
});

app.MapOpenApi("/api/openapi/{documentName}.json").RequireAuthorization(Policies.Viewer);
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") }).AllowAnonymous();

app.MapAgentEndpoints();
app.MapAuthEndpoints();
app.MapWebAuthnEndpoints();
app.MapSsoEndpoints();
app.MapUserEndpoints();
app.MapApiTokenEndpoints();
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
