using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.RateLimiting;

namespace EasyPatch.Api;

public static class RateLimits
{
    public const string Login = "login";
    public const string Enroll = "enroll";
    public const string Agent = "agent";
    public const string Admin = "admin";
    public const string Downloads = "downloads";

    public static IServiceCollection AddEasyPatchRateLimits(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("RateLimits");
        int Limit(string key, int fallback) => int.TryParse(section[key], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0 ? v : fallback;
        var login = Limit("LoginPerMinute", 20);
        var enroll = Limit("EnrollPerMinute", 30);
        var agent = Limit("AgentPerMinute", 120);
        var admin = Limit("AdminPerMinute", 600);
        var downloads = Limit("DownloadsPerMinute", 60);

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, ct) =>
            {
                var retry = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var after) ? after : TimeSpan.FromSeconds(60);
                context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retry.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                await ProblemResults.WriteAsync(context.HttpContext, StatusCodes.Status429TooManyRequests, AgentErrorCodes.RateLimited,
                    "Too many requests. Try again later.", new Dictionary<string, object?> { ["retryAfterSeconds"] = (int)Math.Ceiling(retry.TotalSeconds) });
            };

            options.AddPolicy(Login, ctx => Window(IpKey(ctx), login));
            options.AddPolicy(Enroll, ctx => Window(IpKey(ctx), enroll));
            options.AddPolicy(Downloads, ctx => Window(IpKey(ctx), downloads));
            options.AddPolicy(Agent, ctx =>
            {
                var credential = ctx.Request.Headers[AgentAuthHeaders.Credential].ToString();
                return Window(credential.Length is > 0 and <= 64 ? "cred:" + credential : IpKey(ctx), agent);
            });

            // Every authenticated admin request is limited per user or API token; anonymous requests per IP.
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
            {
                if (!ctx.Request.Path.StartsWithSegments("/api/v1") || ctx.Request.Path.StartsWithSegments("/" + AgentRoutes.Prefix))
                {
                    return RateLimitPartition.GetNoLimiter("unlimited");
                }

                var user = ctx.User.FindFirstValue(EasyPatchClaims.UserId);
                var token = ctx.User.FindFirstValue(EasyPatchClaims.ApiTokenId);
                return Window(user is not null ? "user:" + user : token is not null ? "token:" + token : IpKey(ctx), admin);
            });
        });
        return services;
    }

    private static string IpKey(HttpContext ctx) => "ip:" + (ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    private static RateLimitPartition<string> Window(string key, int permitsPerMinute) =>
        RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitsPerMinute,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true,
        });
}

/// <summary>Flushes buffered agent presence (last check-in) to the database every few seconds and on shutdown.</summary>
public sealed class PresenceFlushService(PresenceTracker tracker, ILogger<PresenceFlushService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await tracker.FlushAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }

        try
        {
            await tracker.FlushAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Final presence flush failed");
        }
    }
}
