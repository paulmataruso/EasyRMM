using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Reports;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using EasyPatch.Infrastructure.Vulnerabilities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace EasyPatch.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Registers the database, domain services and shared singletons used by both the API and the worker.</summary>
    public static IServiceCollection AddEasyPatchCore(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var connectionString = DatabaseConnection.Build(configuration);
        services.AddDbContext<EasyPatchDbContext>(o => o.UseNpgsql(connectionString, n =>
        {
            n.EnableRetryOnFailure(0); // explicit transactions are used; retries are handled by callers
            n.CommandTimeout(60);
        }));

        services.AddOptions<EasyPatchOptions>().Bind(configuration.GetSection(EasyPatchOptions.Section));
        services.AddSingleton(TimeProvider.System);
        services.AddMemoryCache();
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();

        services.AddScoped<SettingsService>();
        services.AddScoped<PolicyService>();
        services.AddScoped<AuditService>();
        services.AddScoped<VulnerabilityMatcher>();
        services.AddScoped<ComplianceService>();
        services.AddScoped<ScanIngestionService>();
        services.AddScoped<InstallPreviewService>();
        services.AddScoped<JobService>();
        services.AddScoped<UpdateRemovalService>();
        services.AddScoped<UpdateHoldService>();
        services.AddScoped<ApiTokenService>();
        services.AddScoped<EnrollmentService>();
        services.AddScoped<CheckInService>();

        services.AddSingleton<CredentialCache>();
        services.AddSingleton<NonceStore>();
        services.AddSingleton<PresenceTracker>();
        services.AddSingleton<AgentPackageService>();
        services.AddSingleton(WingetMirrorFiles.Pinned);
        services.AddSingleton<WingetMirrorService>();

        services.AddScoped<NotificationSecrets>();
        services.AddScoped<AlertEngine>();
        services.AddScoped<NotificationDispatcher>();
        services.AddScoped<MonthlyReportDataBuilder>();
        services.AddScoped<MonthlyReportService>();
        services.AddSingleton<INotificationTransport, NotificationTransport>();
        var version = typeof(DependencyInjection).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        services.AddHttpClient(NotificationTransport.WebhookClient, c =>
            {
                c.Timeout = TimeSpan.FromSeconds(30);
                c.DefaultRequestHeaders.UserAgent.ParseAdd($"EasyPatch/{version}");
            })
            .ConfigurePrimaryHttpMessageHandler(WebhookHttp.CreateHandler)
            .RemoveAllLoggers(); // request logging would write webhook URLs (which contain secrets) to the log

        // The winget release on GitHub (worker only): github.com redirects to its download host; HTTPS only (checked).
        services.AddHttpClient(WingetMirrorService.HttpClientName, c =>
            {
                c.Timeout = TimeSpan.FromHours(2);
                c.DefaultRequestHeaders.UserAgent.ParseAdd($"EasyPatch/{version}");
            })
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(20),
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            });

        // Public vulnerability feeds (worker only). No redirects: the feed hosts are fixed HTTPS URLs.
        services.AddScoped<VulnerabilityFeedService>();
        services.AddHttpClient(VulnerabilityFeedService.HttpClientName, c =>
            {
                c.Timeout = TimeSpan.FromMinutes(10);
                c.DefaultRequestHeaders.UserAgent.ParseAdd($"EasyPatch/{version}");
            })
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = System.Net.DecompressionMethods.All,
                ConnectTimeout = TimeSpan.FromSeconds(20),
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            });
        return services;
    }

    /// <summary>Data protection keys encrypt TOTP secrets and notification secrets (SMTP password, webhook URLs) at rest.
    /// They are stored on a volume separate from the database so that a database dump alone does not expose them.
    /// The worker reads the same key ring (<paramref name="generateKeys"/> false: only the API creates keys).</summary>
    public static IServiceCollection AddEasyPatchDataProtection(this IServiceCollection services, IConfiguration configuration, bool generateKeys = true)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var keysPath = configuration["EasyPatch:DataProtectionKeysPath"] ?? "/app/keys";
        var builder = services.AddDataProtection()
            .SetApplicationName("EasyPatch")
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath));
        if (!generateKeys)
        {
            builder.DisableAutomaticKeyGeneration();
        }

        return services;
    }

    /// <summary>Registers the worker's periodic maintenance tasks and their hosted loops.</summary>
    public static IServiceCollection AddEasyPatchMaintenance(this IServiceCollection services)
    {
        services.AddScoped<IActorContext, SystemActorContext>();
        services.AddScoped<ITenantContext, SystemTenantContext>();
        services.AddScoped<JobMaintenanceTask>();
        services.AddScoped<PresenceMonitorTask>();
        services.AddScoped<ScheduledInstallTask>();
        services.AddScoped<ScheduledRestartTask>();
        services.AddScoped<AgentUpdateTask>();
        services.AddScoped<ComplianceSnapshotTask>();
        services.AddScoped<RetentionTask>();
        services.AddScoped<DeferralExpiryTask>();
        services.AddScoped<AlertEvaluationTask>();
        services.AddScoped<NotificationDeliveryTask>();
        services.AddScoped<VulnerabilityFeedTask>();
        services.AddScoped<MonthlyReportTask>();
        services.AddScoped<WingetMirrorTask>();
        services.AddScoped<RolloutGuardTask>();
        services.AddScoped<PreDownloadTask>();
        services.AddSingleton<MaintenanceHeartbeat>();
        services.AddHostedService<MaintenanceLoop<JobMaintenanceTask>>();
        services.AddHostedService<MaintenanceLoop<PresenceMonitorTask>>();
        services.AddHostedService<MaintenanceLoop<ScheduledInstallTask>>();
        services.AddHostedService<MaintenanceLoop<ScheduledRestartTask>>();
        services.AddHostedService<MaintenanceLoop<AgentUpdateTask>>();
        services.AddHostedService<MaintenanceLoop<ComplianceSnapshotTask>>();
        services.AddHostedService<MaintenanceLoop<RetentionTask>>();
        services.AddHostedService<MaintenanceLoop<DeferralExpiryTask>>();
        services.AddHostedService<MaintenanceLoop<AlertEvaluationTask>>();
        services.AddHostedService<MaintenanceLoop<NotificationDeliveryTask>>();
        services.AddHostedService<MaintenanceLoop<VulnerabilityFeedTask>>();
        services.AddHostedService<MaintenanceLoop<MonthlyReportTask>>();
        services.AddHostedService<MaintenanceLoop<WingetMirrorTask>>();
        services.AddHostedService<MaintenanceLoop<RolloutGuardTask>>();
        services.AddHostedService<MaintenanceLoop<PreDownloadTask>>();
        return services;
    }
}

/// <summary>Builds the PostgreSQL connection string. The password is read from a Docker secret file when
/// <c>Database:PasswordFile</c> is set, so it never appears in environment variables or image layers.</summary>
public static class DatabaseConnection
{
    public static string Build(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection("Database");
        var explicitConnection = configuration.GetConnectionString("EasyPatch");
        var builder = new Npgsql.NpgsqlConnectionStringBuilder(explicitConnection ?? string.Empty);
        if (explicitConnection is null)
        {
            builder.Host = section["Host"] ?? "postgres";
            builder.Port = int.TryParse(section["Port"], out var port) ? port : 5432;
            builder.Database = section["Name"] ?? "easypatch";
            builder.Username = section["User"] ?? "easypatch";
            // The database is on an internal Docker network with password (SCRAM) authentication. Do not probe for
            // Kerberos/GSS encryption: the runtime image has no GSSAPI library and the probe only produces log noise.
            builder.GssEncryptionMode = Npgsql.GssEncryptionMode.Disable;
        }

        var passwordFile = section["PasswordFile"];
        if (!string.IsNullOrEmpty(passwordFile))
        {
            builder.Password = File.ReadAllText(passwordFile).Trim();
        }
        else if (section["Password"] is { Length: > 0 } password)
        {
            builder.Password = password;
        }

        builder.MaxPoolSize = int.TryParse(section["MaxPoolSize"], out var pool) ? pool : 50;
        builder.ApplicationName = configuration["EasyPatch:ApplicationName"] ?? "easypatch";
        builder.IncludeErrorDetail = false;
        return builder.ConnectionString;
    }
}
