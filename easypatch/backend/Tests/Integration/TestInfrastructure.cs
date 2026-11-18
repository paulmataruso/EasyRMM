using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

[assembly: AssemblyFixture(typeof(EasyPatch.Tests.Integration.PostgresFixture))]

namespace EasyPatch.Tests.Integration;

/// <summary>One PostgreSQL container per test run. A migrated template database is cloned for every test.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    public const string Image = "postgres:18.6-alpine3.24";
    private const string TemplateDb = "easypatch_template";
    // Test classes run in parallel, each test with its own database and connection pool (up to 20 connections): the default
    // max_connections (100) is too few for the whole suite.
    private readonly PostgreSqlContainer container = new PostgreSqlBuilder(Image).WithCommand("-c", "max_connections=400").Build();
    private readonly SemaphoreSlim createLock = new(1, 1);

    public async ValueTask InitializeAsync()
    {
        await container.StartAsync();
        await ExecuteAsync($"CREATE DATABASE {TemplateDb}");
        var options = new DbContextOptionsBuilder<EasyPatchDbContext>().UseNpgsql(ConnectionString(TemplateDb)).Options;
        await using (var db = new EasyPatchDbContext(options))
        {
            await DatabaseSeeder.MigrateAsync(db, TimeProvider.System);
        }

        NpgsqlConnection.ClearAllPools();
    }

    public async ValueTask DisposeAsync() => await container.DisposeAsync();

    /// <summary>Creates an isolated, migrated database for one test.</summary>
    public async Task<string> CreateDatabaseAsync()
    {
        var name = "t_" + Guid.NewGuid().ToString("N");
        await createLock.WaitAsync();
        try
        {
            await ExecuteAsync($"CREATE DATABASE {name} TEMPLATE {TemplateDb}");
        }
        finally
        {
            createLock.Release();
        }

        return ConnectionString(name);
    }

    private string ConnectionString(string database) =>
        new NpgsqlConnectionStringBuilder(container.GetConnectionString()) { Database = database, Pooling = true, MaxPoolSize = 20 }.ConnectionString;

    private async Task ExecuteAsync(string sql)
    {
        await using var conn = new NpgsqlConnection(ConnectionString("postgres"));
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }
}

public sealed class EasyPatchApiFactory(string connectionString, TimeProvider clock, IReadOnlyDictionary<string, string?>? settings = null,
    Action<IServiceCollection>? configureServices = null)
    : WebApplicationFactory<Program>
{
    public string ConnectionString { get; } = connectionString;
    public string KeysPath { get; } = Directory.CreateTempSubdirectory("easypatch-keys-").FullName;
    public string PackagesPath { get; } = Directory.CreateTempSubdirectory("easypatch-packages-").FullName;
    public string WingetCachePath { get; } = Directory.CreateTempSubdirectory("easypatch-winget-").FullName;
    public const string PublicUrl = "https://easypatch.test";

    /// <summary>Records email and webhook sends instead of performing them.</summary>
    public CapturingTransport Transport { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:EasyPatch", ConnectionString);
        builder.UseSetting("EasyPatch:DataProtectionKeysPath", KeysPath);
        builder.UseSetting("EasyPatch:AgentPackagesPath", PackagesPath);
        builder.UseSetting("EasyPatch:WingetCachePath", WingetCachePath);
        builder.UseSetting("EasyPatch:PublicUrl", PublicUrl);
        builder.UseSetting("Logging:Format", "text");
        builder.UseSetting("Logging:LogLevel:Default", "Warning");
        builder.UseSetting("Logging:LogLevel:Microsoft.EntityFrameworkCore", "Warning");
        builder.UseSetting("RateLimits:LoginPerMinute", "1000");
        builder.UseSetting("RateLimits:EnrollPerMinute", "1000");
        builder.UseSetting("RateLimits:AgentPerMinute", "10000");
        builder.UseSetting("RateLimits:AdminPerMinute", "10000");
        foreach (var (key, value) in settings ?? new Dictionary<string, string?>())
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton(clock);
            // Maintenance tasks are executed explicitly by tests (no hosted loops in the API).
            services.AddScoped<JobMaintenanceTask>();
            services.AddScoped<PresenceMonitorTask>();
            services.AddScoped<ScheduledInstallTask>();
            services.AddScoped<DeferralExpiryTask>();
            services.AddScoped<ScheduledRestartTask>();
            services.AddScoped<AgentUpdateTask>();
            services.AddScoped<ComplianceSnapshotTask>();
            services.AddScoped<RetentionTask>();
            services.AddScoped<AlertEvaluationTask>();
            services.AddScoped<NotificationDeliveryTask>();
            services.AddScoped<VulnerabilityFeedTask>();
            services.AddScoped<MonthlyReportTask>();
            services.AddScoped<WingetMirrorTask>();
            services.AddScoped<RolloutGuardTask>();
            services.AddScoped<PreDownloadTask>();
            services.AddSingleton<INotificationTransport>(Transport);
            configureServices?.Invoke(services);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        TryDelete(KeysPath);
        TryDelete(PackagesPath);
        TryDelete(WingetCachePath);
    }

    private static void TryDelete(string path)
    {
        try
        {
            Directory.Delete(path, true);
        }
        catch (IOException)
        {
        }
    }
}

public static class TestJson
{
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }
}

/// <summary>Cookie jar + CSRF header, like the browser SPA.</summary>
public sealed class BrowserHandler : DelegatingHandler
{
    public CookieContainer Cookies { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var header = Cookies.GetCookieHeader(uri);
        if (header.Length > 0)
        {
            request.Headers.Add("Cookie", header);
        }

        if (request.Method != HttpMethod.Get && request.Method != HttpMethod.Head && SkipCsrf is false &&
            Cookies.GetCookies(uri)["XSRF-TOKEN"] is { } xsrf)
        {
            request.Headers.Add("X-XSRF-TOKEN", xsrf.Value);
        }

        var response = await base.SendAsync(request, cancellationToken);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            foreach (var value in values)
            {
                Cookies.SetCookies(uri, value);
            }
        }

        return response;
    }

    public bool SkipCsrf { get; set; }
}

/// <summary>An administrator browser session.</summary>
public sealed class AdminSession(HttpClient http, BrowserHandler browser, string username, string password)
{
    public HttpClient Http { get; } = http;
    public BrowserHandler Browser { get; } = browser;
    public string Username { get; } = username;
    public string Password { get; } = password;
    public byte[]? MfaSecret { get; set; }

    public async Task<T> GetAsync<T>(string url)
    {
        using var response = await Http.GetAsync(new Uri(url, UriKind.Relative));
        await EnsureAsync(response, HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<T>(TestJson.Options))!;
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, object? body = null)
    {
        using var request = new HttpRequestMessage(method, new Uri(url, UriKind.Relative));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType(), options: TestJson.Options);
        }

        return await Http.SendAsync(request);
    }

    public async Task<T> SendAsync<T>(HttpMethod method, string url, object? body, HttpStatusCode expected)
    {
        using var response = await SendAsync(method, url, body);
        await EnsureAsync(response, expected);
        return (await response.Content.ReadFromJsonAsync<T>(TestJson.Options))!;
    }

    public async Task ExpectAsync(HttpMethod method, string url, object? body, HttpStatusCode expected, string? code = null)
    {
        using var response = await SendAsync(method, url, body);
        await EnsureAsync(response, expected);
        if (code is not null)
        {
            Assert.Equal(code, await ProblemCodeAsync(response));
        }
    }

    public static async Task EnsureAsync(HttpResponseMessage response, HttpStatusCode expected)
    {
        if (response.StatusCode != expected)
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.Fail($"{response.RequestMessage?.Method} {response.RequestMessage?.RequestUri}: expected {(int)expected}, got {(int)response.StatusCode}: {body}");
        }
    }

    public static async Task<string?> ProblemCodeAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.TryGetProperty("code", out var c) ? c.GetString() : null;
    }
}

/// <summary>Signs agent requests exactly like the Windows agent.</summary>
public sealed class SignedAgent(HttpClient http, TimeProvider clock) : IDisposable
{
    public ECDsa Key { get; } = AgentKeys.Generate();
    public string CredentialId { get; set; } = string.Empty;
    public Guid EndpointId { get; set; }
    public string PublicKeyBase64 => Convert.ToBase64String(AgentKeys.ExportPublicKey(Key));
    public string? LastNonce { get; private set; }

    public static DeviceIdentity Device(string hostname) => new()
    {
        Hostname = hostname,
        SmbiosUuid = Guid.NewGuid().ToString().ToUpperInvariant(),
        SerialNumber = "SN-" + hostname,
        OsCaption = "Microsoft Windows 11 Pro",
        OsBuild = "26100.2314",
        Manufacturer = "Contoso",
        Model = "Desktop 9000",
    };

    public Task<HttpResponseMessage> EnrollAsync(string? token, string? deploymentCode, string hostname) =>
        http.PostAsJsonAsync(new Uri("/" + AgentRoutes.Enroll, UriKind.Relative), new EnrollRequest
        {
            EnrollmentToken = token,
            DeploymentCode = deploymentCode,
            PublicKey = PublicKeyBase64,
            AgentVersion = "1.0.0",
            Device = Device(hostname),
        }, TestJson.Options);

    public async Task<HttpResponseMessage> PostAsync(string path, object body, string? nonce = null, DateTimeOffset? at = null, Action<HttpRequestMessage>? tamper = null)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(body, body.GetType(), TestJson.Options);
        var route = path.StartsWith('/') ? path : "/" + path;
        var headers = RequestSigner.Sign(Key, CredentialId, "POST", route, bytes, at ?? clock.GetUtcNow());
        if (nonce is not null)
        {
            // Re-sign with the chosen nonce (replay tests).
            var canonical = RequestSigner.BuildCanonicalString("POST", route, headers.Timestamp, nonce, headers.ContentSha256, CredentialId);
            var sig = Key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            headers = headers with { Nonce = nonce, Signature = Convert.ToBase64String(sig) };
        }

        LastNonce = headers.Nonce;
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(route, UriKind.Relative)) { Content = new ByteArrayContent(bytes) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add(AgentAuthHeaders.Credential, headers.CredentialId);
        request.Headers.Add(AgentAuthHeaders.Timestamp, headers.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.Add(AgentAuthHeaders.Nonce, headers.Nonce);
        request.Headers.Add(AgentAuthHeaders.ContentSha256, headers.ContentSha256);
        request.Headers.Add(AgentAuthHeaders.Signature, headers.Signature);
        tamper?.Invoke(request);
        return await http.SendAsync(request);
    }

    public Task<CheckInResponse> CheckInAsync(IReadOnlyList<Guid>? activeJobs = null, bool rebootPending = false) =>
        CheckInAsync(new CheckInRequest
        {
            AgentVersion = "1.0.0",
            RebootPending = rebootPending,
            ActiveJobIds = activeJobs ?? [],
        });

    public async Task<CheckInResponse> CheckInAsync(CheckInRequest request)
    {
        using var response = await PostAsync(AgentRoutes.CheckIn, request);
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<CheckInResponse>(TestJson.Options))!;
    }

    public void Dispose() => Key.Dispose();
}

/// <summary>Base class: a fresh database and API host per test, plus helpers for admins and agents.</summary>
public abstract class IntegrationTest(PostgresFixture postgres) : IAsyncLifetime
{
    protected const string DefaultPassword = "Correct-Horse-Battery-9";
    private readonly List<IDisposable> disposables = [];

    protected ManualTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
    protected EasyPatchApiFactory Factory { get; private set; } = null!;

    /// <summary>Extra configuration for the API host (override per test class).</summary>
    protected virtual IReadOnlyDictionary<string, string?>? Settings => null;

    /// <summary>Replaces services of the API host (override per test class).</summary>
    protected virtual void ConfigureServices(IServiceCollection services)
    {
    }

    public virtual async ValueTask InitializeAsync()
    {
        var connectionString = await postgres.CreateDatabaseAsync();
        Factory = new EasyPatchApiFactory(connectionString, Clock, Settings, ConfigureServices);
        _ = Factory.Server; // start the host
    }

    public virtual async ValueTask DisposeAsync()
    {
        foreach (var d in disposables)
        {
            d.Dispose();
        }

        await Factory.DisposeAsync();

        // Close this test's pooled connections now. Each test has its own database (and so its own pool), and idle
        // connections would otherwise stay open until Npgsql prunes them, running the shared container out of connections.
        await using (var connection = new NpgsqlConnection(Factory.ConnectionString))
        {
            NpgsqlConnection.ClearPool(connection);
        }

        GC.SuppressFinalize(this);
    }

    protected HttpClient NewHttpClient(params DelegatingHandler[] handlers)
    {
        var client = Factory.CreateDefaultClient(new Uri(EasyPatchApiFactory.PublicUrl + "/"), handlers);
        disposables.Add(client);
        return client;
    }

    protected SignedAgent NewAgent()
    {
        var agent = new SignedAgent(NewHttpClient(), Clock);
        disposables.Add(agent);
        return agent;
    }

    protected async Task<T> WithScopeAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        await using var scope = Factory.Services.CreateAsyncScope();
        return await action(scope.ServiceProvider);
    }

    protected Task WithDbAsync(Func<EasyPatchDbContext, Task> action) =>
        WithScopeAsync<int>(async sp =>
        {
            await action(sp.GetRequiredService<EasyPatchDbContext>());
            return 0;
        });

    protected Task<T> WithDbAsync<T>(Func<EasyPatchDbContext, Task<T>> action) =>
        WithScopeAsync(sp => action(sp.GetRequiredService<EasyPatchDbContext>()));

    protected Task RunMaintenanceAsync<TTask>() where TTask : IMaintenanceTask =>
        WithScopeAsync<int>(async sp =>
        {
            await sp.GetRequiredService<TTask>().RunOnceAsync(CancellationToken.None);
            return 0;
        });

    protected Task FlushPresenceAsync() => Factory.Services.GetRequiredService<PresenceTracker>().FlushAsync();

    /// <summary>Creates a user directly (as the CLI would) and signs in through the API, completing MFA enrollment.</summary>
    protected async Task<AdminSession> CreateAndLoginAsync(string username, UserRole role, params Guid[] organizations)
    {
        await WithScopeAsync(async sp =>
        {
            var auth = sp.GetRequiredService<AuthService>();
            var user = await auth.CreateUserAsync(username, EmailOf(username), role, DefaultPassword);
            if (organizations.Length > 0)
            {
                await auth.SetOrganizationAccessAsync(user.Id, organizations);
            }

            return user;
        });
        return await LoginAsync(username, DefaultPassword);
    }

    protected Task<AdminSession> SuperAdminAsync() => CreateAndLoginAsync("root", UserRole.SuperAdmin);

    /// <summary>The email address <see cref="CreateAndLoginAsync"/> gives a test user (users sign in with it).</summary>
    protected static string EmailOf(string username) => username + "@example.test";

    /// <summary>Signs in with the email address of <paramref name="username"/> (see <see cref="EmailOf"/>).</summary>
    protected async Task<AdminSession> LoginAsync(string username, string password, byte[]? mfaSecret = null)
    {
        var browser = new BrowserHandler();
        var session = new AdminSession(NewHttpClient(browser), browser, username, password) { MfaSecret = mfaSecret };
        var login = await session.SendAsync<LoginResponse>(HttpMethod.Post, "/api/v1/auth/login", new LoginRequest(EmailOf(username), password),
            HttpStatusCode.OK);
        if (login.MfaSetupRequired)
        {
            var setup = await session.SendAsync<MfaSetupResponse>(HttpMethod.Post, "/api/v1/auth/mfa/setup", null, HttpStatusCode.OK);
            session.MfaSecret = Totp.Base32Decode(setup.Secret);
            await session.SendAsync<RecoveryCodesResponse>(HttpMethod.Post, "/api/v1/auth/mfa/enable",
                new MfaCodeRequest(Totp.Compute(session.MfaSecret, Totp.CurrentStep(Clock.GetUtcNow()))), HttpStatusCode.OK);
        }
        else if (login.MfaRequired)
        {
            Assert.NotNull(session.MfaSecret);
            Clock.Advance(TimeSpan.FromSeconds(31)); // a fresh TOTP step (codes cannot be replayed)
            await session.ExpectAsync(HttpMethod.Post, "/api/v1/auth/mfa/verify",
                new MfaCodeRequest(Totp.Compute(session.MfaSecret!, Totp.CurrentStep(Clock.GetUtcNow()))), HttpStatusCode.NoContent);
        }

        return session;
    }

    protected static async Task<(OrganizationDto Org, SiteDto Site)> CreateOrgAsync(AdminSession admin, string name = "Contoso")
    {
        var org = await admin.SendAsync<OrganizationDto>(HttpMethod.Post, "/api/v1/organizations",
            new OrganizationRequest(name, null, null, null, null, "UTC"), HttpStatusCode.Created);
        var site = await admin.SendAsync<SiteDto>(HttpMethod.Post, $"/api/v1/organizations/{org.Id}/sites",
            new SiteRequest("HQ", null, null, null), HttpStatusCode.Created);
        return (org, site);
    }

    protected static async Task<string> CreateTokenAsync(AdminSession admin, Guid orgId, Guid? siteId = null, int maxUses = 10, int hours = 24)
    {
        var tokens = await admin.SendAsync<List<CreatedTokenDto>>(HttpMethod.Post, "/api/v1/enrollment-tokens",
            new CreateTokensRequest(orgId, siteId, "test", hours, maxUses, 1), HttpStatusCode.OK);
        return tokens.Single().PlaintextToken;
    }

    /// <summary>Enrolls a signed test agent with a fresh token.</summary>
    protected async Task<SignedAgent> EnrollAgentAsync(AdminSession admin, Guid orgId, Guid? siteId, string hostname)
    {
        var token = await CreateTokenAsync(admin, orgId, siteId);
        var agent = NewAgent();
        using var response = await agent.EnrollAsync(token, null, hostname);
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        var enrolled = (await response.Content.ReadFromJsonAsync<EnrollResponse>(TestJson.Options))!;
        Assert.Equal(EnrollmentState.Active, enrolled.State);
        agent.CredentialId = enrolled.CredentialId;
        agent.EndpointId = enrolled.EndpointId!.Value;
        return agent;
    }
}

/// <summary>Fake notification transport: records what would have been sent; can be told to fail.</summary>
public sealed class CapturingTransport : INotificationTransport
{
    public sealed record Email(IReadOnlyList<string> Recipients, string Subject, string Text, string Html, string? Password, NotificationSettingsRow Smtp,
        IReadOnlyList<EmailAttachment> Attachments);

    public sealed record Webhook(Uri Url, string Body, IReadOnlyDictionary<string, string> Headers, bool AllowPrivate);

    public System.Collections.Concurrent.ConcurrentQueue<Email> Emails { get; } = new();
    public System.Collections.Concurrent.ConcurrentQueue<Webhook> Webhooks { get; } = new();
    public string? FailWith { get; set; }

    public Task SendEmailAsync(NotificationSettingsRow smtp, string? password, IReadOnlyList<string> recipients, string subject, string text, string html,
        IReadOnlyList<EmailAttachment>? attachments, CancellationToken ct)
    {
        if (FailWith is not null)
        {
            throw new NotificationException(FailWith);
        }

        Emails.Enqueue(new Email(recipients, subject, text, html, password, smtp, attachments ?? []));
        return Task.CompletedTask;
    }

    public Task PostWebhookAsync(Uri url, string body, IReadOnlyDictionary<string, string> headers, bool allowPrivateNetworks, CancellationToken ct)
    {
        if (FailWith is not null)
        {
            throw new NotificationException(FailWith);
        }

        Webhooks.Enqueue(new Webhook(url, body, headers, allowPrivateNetworks));
        return Task.CompletedTask;
    }
}
