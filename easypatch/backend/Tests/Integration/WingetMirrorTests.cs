using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// The server's copy of winget for agents that cannot download it from GitHub: only the pinned files are served, and only
/// after their size and SHA-256 match; the worker downloads them when an agent first asks.
/// </summary>
public sealed class WingetMirrorTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private const string ReleaseUrl = "https://github.example/winget/v1.29.380/";

    private static readonly Dictionary<string, byte[]> Released = new(StringComparer.Ordinal)
    {
        ["App.msixbundle"] = Encoding.UTF8.GetBytes("the App Installer bundle"),
        ["Deps.zip"] = Encoding.UTF8.GetBytes("the dependency archive"),
        ["License.xml"] = Encoding.UTF8.GetBytes("<License/>"),
    };

    private readonly GitHubStub github = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    protected override void ConfigureServices(IServiceCollection services)
    {
        var files = new WingetMirrorFiles(Released.Select(f => new WingetFile(f.Key, f.Value.Length, Sha256(f.Value))).ToList(), ReleaseUrl);
        services.AddSingleton(files);
        services.AddSingleton(sp => new WingetMirrorService(sp.GetRequiredService<IOptions<EasyPatchOptions>>(), files, github,
            NullLogger<WingetMirrorService>.Instance));
    }

    [Fact]
    public async Task Missing_files_are_requested_downloaded_by_the_worker_verified_and_then_served()
    {
        var http = NewHttpClient();

        // Nothing has been requested: the worker leaves GitHub alone.
        await RunMaintenanceAsync<WingetMirrorTask>();
        Assert.Empty(github.Requests);

        // Only the pinned names exist.
        foreach (var name in new[] { "winget.exe", "app.msixbundle", "..%2FLicense.xml", "License.xml.part" })
        {
            using var unknown = await http.GetAsync("/downloads/winget/" + name, Ct);
            Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        }

        Assert.Null(await StateAsync());

        // An agent asks for a file the server does not have: 503 with Retry-After, and the request is recorded.
        using (var missing = await http.GetAsync("/downloads/winget/App.msixbundle", Ct))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, missing.StatusCode);
            Assert.Equal(TimeSpan.FromSeconds(900), missing.Headers.RetryAfter?.Delta);
            Assert.Contains("winget_not_ready", await missing.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }

        Assert.NotNull((await StateAsync())!.RequestedAt);

        // GitHub sends a different dependency archive: the bundle and license are kept, the archive is not.
        github.Files["App.msixbundle"] = Released["App.msixbundle"];
        github.Files["Deps.zip"] = Encoding.UTF8.GetBytes("the dependency archive, changed");
        github.Files["License.xml"] = Released["License.xml"];
        await RunMaintenanceAsync<WingetMirrorTask>();
        var failed = (await StateAsync())!;
        Assert.Equal(1, failed.Failures);
        Assert.Contains("Deps.zip", failed.LastError, StringComparison.Ordinal);
        Assert.Equal([ReleaseUrl + "App.msixbundle", ReleaseUrl + "Deps.zip"], github.Requests);
        Assert.Equal(Released["App.msixbundle"], await http.GetByteArrayAsync("/downloads/winget/App.msixbundle", Ct));
        using (var deps = await http.GetAsync("/downloads/winget/Deps.zip", Ct))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, deps.StatusCode);
        }

        Assert.Equal(["App.msixbundle"], Directory.GetFiles(Factory.WingetCachePath).Select(Path.GetFileName));

        // The next attempt waits 15 minutes.
        github.Files["Deps.zip"] = Released["Deps.zip"];
        await RunMaintenanceAsync<WingetMirrorTask>();
        Assert.Equal(2, github.Requests.Count);

        Clock.Advance(TimeSpan.FromMinutes(16));
        await RunMaintenanceAsync<WingetMirrorTask>();
        var ready = (await StateAsync())!;
        Assert.Equal((0, (string?)null), (ready.Failures, ready.LastError));
        Assert.NotNull(ready.LastSuccessAt);
        Assert.Equal([ReleaseUrl + "App.msixbundle", ReleaseUrl + "Deps.zip", ReleaseUrl + "Deps.zip", ReleaseUrl + "License.xml"], github.Requests);

        foreach (var (name, bytes) in Released)
        {
            Assert.Equal(bytes, await http.GetByteArrayAsync("/downloads/winget/" + name, Ct));
        }

        // Range requests let an agent resume a large download.
        using var range = new HttpRequestMessage(HttpMethod.Get, "/downloads/winget/App.msixbundle");
        range.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(4, null);
        using var partial = await http.SendAsync(range, Ct);
        Assert.Equal(HttpStatusCode.PartialContent, partial.StatusCode);
        Assert.Equal(Released["App.msixbundle"][4..], await partial.Content.ReadAsByteArrayAsync(Ct));

        // Complete: nothing more is downloaded.
        await RunMaintenanceAsync<WingetMirrorTask>();
        Assert.Equal(4, github.Requests.Count);
    }

    [Fact]
    public async Task Files_an_administrator_places_with_the_agent_packages_are_served_only_when_they_match()
    {
        var directory = Directory.CreateDirectory(Path.Combine(Factory.PackagesPath, "winget")).FullName;
        await File.WriteAllBytesAsync(Path.Combine(directory, "License.xml"), Released["License.xml"], Ct);
        await File.WriteAllBytesAsync(Path.Combine(directory, "Deps.zip"), Encoding.UTF8.GetBytes("the dependency archivE"), Ct); // same size, other SHA-256

        var http = NewHttpClient();
        Assert.Equal(Released["License.xml"], await http.GetByteArrayAsync("/downloads/winget/License.xml", Ct));
        using var wrong = await http.GetAsync("/downloads/winget/Deps.zip", Ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, wrong.StatusCode);
    }

    [Fact]
    public async Task The_endpoint_page_shows_why_winget_could_not_be_installed()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-WINGET");
        var url = $"/api/v1/endpoints/{agent.EndpointId}";

        // A failed server copy is shown together with the agent's error.
        await WithDbAsync(async db =>
        {
            db.MirrorStates.Add(new MirrorState { Name = Mirrors.Winget, RequestedAt = Clock.GetUtcNow(), LastError = "GitHub failed with HTTP 403.", Failures = 1 });
            await db.SaveChangesAsync();
        });
        await agent.CheckInAsync(new CheckInRequest
        {
            AgentVersion = "1.7.0",
            ActiveJobIds = [],
            Winget = new WingetStatusReport { SetupError = "Could not download winget from GitHub or the EasyPatch server.", CheckedAt = Clock.GetUtcNow() },
        });
        var failed = (await root.GetAsync<EndpointDetailDto>(url)).Applications!;
        Assert.Equal(("Could not download winget from GitHub or the EasyPatch server.", "GitHub failed with HTTP 403.", (string?)null),
            (failed.WingetSetupError, failed.ServerCopyError, failed.WingetVersion));

        // Older agents send no winget status: what was reported stays.
        await agent.CheckInAsync(new CheckInRequest { AgentVersion = "1.6.1", ActiveJobIds = [] });
        Assert.NotNull((await root.GetAsync<EndpointDetailDto>(url)).Applications!.WingetSetupError);

        await agent.CheckInAsync(new CheckInRequest
        {
            AgentVersion = "1.7.0",
            ActiveJobIds = [],
            Winget = new WingetStatusReport { Version = "1.29.380", InstalledByAgent = true, CheckedAt = Clock.GetUtcNow() },
        });
        var ready = (await root.GetAsync<EndpointDetailDto>(url)).Applications!;
        Assert.Equal(("1.29.380", (string?)null, (string?)null), (ready.WingetVersion, ready.WingetSetupError, ready.ServerCopyError));
    }

    private Task<MirrorState?> StateAsync() =>
        WithDbAsync(db => db.MirrorStates.AsNoTracking().FirstOrDefaultAsync(m => m.Name == Mirrors.Winget));

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    /// <summary>The GitHub release, served from memory; a missing file is a 404.</summary>
    private sealed class GitHubStub : HttpMessageHandler, IHttpClientFactory
    {
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public List<string> Requests { get; } = [];

        public HttpClient CreateClient(string name) => new(this, disposeHandler: false);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            lock (Requests)
            {
                Requests.Add(url);
            }

            var name = url.StartsWith(ReleaseUrl, StringComparison.Ordinal) ? url[ReleaseUrl.Length..] : string.Empty;
            return Task.FromResult(Files.TryGetValue(name, out var bytes)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes), RequestMessage = request }
                : new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request });
        }
    }
}
