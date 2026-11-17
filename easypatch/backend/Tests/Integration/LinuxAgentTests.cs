using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Linux agents: enrollment, inventory, package scans, install scripts and package-format-aware agent updates.</summary>
public sealed class LinuxAgentTests(PostgresFixture postgres) : AgentUpdateTestBase(postgres)
{
    private static readonly DeviceIdentity Debian = new()
    {
        Hostname = "web-01",
        SmbiosUuid = Guid.NewGuid().ToString().ToUpperInvariant(),
        OsCaption = "Debian GNU/Linux 12 (bookworm)",
        OsBuild = "6.1.0-37-amd64",
        Architecture = "X64",
        Platform = AgentPlatforms.Linux,
        OsId = "debian",
        OsVersion = "12",
    };

    private async Task<SignedAgent> EnrollLinuxAsync()
    {
        var token = await CreateTokenAsync(Root, Org.Id, Site.Id);
        var agent = NewAgent();
        using var response = await NewHttpClient().PostAsJsonAsync(new Uri("/" + AgentRoutes.Enroll, UriKind.Relative), new EnrollRequest
        {
            EnrollmentToken = token,
            PublicKey = agent.PublicKeyBase64,
            AgentVersion = "1.3.0",
            Device = Debian,
        }, TestJson.Options, TestContext.Current.CancellationToken);
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        var enrolled = (await response.Content.ReadFromJsonAsync<EnrollResponse>(TestJson.Options, TestContext.Current.CancellationToken))!;
        agent.CredentialId = enrolled.CredentialId;
        agent.EndpointId = enrolled.EndpointId!.Value;
        return agent;
    }

    private static ReportedUpdate Package(string name, string version, string installed, bool security, string? severity = null) => new()
    {
        UpdateGuid = Guid.NewGuid(),
        RevisionNumber = 1,
        Title = $"{name} {version}",
        Categories =
        [
            new UpdateCategoryRef { Id = Guid.NewGuid(), Name = security ? "Security Updates" : "Updates", Type = "UpdateClassification" },
            new UpdateCategoryRef { Id = Guid.NewGuid(), Name = "Debian 12", Type = "Product" },
        ],
        MsrcSeverity = severity,
        RebootBehavior = name.StartsWith("linux-image", StringComparison.Ordinal) ? 1 : 0,
        Package = new PackageUpdateInfo
        {
            Name = name,
            Architecture = "amd64",
            Version = version,
            InstalledVersion = installed,
            Repository = security ? "Debian-Security:12/stable-security" : "Debian:12.11/stable",
            Security = security,
            Advisories = security ? ["DSA-5900-1"] : [],
        },
    };

    private async Task ScanAsync(SignedAgent agent, IReadOnlyList<ReportedUpdate> missing, IReadOnlyList<ReportedUpdate>? installed = null)
    {
        var now = Clock.GetUtcNow();
        using var response = await agent.PostAsync(AgentRoutes.ScanResults, new ScanResultReport
        {
            ScanId = Guid.NewGuid(),
            Trigger = ScanTrigger.Scheduled,
            StartedAt = now.AddMinutes(-1),
            CompletedAt = now,
            Succeeded = true,
            Source = new UpdateSourceInfo { Type = UpdateSourceType.PackageRepositories, AutomaticUpdatesMode = "Disabled (unattended-upgrades)" },
            Missing = missing,
            Installed = installed ?? [],
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task Messages_to_users_are_refused_for_linux_endpoints_with_a_clear_reason()
    {
        var agent = await EnrollLinuxAsync();
        await Root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/notify", new NotifyRequest(UserMessagePreset.SaveYourWork, null),
            HttpStatusCode.Conflict, "not_supported_on_linux");
    }

    [Fact]
    public async Task A_linux_endpoint_reports_its_distribution_kernel_and_key_protection()
    {
        var agent = await EnrollLinuxAsync();
        using var inventory = await agent.PostAsync(AgentRoutes.Inventory, new InventoryReport
        {
            Hostname = "web-01",
            OsCaption = "Debian GNU/Linux 12 (bookworm)",
            OsDisplayVersion = "12",
            Architecture = "X64",
            AgentVersion = "1.3.0",
            Platform = AgentPlatforms.Linux,
            OsId = "debian",
            OsVersion = "12",
            KernelVersion = "6.1.0-37-amd64",
            PackageManager = "apt",
            KeyProtection = "systemd-creds-host",
            UpdateSource = new UpdateSourceInfo { Type = UpdateSourceType.PackageRepositories, AutomaticUpdatesMode = "Disabled (unattended-upgrades)" },
        });
        await AdminSession.EnsureAsync(inventory, HttpStatusCode.NoContent);

        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");

        Assert.Equal(AgentPlatforms.Linux, detail.Summary.Platform);
        Assert.Equal("12", detail.Summary.OsVersion);
        Assert.Equal("6.1.0-37-amd64", detail.Summary.OsBuild);
        Assert.Equal(new LinuxDetailsDto("debian", "12", "6.1.0-37-amd64", "apt", "systemd-creds-host"), detail.Linux);
        Assert.Equal(OsSupportStatus.Supported, detail.Summary.OsSupportStatus);
        Assert.Equal(new DateOnly(2028, 6, 30), detail.OsEndOfServicing);
    }

    [Fact]
    public async Task Package_updates_are_classified_and_shown_with_their_versions()
    {
        var agent = await EnrollLinuxAsync();
        var openssl = Package("libssl3", "3.0.17-1~deb12u2", "3.0.15-1~deb12u1", security: true);
        var tzdata = Package("tzdata", "2025b-0+deb12u1", "2024a-0+deb12u1", security: false);

        await ScanAsync(agent, [openssl, tzdata]);

        var updates = await Root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agent.EndpointId}/updates");
        var ssl = updates.Single(u => u.UpdateGuid == openssl.UpdateGuid);
        Assert.Equal(UpdateCategory.Security, ssl.Category);
        Assert.Equal("libssl3", ssl.Package!.Name);
        Assert.Equal("3.0.15-1~deb12u1", ssl.Package.InstalledVersion);
        Assert.Equal("3.0.17-1~deb12u2", ssl.Package.Version);
        Assert.Equal(["DSA-5900-1"], ssl.Package.Advisories);
        Assert.Equal(UpdateCategory.Other, updates.Single(u => u.UpdateGuid == tzdata.UpdateGuid).Category);
        Assert.True(ssl.IsRequired); // security updates are required by the default policy

        // The agent reports the upgrade as installed once the package database shows the new version.
        await ScanAsync(agent, [tzdata], [openssl with { IsInstalled = true }]);
        updates = await Root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agent.EndpointId}/updates");
        Assert.DoesNotContain(updates, u => u.UpdateGuid == openssl.UpdateGuid);
        var fleet = await Root.GetAsync<PagedResult<FleetUpdateDto>>("/api/v1/updates?search=libssl3&state=Installed");
        Assert.Equal(1, Assert.Single(fleet.Items).InstalledCount);
    }

    [Fact]
    public async Task Agents_are_only_offered_updates_in_their_own_package_format()
    {
        Publish("1.3.1"); // MSI
        var deb = PublishPackage("1.3.1", "deb");
        var linux = await EnrollLinuxAsync();
        var windows = await UpdatableAgentAsync("PC-WIN");

        var linuxCheckIn = UpdatableCheckIn("1.3.0") with { AgentPackageFormat = "deb" };
        await linux.CheckInAsync(linuxCheckIn);
        await windows.CheckInAsync(UpdatableCheckIn("1.3.0"));

        var linuxDetail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{linux.EndpointId}");
        Assert.Equal("deb", linuxDetail.AgentUpdate!.PackageFormat);
        Assert.Equal("1.3.1", linuxDetail.AgentUpdate.AvailableVersion);

        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{linux.EndpointId}/agent-update", Newest, HttpStatusCode.Accepted);
        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{windows.EndpointId}/agent-update", Newest, HttpStatusCode.Accepted);

        var linuxJob = Assert.Single((await linux.CheckInAsync(linuxCheckIn)).Jobs);
        Assert.Equal(Path.GetFileName(deb), linuxJob.AgentUpdate!.Package.FileName);
        var windowsJob = Assert.Single((await windows.CheckInAsync(UpdatableCheckIn("1.3.0"))).Jobs);
        Assert.Equal("EasyPatchAgent-1.3.1-x64.msi", windowsJob.AgentUpdate!.Package.FileName);

        var packages = await Root.GetAsync<List<AgentPackageDto>>("/api/v1/agent-packages");
        Assert.Equal("deb", packages.Single(p => p.FileName == Path.GetFileName(deb)).Format);
    }

    [Fact]
    public async Task The_linux_install_script_is_served_for_a_deployment_code()
    {
        var code = await Root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(Org.Id, Site.Id, "Linux rollout", 30, null, null), HttpStatusCode.Created);
        Assert.EndsWith($"/downloads/install/{code.Code}.sh", code.LinuxScriptUrl, StringComparison.Ordinal);
        Assert.Contains("| sudo sh", code.LinuxOneLiner, StringComparison.Ordinal);

        using var client = NewHttpClient();
        using var none = await client.GetAsync($"/downloads/install/{code.Code}.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, none.StatusCode);

        PublishPackage("1.3.0", "deb");
        PublishPackage("1.3.0", "rpm");
        using var response = await client.GetAsync($"/downloads/install/{code.Code}.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var script = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("#!/bin/sh", script, StringComparison.Ordinal);
        Assert.Contains($"DEPLOYMENT_CODE='{code.Code}'", script, StringComparison.Ordinal);
        Assert.Contains("EasyPatchAgent-1.3.0-x64.deb", script, StringComparison.Ordinal);
        Assert.Contains("EasyPatchAgent-1.3.0-x64.rpm", script, StringComparison.Ordinal);

        using var unknown = await client.GetAsync("/downloads/install/EPD-ZZZZZZZZZZZZZZZZ.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    /// <summary>A signed deb or rpm agent package in the server's package folder.</summary>
    private string PublishPackage(string version, string format, string architecture = "x64")
    {
        var path = Path.Combine(Factory.PackagesPath, $"EasyPatchAgent-{version}-{architecture}.{format}");
        File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(2048));
        var manifest = AgentRelease.Describe(path);
        var signature = new AgentReleaseSignature { KeyId = KeyId, Manifest = manifest, Signature = AgentRelease.Sign(manifest, ReleaseKey) };
        File.WriteAllText(path + AgentRelease.SignatureExtension, JsonSerializer.Serialize(signature, ContractJson.Options));
        Clock.Advance(TimeSpan.FromSeconds(61));
        return path;
    }
}
