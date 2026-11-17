using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>The experimental macOS agent: enrollment, inventory, pkg agent updates, Windows-only jobs and the install script.</summary>
public sealed class MacAgentTests(PostgresFixture postgres) : AgentUpdateTestBase(postgres)
{
    private static readonly DeviceIdentity Mac = new()
    {
        Hostname = "mbp-01",
        SmbiosUuid = Guid.NewGuid().ToString().ToUpperInvariant(),
        SerialNumber = "C02XL0GHJGH5",
        Manufacturer = "Apple Inc.",
        Model = "Mac15,3",
        OsCaption = "macOS Sequoia 15.7.2",
        OsBuild = "24G325",
        Architecture = "Arm64",
        Platform = AgentPlatforms.MacOS,
        OsId = "macos",
        OsVersion = "15.7.2",
    };

    private async Task<SignedAgent> EnrollMacAsync()
    {
        var token = await CreateTokenAsync(Root, Org.Id, Site.Id);
        var agent = NewAgent();
        using var response = await NewHttpClient().PostAsJsonAsync(new Uri("/" + AgentRoutes.Enroll, UriKind.Relative), new EnrollRequest
        {
            EnrollmentToken = token,
            PublicKey = agent.PublicKeyBase64,
            AgentVersion = "1.9.0",
            Device = Mac,
        }, TestJson.Options, TestContext.Current.CancellationToken);
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        var enrolled = (await response.Content.ReadFromJsonAsync<EnrollResponse>(TestJson.Options, TestContext.Current.CancellationToken))!;
        agent.CredentialId = enrolled.CredentialId;
        agent.EndpointId = enrolled.EndpointId!.Value;
        return agent;
    }

    private static InventoryReport Inventory(string build) => new()
    {
        Hostname = "mbp-01",
        OsCaption = "macOS Sequoia 15.7.2",
        Architecture = "Arm64",
        AgentVersion = "1.9.0",
        Platform = AgentPlatforms.MacOS,
        OsId = "macos",
        OsVersion = "15.7.2",
        OsBuildVersion = build,
        KernelVersion = "24.6.0",
        PackageManager = "softwareupdate",
        KeyProtection = "file-permissions",
        UpdateSource = new UpdateSourceInfo { Type = UpdateSourceType.AppleSoftwareUpdate },
    };

    /// <summary>The check-in of a macOS agent that can update itself from pkg packages.</summary>
    private static CheckInRequest MacCheckIn(string? format = AgentRelease.FormatPkg) =>
        UpdatableCheckIn("1.9.0", architecture: "arm64") with
        {
            Capabilities = [AgentCapabilities.Restart, AgentCapabilities.SelfUpdate, AgentCapabilities.Uninstall],
            AgentPackageFormat = format,
        };

    [Fact]
    public async Task A_mac_enrolls_as_macOS_and_reports_its_version_build_and_software_update_source()
    {
        var agent = await EnrollMacAsync();
        var enrolled = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal(AgentPlatforms.MacOS, enrolled.Summary.Platform);

        using (var inventory = await agent.PostAsync(AgentRoutes.Inventory, Inventory("24G325")))
        {
            await AdminSession.EnsureAsync(inventory, HttpStatusCode.NoContent);
        }

        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal(AgentPlatforms.MacOS, detail.Summary.Platform);
        Assert.Equal("macOS Sequoia 15.7.2", detail.Summary.OperatingSystem);
        Assert.Equal("15.7.2", detail.Summary.OsVersion);
        Assert.Equal("24G325", detail.Summary.OsBuild);
        Assert.Equal(new MacOSDetailsDto("macos", "15.7.2", "24G325", "24.6.0", "softwareupdate", "file-permissions"), detail.MacOS);
        Assert.Null(detail.Linux);
        Assert.Null(detail.Applications);
        Assert.Equal(nameof(UpdateSourceType.AppleSoftwareUpdate), detail.UpdateSourceType);
        // Apple publishes no end-of-support dates.
        Assert.Equal(OsSupportStatus.Unknown, detail.Summary.OsSupportStatus);
        Assert.Null(detail.OsEndOfServicing);

        // A macOS update changes the build.
        using (var inventory = await agent.PostAsync(AgentRoutes.Inventory, Inventory("24G400")))
        {
            await AdminSession.EnsureAsync(inventory, HttpStatusCode.NoContent);
        }

        var events = await WithDbAsync(db => db.EndpointEvents.AsNoTracking()
            .Where(e => e.EndpointId == agent.EndpointId && e.Type == "OsChanged").Select(e => e.Message).ToListAsync());
        Assert.Equal("macOS build changed from 24G325 to 24G400.", Assert.Single(events));
    }

    [Fact]
    public async Task A_mac_is_only_offered_pkg_packages_of_its_architecture()
    {
        Publish("1.9.1"); // MSI x64
        Publish("1.9.1", architecture: "arm64"); // MSI arm64
        PublishPackage("1.9.1", AgentRelease.FormatDeb, "arm64");
        var agent = await EnrollMacAsync();

        // No pkg on the server: the MSI and deb packages are not offered.
        Assert.Null((await agent.CheckInAsync(MacCheckIn())).LatestAgent);
        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal(AgentRelease.FormatPkg, detail.AgentUpdate!.PackageFormat);
        Assert.Equal(AgentUpdateTarget.NoPackage, detail.AgentUpdate.Code);
        Assert.Null(detail.AgentUpdate.AvailableVersion);

        PublishPackage("1.9.1", AgentRelease.FormatPkg, "x64");
        var pkg = PublishPackage("1.9.1", AgentRelease.FormatPkg, "arm64");
        var latest = (await agent.CheckInAsync(MacCheckIn())).LatestAgent;
        Assert.Equal(Path.GetFileName(pkg), latest!.FileName);
        detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal("1.9.1", detail.AgentUpdate!.AvailableVersion);

        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/agent-update", Newest, HttpStatusCode.Accepted);
        var job = Assert.Single((await agent.CheckInAsync(MacCheckIn())).Jobs);
        Assert.Equal("EasyPatchAgent-1.9.1-arm64.pkg", job.AgentUpdate!.Package.FileName);

        var packages = await Root.GetAsync<List<AgentPackageDto>>("/api/v1/agent-packages");
        Assert.Equal(AgentRelease.FormatPkg, packages.Single(p => p.FileName == Path.GetFileName(pkg)).Format);
        using var client = NewHttpClient();
        using var download = await client.GetAsync($"/downloads/agent/{Path.GetFileName(pkg)}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal("application/octet-stream", download.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A_mac_that_reports_no_package_format_is_never_offered_an_msi()
    {
        Publish("1.9.1");
        Publish("1.9.1", architecture: "arm64");
        var agent = await EnrollMacAsync();

        // Agents that do not name a format are taken to install MSIs, which a Mac cannot.
        Assert.Null((await agent.CheckInAsync(MacCheckIn(format: null))).LatestAgent);
        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal(AgentUpdateTarget.NoPackage, detail.AgentUpdate!.Code);
    }

    [Fact]
    public async Task Windows_only_jobs_are_refused_for_macOS_endpoints_with_a_clear_reason()
    {
        var agent = await EnrollMacAsync();
        await agent.CheckInAsync(MacCheckIn());

        await Root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/notify", new NotifyRequest(UserMessagePreset.SaveYourWork, null),
            HttpStatusCode.Conflict, "not_supported_on_macos");
        await Root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/updates/{Guid.NewGuid()}/uninstall", new UninstallUpdateRequest(),
            HttpStatusCode.Conflict, "not_supported_on_macos");
        var download = await Assert.ThrowsAsync<AppException>(() => WithScopeAsync(sp =>
            sp.GetRequiredService<JobService>().CreateAsync(new CreateJobRequest(agent.EndpointId, JobType.DownloadUpdates))));
        Assert.Equal("not_supported_on_macos", download.Code);

        // Restarts are supported.
        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/restart",
            new RestartRequest(RestartMode.Immediate, RestartCondition.Always, null, null, null, null, false), HttpStatusCode.Accepted);
    }

    [Fact]
    public async Task The_macOS_install_script_is_only_offered_once_a_pkg_package_is_on_the_server()
    {
        var code = await Root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(Org.Id, Site.Id, "Mac rollout", 30, null, null), HttpStatusCode.Created);
        Assert.Null(code.MacOneLiner);
        Assert.Null(code.MacScriptUrl);
        await Root.ExpectAsync(HttpMethod.Get, $"/api/v1/deployment-codes/{code.Id}/install-script?platform=macOS", null, HttpStatusCode.Conflict,
            "no_agent_package");

        using var client = NewHttpClient();
        using var none = await client.GetAsync($"/downloads/install/macos/{code.Code}.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, none.StatusCode);
        var tokens = await Root.SendAsync<List<CreatedTokenDto>>(HttpMethod.Post, "/api/v1/enrollment-tokens",
            new CreateTokensRequest(Org.Id, Site.Id, null, 24, 1, 1), HttpStatusCode.OK);
        Assert.Null(Assert.Single(tokens).MacEnrollCommand);

        var x64 = PublishPackage("1.9.0", AgentRelease.FormatPkg, "x64");
        var arm64 = PublishPackage("1.9.0", AgentRelease.FormatPkg, "arm64");
        code = (await Root.GetAsync<List<DeploymentCodeDto>>("/api/v1/deployment-codes")).Single(c => c.Id == code.Id);
        Assert.EndsWith($"/downloads/install/macos/{code.Code}.sh", code.MacScriptUrl, StringComparison.Ordinal);
        Assert.Equal($"curl -fsSL {code.MacScriptUrl} | sudo sh", code.MacOneLiner);

        var response = await Root.GetAsync<InstallScriptResponse>($"/api/v1/deployment-codes/{code.Id}/install-script?platform=macOS");
        Assert.Equal(AgentPlatforms.MacOS, response.Platform);
        Assert.Equal(code.MacOneLiner, response.OneLiner);
        Assert.Equal("EasyPatchAgent-1.9.0-arm64.pkg, EasyPatchAgent-1.9.0-x64.pkg", response.PackageFileName);

        using var served = await client.GetAsync($"/downloads/install/macos/{code.Code}.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("no-store", served.Headers.CacheControl?.ToString());
        var script = await served.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("#!/bin/sh", script, StringComparison.Ordinal);
        Assert.Contains($"DEPLOYMENT_CODE='{code.Code}'", script, StringComparison.Ordinal);
        foreach (var path in new[] { x64, arm64 })
        {
            Assert.Contains(AgentRelease.Describe(path).Sha256.ToLowerInvariant(), script, StringComparison.Ordinal);
        }

        tokens = await Root.SendAsync<List<CreatedTokenDto>>(HttpMethod.Post, "/api/v1/enrollment-tokens",
            new CreateTokensRequest(Org.Id, Site.Id, null, 24, 1, 1), HttpStatusCode.OK);
        var token = Assert.Single(tokens);
        Assert.Equal(MacInstallScriptBuilder.TokenEnrollCommand(EasyPatchApiFactory.PublicUrl, token.PlaintextToken), token.MacEnrollCommand);

        using var unknown = await client.GetAsync("/downloads/install/macos/EPD-ZZZZZZZZZZZZZZZZ.sh", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    /// <summary>A signed agent package of any format in the server's package folder.</summary>
    private string PublishPackage(string version, string format, string architecture)
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
