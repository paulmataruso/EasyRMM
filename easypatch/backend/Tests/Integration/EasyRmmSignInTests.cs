using System.Net;
using System.Net.Http.Json;
using System.Web;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// Signing in through EasyRMM, which owns EasyPatch: a provider marked as EasyRMM manages its accounts. They are matched by issuer and
/// subject only, take their role and organizations from the <c>easypatch</c> claim at every sign-in, and sign in only through EasyRMM.
/// <see cref="FakeOidcProvider"/> stands in for EasyRMM; EasyRMM's own side is tested against a real client in EasyRMM's repository.
/// </summary>
public sealed class EasyRmmSignInTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private static readonly HttpMethod Post = HttpMethod.Post;
    private readonly FakeOidcProvider idp = new();

    protected override void ConfigureServices(IServiceCollection services) =>
        services.AddHttpClient(OidcService.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => idp);

    private sealed record Flow(HttpClient Http, BrowserHandler Browser, string State, string Nonce, string Challenge);

    [Fact]
    public async Task EasyRMM_creates_managed_accounts_from_its_claim_and_never_links_one_by_email()
    {
        var root = await SuperAdminAsync();
        var (contoso, _) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, _) = await CreateOrgAsync(root, "Fabrikam");
        Assert.Contains(ServerCapabilities.EasyRmmSignIn, (await root.GetAsync<ServerInfoDto>("/api/v1/server-info")).Capabilities);
        var standard = (await root.SendAsync<SsoProviderDto>(Post, "/api/v1/sso/providers", Request("Lab IdP", easyRmm: false), HttpStatusCode.Created)).Id;
        var rmm = await root.SendAsync<SsoProviderDto>(Post, "/api/v1/sso/providers", Request("EasyRMM"), HttpStatusCode.Created);
        Assert.True(rmm.IsEasyRmm);

        // The sign-in page lists EasyRMM first, and marks it.
        var buttons = await NewHttpClient().GetFromJsonAsync<List<SsoProviderSummaryDto>>("/api/v1/auth/sso/providers", TestJson.Options);
        Assert.Equal([(rmm.Id, true), (standard, false)], buttons!.Select(b => (b.Id, b.IsEasyRmm)));

        // An EasyPatch account with the person's address is never taken over: its owner must link it.
        await CreateAndLoginAsync("dana", UserRole.Admin);
        var refused = await StartAsync(rmm.Id);
        Assert.Equal("/login?sso_error=email_in_use", await FinishAsync(refused, Token(refused, "rmm-dana", EmailOf("dana"), "SuperAdmin", [])));
        var dana = await WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Username == "dana"));
        Assert.Equal(UserRole.Admin, dana.Role);
        Assert.False(await WithDbAsync(db => db.ExternalLogins.AnyAsync()));

        // A new person: an account managed by EasyRMM, with the granted organizations that exist here, and a one-hour session.
        var unknown = Guid.NewGuid();
        var erikFlow = await StartAsync(rmm.Id, "/endpoints?status=offline");
        Assert.Equal("/endpoints?status=offline",
            await FinishAsync(erikFlow, Token(erikFlow, "rmm-erik", "Erik@Example.test", "ReadOnly", [contoso.Id, unknown])));
        var erik = await MeAsync(erikFlow);
        Assert.Equal(("erik@example.test", UserRole.ReadOnly, false, true), (erik.Email, erik.Role, erik.AllOrganizations, erik.ManagedByEasyRmm));
        Assert.Equal(FakeOidcProvider.Issuer, erik.EasyRmmUrl); // where the console's product switch links
        Assert.Equal([contoso.Id], erik.OrganizationIds);
        Assert.True(erik.MfaCompleted); // amr said "mfa"
        Assert.False(erik.MfaSetupRequired);
        Assert.False(erik.HasPassword);
        Assert.False(erik.PasskeyPrompt); // a passkey would not sign this account in
        var session = await WithDbAsync(db => db.UserSessions.AsNoTracking().SingleAsync(s => s.UserId == erik.Id));
        AssertAbout(Clock.GetUtcNow() + OidcProvider.EasyRmmSessionLifetime, session.ExpiresAt);
        Assert.True(session.MfaByProvider);
        Assert.Contains(await root.GetAsync<List<UserDto>>("/api/v1/users"), u => u.Id == erik.Id && u.ManagedByEasyRmm);

        // Every sign-in applies the claim again, and records only a change.
        var promoted = await StartAsync(rmm.Id);
        await FinishAsync(promoted, Token(promoted, "rmm-erik", "erik@example.test", "Admin", [contoso.Id, fabrikam.Id]));
        var admin = await MeAsync(promoted);
        Assert.Equal(UserRole.Admin, admin.Role);
        Assert.Equal(new[] { contoso.Id, fabrikam.Id }.Order(), admin.OrganizationIds.Order());
        var same = await StartAsync(rmm.Id);
        await FinishAsync(same, Token(same, "rmm-erik", "erik@example.test", "Admin", [fabrikam.Id, contoso.Id]));
        Assert.Equal(1, await AuditCountAsync("user.access_from_easyrmm", erik.Id));

        // Nothing granted here: refused, and the account keeps what it had.
        var nothing = await StartAsync(rmm.Id);
        Assert.Equal("/login?sso_error=easyrmm_no_access", await FinishAsync(nothing, Token(nothing, "rmm-erik", "erik@example.test", "Admin", [unknown])));
        var malformed = await StartAsync(rmm.Id);
        Assert.Equal("/login?sso_error=failed", await FinishAsync(malformed, Token(malformed, "rmm-erik", "erik@example.test", "Owner", [contoso.Id])));
        Assert.Equal(UserRole.Admin, (await WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Id == erik.Id))).Role);

        // Its role and organizations are EasyRMM's to change; deactivating it is still EasyPatch's.
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{erik.Id}", new { role = UserRole.SuperAdmin }, HttpStatusCode.Conflict, "managed_by_easyrmm");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{erik.Id}/organizations", new { organizationIds = new[] { contoso.Id } },
            HttpStatusCode.Conflict, "managed_by_easyrmm");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{erik.Id}", new { role = UserRole.Admin }, HttpStatusCode.OK); // unchanged
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{erik.Id}", new { isActive = false }, HttpStatusCode.OK);
        var inactive = await StartAsync(rmm.Id);
        Assert.Equal("/login?sso_error=no_account", await FinishAsync(inactive, Token(inactive, "rmm-erik", "erik@example.test", "Admin", [contoso.Id])));
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{erik.Id}", new { isActive = true }, HttpStatusCode.OK);

        // Another provider reaches a managed account neither by its address nor by a link.
        var other = await StartAsync(standard);
        Assert.Equal("/login?sso_error=easyrmm_only",
            await FinishAsync(other, idp.Sign(Claims(other, "lab-erik", "erik@example.test", verified: true))));
        var sameSubject = await StartAsync(standard);
        Assert.Equal("/login?sso_error=easyrmm_only", await FinishAsync(sameSubject, idp.Sign(Claims(sameSubject, "rmm-erik", "erik@example.test"))));

        // SuperAdmin comes only from EasyRMM, over every organization; amr without "mfa" leaves EasyPatch's own second factor to set up.
        var fay = await StartAsync(rmm.Id);
        await FinishAsync(fay, Token(fay, "rmm-fay", "fay@example.test", "SuperAdmin", []));
        var fayMe = await MeAsync(fay);
        Assert.Equal((UserRole.SuperAdmin, true), (fayMe.Role, fayMe.AllOrganizations));
        var gus = await StartAsync(rmm.Id);
        await FinishAsync(gus, Token(gus, "rmm-gus", "gus@example.test", "ReadOnly", [contoso.Id], amr: ["pwd"]));
        Assert.True((await MeAsync(gus)).MfaSetupRequired);

        // The last active SuperAdmin is never demoted by a sign-in.
        await WithDbAsync(db => db.Users.Where(u => u.Username == "root").ExecuteUpdateAsync(u => u.SetProperty(x => x.IsActive, false)));
        var demote = await StartAsync(rmm.Id);
        Assert.Equal("/login?sso_error=failed", await FinishAsync(demote, Token(demote, "rmm-fay", "fay@example.test", "Admin", [contoso.Id])));
        Assert.Equal(UserRole.SuperAdmin, (await WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Id == fayMe.Id))).Role);
        await WithDbAsync(db => db.Users.Where(u => u.Username == "root").ExecuteUpdateAsync(u => u.SetProperty(x => x.IsActive, true)));

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().ToListAsync());
        Assert.Contains(audit, a => a.Action == "user.create" && a.TargetId == erik.Id.ToString() && a.Details!.Contains("easyrmm", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.Action == "auth.sso_failed" && a.Details!.Contains("email_in_use", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.Action == "auth.sso_failed" && a.Details!.Contains("last_super_admin", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_owner_links_an_account_which_then_signs_in_only_through_EasyRMM()
    {
        var root = await SuperAdminAsync();
        var (contoso, _) = await CreateOrgAsync(root, "Contoso");
        await root.ExpectAsync(Post, "/api/v1/auth/sso/link", new LinkEasyRmmRequest(DefaultPassword), HttpStatusCode.Conflict, "easyrmm_not_configured");
        var rmm = (await root.SendAsync<SsoProviderDto>(Post, "/api/v1/sso/providers", Request("EasyRMM"), HttpStatusCode.Created)).Id;

        var dana = await CreateAndLoginAsync("dana", UserRole.Admin);
        var before = await dana.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.Equal((false, (string?)null), (before.ManagedByEasyRmm, before.EasyRmmUrl));
        var danaId = await WithDbAsync(db => db.Users.Where(u => u.Username == "dana").Select(u => u.Id).SingleAsync());
        await dana.ExpectAsync(Post, "/api/v1/auth/sso/link", new LinkEasyRmmRequest("wrong-password"), HttpStatusCode.BadRequest, "invalid_password");
        Clock.Advance(TimeSpan.FromMinutes(11)); // no longer a recent sign-in: the password is required
        await dana.ExpectAsync(Post, "/api/v1/auth/sso/link", new LinkEasyRmmRequest(null), HttpStatusCode.BadRequest, "invalid_password");

        var link = await LinkAsync(dana);
        Assert.Equal("/account?linked=easyrmm", await FinishAsync(link, Token(link, "rmm-dana", "dana.rmm@example.test", "ReadOnly", [contoso.Id])));
        var me = await MeAsync(link);
        Assert.Equal((danaId, UserRole.ReadOnly, true), (me.Id, me.Role, me.ManagedByEasyRmm));
        Assert.Equal(EmailOf("dana"), me.Email); // the account keeps its own address
        Assert.Equal([contoso.Id], me.OrganizationIds);
        // Signed in through EasyRMM now: one session, of at most an hour; the password session ended.
        var sessions = await WithDbAsync(db => db.UserSessions.AsNoTracking().Where(s => s.UserId == danaId && s.RevokedAt == null).ToListAsync());
        AssertAbout(Clock.GetUtcNow() + OidcProvider.EasyRmmSessionLifetime, Assert.Single(sessions).ExpiresAt);

        // From now on only EasyRMM signs dana in.
        using (var login = await NewHttpClient(new BrowserHandler()).PostAsJsonAsync("/api/v1/auth/login",
                   new LoginRequest(EmailOf("dana"), DefaultPassword), TestJson.Options))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
            Assert.Equal("easyrmm_only", await AdminSession.ProblemCodeAsync(login));
        }

        var again = await StartAsync(rmm);
        Assert.Equal("/endpoints", await FinishAsync(again, Token(again, "rmm-dana", "dana.rmm@example.test", "ReadOnly", [contoso.Id])));
        Assert.Equal(danaId, (await MeAsync(again)).Id);
        var danaAgain = new AdminSession(again.Http, again.Browser, "dana", "");
        await danaAgain.ExpectAsync(Post, "/api/v1/auth/sso/link", new LinkEasyRmmRequest(null), HttpStatusCode.Conflict, "already_linked");

        // An EasyRMM account already linked to dana cannot be linked to another EasyPatch account.
        var ed = await CreateAndLoginAsync("eddie", UserRole.ReadOnly, contoso.Id);
        var edLink = await LinkAsync(ed);
        Assert.Equal("/account?easyrmm_link_error=easyrmm_linked_elsewhere",
            await FinishAsync(edLink, Token(edLink, "rmm-dana", "dana.rmm@example.test", "Admin", [contoso.Id])));
        var edMe = await ed.GetAsync<CurrentUserDto>("/api/v1/auth/me"); // still signed in, as before
        Assert.Equal((UserRole.ReadOnly, false), (edMe.Role, edMe.ManagedByEasyRmm));

        // A super administrator removing the link makes dana an ordinary account again.
        var links = await root.GetAsync<List<ExternalLoginDto>>($"/api/v1/users/{danaId}/external-logins");
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/users/{danaId}/external-logins/{links.Single().Id}", null, HttpStatusCode.NoContent);
        Assert.False((await root.GetAsync<UserDto>($"/api/v1/users/{danaId}")).ManagedByEasyRmm);
        await LoginAsync("dana", DefaultPassword, dana.MfaSecret);

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.TargetId == danaId.ToString()).ToListAsync());
        Assert.Contains(audit, a => a.Action == "auth.sso_linked" && a.Details!.Contains("owner", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.Action == "user.access_from_easyrmm");
        Assert.Contains(audit, a => a.Action == "auth.login_failed" && a.Details!.Contains("easyrmm_only", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Only_one_provider_is_EasyRMM_and_its_kind_stays_while_people_are_linked()
    {
        var root = await SuperAdminAsync();
        var (contoso, _) = await CreateOrgAsync(root, "Contoso");
        await root.ExpectAsync(Post, "/api/v1/sso/providers", Request("EasyRMM") with { AutoProvision = true, AllowedDomains = ["example.test"] },
            HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(Post, "/api/v1/sso/providers", Request("EasyRMM") with { TrustEmailClaim = true }, HttpStatusCode.BadRequest,
            "validation_failed");
        await root.ExpectAsync(Post, "/api/v1/sso/providers", Request("EasyRMM") with { ProviderEnforcesMfa = true }, HttpStatusCode.BadRequest,
            "validation_failed");
        var rmm = (await root.SendAsync<SsoProviderDto>(Post, "/api/v1/sso/providers", Request("EasyRMM"), HttpStatusCode.Created)).Id;
        await root.ExpectAsync(Post, "/api/v1/sso/providers", Request("EasyRMM again"), HttpStatusCode.Conflict, "easyrmm_provider_exists");

        // Without linked people the kind can change; with them it cannot.
        await root.SendAsync<SsoProviderDto>(HttpMethod.Put, $"/api/v1/sso/providers/{rmm}", Request("EasyRMM", easyRmm: false), HttpStatusCode.OK);
        await root.SendAsync<SsoProviderDto>(HttpMethod.Put, $"/api/v1/sso/providers/{rmm}", Request("EasyRMM"), HttpStatusCode.OK);
        var flow = await StartAsync(rmm);
        await FinishAsync(flow, Token(flow, "rmm-hana", "hana@example.test", "ReadOnly", [contoso.Id]));
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/sso/providers/{rmm}", Request("EasyRMM", easyRmm: false), HttpStatusCode.Conflict,
            "provider_in_use");

        // Removing the provider removes the links: the account is no longer managed, and nobody signs in to it until someone sets it up.
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/sso/providers/{rmm}", null, HttpStatusCode.NoContent);
        Assert.DoesNotContain(await root.GetAsync<List<UserDto>>("/api/v1/users"), u => u.ManagedByEasyRmm);
    }

    // -------------------------------------------------------------------------------------------

    private static SsoProviderRequest Request(string name, bool easyRmm = true) =>
        new(name, FakeOidcProvider.Issuer, FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, null, true, false, false, false,
            UserRole.ReadOnly, null, easyRmm);

    private async Task<Flow> StartAsync(Guid providerId, string returnTo = "/endpoints")
    {
        var browser = new BrowserHandler();
        var http = NewHttpClient(browser);
        using var response = await http.GetAsync(new Uri($"/api/v1/auth/sso/{providerId}/start?returnTo={Uri.EscapeDataString(returnTo)}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return FlowFrom(http, browser, response.Headers.Location!);
    }

    /// <summary>My account → Link EasyRMM, for a signed-in user: the console goes where the response says.</summary>
    private async Task<Flow> LinkAsync(AdminSession user)
    {
        var start = await user.SendAsync<LinkEasyRmmResponse>(Post, "/api/v1/auth/sso/link", new LinkEasyRmmRequest(DefaultPassword), HttpStatusCode.OK);
        return FlowFrom(user.Http, user.Browser, new Uri(start.Redirect));
    }

    private static Flow FlowFrom(HttpClient http, BrowserHandler browser, Uri location)
    {
        Assert.StartsWith(FakeOidcProvider.Issuer + "/auth?", location.AbsoluteUri, StringComparison.Ordinal);
        var query = HttpUtility.ParseQueryString(location.Query);
        return new Flow(http, browser, query["state"]!, query["nonce"]!, query["code_challenge"]!);
    }

    private Dictionary<string, object?> Claims(Flow flow, string sub, string? email, bool verified = false)
    {
        var exp = Clock.GetUtcNow().AddMinutes(5);
        return new Dictionary<string, object?>
        {
            ["iss"] = FakeOidcProvider.Issuer,
            ["sub"] = sub,
            ["aud"] = FakeOidcProvider.ClientId,
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["iat"] = exp.AddMinutes(-5).ToUnixTimeSeconds(),
            ["nonce"] = flow.Nonce,
            ["email"] = email,
            ["email_verified"] = verified,
        };
    }

    /// <summary>An ID token as EasyRMM issues it: <c>email_verified</c> false, <c>amr</c>, and the <c>easypatch</c> claim.</summary>
    private string Token(Flow flow, string sub, string email, string role, Guid[] organizations, string[]? amr = null)
    {
        var claims = Claims(flow, sub, email);
        claims["name"] = sub;
        claims["amr"] = amr ?? ["pwd", "otp", "mfa"];
        claims["easypatch"] = new Dictionary<string, object> { ["role"] = role, ["organizations"] = organizations };
        return idp.Sign(claims);
    }

    /// <summary>EasyRMM redirects back with a code for <paramref name="idToken"/>; returns where EasyPatch sends the browser.</summary>
    private async Task<string> FinishAsync(Flow flow, string idToken)
    {
        var code = "code-" + Guid.NewGuid().ToString("N");
        idp.IssueCode(code, flow.Challenge, idToken);
        using var response = await flow.Http.GetAsync(new Uri($"/api/v1/auth/sso/callback?code={code}&state={Uri.EscapeDataString(flow.State)}",
            UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return response.Headers.Location!.OriginalString;
    }

    private static Task<CurrentUserDto> MeAsync(Flow flow) => new AdminSession(flow.Http, flow.Browser, "", "").GetAsync<CurrentUserDto>("/api/v1/auth/me");

    /// <summary>PostgreSQL keeps microseconds; .NET keeps ticks.</summary>
    private static void AssertAbout(DateTimeOffset expected, DateTimeOffset actual) =>
        Assert.True((expected - actual).Duration() < TimeSpan.FromMilliseconds(1), $"expected {expected:O}, got {actual:O}");

    private Task<int> AuditCountAsync(string action, Guid userId) =>
        WithDbAsync(db => db.AuditLogs.CountAsync(a => a.Action == action && a.TargetId == userId.ToString()));

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        idp.Key.Dispose();
    }
}
