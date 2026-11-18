using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>An OpenID Connect provider served from memory: discovery, JWKS and a token endpoint that checks the client, the redirect
/// URI and the PKCE verifier before handing out the ID token the test prepared.</summary>
public sealed class FakeOidcProvider : HttpMessageHandler
{
    public const string Issuer = "https://idp.test/realms/lab";
    public const string ClientId = "easypatch-console";
    public const string ClientSecret = "idp-Client-Secret-42";
    private readonly ConcurrentDictionary<string, (string Challenge, string IdToken)> codes = new();
    private int tokenRequests;

    public RSA Key { get; } = RSA.Create(2048);
    public string DiscoveryIssuer { get; set; } = Issuer;
    public int TokenRequests => tokenRequests;

    public void IssueCode(string code, string challenge, string idToken) => codes[code] = (challenge, idToken);

    public string Sign(IReadOnlyDictionary<string, object?> claims, RSA? key = null) =>
        new JsonWebTokenHandler().CreateToken(JsonSerializer.Serialize(claims.Where(c => c.Value is not null).ToDictionary()),
            new SigningCredentials(new RsaSecurityKey(key ?? Key) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.GetLeftPart(UriPartial.Path);
        if (request.Method == HttpMethod.Get && path == Issuer + "/.well-known/openid-configuration")
        {
            return Json(new Dictionary<string, object>
            {
                ["issuer"] = DiscoveryIssuer,
                ["authorization_endpoint"] = Issuer + "/auth",
                ["token_endpoint"] = Issuer + "/token",
                ["jwks_uri"] = Issuer + "/certs",
                ["response_types_supported"] = new[] { "code" },
                ["subject_types_supported"] = new[] { "public" },
                ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
                ["token_endpoint_auth_methods_supported"] = new[] { "client_secret_post", "client_secret_basic" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
            });
        }

        if (request.Method == HttpMethod.Get && path == Issuer + "/certs")
        {
            var p = Key.ExportParameters(false);
            return Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "k1", n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        }

        if (request.Method == HttpMethod.Post && path == Issuer + "/token")
        {
            Interlocked.Increment(ref tokenRequests);
            var form = (await request.Content!.ReadAsStringAsync(cancellationToken)).Split('&')
                .Select(kv => kv.Split('=', 2)).ToDictionary(kv => Unescape(kv[0]), kv => Unescape(kv[1]));
            if (form.GetValueOrDefault("grant_type") == "authorization_code" &&
                codes.TryRemove(form.GetValueOrDefault("code") ?? "", out var issued) &&
                form.GetValueOrDefault("client_id") == ClientId && form.GetValueOrDefault("client_secret") == ClientSecret &&
                form.GetValueOrDefault("redirect_uri") == EasyPatchApiFactory.PublicUrl + OidcService.CallbackPath &&
                B64(SHA256.HashData(Encoding.ASCII.GetBytes(form.GetValueOrDefault("code_verifier") ?? ""))) == issued.Challenge)
            {
                return Json(new { access_token = "opaque", token_type = "Bearer", id_token = issued.IdToken });
            }

            return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"error\":\"invalid_grant\"}", Encoding.UTF8, "application/json") };
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    public static string B64(byte[] bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);

    private static string Unescape(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));

    private static HttpResponseMessage Json(object body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
}

/// <summary>Single sign-on with OpenID Connect against <see cref="FakeOidcProvider"/>.</summary>
public sealed class SsoTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private static readonly HttpMethod Post = HttpMethod.Post;
    private readonly FakeOidcProvider idp = new();

    protected override void ConfigureServices(IServiceCollection services) =>
        services.AddHttpClient(OidcService.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => idp);

    private sealed record Flow(HttpClient Http, BrowserHandler Browser, string State, string Nonce, string Challenge);

    [Fact]
    public async Task A_verified_email_links_an_existing_user_who_still_completes_EasyPatch_MFA()
    {
        var root = await SuperAdminAsync();
        var providerId = await AddProviderAsync(root);

        var settingsJson = await (await root.SendAsync(HttpMethod.Get, "/api/v1/sso/providers")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(FakeOidcProvider.ClientSecret, settingsJson, StringComparison.Ordinal);
        var settings = JsonSerializer.Deserialize<SsoSettingsDto>(settingsJson, TestJson.Options)!;
        Assert.Equal("https://easypatch.test/api/v1/auth/sso/callback", settings.RedirectUri);
        Assert.True(settings.Providers.Single().ClientSecretConfigured);
        Assert.Equal("openid email profile", settings.Providers.Single().Scopes);
        var stored = await WithDbAsync(db => db.OidcProviders.AsNoTracking().SingleAsync());
        Assert.DoesNotContain(FakeOidcProvider.ClientSecret, stored.ClientSecretProtected!, StringComparison.Ordinal);

        var buttons = await (await NewHttpClient().GetAsync(new Uri("/api/v1/auth/sso/providers", UriKind.Relative))).Content.ReadAsStringAsync();
        Assert.Contains("Lab IdP", buttons, StringComparison.Ordinal);

        var alice = await CreateAndLoginAsync("alice", UserRole.Admin); // has an authenticator app
        var aliceId = await WithDbAsync(db => db.Users.Where(u => u.Username == "alice").Select(u => u.Id).SingleAsync());

        var flow = await StartAsync(providerId, "/endpoints?status=offline");
        Assert.Equal("/endpoints?status=offline", await FinishAsync(flow, idp.Sign(Claims(flow, "alice-sub", "Alice@Example.test"))));
        var session = new AdminSession(flow.Http, flow.Browser, "alice", "") { MfaSecret = alice.MfaSecret };
        var me = await session.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.Equal(aliceId, me.Id);
        Assert.False(me.MfaCompleted); // EasyPatch's second factor is still required after single sign-on by default
        Assert.True(me.HasPassword);
        Assert.Equal(HttpStatusCode.Forbidden, (await flow.Http.GetAsync(new Uri("/api/v1/auth/sessions", UriKind.Relative))).StatusCode);
        Clock.Advance(TimeSpan.FromSeconds(31));
        await session.ExpectAsync(Post, "/api/v1/auth/mfa/verify",
            new MfaCodeRequest(Totp.Compute(alice.MfaSecret!, Totp.CurrentStep(Clock.GetUtcNow()))), HttpStatusCode.NoContent);
        Assert.True((await session.GetAsync<CurrentUserDto>("/api/v1/auth/me")).MfaCompleted);

        var link = await WithDbAsync(db => db.ExternalLogins.AsNoTracking().SingleAsync());
        Assert.Equal((aliceId, FakeOidcProvider.Issuer, "alice-sub", "alice@example.test"), (link.UserId, link.Issuer, link.Subject, link.Email));
        Assert.NotNull(link.LastUsedAt);

        // Linked by issuer and subject: a new, unverified address at the provider still signs alice in.
        var renamed = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(renamed, idp.Sign(Claims(renamed, "alice-sub", "alice.new@elsewhere.test", verified: false))));
        Assert.Equal(aliceId, (await new AdminSession(renamed.Http, renamed.Browser, "alice", "").GetAsync<CurrentUserDto>("/api/v1/auth/me")).Id);

        // Super administrators see the link and can remove it. Then the unverified address no longer signs in.
        var links = await root.GetAsync<List<ExternalLoginDto>>($"/api/v1/users/{aliceId}/external-logins");
        Assert.Equal(("Lab IdP", "alice-sub"), (links.Single().ProviderName, links.Single().Subject));
        Assert.Equal(1, (await root.GetAsync<List<UserDto>>("/api/v1/users")).Single(u => u.Id == aliceId).ExternalLoginCount);
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/users/{aliceId}/external-logins/{links.Single().Id}", null, HttpStatusCode.NoContent);
        var unlinked = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account",
            await FinishAsync(unlinked, idp.Sign(Claims(unlinked, "alice-sub", "alice.new@elsewhere.test", verified: false))));

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().ToListAsync());
        Assert.Contains(audit, a => a.Action == "auth.sso_linked" && a.TargetId == aliceId.ToString());
        Assert.Contains(audit, a => a.Action == "auth.sso_verified" && a.TargetId == aliceId.ToString());
        Assert.Contains(audit, a => a.Action == "user.sso_unlinked");
        Assert.Contains(audit, a => a.Action == "sso.provider_create" && a.Details!.Contains("Lab IdP", StringComparison.Ordinal));
        Assert.All(audit, a => Assert.DoesNotContain(FakeOidcProvider.ClientSecret, a.Details ?? "", StringComparison.Ordinal));
        Assert.All(audit, a => Assert.DoesNotContain(flow.Nonce, a.Details ?? "", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Accounts_are_created_only_when_allowed_and_only_for_allowed_domains()
    {
        var root = await SuperAdminAsync();
        var providerId = await AddProviderAsync(root);

        var refused = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account", await FinishAsync(refused, idp.Sign(Claims(refused, "n-1", "newbie@contoso.test"))));
        Assert.False(await WithDbAsync(db => db.Users.AnyAsync(u => u.Email == "newbie@contoso.test")));

        // Created accounts need allowed domains and can never be super administrators.
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/sso/providers/{providerId}", Request(autoProvision: true), HttpStatusCode.BadRequest,
            "validation_failed");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/sso/providers/{providerId}",
            Request(autoProvision: true, domains: ["contoso.test"]) with { DefaultRole = UserRole.SuperAdmin }, HttpStatusCode.BadRequest,
            "validation_failed");
        // The secret is write-only: null keeps it (the fake provider checks it on every code exchange).
        await root.SendAsync<SsoProviderDto>(HttpMethod.Put, $"/api/v1/sso/providers/{providerId}",
            Request(autoProvision: true, domains: ["@Contoso.test"]) with { ClientSecret = null }, HttpStatusCode.OK);

        var created = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(created, idp.Sign(Claims(created, "n-1", "Newbie@contoso.test"))));
        var me = await new AdminSession(created.Http, created.Browser, "newbie", "").GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.Equal(("newbie@contoso.test", UserRole.ReadOnly), (me.Email, me.Role));
        Assert.False(me.HasPassword);
        Assert.True(me.MfaCompleted);
        Assert.True(me.MfaSetupRequired); // the server requires MFA and this provider does not enforce it
        var user = await WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Email == "newbie@contoso.test"));
        Assert.False(AuthService.HasUsablePassword(user));

        var otherDomain = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account", await FinishAsync(otherDomain, idp.Sign(Claims(otherDomain, "x-1", "intruder@evil.test"))));
        var unverified = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account",
            await FinishAsync(unverified, idp.Sign(Claims(unverified, "u-1", "unverified@contoso.test", verified: false))));
        Assert.False(await WithDbAsync(db => db.Users.AnyAsync(u => u.Email == "intruder@evil.test" || u.Email == "unverified@contoso.test")));

        // An unverified address links an existing user only when the provider's email claim is trusted.
        await WithScopeAsync(sp => sp.GetRequiredService<AuthService>().CreateUserAsync("bob", "bob@fabrikam.test", UserRole.Admin, DefaultPassword));
        var untrusted = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account", await FinishAsync(untrusted, idp.Sign(Claims(untrusted, "bob-sub", "bob@fabrikam.test", verified: false))));
        await root.SendAsync<SsoProviderDto>(HttpMethod.Put, $"/api/v1/sso/providers/{providerId}",
            Request(autoProvision: true, domains: ["contoso.test"], trustEmail: true) with { ClientSecret = null }, HttpStatusCode.OK);
        var trusted = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(trusted, idp.Sign(Claims(trusted, "bob-sub", "bob@fabrikam.test", verified: false))));

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "auth.sso_failed").ToListAsync());
        Assert.Contains(audit, a => a.Details!.Contains("no_matching_user", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.Details!.Contains("domain_not_allowed", StringComparison.Ordinal));
        Assert.Contains(audit, a => a.Details!.Contains("email_not_verified", StringComparison.Ordinal));
        Assert.All(audit, a => Assert.DoesNotContain("evil.test", a.Details!, StringComparison.Ordinal)); // claims are not recorded
    }

    [Fact]
    public async Task ID_tokens_that_fail_validation_are_refused()
    {
        var root = await SuperAdminAsync();
        var providerId = await AddProviderAsync(root);
        await WithScopeAsync(sp => sp.GetRequiredService<AuthService>().CreateUserAsync("carol", "carol@example.test", UserRole.Admin, DefaultPassword));
        using var otherKey = RSA.Create(2048);

        var cases = new (string Name, Func<Flow, string> Token)[]
        {
            ("bad signature", f => idp.Sign(Claims(f, "carol-sub", "carol@example.test"), otherKey)),
            ("wrong audience", f => idp.Sign(Claims(f, "carol-sub", "carol@example.test", aud: "someone-else"))),
            ("wrong issuer", f => idp.Sign(Claims(f, "carol-sub", "carol@example.test", iss: "https://evil.test/realms/lab"))),
            ("expired", f => idp.Sign(Claims(f, "carol-sub", "carol@example.test", expires: Clock.GetUtcNow().AddMinutes(-3)))),
            ("nonce mismatch", f => idp.Sign(Claims(f with { Nonce = "another-nonce" }, "carol-sub", "carol@example.test"))),
            ("several audiences without azp", f => idp.Sign(Claims(f, "carol-sub", "carol@example.test", aud: new[] { FakeOidcProvider.ClientId, "other" }))),
            ("not a JWT", _ => "not-a-token"),
        };
        foreach (var (name, token) in cases)
        {
            var flow = await StartAsync(providerId);
            Assert.Equal((name, "/login?sso_error=failed"), (name, await FinishAsync(flow, token(flow))));
            Assert.Equal(HttpStatusCode.Unauthorized, (await flow.Http.GetAsync(new Uri("/api/v1/auth/me", UriKind.Relative))).StatusCode);
        }

        Assert.False(await WithDbAsync(db => db.ExternalLogins.AnyAsync()));
        Assert.False(await WithDbAsync(db => db.UserSessions.AnyAsync(s => s.User!.Username == "carol")));
        var reasons = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "auth.sso_failed").Select(a => a.Details!).ToListAsync());
        foreach (var expected in new[] { "Signature", "InvalidAudience", "InvalidIssuer", "InvalidLifetime", "nonce_mismatch", "azp_mismatch", "Malformed" })
        {
            Assert.Contains(reasons, r => r.Contains(expected, StringComparison.Ordinal)); // each token failed the check it was built for
        }

        // The discovery document must name the configured issuer. The settings page's check reports it; sign-in is unavailable.
        Assert.True((await root.SendAsync<SsoProbeDto>(Post, "/api/v1/sso/providers/probe", new SsoProbeRequest(FakeOidcProvider.Issuer), HttpStatusCode.OK)).Ok);
        idp.DiscoveryIssuer = "https://idp.test/realms/other";
        var probe = await root.SendAsync<SsoProbeDto>(Post, "/api/v1/sso/providers/probe", new SsoProbeRequest(FakeOidcProvider.Issuer), HttpStatusCode.OK);
        Assert.False(probe.Ok);
        Assert.Contains("https://idp.test/realms/other", probe.Message, StringComparison.Ordinal);
        var browser = new BrowserHandler();
        using var start = await NewHttpClient(browser).GetAsync(new Uri($"/api/v1/auth/sso/{providerId}/start", UriKind.Relative));
        Assert.Equal("/login?sso_error=unavailable", start.Headers.Location!.OriginalString);

        // A valid token still works once the provider is right again.
        idp.DiscoveryIssuer = FakeOidcProvider.Issuer;
        await root.SendAsync<SsoProbeDto>(Post, "/api/v1/sso/providers/probe", new SsoProbeRequest(FakeOidcProvider.Issuer), HttpStatusCode.OK);
        var good = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(good, idp.Sign(Claims(good, "carol-sub", "carol@example.test"))));
    }

    [Fact]
    public async Task A_sign_in_state_is_used_once_by_the_browser_that_started_it_within_10_minutes()
    {
        var root = await SuperAdminAsync();
        var providerId = await AddProviderAsync(root);
        await WithScopeAsync(sp => sp.GetRequiredService<AuthService>().CreateUserAsync("dave", "dave@example.test", UserRole.Admin, DefaultPassword));

        var flow = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(flow, idp.Sign(Claims(flow, "dave-sub", "dave@example.test"))));
        Assert.Equal("/login?sso_error=expired", await FinishAsync(flow, idp.Sign(Claims(flow, "dave-sub", "dave@example.test")))); // replayed state

        var started = await StartAsync(providerId);
        var otherBrowser = new BrowserHandler();
        var stolen = started with { Http = NewHttpClient(otherBrowser), Browser = otherBrowser };
        Assert.Equal("/login?sso_error=expired", await FinishAsync(stolen, idp.Sign(Claims(started, "dave-sub", "dave@example.test"))));
        Assert.Equal("/login?sso_error=expired", await FinishAsync(started, idp.Sign(Claims(started, "dave-sub", "dave@example.test"))));

        var slow = await StartAsync(providerId);
        Clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal("/login?sso_error=expired", await FinishAsync(slow, idp.Sign(Claims(slow, "dave-sub", "dave@example.test"))));

        var cancelled = await StartAsync(providerId);
        using var denied = await cancelled.Http.GetAsync(new Uri($"/api/v1/auth/sso/callback?error=access_denied&state={cancelled.State}", UriKind.Relative));
        Assert.Equal("/login?sso_error=denied", denied.Headers.Location!.OriginalString);

        Assert.Equal(1, idp.TokenRequests); // no code was redeemed for a refused state
        Assert.Equal(0, await WithDbAsync(db => db.OidcLoginStates.CountAsync()));

        // A return address outside the console is replaced by the start page.
        var offsite = await StartAsync(providerId, "//evil.test/phish");
        Assert.Equal("/", await FinishAsync(offsite, idp.Sign(Claims(offsite, "dave-sub", "dave@example.test"))));
    }

    [Fact]
    public async Task A_provider_that_enforces_MFA_replaces_EasyPatch_MFA_and_inactive_users_cannot_sign_in()
    {
        var root = await SuperAdminAsync();
        var providerId = await AddProviderAsync(root, enforcesMfa: true);
        await CreateAndLoginAsync("erin", UserRole.Admin); // has an authenticator app
        var frank = await WithScopeAsync(sp => sp.GetRequiredService<AuthService>().CreateUserAsync("frank", "frank@example.test", UserRole.ReadOnly, DefaultPassword));

        var erin = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(erin, idp.Sign(Claims(erin, "erin-sub", "erin@example.test"))));
        var me = await new AdminSession(erin.Http, erin.Browser, "erin", "").GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.True(me.MfaCompleted);
        Assert.Equal(HttpStatusCode.OK, (await erin.Http.GetAsync(new Uri("/api/v1/auth/sessions", UriKind.Relative))).StatusCode);

        var noMfa = await StartAsync(providerId);
        Assert.Equal("/endpoints", await FinishAsync(noMfa, idp.Sign(Claims(noMfa, "frank-sub", "frank@example.test"))));
        Assert.False((await new AdminSession(noMfa.Http, noMfa.Browser, "frank", "").GetAsync<CurrentUserDto>("/api/v1/auth/me")).MfaSetupRequired);

        await root.SendAsync<UserDto>(HttpMethod.Put, $"/api/v1/users/{frank.Id}", new { isActive = false }, HttpStatusCode.OK);
        var inactive = await StartAsync(providerId);
        Assert.Equal("/login?sso_error=no_account", await FinishAsync(inactive, idp.Sign(Claims(inactive, "frank-sub", "frank@example.test"))));

        // Disabled providers offer no button and cannot start a sign-in.
        await root.SendAsync<SsoProviderDto>(HttpMethod.Put, $"/api/v1/sso/providers/{providerId}", Request(enforcesMfa: true) with { Enabled = false },
            HttpStatusCode.OK);
        var buttons = await (await NewHttpClient().GetAsync(new Uri("/api/v1/auth/sso/providers", UriKind.Relative))).Content.ReadAsStringAsync();
        Assert.Equal("[]", buttons);
        using var start = await NewHttpClient(new BrowserHandler()).GetAsync(new Uri($"/api/v1/auth/sso/{providerId}/start", UriKind.Relative));
        Assert.Equal("/login?sso_error=unavailable", start.Headers.Location!.OriginalString);
    }

    // -------------------------------------------------------------------------------------------

    private static SsoProviderRequest Request(bool autoProvision = false, string[]? domains = null, bool trustEmail = false, bool enforcesMfa = false) =>
        new("Lab IdP", FakeOidcProvider.Issuer, FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, null, true, trustEmail, enforcesMfa,
            autoProvision, UserRole.ReadOnly, domains);

    private static async Task<Guid> AddProviderAsync(AdminSession root, bool enforcesMfa = false) =>
        (await root.SendAsync<SsoProviderDto>(Post, "/api/v1/sso/providers", Request(enforcesMfa: enforcesMfa), HttpStatusCode.Created)).Id;

    private async Task<Flow> StartAsync(Guid providerId, string returnTo = "/endpoints")
    {
        var browser = new BrowserHandler();
        var http = NewHttpClient(browser);
        using var response = await http.GetAsync(new Uri($"/api/v1/auth/sso/{providerId}/start?returnTo={Uri.EscapeDataString(returnTo)}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.StartsWith(FakeOidcProvider.Issuer + "/auth?", location.AbsoluteUri, StringComparison.Ordinal);
        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        Assert.Equal(("code", FakeOidcProvider.ClientId, "openid email profile", "S256"),
            (query["response_type"], query["client_id"], query["scope"], query["code_challenge_method"]));
        Assert.Equal(EasyPatchApiFactory.PublicUrl + OidcService.CallbackPath, query["redirect_uri"]);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("__Host-easypatch-sso=", StringComparison.Ordinal) &&
                                                                       c.Contains("samesite=lax", StringComparison.OrdinalIgnoreCase));
        return new Flow(http, browser, query["state"]!, query["nonce"]!, query["code_challenge"]!);
    }

    private Dictionary<string, object?> Claims(Flow flow, string sub, string? email, bool verified = true, object? aud = null, string? iss = null,
        DateTimeOffset? expires = null)
    {
        var exp = expires ?? Clock.GetUtcNow().AddMinutes(5);
        return new Dictionary<string, object?>
        {
            ["iss"] = iss ?? FakeOidcProvider.Issuer,
            ["sub"] = sub,
            ["aud"] = aud ?? FakeOidcProvider.ClientId,
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["iat"] = exp.AddMinutes(-5).ToUnixTimeSeconds(),
            ["nonce"] = flow.Nonce,
            ["email"] = email,
            ["email_verified"] = verified,
        };
    }

    /// <summary>The provider redirects back with a code for <paramref name="idToken"/>; returns where the console sends the browser.</summary>
    private async Task<string> FinishAsync(Flow flow, string idToken)
    {
        var code = "code-" + Guid.NewGuid().ToString("N");
        idp.IssueCode(code, flow.Challenge, idToken);
        using var response = await flow.Http.GetAsync(new Uri($"/api/v1/auth/sso/callback?code={code}&state={Uri.EscapeDataString(flow.State)}",
            UriKind.Relative));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return response.Headers.Location!.OriginalString;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        idp.Key.Dispose();
    }
}
