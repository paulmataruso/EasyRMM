using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Security keys and passkeys, exercised with a software authenticator against the real WebAuthn verification.</summary>
public sealed class WebAuthnTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private static readonly HttpMethod Post = HttpMethod.Post;

    [Fact]
    public async Task A_security_key_is_a_second_factor_after_the_password()
    {
        using var key = new SoftwareAuthenticator();
        var (kim, userId) = await NewUserAsync("kim");

        // Server policy requires MFA: the new user may set up a security key instead of an authenticator app.
        var options = await kim.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options", new WebAuthnRegisterOptionsRequest(false, null),
            HttpStatusCode.OK);
        Assert.Equal("easypatch.test", options.GetProperty("rp").GetProperty("id").GetString());
        Assert.Equal("discouraged", options.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString());
        var registered = await kim.SendAsync<WebAuthnRegisterResponse>(Post, "/api/v1/auth/webauthn/register",
            new { name = "YubiKey 5C", credential = key.Create(options, residentKey: false) }, HttpStatusCode.OK);
        Assert.Equal("YubiKey 5C", registered.Credential.Name);
        Assert.False(registered.Credential.IsPasskey);
        Assert.Equal(10, registered.RecoveryCodes!.Count); // the first second factor comes with recovery codes

        var me = await kim.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.True(me.MfaEnabled);
        Assert.False(me.TotpEnabled);
        Assert.False(me.MfaSetupRequired);
        Assert.Equal((1, 0), (me.SecurityKeyCount, me.PasskeyCount));
        Assert.True(me.PasskeyPrompt); // a security key used only as a second factor is not a passkey

        // Next sign-in: password, then the key.
        var again = await PasswordAsync("kim");
        Assert.Equal(HttpStatusCode.Forbidden, (await again.Http.GetAsync(new Uri("/api/v1/auth/sessions", UriKind.Relative))).StatusCode);
        var assertion = await again.SendAsync<JsonElement>(Post, "/api/v1/auth/mfa/webauthn/options", null, HttpStatusCode.OK);
        Assert.Equal(SoftwareAuthenticator.B64(key.CredentialId),
            assertion.GetProperty("allowCredentials").EnumerateArray().Single().GetProperty("id").GetString());
        await again.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = key.Get(assertion, includeUserHandle: false) },
            HttpStatusCode.NoContent);
        Assert.True((await again.GetAsync<CurrentUserDto>("/api/v1/auth/me")).MfaCompleted);
        await again.GetAsync<List<SessionDto>>("/api/v1/auth/sessions");

        var stored = await WithDbAsync(db => db.WebAuthnCredentials.AsNoTracking().SingleAsync(c => c.UserId == userId));
        Assert.Equal(1, stored.SignCount);
        Assert.NotNull(stored.LastUsedAt);

        // A recovery code also works for a user whose only second factor is a security key.
        var lost = await PasswordAsync("kim");
        await lost.ExpectAsync(Post, "/api/v1/auth/mfa/verify", new MfaCodeRequest(registered.RecoveryCodes[0]), HttpStatusCode.NoContent);

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.TargetId == userId.ToString()).ToListAsync());
        Assert.Contains(audit, a => a.Action == "auth.webauthn_added");
        Assert.Contains(audit, a => a.Action == "auth.login" && a.Details != null && a.Details.Contains("security_key", StringComparison.Ordinal));
        var challenge = assertion.GetProperty("challenge").GetString()!;
        Assert.DoesNotContain(audit, a => a.Details != null &&
                                          (a.Details.Contains(challenge, StringComparison.Ordinal) ||
                                           a.Details.Contains(SoftwareAuthenticator.B64(stored.PublicKey), StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_passkey_signs_in_without_a_password_and_counts_as_both_factors()
    {
        using var passkey = new SoftwareAuthenticator();
        var (sam, userId) = await NewUserAsync("sam");
        var options = await sam.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options", new WebAuthnRegisterOptionsRequest(true, null),
            HttpStatusCode.OK);
        var selection = options.GetProperty("authenticatorSelection");
        Assert.Equal(("required", "required"), (selection.GetProperty("residentKey").GetString(), selection.GetProperty("userVerification").GetString()));
        var registered = await sam.SendAsync<WebAuthnRegisterResponse>(Post, "/api/v1/auth/webauthn/register",
            new { name = (string?)null, credential = passkey.Create(options, residentKey: true) }, HttpStatusCode.OK);
        Assert.True(registered.Credential.IsPasskey);
        Assert.Equal("Passkey", registered.Credential.Name);
        Assert.Equal(userId.ToByteArray(), passkey.UserHandle);
        Assert.False((await sam.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);

        var browser = Anonymous();
        var request = await browser.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        Assert.Empty(request.GetProperty("allowCredentials").EnumerateArray());
        Assert.Equal("required", request.GetProperty("userVerification").GetString());
        var login = await browser.SendAsync<LoginResponse>(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: true) },
            HttpStatusCode.OK);
        Assert.False(login.MfaRequired);
        Assert.True(login.User.MfaCompleted);
        Assert.Equal("sam", login.User.Username);
        await browser.GetAsync<List<SessionDto>>("/api/v1/auth/sessions"); // fully signed in

        // A passkey must verify the user (PIN or biometrics) to sign in on its own.
        var noUv = Anonymous();
        request = await noUv.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await noUv.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: false) }, HttpStatusCode.Unauthorized,
            "invalid_passkey");

        // The sign-in completes only in the browser that started it.
        request = await Anonymous().SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await Anonymous().ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: true) },
            HttpStatusCode.BadRequest, "webauthn_challenge_expired");

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "auth.login" && a.TargetId == userId.ToString())
            .Select(a => a.Details).ToListAsync());
        Assert.Contains(audit, d => d != null && d.Contains("passkey", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Wrong_origins_unknown_keys_replays_clones_and_expired_challenges_are_rejected()
    {
        using var passkey = new SoftwareAuthenticator();
        var (_, userId) = await NewUserAsync("lee", passkey, asPasskey: true);

        // A response made for another site (phishing page) is refused.
        var phished = Anonymous();
        var request = await phished.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        passkey.Origin = "https://easypatch.test.evil.example";
        await phished.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: true) },
            HttpStatusCode.Unauthorized, "invalid_passkey");
        passkey.Origin = EasyPatchApiFactory.PublicUrl;

        // A key this server never registered.
        using var stranger = new SoftwareAuthenticator { UserHandle = userId.ToByteArray() };
        var unknown = Anonymous();
        request = await unknown.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await unknown.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = stranger.Get(request, userVerified: true) },
            HttpStatusCode.Unauthorized, "invalid_passkey");

        // A valid response works once; replaying it, or answering a new challenge with it, does not.
        var browser = Anonymous();
        request = await browser.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        var answer = passkey.Get(request, userVerified: true);
        await browser.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = answer }, HttpStatusCode.OK);
        await browser.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = answer }, HttpStatusCode.BadRequest, "webauthn_challenge_expired");
        _ = await browser.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await browser.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = answer }, HttpStatusCode.Unauthorized, "invalid_passkey");

        // A signature counter that goes backwards means a cloned authenticator.
        passkey.SignCount = 0;
        var clone = Anonymous();
        request = await clone.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await clone.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: true) },
            HttpStatusCode.Unauthorized, "invalid_passkey");
        passkey.SignCount = 100;

        // Challenges expire after five minutes.
        var slow = Anonymous();
        request = await slow.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        Clock.Advance(TimeSpan.FromMinutes(6));
        await slow.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = passkey.Get(request, userVerified: true) },
            HttpStatusCode.BadRequest, "webauthn_challenge_expired");

        var failures = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "auth.login_failed").Select(a => a.Details).ToListAsync());
        Assert.Contains(failures, d => d!.Contains("unknown_credential", StringComparison.Ordinal));
        Assert.Contains(failures, d => d!.Contains("\"invalid\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_second_factor_challenge_is_used_once_even_when_the_answer_is_wrong()
    {
        using var key = new SoftwareAuthenticator();
        await NewUserAsync("ana", key, asPasskey: false);

        var first = await PasswordAsync("ana");
        var stale = key.Get(await first.SendAsync<JsonElement>(Post, "/api/v1/auth/mfa/webauthn/options", null, HttpStatusCode.OK), includeUserHandle: false);

        var second = await PasswordAsync("ana");
        var options = await second.SendAsync<JsonElement>(Post, "/api/v1/auth/mfa/webauthn/options", null, HttpStatusCode.OK);
        await second.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = stale }, HttpStatusCode.Unauthorized, "invalid_security_key");
        await second.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = key.Get(options, includeUserHandle: false) },
            HttpStatusCode.BadRequest, "webauthn_challenge_expired");
        Assert.False((await second.GetAsync<CurrentUserDto>("/api/v1/auth/me")).MfaCompleted);
        Assert.Contains(await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action == "auth.mfa_failed").Select(a => a.Details).ToListAsync()),
            d => d!.Contains("security_key", StringComparison.Ordinal));

        // A malformed answer for a known key is a failed verification, not a server error.
        options = await second.SendAsync<JsonElement>(Post, "/api/v1/auth/mfa/webauthn/options", null, HttpStatusCode.OK);
        var garbled = key.Get(options, includeUserHandle: false);
        garbled["response"]!["authenticatorData"] = SoftwareAuthenticator.B64([1, 2, 3]);
        await second.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = garbled }, HttpStatusCode.Unauthorized, "invalid_security_key");
        options = await second.SendAsync<JsonElement>(Post, "/api/v1/auth/mfa/webauthn/options", null, HttpStatusCode.OK);
        await second.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = new { id = "%", type = "public-key" } }, HttpStatusCode.Unauthorized,
            "invalid_security_key");
        await second.ExpectAsync(Post, "/api/v1/auth/mfa/webauthn", new { credential = "not a credential" }, HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task Keys_are_renamed_and_removed_but_the_last_second_factor_stays_while_mfa_is_required()
    {
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        var (max, userId) = await NewUserAsync("max", first, asPasskey: false);
        var keys = await max.GetAsync<List<WebAuthnCredentialDto>>("/api/v1/auth/webauthn/credentials");
        var firstId = Assert.Single(keys).Id;

        await max.ExpectAsync(Post, $"/api/v1/auth/webauthn/credentials/{firstId}/remove", new { password = "wrong" }, HttpStatusCode.BadRequest,
            "invalid_password");
        await max.ExpectAsync(Post, $"/api/v1/auth/webauthn/credentials/{firstId}/remove", new PasswordConfirmRequest(DefaultPassword),
            HttpStatusCode.Conflict, "mfa_required");

        // Adding a key to an account that already has a second factor needs the password, unless the user signed in minutes ago.
        Clock.Advance(TimeSpan.FromMinutes(11));
        await max.ExpectAsync(Post, "/api/v1/auth/webauthn/register/options", new WebAuthnRegisterOptionsRequest(false, null), HttpStatusCode.BadRequest,
            "invalid_password");
        var options = await max.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options",
            new WebAuthnRegisterOptionsRequest(false, DefaultPassword), HttpStatusCode.OK);
        Assert.Equal(SoftwareAuthenticator.B64(first.CredentialId),
            options.GetProperty("excludeCredentials").EnumerateArray().Single().GetProperty("id").GetString());
        var added = await max.SendAsync<WebAuthnRegisterResponse>(Post, "/api/v1/auth/webauthn/register",
            new { name = "Backup key", credential = second.Create(options) }, HttpStatusCode.OK);
        Assert.Null(added.RecoveryCodes);

        // The same authenticator cannot be registered twice (by anyone).
        options = await max.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options",
            new WebAuthnRegisterOptionsRequest(false, DefaultPassword), HttpStatusCode.OK);
        await max.ExpectAsync(Post, "/api/v1/auth/webauthn/register", new { credential = second.Create(options) }, HttpStatusCode.BadRequest,
            "webauthn_failed");

        var renamed = await max.SendAsync<WebAuthnCredentialDto>(HttpMethod.Put, $"/api/v1/auth/webauthn/credentials/{firstId}",
            new WebAuthnRenameRequest("  Desk key  "), HttpStatusCode.OK);
        Assert.Equal("Desk key", renamed.Name);
        var root = await SuperAdminAsync();
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/auth/webauthn/credentials/{firstId}", new WebAuthnRenameRequest("mine"), HttpStatusCode.NotFound);

        await max.ExpectAsync(Post, $"/api/v1/auth/webauthn/credentials/{firstId}/remove", new PasswordConfirmRequest(DefaultPassword),
            HttpStatusCode.NoContent);
        Assert.Equal("Backup key", Assert.Single(await max.GetAsync<List<WebAuthnCredentialDto>>("/api/v1/auth/webauthn/credentials")).Name);
        Assert.True(await WithDbAsync(db => db.AuditLogs.AnyAsync(a => a.Action == "auth.webauthn_removed" && a.TargetId == userId.ToString())));
    }

    [Fact]
    public async Task The_authenticator_app_can_be_removed_while_a_security_key_remains()
    {
        using var key = new SoftwareAuthenticator();
        var pat = await CreateAndLoginAsync("pat", UserRole.Admin); // enrolls an authenticator app
        // Just signed in: no need to type the password again.
        var options = await pat.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options",
            new WebAuthnRegisterOptionsRequest(false, null), HttpStatusCode.OK);
        await pat.SendAsync<WebAuthnRegisterResponse>(Post, "/api/v1/auth/webauthn/register", new { credential = key.Create(options) }, HttpStatusCode.OK);

        Clock.Advance(TimeSpan.FromSeconds(31));
        var code = Totp.Compute(pat.MfaSecret!, Totp.CurrentStep(Clock.GetUtcNow()));
        await pat.ExpectAsync(Post, "/api/v1/auth/mfa/disable", new MfaDisableRequest(DefaultPassword, code), HttpStatusCode.NoContent);
        var me = await pat.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.Equal((true, false, 1), (me.MfaEnabled, me.TotpEnabled, me.SecurityKeyCount));

        var users = await (await SuperAdminAsync()).GetAsync<List<UserDto>>("/api/v1/users");
        var listed = users.Single(u => u.Username == "pat");
        Assert.Equal((true, false, 1), (listed.MfaEnabled, listed.TotpEnabled, listed.SecurityKeyCount));
    }

    [Fact]
    public async Task An_administrator_mfa_reset_also_removes_security_keys_and_passkeys()
    {
        using var key = new SoftwareAuthenticator();
        var (_, userId) = await NewUserAsync("eve", key, asPasskey: true);
        var root = await SuperAdminAsync();
        await root.ExpectAsync(Post, $"/api/v1/users/{userId}/mfa/reset", null, HttpStatusCode.NoContent);
        Assert.False(await WithDbAsync(db => db.WebAuthnCredentials.AnyAsync(c => c.UserId == userId)));
        var reset = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "user.mfa_reset" && a.TargetId == userId.ToString()));
        Assert.Contains("\"securityKeysRemoved\": 1", reset.Details, StringComparison.Ordinal);

        // The passkey no longer signs in, and a password sign-in must set up a second factor again.
        var browser = Anonymous();
        var request = await browser.SendAsync<JsonElement>(Post, "/api/v1/auth/passkey/options", null, HttpStatusCode.OK);
        await browser.ExpectAsync(Post, "/api/v1/auth/passkey", new { credential = key.Get(request, userVerified: true) }, HttpStatusCode.Unauthorized,
            "invalid_passkey");
        var login = await Anonymous().SendAsync<LoginResponse>(Post, "/api/v1/auth/login", new LoginRequest(EmailOf("eve"), DefaultPassword),
            HttpStatusCode.OK);
        Assert.True(login.MfaSetupRequired);
    }

    [Fact]
    public async Task The_passkey_offer_returns_thirty_days_after_not_now()
    {
        var zoe = await CreateAndLoginAsync("zoe", UserRole.ReadOnly);
        Assert.True((await zoe.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);
        await zoe.ExpectAsync(Post, "/api/v1/auth/passkey-prompt/dismiss", null, HttpStatusCode.NoContent);
        Assert.False((await zoe.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);

        // Not while the sign-in is still waiting for the second factor.
        var pending = await Anonymous().SendAsync<LoginResponse>(Post, "/api/v1/auth/login", new LoginRequest(EmailOf("zoe"), DefaultPassword),
            HttpStatusCode.OK);
        Assert.True(pending.MfaRequired);
        Assert.False(pending.User.PasskeyPrompt);

        Clock.Advance(TimeSpan.FromDays(29));
        var soon = await LoginAsync("zoe", DefaultPassword, zoe.MfaSecret);
        Assert.False((await soon.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);
        Clock.Advance(TimeSpan.FromDays(2));
        var later = await LoginAsync("zoe", DefaultPassword, zoe.MfaSecret);
        Assert.True((await later.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);
        Assert.NotNull(await WithDbAsync(db => db.Users.Where(u => u.Username == "zoe").Select(u => u.PasskeyPromptDismissedAt).FirstAsync()));
    }

    // ---------------------------------------------------------------------------------------------------------------------------

    /// <summary>Creates a user and signs in with the password; server policy then asks them to set up a second factor.</summary>
    private async Task<(AdminSession Session, Guid UserId)> NewUserAsync(string username)
    {
        var userId = await WithScopeAsync(async sp =>
            (await sp.GetRequiredService<AuthService>().CreateUserAsync(username, EmailOf(username), UserRole.ReadOnly, DefaultPassword)).Id);
        var session = Anonymous(username);
        var login = await session.SendAsync<LoginResponse>(Post, "/api/v1/auth/login", new LoginRequest(EmailOf(username), DefaultPassword),
            HttpStatusCode.OK);
        Assert.True(login.MfaSetupRequired);
        return (session, userId);
    }

    /// <summary>A user whose only second factor is <paramref name="key"/>.</summary>
    private async Task<(AdminSession Session, Guid UserId)> NewUserAsync(string username, SoftwareAuthenticator key, bool asPasskey)
    {
        var (session, userId) = await NewUserAsync(username);
        var options = await session.SendAsync<JsonElement>(Post, "/api/v1/auth/webauthn/register/options",
            new WebAuthnRegisterOptionsRequest(asPasskey, null), HttpStatusCode.OK);
        await session.SendAsync<WebAuthnRegisterResponse>(Post, "/api/v1/auth/webauthn/register",
            new { name = username + "'s key", credential = key.Create(options, residentKey: asPasskey) }, HttpStatusCode.OK);
        return (session, userId);
    }

    /// <summary>A password sign-in that now waits for the second factor.</summary>
    private async Task<AdminSession> PasswordAsync(string username)
    {
        var session = Anonymous(username);
        var login = await session.SendAsync<LoginResponse>(Post, "/api/v1/auth/login", new LoginRequest(EmailOf(username), DefaultPassword),
            HttpStatusCode.OK);
        Assert.True(login.MfaRequired);
        return session;
    }

    private AdminSession Anonymous(string username = "")
    {
        var browser = new BrowserHandler();
        return new AdminSession(NewHttpClient(browser), browser, username, DefaultPassword);
    }
}

/// <summary>Browsers offer WebAuthn only on HTTPS origins with a domain name: on an IP address the server says so and refuses.</summary>
public sealed class WebAuthnUnavailableTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    protected override IReadOnlyDictionary<string, string?>? Settings =>
        new Dictionary<string, string?> { ["EasyPatch:PublicUrl"] = "https://172.16.0.45:8443" };

    [Fact]
    public async Task Passkeys_are_unavailable_when_the_console_is_reached_by_ip_address()
    {
        var http = NewHttpClient(new BrowserHandler());
        var status = (await http.GetFromJsonAsync<WebAuthnStatusDto>(new Uri("/api/v1/auth/webauthn", UriKind.Relative), TestJson.Options))!;
        Assert.False(status.Available);
        Assert.Equal("ip_address", status.Reason);
        Assert.Contains("DNS name", status.Message, StringComparison.Ordinal);

        using (var options = await http.PostAsync(new Uri("/api/v1/auth/passkey/options", UriKind.Relative), null))
        {
            Assert.Equal(HttpStatusCode.Conflict, options.StatusCode);
            Assert.Equal("webauthn_unavailable", await AdminSession.ProblemCodeAsync(options));
        }

        var root = await SuperAdminAsync();
        Assert.False((await root.GetAsync<CurrentUserDto>("/api/v1/auth/me")).PasskeyPrompt);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/auth/webauthn/register/options", new WebAuthnRegisterOptionsRequest(true, DefaultPassword),
            HttpStatusCode.Conflict, "webauthn_unavailable");
    }
}
