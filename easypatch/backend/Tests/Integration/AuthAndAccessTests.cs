using System.Net;
using System.Net.Http.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

public sealed class AuthTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Anonymous_requests_are_rejected_and_bad_passwords_do_not_reveal_accounts()
    {
        var http = NewHttpClient(new BrowserHandler());
        using (var anonymous = await http.GetAsync(new Uri("/api/v1/organizations", UriKind.Relative)))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            Assert.Equal("unauthenticated", await AdminSession.ProblemCodeAsync(anonymous));
        }

        await SuperAdminAsync();
        // The username is not a sign-in name: only the email address is.
        foreach (var (user, password) in new[] { (EmailOf("root"), "wrong-password-123"), (EmailOf("nobody"), DefaultPassword), ("root", DefaultPassword) })
        {
            using var response = await http.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), new LoginRequest(user, password), TestJson.Options);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("invalid_credentials", await AdminSession.ProblemCodeAsync(response)); // same answer for unknown users
        }

        var audited = await WithDbAsync(db => db.AuditLogs.Where(a => a.Action == "auth.login_failed").Select(a => a.Details).ToListAsync());
        Assert.Contains(audited, d => d != null && d.Contains("nobody@example.test", StringComparison.Ordinal));
        Assert.DoesNotContain(audited, d => d != null && d.Contains(DefaultPassword, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Users_sign_in_with_their_email_address_in_any_case()
    {
        var root = await SuperAdminAsync();
        await root.SendAsync<CreateUserResponse>(HttpMethod.Post, "/api/v1/users",
            new CreateUserRequest("jane", "  Jane.Doe@Example.TEST ", UserRole.Admin, DefaultPassword, null), HttpStatusCode.Created);
        Assert.Equal("jane.doe@example.test", await WithDbAsync(db => db.Users.Where(u => u.Username == "jane").Select(u => u.Email).FirstAsync()));

        var http = NewHttpClient(new BrowserHandler());
        using (var ok = await http.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative),
                   new LoginRequest("JANE.DOE@example.test ", DefaultPassword), TestJson.Options))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var byName = await NewHttpClient(new BrowserHandler()).PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative),
            new LoginRequest("jane", DefaultPassword), TestJson.Options);
        Assert.Equal(HttpStatusCode.Unauthorized, byName.StatusCode);
    }

    [Fact]
    public async Task Email_addresses_are_unique_ignoring_case_and_must_be_valid()
    {
        var root = await SuperAdminAsync();
        await root.SendAsync<CreateUserResponse>(HttpMethod.Post, "/api/v1/users",
            new CreateUserRequest("alice", "alice@example.test", UserRole.Admin, DefaultPassword, null), HttpStatusCode.Created);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/users", new CreateUserRequest("alice2", "ALICE@example.test", UserRole.Admin, null, null),
            HttpStatusCode.Conflict, "email_in_use");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/users", new CreateUserRequest("alice", "alice.other@example.test", UserRole.Admin, null, null),
            HttpStatusCode.Conflict, "username_in_use");
        foreach (var bad in new[] { "alice", "Alice <alice3@example.test>", "a b@example.test", "@example.test", "alice3@" })
        {
            await root.ExpectAsync(HttpMethod.Post, "/api/v1/users", new CreateUserRequest("alice3", bad, UserRole.Admin, null, null),
                HttpStatusCode.BadRequest, "validation_failed");
        }

        var bob = await root.SendAsync<CreateUserResponse>(HttpMethod.Post, "/api/v1/users",
            new CreateUserRequest("bob", "bob@example.test", UserRole.Admin, DefaultPassword, null), HttpStatusCode.Created);
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{bob.User.Id}", new UpdateUserRequest("Alice@Example.test", null, null),
            HttpStatusCode.Conflict, "email_in_use");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/users/{bob.User.Id}", new UpdateUserRequest("not-an-address", null, null),
            HttpStatusCode.BadRequest, "validation_failed");

        // The database refuses two addresses that differ only in case even if a row bypasses the application.
        var duplicate = await Assert.ThrowsAnyAsync<DbUpdateException>(() => WithDbAsync(async db =>
        {
            var row = await db.Users.FirstAsync(u => u.Username == "bob");
            row.Email = "ALICE@EXAMPLE.TEST";
            await db.SaveChangesAsync();
        }));
        Assert.Contains("IX_users_email_lower", duplicate.InnerException?.Message ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Repeated_failures_lock_the_account_until_the_lockout_expires()
    {
        await SuperAdminAsync();
        var http = NewHttpClient(new BrowserHandler());
        for (var i = 0; i < 5; i++)
        {
            using var bad = await http.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), new LoginRequest(EmailOf("root"), "wrong-password-123"),
                TestJson.Options);
            Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        }

        // Correct password while locked: still rejected, with the same generic error.
        using (var locked = await http.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), new LoginRequest(EmailOf("root"), DefaultPassword),
                   TestJson.Options))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
            Assert.Equal("invalid_credentials", await AdminSession.ProblemCodeAsync(locked));
        }

        Assert.NotNull(await WithDbAsync(db => db.Users.Where(u => u.Username == "root").Select(u => u.LockoutUntil).FirstAsync()));
        Assert.Contains("auth.locked_out", await WithDbAsync(db => db.AuditLogs.Select(a => a.Action).ToListAsync()));

        Clock.Advance(TimeSpan.FromMinutes(16));
        using var ok = await http.PostAsJsonAsync(new Uri("/api/v1/auth/login", UriKind.Relative), new LoginRequest(EmailOf("root"), DefaultPassword),
            TestJson.Options);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Mfa_is_enforced_and_codes_cannot_be_replayed()
    {
        var first = await SuperAdminAsync();
        Assert.NotNull(first.MfaSecret);
        await first.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");

        // A second sign-in requires the second factor before any data is available.
        var browser = new BrowserHandler();
        var second = new AdminSession(NewHttpClient(browser), browser, "root", DefaultPassword) { MfaSecret = first.MfaSecret };
        var login = await second.SendAsync<LoginResponse>(HttpMethod.Post, "/api/v1/auth/login", new LoginRequest(EmailOf("root"), DefaultPassword),
            HttpStatusCode.OK);
        Assert.True(login.MfaRequired);
        using (var blocked = await second.Http.GetAsync(new Uri("/api/v1/organizations", UriKind.Relative)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
            Assert.Equal("mfa_required", await AdminSession.ProblemCodeAsync(blocked));
        }

        await second.ExpectAsync(HttpMethod.Post, "/api/v1/auth/mfa/verify", new MfaCodeRequest("000000"), HttpStatusCode.Unauthorized, "invalid_mfa_code");

        Clock.Advance(TimeSpan.FromSeconds(31));
        var code = Totp.Compute(first.MfaSecret!, Totp.CurrentStep(Clock.GetUtcNow()));
        await second.ExpectAsync(HttpMethod.Post, "/api/v1/auth/mfa/verify", new MfaCodeRequest(code), HttpStatusCode.NoContent);
        await second.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");

        // The same code cannot be used again (third session, same TOTP step).
        var thirdBrowser = new BrowserHandler();
        var third = new AdminSession(NewHttpClient(thirdBrowser), thirdBrowser, "root", DefaultPassword);
        await third.SendAsync<LoginResponse>(HttpMethod.Post, "/api/v1/auth/login", new LoginRequest(EmailOf("root"), DefaultPassword), HttpStatusCode.OK);
        await third.ExpectAsync(HttpMethod.Post, "/api/v1/auth/mfa/verify", new MfaCodeRequest(code), HttpStatusCode.Unauthorized, "invalid_mfa_code");
    }

    [Fact]
    public async Task State_changing_requests_require_the_csrf_header()
    {
        var admin = await SuperAdminAsync();
        admin.Browser.SkipCsrf = true;
        await admin.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("Fabrikam", null, null, null, null, null),
            HttpStatusCode.Forbidden, "csrf_failed");

        admin.Browser.SkipCsrf = false;
        await admin.SendAsync<OrganizationDto>(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("Fabrikam", null, null, null, null, null),
            HttpStatusCode.Created);
    }

    [Fact]
    public async Task Sessions_expire_after_the_idle_timeout_and_logout_revokes_them()
    {
        var admin = await SuperAdminAsync();
        Clock.Advance(TimeSpan.FromMinutes(31));
        await admin.ExpectAsync(HttpMethod.Get, "/api/v1/auth/me", null, HttpStatusCode.Unauthorized);

        var again = await LoginAsync("root", DefaultPassword, admin.MfaSecret);
        await again.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        await again.ExpectAsync(HttpMethod.Post, "/api/v1/auth/logout", null, HttpStatusCode.NoContent);
        await again.ExpectAsync(HttpMethod.Get, "/api/v1/auth/me", null, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Password_reset_link_sets_a_new_password_once_and_revokes_sessions()
    {
        var root = await SuperAdminAsync();
        var created = await root.SendAsync<CreateUserResponse>(HttpMethod.Post, "/api/v1/users",
            new CreateUserRequest("operator1", "operator1@example.test", UserRole.Admin, null, null), HttpStatusCode.Created);
        Assert.NotNull(created.ResetLink);
        Assert.StartsWith(EasyPatchApiFactory.PublicUrl + "/reset-password#token=", created.ResetLink!.Url, StringComparison.Ordinal);
        var token = created.ResetLink.Url[(created.ResetLink.Url.IndexOf("#token=", StringComparison.Ordinal) + 7)..];

        var anonymous = new AdminSession(NewHttpClient(new BrowserHandler()), new BrowserHandler(), "operator1", string.Empty);
        await anonymous.ExpectAsync(HttpMethod.Post, "/api/v1/auth/password/reset", new ResetPasswordRequest(token, "short"), HttpStatusCode.BadRequest, "weak_password");
        await anonymous.ExpectAsync(HttpMethod.Post, "/api/v1/auth/password/reset", new ResetPasswordRequest(token, "Brand-New-Passphrase-42"), HttpStatusCode.NoContent);
        await anonymous.ExpectAsync(HttpMethod.Post, "/api/v1/auth/password/reset", new ResetPasswordRequest(token, "Another-Passphrase-43"), HttpStatusCode.BadRequest,
            "invalid_reset_token");

        var operatorSession = await LoginAsync("operator1", "Brand-New-Passphrase-42");
        var me = await operatorSession.GetAsync<CurrentUserDto>("/api/v1/auth/me");
        Assert.Equal(UserRole.Admin, me.Role);
        Assert.True(me.MfaEnabled);

        // Stored values are hashes, never the plaintext token or password.
        var stored = await WithDbAsync(db => db.Users.AsNoTracking().FirstAsync(u => u.Username == "operator1"));
        Assert.StartsWith("$argon2id$", stored.PasswordHash, StringComparison.Ordinal);
        Assert.DoesNotContain(token, await WithDbAsync(db => db.PasswordResetTokens.Select(t => t.TokenHash).ToListAsync()));
    }

    [Fact]
    public async Task Read_only_users_can_view_but_not_change_anything()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        var viewer = await CreateAndLoginAsync("viewer1", UserRole.ReadOnly);

        await viewer.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        await viewer.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("X", null, null, null, null, null), HttpStatusCode.Forbidden, "forbidden");
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/organizations/{org.Id}/sites", new SiteRequest("Branch", null, null, null), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/enrollment-tokens", new CreateTokensRequest(org.Id, site.Id, null, 24, 1, 1), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Get, "/api/v1/enrollment-tokens", null, HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Get, "/api/v1/users", null, HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Get, "/api/v1/audit-logs", null, HttpStatusCode.Forbidden);

        // Admins manage endpoints but not users or server settings.
        var admin = await CreateAndLoginAsync("admin1", UserRole.Admin);
        await admin.GetAsync<List<EnrollmentTokenDto>>("/api/v1/enrollment-tokens");
        await admin.ExpectAsync(HttpMethod.Get, "/api/v1/users", null, HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Put, "/api/v1/settings", new Core.Domain.ServerSettings(), HttpStatusCode.Forbidden);
    }
}

public sealed class TenantIsolationTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Users_restricted_to_an_organization_cannot_see_or_touch_another()
    {
        var root = await SuperAdminAsync();
        var (contoso, contosoSite) = await CreateOrgAsync(root, "Contoso");
        var (fabrikam, fabrikamSite) = await CreateOrgAsync(root, "Fabrikam");
        var contosoAgent = await EnrollAgentAsync(root, contoso.Id, contosoSite.Id, "CONTOSO-PC1");
        var fabrikamAgent = await EnrollAgentAsync(root, fabrikam.Id, fabrikamSite.Id, "FABRIKAM-PC1");

        var tech = await CreateAndLoginAsync("contoso-tech", UserRole.Admin, contoso.Id);

        var orgs = await tech.GetAsync<List<OrganizationSummaryDto>>("/api/v1/organizations");
        Assert.Equal([contoso.Id], orgs.Select(o => o.Id));
        var endpoints = await tech.GetAsync<PagedResult<EndpointSummaryDto>>("/api/v1/endpoints");
        Assert.Equal([contosoAgent.EndpointId], endpoints.Items.Select(e => e.Id));

        // Everything about the other tenant answers 404 (no existence oracle).
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/organizations/{fabrikam.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/sites/{fabrikamSite.Id}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Get, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/scan", null, HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{fabrikamAgent.EndpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.AllEligible, null, false), HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, "/api/v1/enrollment-tokens", new CreateTokensRequest(fabrikam.Id, null, null, 24, 1, 1), HttpStatusCode.NotFound);
        await tech.ExpectAsync(HttpMethod.Post, "/api/v1/organizations", new OrganizationRequest("Mine", null, null, null, null, null), HttpStatusCode.Forbidden);

        // Bulk operations silently scope to the caller's tenants.
        var bulk = await tech.SendAsync<BulkResultDto>(HttpMethod.Post, "/api/v1/endpoints/bulk/scan",
            new BulkEndpointsRequest([contosoAgent.EndpointId, fabrikamAgent.EndpointId], false), HttpStatusCode.OK);
        Assert.Equal(1, bulk.Succeeded);
        Assert.Equal("not_found", bulk.Results.Single(r => r.EndpointId == fabrikamAgent.EndpointId).ErrorCode);

        var jobs = await tech.GetAsync<PagedResult<JobSummaryDto>>("/api/v1/jobs");
        Assert.All(jobs.Items, j => Assert.Equal(contoso.Id, j.OrganizationId));
        var report = await tech.GetAsync<ComplianceReportDto>("/api/v1/reports/compliance");
        Assert.All(report.Rows, r => Assert.Equal("Contoso", r.OrganizationName));
        var audit = await tech.GetAsync<PagedResult<AuditLogDto>>("/api/v1/audit-logs");
        Assert.All(audit.Items, a => Assert.Equal(contoso.Id, a.OrganizationId));
    }
}
