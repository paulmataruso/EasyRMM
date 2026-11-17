using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>A signed-in user changes their own email address.</summary>
public sealed class ChangeEmailTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    [Fact]
    public async Task Users_change_their_own_email_with_their_current_password()
    {
        var root = await SuperAdminAsync();
        await CreateAndLoginAsync("other", UserRole.ReadOnly); // other@example.test

        await root.ExpectAsync(HttpMethod.Post, "/api/v1/auth/email/change", new ChangeEmailRequest("wrong password", "me@example.org"),
            HttpStatusCode.BadRequest, "invalid_password");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/auth/email/change", new ChangeEmailRequest(DefaultPassword, "not an address"),
            HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/auth/email/change", new ChangeEmailRequest(DefaultPassword, "Other@Example.test"),
            HttpStatusCode.Conflict, "email_in_use");

        await root.ExpectAsync(HttpMethod.Post, "/api/v1/auth/email/change", new ChangeEmailRequest(DefaultPassword, "  Me@Example.ORG "),
            HttpStatusCode.NoContent);
        Assert.Equal("me@example.org", (await root.GetAsync<CurrentUserDto>("/api/v1/auth/me")).Email);
        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "auth.email_changed"));
        Assert.Contains("me@example.org", audit.Details, StringComparison.Ordinal);
    }
}
