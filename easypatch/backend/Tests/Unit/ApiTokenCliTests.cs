using EasyPatch.Api.Cli;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary><c>create-api-token</c> checks its options; the account commands are gone.</summary>
public sealed class ApiTokenCliTests
{
    private static Dictionary<string, string?> Options(params (string Key, string Value)[] pairs)
    {
        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in pairs)
        {
            options[key] = value;
        }

        return options;
    }

    [Theory]
    [InlineData("operator", UserRole.Admin)]
    [InlineData("Admin", UserRole.Admin)]
    [InlineData("read-only", UserRole.ReadOnly)]
    [InlineData("READONLY", UserRole.ReadOnly)]
    public void Roles_are_operator_or_read_only(string role, UserRole expected)
    {
        var parsed = AdminCli.ParseApiTokenOptions(Options(("name", " EasyRMM "), ("role", role), ("expires-days", "90")));
        Assert.Equal(expected, parsed.Role);
        Assert.Equal("EasyRMM", parsed.Name);
        Assert.Equal(90, parsed.ExpiresInDays);
        Assert.Empty(parsed.OrganizationIds);
    }

    [Theory]
    [InlineData("superadmin")]
    [InlineData("SuperAdmin")]
    [InlineData("owner")]
    public void A_token_is_never_a_super_administrator(string role) =>
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("role", role), ("expires-days", "30"))));

    [Theory]
    [InlineData("0")]
    [InlineData("366")]
    [InlineData("-1")]
    [InlineData("30d")]
    [InlineData("1e2")]
    public void Expiry_is_one_to_365_days(string days) =>
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("role", "operator"), ("expires-days", days))));

    [Fact]
    public void Name_role_and_expiry_are_required()
    {
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("role", "operator"), ("expires-days", "30"))));
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("expires-days", "30"))));
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("role", "operator"))));
        // A flag given without a value parses as "true", which is not a value.
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "true"), ("role", "operator"), ("expires-days", "30"))));
    }

    [Fact]
    public void Names_are_limited_like_the_console()
    {
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", new string('a', 51)), ("role", "operator"), ("expires-days", "30"))));
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "a\u0007b"), ("role", "operator"), ("expires-days", "30"))));
        Assert.Equal(50, AdminCli.ParseApiTokenOptions(Options(("name", new string('a', 50)), ("role", "operator"), ("expires-days", "30"))).Name.Length);
    }

    [Fact]
    public void Organizations_are_a_comma_separated_list_of_ids()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var parsed = AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("role", "read-only"), ("expires-days", "7"),
            ("organizations", $"{a}, {b},{a},")));
        Assert.Equal(new[] { a, b }, parsed.OrganizationIds);
        Assert.Throws<ArgumentException>(() => AdminCli.ParseApiTokenOptions(Options(("name", "x"), ("role", "read-only"), ("expires-days", "7"),
            ("organizations", "acme"))));
    }

    [Theory]
    [InlineData("create-admin")]
    [InlineData("reset-password")]
    [InlineData("reset-mfa")]
    [InlineData("unlock")]
    public async Task The_removed_account_commands_fail_instead_of_starting_the_server(string command)
    {
        // Program.cs runs the CLI, not the web server, for these names; the CLI refuses them before it touches configuration or the database.
        Assert.Contains(command, AdminCli.Commands);
        Assert.Equal(2, await AdminCli.RunAsync([command, "--email", "admin@example.test"]));
    }
}
