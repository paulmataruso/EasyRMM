using EasyPatch.Api.Cli;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>The account and API token commands are gone: they fail with a message instead of starting the server.</summary>
public sealed class AdminCliTests
{
    [Theory]
    [InlineData("create-admin", "--email", "admin@example.test")]
    [InlineData("reset-password", "--email", "admin@example.test")]
    [InlineData("reset-mfa", "--email", "admin@example.test")]
    [InlineData("unlock", "--email", "admin@example.test")]
    [InlineData("create-api-token", "--name", "Reports")]
    public async Task The_removed_commands_fail_instead_of_starting_the_server(string command, string option, string value)
    {
        // Program.cs runs the CLI, not the web server, for these names; the CLI refuses them before it touches configuration or the database.
        Assert.Contains(command, AdminCli.Commands);
        Assert.Equal(2, await AdminCli.RunAsync([command, option, value]));
    }

    [Fact]
    public async Task Create_api_token_says_why_it_is_refused()
    {
        var error = new StringWriter();
        var before = Console.Error;
        Console.SetError(error);
        try
        {
            Assert.Equal(2, await AdminCli.RunAsync(["create-api-token", "--name", "Reports", "--role", "read-only", "--expires-days", "365"]));
        }
        finally
        {
            Console.SetError(before);
        }

        Assert.Contains("'create-api-token' was removed", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("EasyRMM", error.ToString(), StringComparison.Ordinal);
    }
}
