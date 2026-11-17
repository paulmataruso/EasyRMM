using EasyPatch.Api.Cli;
using EasyPatch.Infrastructure.Services;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>Users sign in with their email address: how addresses are normalized and validated.</summary>
public sealed class SignInNameTests
{
    [Theory]
    [InlineData("  Jane.Doe@Example.COM ", "jane.doe@example.com")]
    [InlineData("ADMIN@EXAMPLE.TEST", "admin@example.test")]
    public void Addresses_are_trimmed_and_lower_cased(string input, string expected) => Assert.Equal(expected, AuthService.NormalizeEmail(input));

    [Theory]
    [InlineData("jane@example.com", true)]
    [InlineData("jane+patch@mail.example.co.uk", true)]
    [InlineData("admin@intranet", true)]
    [InlineData("jane", false)]
    [InlineData("@example.com", false)]
    [InlineData("jane@", false)]
    [InlineData("jane doe@example.com", false)]
    [InlineData("jane <jane@example.com>", false)]
    [InlineData("", false)]
    public void Only_plain_addresses_are_valid(string address, bool valid) => Assert.Equal(valid, AuthService.IsValidEmail(address));

    [Fact]
    public void Too_long_addresses_are_invalid() => Assert.False(AuthService.IsValidEmail(new string('a', 250) + "@example.com"));

    [Theory]
    [InlineData("admin@example.com", "admin")]
    [InlineData("Jane.Doe@Example.com", "jane.doe")]
    [InlineData("ops+patch@example.com", "ops-patch")]
    public void Create_admin_derives_the_account_name_from_the_address(string email, string name) => Assert.Equal(name, AdminCli.NameFromEmail(email));
}
