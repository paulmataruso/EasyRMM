using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>Signs statements the way EasyRMM does, for tests. Any claim can be replaced or removed (a null value removes it).</summary>
public static class EasyRmmTestSigner
{
    public static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    public static Dictionary<string, object?> Claims(string method, string target, DateTimeOffset now, object? orgs = null, string role = "Admin") => new()
    {
        ["iss"] = "easyrmm",
        ["aud"] = "easypatch",
        ["sub"] = "6f1c2a52-3e0d-4b8a-9d55-0b6f1e8c2a10",
        ["name"] = "jane@example.com",
        ["role"] = role,
        ["orgs"] = orgs ?? "*",
        ["htm"] = method,
        ["htu"] = target,
        ["iat"] = now.ToUnixTimeSeconds(),
        ["exp"] = now.AddSeconds(30).ToUnixTimeSeconds(),
    };

    public static string Sign(IDictionary<string, object?> claims, byte[]? key = null, string alg = "HS256", string typ = EasyRmmStatement.TokenType)
    {
        var header = Encode(new Dictionary<string, object?> { ["alg"] = alg, ["typ"] = typ });
        var payload = Encode(claims.Where(c => c.Value is not null).ToDictionary(c => c.Key, c => c.Value));
        var signature = HMACSHA256.HashData(key ?? Key, Encoding.ASCII.GetBytes(header + "." + payload));
        return header + "." + payload + "." + Base64Url.EncodeToString(signature);
    }

    private static string Encode(object value) => Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(value));
}

/// <summary>Statements from EasyRMM: accepted only exactly as made, for the one request, while they live.</summary>
public sealed class EasyRmmStatementTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
    private const string Target = "/api/v1/endpoints/0b4b5c3e-2a8f-4f7e-9f3d-6a1e2b3c4d5e/uninstall-agent";

    private static EasyRmmStatement? Validate(string token, string method = "POST", string target = Target, DateTimeOffset? now = null, byte[]? key = null) =>
        EasyRmmStatement.Validate(token, key ?? EasyRmmTestSigner.Key, method, target, now ?? Now, out _);

    private static string Signed(Action<Dictionary<string, object?>>? change = null, byte[]? key = null, string alg = "HS256",
        string typ = EasyRmmStatement.TokenType)
    {
        var claims = EasyRmmTestSigner.Claims("POST", Target, Now);
        change?.Invoke(claims);
        return EasyRmmTestSigner.Sign(claims, key, alg, typ);
    }

    /// <summary>
    /// The statement EasyRMM's Go signer makes (server/internal/easypatch/testdata/gateway-statement.json; its own test checks it
    /// produces exactly this). Accepted here, the two sides agree on the format.
    /// </summary>
    [Fact]
    public void The_statement_EasyRMMs_signer_makes_is_accepted()
    {
        using var file = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "gateway-statement.json")));
        var g = file.RootElement;
        string Part(string name) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(g.GetProperty(name).GetString()!));
        var token = Part("header") + "." + Part("payload") + "." + g.GetProperty("signature").GetString();
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(); // the test key: bytes 0 to 31
        var now = DateTimeOffset.FromUnixTimeSeconds(g.GetProperty("now").GetInt64());

        var statement = EasyRmmStatement.Validate(token, key, g.GetProperty("method").GetString()!, g.GetProperty("target").GetString()!, now, out var reason);
        Assert.True(statement is not null, reason);
        Assert.Equal((g.GetProperty("subject").GetString(), g.GetProperty("name").GetString(), g.GetProperty("role").GetString(), false),
            (statement.Subject, statement.Name, statement.Role.ToString(), statement.AllOrganizations));
        Assert.Equal(Guid.Parse(g.GetProperty("organizations")[0].GetString()!), Assert.Single(statement.Organizations));
    }

    [Fact]
    public void A_statement_made_for_the_request_is_accepted_with_what_it_says()
    {
        var all = Validate(Signed());
        Assert.NotNull(all);
        Assert.Equal(("6f1c2a52-3e0d-4b8a-9d55-0b6f1e8c2a10", "jane@example.com", UserRole.Admin, true), (all.Subject, all.Name, all.Role, all.AllOrganizations));

        var org = Guid.NewGuid();
        var some = Validate(Signed(c => (c["orgs"], c["role"]) = (new[] { org.ToString() }, "ReadOnly")));
        Assert.NotNull(some);
        Assert.Equal((UserRole.ReadOnly, false, org), (some.Role, some.AllOrganizations, Assert.Single(some.Organizations)));

        // An empty list is no organization at all, not every one.
        var none = Validate(Signed(c => c["orgs"] = Array.Empty<string>()));
        Assert.NotNull(none);
        Assert.False(none.AllOrganizations);
        Assert.Empty(none.Organizations);
    }

    [Fact]
    public void Only_the_request_it_was_made_for()
    {
        var token = Signed();
        Assert.Null(Validate(token, method: "GET"));
        Assert.Null(Validate(token, target: "/api/v1/endpoints/0b4b5c3e-2a8f-4f7e-9f3d-6a1e2b3c4d5e/install"));
        Assert.Null(Validate(token, target: Target + "?force=true"));
        Assert.Null(Validate(token, target: Target.ToUpperInvariant()));
    }

    [Fact]
    public void Only_while_it_lives()
    {
        var token = Signed();
        Assert.NotNull(Validate(token, now: Now.AddSeconds(34)));
        Assert.Null(Validate(token, now: Now.AddSeconds(35)));
        // Issued in the future, beyond the clock leeway.
        Assert.NotNull(Validate(token, now: Now.AddSeconds(-5)));
        Assert.Null(Validate(token, now: Now.AddSeconds(-6)));
        // Longer than a minute, or ending before it starts.
        Assert.Null(Validate(Signed(c => c["exp"] = Now.AddSeconds(61).ToUnixTimeSeconds())));
        Assert.Null(Validate(Signed(c => c["exp"] = Now.ToUnixTimeSeconds())));
        Assert.Null(Validate(Signed(c => c["exp"] = null)));
        Assert.Null(Validate(Signed(c => c["iat"] = "now")));
        Assert.Null(Validate(Signed(c => c["exp"] = 1.5e300)));
        Assert.Null(Validate(Signed(c => c["iat"] = -1)));
    }

    [Fact]
    public void Only_signed_with_the_gateway_key_as_EasyRMM_signs()
    {
        Assert.Null(Validate(Signed(key: RandomNumberGenerator.GetBytes(32))));
        Assert.Null(Validate(Signed(alg: "HS512")));
        Assert.Null(Validate(Signed(alg: "none")));
        Assert.Null(Validate(Signed(typ: "JWT")));

        // A signature that is not over these bytes, or none at all.
        var token = Signed();
        var parts = token.Split('.');
        var other = Signed(c => c["role"] = "SuperAdmin").Split('.');
        Assert.Null(Validate(parts[0] + "." + other[1] + "." + parts[2]));
        Assert.Null(Validate(parts[0] + "." + parts[1] + "."));
        Assert.Null(Validate(parts[0] + "." + parts[1]));
        Assert.Null(Validate(token + "." + parts[2]));
        Assert.Null(Validate(""));
        Assert.Null(Validate(new string('a', EasyRmmStatement.MaxLength + 1)));
    }

    [Theory]
    [InlineData("iss", "someone-else")]
    [InlineData("aud", "easyrmm")]
    [InlineData("iss", null)]
    [InlineData("aud", null)]
    [InlineData("sub", null)]
    [InlineData("sub", "")]
    [InlineData("name", null)]
    [InlineData("name", "line\nbreak")]
    [InlineData("role", "Owner")]
    [InlineData("role", "superadmin")]
    [InlineData("role", "7")]
    [InlineData("role", "0")]
    [InlineData("role", null)]
    [InlineData("orgs", null)]
    [InlineData("orgs", "all")]
    public void Not_with_a_claim_it_should_not_have(string claim, string? value) =>
        Assert.Null(Validate(Signed(c => c[claim] = value)));

    [Fact]
    public void Not_with_organizations_that_are_not_ids()
    {
        Assert.Null(Validate(Signed(c => c["orgs"] = new[] { "Contoso" })));
        Assert.Null(Validate(Signed(c => c["orgs"] = new object[] { 7 })));
        Assert.Null(Validate(Signed(c => c["orgs"] = Enumerable.Range(0, 1001).Select(_ => Guid.NewGuid().ToString()).ToArray())));
    }
}
