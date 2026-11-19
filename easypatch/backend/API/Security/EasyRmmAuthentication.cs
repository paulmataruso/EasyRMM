using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Security;

/// <summary>
/// The key EasyRMM signs its statements with when EasyPatch runs as EasyRMM's patching engine (<c>EasyRmm:GatewayKey</c>: base64,
/// at least 32 bytes). Without it, statements are refused. A key that is set but unusable stops the server at start.
/// </summary>
public sealed class EasyRmmGateway
{
    public const string KeySetting = "EasyRmm:GatewayKey";
    public const int MinimumKeyBytes = 32;

    public EasyRmmGateway(IConfiguration configuration)
    {
        var raw = configuration[KeySetting];
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(raw.Trim());
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"{KeySetting} is not base64.");
        }

        if (key.Length < MinimumKeyBytes)
        {
            throw new InvalidOperationException($"{KeySetting} must be at least {MinimumKeyBytes} bytes.");
        }

        Key = key;
    }

    /// <summary>The shared key, or null when EasyPatch is not an EasyRMM server's engine.</summary>
    public byte[]? Key { get; }
}

/// <summary>What one valid statement from EasyRMM says.</summary>
/// <param name="Subject">The EasyRMM user (its id), or <see cref="EasyRmmStatement.ServiceSubject"/> for EasyRMM's own work.</param>
/// <param name="Name">Who to name in the audit trail.</param>
/// <param name="Role">The role this one call may use.</param>
/// <param name="AllOrganizations">True when the call may touch every organization.</param>
/// <param name="Organizations">Otherwise, the organizations it may touch.</param>
public sealed record EasyRmmStatement(string Subject, string Name, UserRole Role, bool AllOrganizations, IReadOnlySet<Guid> Organizations)
{
    public const string TokenType = "easyrmm-gateway+jwt";
    public const string Issuer = "easyrmm";
    public const string Audience = "easypatch";
    public const string ServiceSubject = "service";

    /// <summary>Clock difference tolerated: both programs run on one host.</summary>
    public static readonly TimeSpan Leeway = TimeSpan.FromSeconds(5);

    /// <summary>The longest a statement may be valid for.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(60);

    public const int MaxLength = 16 * 1024;
    private const int MaxOrganizations = 1000;

    /// <summary>
    /// Validates a statement for one request: the signature (HS256 with the gateway key), its type, issuer and audience, that it was
    /// made for this method and request target, and its lifetime. Returns null with a reason otherwise; the reason is for logs only.
    /// </summary>
    public static EasyRmmStatement? Validate(string token, byte[] key, string method, string target, DateTimeOffset now, out string reason)
    {
        reason = "malformed";
        if (token.Length is 0 or > MaxLength)
        {
            return null;
        }

        var parts = token.Split('.');
        if (parts.Length != 3 || !TryDecode(parts[0], out var header) || !TryDecode(parts[1], out var payload) || !TryDecode(parts[2], out var signature))
        {
            return null;
        }

        // The signature first: nothing else in an unsigned statement is worth reading.
        var expected = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]));
        if (!CryptographicOperations.FixedTimeEquals(expected, signature))
        {
            reason = "bad signature";
            return null;
        }

        try
        {
            using var h = JsonDocument.Parse(header);
            if (Text(h.RootElement, "alg") != "HS256" || Text(h.RootElement, "typ") != TokenType || h.RootElement.TryGetProperty("crit", out _))
            {
                reason = "wrong algorithm or type";
                return null;
            }

            using var p = JsonDocument.Parse(payload);
            var claims = p.RootElement;
            if (Text(claims, "iss") != Issuer || Text(claims, "aud") != Audience)
            {
                reason = "wrong issuer or audience";
                return null;
            }

            if (Text(claims, "htm") != method || Text(claims, "htu") != target)
            {
                reason = "made for another request";
                return null;
            }

            if (Seconds(claims, "iat") is not { } iat || Seconds(claims, "exp") is not { } exp)
            {
                return null;
            }

            var issued = DateTimeOffset.FromUnixTimeSeconds(iat);
            var expires = DateTimeOffset.FromUnixTimeSeconds(exp);
            if (expires <= issued || expires - issued > MaxLifetime || issued > now + Leeway || now >= expires + Leeway)
            {
                reason = "expired or not yet valid";
                return null;
            }

            var subject = Text(claims, "sub");
            var name = Text(claims, "name");
            if (subject is not { Length: > 0 and <= 128 } || subject.Any(char.IsControl) ||
                name is not { Length: > 0 and <= 254 } || name.Any(char.IsControl) ||
                Text(claims, "role") is not { } roleName || !Enum.GetNames<UserRole>().Contains(roleName, StringComparer.Ordinal) ||
                !claims.TryGetProperty("orgs", out var orgs))
            {
                return null;
            }

            var role = Enum.Parse<UserRole>(roleName);
            if (orgs.ValueKind == JsonValueKind.String && orgs.GetString() == "*")
            {
                return new EasyRmmStatement(subject, name, role, true, new HashSet<Guid>());
            }

            if (orgs.ValueKind != JsonValueKind.Array || orgs.GetArrayLength() > MaxOrganizations)
            {
                return null;
            }

            var ids = new HashSet<Guid>();
            foreach (var org in orgs.EnumerateArray())
            {
                if (org.ValueKind != JsonValueKind.String || !Guid.TryParse(org.GetString(), out var id))
                {
                    return null;
                }

                ids.Add(id);
            }

            return new EasyRmmStatement(subject, name, role, false, ids);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>A whole number of seconds, or null for anything else (TryGetInt64 throws on a value that is not a number).</summary>
    private static long? Seconds(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var seconds) && seconds is > 0 and < 253402300800
            ? seconds
            : null;

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool TryDecode(string part, out byte[] bytes)
    {
        try
        {
            bytes = Base64Url.DecodeFromChars(part);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}

public sealed class EasyRmmAuthenticationOptions : AuthenticationSchemeOptions;

/// <summary>
/// Authenticates EasyRMM's calls to its patching engine (the one-product plan, phase B2): a statement in <c>X-EasyRMM-Assertion</c>
/// (<see cref="EasyRmmStatement"/>). EasyRMM has applied its own sign-in rules, second factor and permissions before signing; the
/// statement carries the role and organizations that one call needs, and EasyPatch's own role and tenant checks still apply to them.
/// The principal is built from the statement alone: no user rows and no session.
/// </summary>
public sealed class EasyRmmAuthenticationHandler(
    IOptionsMonitor<EasyRmmAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    EasyRmmGateway gateway,
    TimeProvider clock) : AuthenticationHandler<EasyRmmAuthenticationOptions>(options, logger, encoder)
{
    public const string SchemeName = "EasyRmm";
    public const string HeaderName = "X-EasyRMM-Assertion";

    /// <summary>The audit name of a statement's actor: <c>easyrmm:&lt;name&gt;</c>.</summary>
    public const string ActorPrefix = ActorContextExtensions.EasyRmmPrefix;

    /// <summary>True when the request carries a statement; such a request is authenticated by it alone.</summary>
    public static bool HasAssertion(HttpRequest request) => request.Headers.ContainsKey(HeaderName);

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderName, out var values))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (gateway.Key is null)
        {
            return Task.FromResult(AuthenticateResult.Fail("This server is not an EasyRMM server's patching engine."));
        }

        var target = Context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target))
        {
            target = Request.PathBase + Request.Path + Request.QueryString;
        }

        var reason = "more than one statement";
        var statement = values.Count == 1 && values[0] is { } token
            ? EasyRmmStatement.Validate(token, gateway.Key, Request.Method, target, clock.GetUtcNow(), out reason)
            : null;
        if (statement is null)
        {
            // The reason, never the statement: it is a credential for as long as it lives.
            Logger.LogWarning("Refused a statement from EasyRMM for {Method} {Path}: {Reason}.",
                LogSafe(Request.Method), LogSafe(Request.Path.Value), reason);
            return Task.FromResult(AuthenticateResult.Fail("The statement from EasyRMM is not valid for this request."));
        }

        var claims = new List<Claim>
        {
            new(EasyPatchClaims.EasyRmmSubject, statement.Subject),
            new(EasyPatchClaims.Username, ActorPrefix + statement.Name),
            new(EasyPatchClaims.Role, statement.Role.ToString()),
            new(EasyPatchClaims.AllOrganizations, statement.AllOrganizations ? "true" : "false"),
        };
        claims.AddRange(statement.Organizations.Select(id => new Claim(EasyPatchClaims.Organization, id.ToString())));
        var identity = new ClaimsIdentity(claims, SchemeName, EasyPatchClaims.Username, EasyPatchClaims.Role);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status401Unauthorized, "unauthenticated", "The statement from EasyRMM is not valid.");

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status403Forbidden, "forbidden", "This call does not have permission to perform this action.");

    // What the caller sent, with its line breaks escaped: whoever reads the log as plain text must not take a
    // line the caller wrote for one of the server's.
    private static string LogSafe(string? value) =>
        (value ?? "").Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
}
