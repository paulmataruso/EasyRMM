using System.Security.Cryptography;
using System.Text;
using EasyPatch.Contracts.Security;
using Microsoft.AspNetCore.DataProtection;

namespace EasyPatch.Api.Security;

/// <summary>
/// CSRF protection for cookie-authenticated requests. The token is an authenticated-encryption blob (ASP.NET Core
/// Data Protection) binding the session ID. The SPA reads it from the <c>XSRF-TOKEN</c> cookie and echoes it in the
/// <c>X-XSRF-TOKEN</c> header; a cross-site attacker can neither read the cookie nor forge a token for the session.
/// SameSite=Strict on the session cookie is a second, independent layer.
/// </summary>
public sealed class CsrfProtection(IDataProtectionProvider provider)
{
    public const string CookieName = "XSRF-TOKEN";
    public const string HeaderName = "X-XSRF-TOKEN";
    private readonly IDataProtector protector = provider.CreateProtector("EasyPatch.Csrf.v1");

    public static CookieOptions CookieOptions() => new()
    {
        HttpOnly = false, // the SPA must read it
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        IsEssential = true,
    };

    public string CreateToken(Guid sessionId) =>
        RequestSigner.Base64UrlEncode(protector.Protect(Encoding.UTF8.GetBytes(sessionId.ToString("N"))));

    public void IssueCookie(HttpContext context, Guid sessionId) =>
        context.Response.Cookies.Append(CookieName, CreateToken(sessionId), CookieOptions());

    public bool Validate(string? token, Guid sessionId)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 1024)
        {
            return false;
        }

        try
        {
            var payload = protector.Unprotect(Base64UrlDecode(token));
            var expected = Encoding.UTF8.GetBytes(sessionId.ToString("N"));
            return CryptographicOperations.FixedTimeEquals(payload, expected);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + ((4 - (s.Length % 4)) % 4), '=');
        return Convert.FromBase64String(s);
    }
}

/// <summary>Rejects unsafe-method requests authenticated by the session cookie unless they carry a valid CSRF token.</summary>
public sealed class CsrfMiddleware(RequestDelegate next, CsrfProtection csrf)
{
    /// <summary>Routes that do not act on behalf of an existing session (a stale cookie must not block them).</summary>
    private static readonly PathString[] Exempt =
    [
        "/api/v1/auth/login", "/api/v1/auth/password/reset",
        // Passkey sign-in: the finish request must come from the browser holding the SameSite=Strict binding cookie set by the start.
        "/api/v1/auth/passkey/options", "/api/v1/auth/passkey",
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        if (!Exempt.Any(p => context.Request.Path.Equals(p, StringComparison.OrdinalIgnoreCase)) &&
            !HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method) &&
            !HttpMethods.IsOptions(context.Request.Method) &&
            context.User.Identity is { IsAuthenticated: true, AuthenticationType: SessionAuthenticationHandler.SchemeName })
        {
            var sid = context.User.FindFirst(EasyPatchClaims.SessionId)?.Value;
            var header = context.Request.Headers[CsrfProtection.HeaderName].ToString();
            if (sid is null || !Guid.TryParse(sid, out var sessionId) || !csrf.Validate(header, sessionId))
            {
                await ProblemResults.WriteAsync(context, StatusCodes.Status403Forbidden, "csrf_failed",
                    "The request could not be verified. Reload the page and try again.");
                return;
            }
        }

        await next(context);
    }
}
