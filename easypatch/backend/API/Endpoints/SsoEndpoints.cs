using System.Text.RegularExpressions;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>
/// Single sign-on with OpenID Connect. The browser goes to <c>/auth/sso/{id}/start</c>, which sends it to the provider; the provider
/// sends it back to <c>/auth/sso/callback</c>, which signs it in and redirects into the console (or to the sign-in page with
/// <c>?sso_error=</c>). Providers are configured by super administrators under <c>/sso/providers</c>.
/// </summary>
public static partial class SsoEndpoints
{
    /// <summary>Binds a sign-in at a provider to the browser that started it. <c>SameSite=Lax</c>, because the provider's redirect back
    /// is a cross-site navigation (a <c>Strict</c> cookie would not be sent with it).</summary>
    public const string BindingCookie = "__Host-easypatch-sso";

    public static void MapSsoEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/api/v1/auth/sso").WithTags("Authentication");

        auth.MapGet("/providers", async (EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.OidcProviders.AsNoTracking().Where(p => p.Enabled).OrderBy(p => p.DisplayName)
                .Select(p => new SsoProviderSummaryDto(p.Id, p.DisplayName)).ToListAsync(ct)))
            .AllowAnonymous();

        auth.MapGet("/{id:guid}/start", async (Guid id, string? returnTo, OidcService sso, HttpContext http, TimeProvider clock, CancellationToken ct) =>
        {
            var start = await sso.StartAsync(id, returnTo, ct);
            if (start.Binding is not null)
            {
                http.Response.Cookies.Append(BindingCookie, start.Binding, Cookie(clock.GetUtcNow() + OidcService.StateLifetime));
            }

            NoStore(http);
            return Results.Redirect(start.Redirect);
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);

        auth.MapGet("/callback", async (string? code, string? state, string? error, OidcService sso, CsrfProtection csrf, HttpContext http,
            CancellationToken ct) =>
        {
            var binding = http.Request.Cookies[BindingCookie];
            http.Response.Cookies.Delete(BindingCookie, Cookie(null));
            var ua = http.Request.Headers.UserAgent.ToString();
            var result = await sso.CompleteAsync(state, code, error, binding, http.Connection.RemoteIpAddress?.ToString(),
                ua.Length > 0 ? ua[..Math.Min(ua.Length, 512)] : null, ct);
            if (result.Session is { } session)
            {
                SessionCookies.Issue(http, result.SessionToken!, session.ExpiresAt);
                csrf.IssueCookie(http, session.Id);
            }

            NoStore(http);
            return Results.Redirect(result.Redirect);
        }).AllowAnonymous().RequireRateLimiting(RateLimits.Login);

        // ---- Administration (super administrators) ----

        var admin = app.MapGroup("/api/v1/sso/providers").WithTags("Single sign-on").RequireAuthorization(Policies.SuperAdmin);

        admin.MapGet("/", async (EasyPatchDbContext db, OidcService sso, CancellationToken ct) =>
            TypedResults.Ok(new SsoSettingsDto(sso.RedirectUri, await ProvidersAsync(db, null, ct))));

        admin.MapPost("/", async (SsoProviderRequest request, EasyPatchDbContext db, NotificationSecrets secrets, AuditService audit, TimeProvider clock,
            CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var provider = new OidcProvider { Id = Guid.CreateVersion7(now), DisplayName = "", Issuer = "", ClientId = "", CreatedAt = now };
            Apply(provider, request, secrets, now);
            db.OidcProviders.Add(provider);
            audit.Record("sso.provider_create", "OidcProvider", provider.Id.ToString(), details: AuditDetails(provider, request));
            await db.SaveChangesAsync(ct);
            return TypedResults.Created($"/api/v1/sso/providers/{provider.Id}", (await ProvidersAsync(db, provider.Id, ct)).Single());
        });

        admin.MapPut("/{id:guid}", async (Guid id, SsoProviderRequest request, EasyPatchDbContext db, NotificationSecrets secrets, OidcService sso,
            AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var provider = await db.OidcProviders.FirstOrDefaultAsync(p => p.Id == id, ct) ?? throw AppException.NotFound("Provider");
            var issuer = provider.Issuer;
            Apply(provider, request, secrets, clock.GetUtcNow());
            sso.Forget(issuer);
            audit.Record("sso.provider_update", "OidcProvider", provider.Id.ToString(), details: AuditDetails(provider, request));
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok((await ProvidersAsync(db, provider.Id, ct)).Single());
        });

        admin.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, OidcService sso, AuditService audit, CancellationToken ct) =>
        {
            var provider = await db.OidcProviders.FirstOrDefaultAsync(p => p.Id == id, ct) ?? throw AppException.NotFound("Provider");
            var links = await db.ExternalLogins.CountAsync(l => l.ProviderId == id, ct);
            db.OidcProviders.Remove(provider); // its links to users go with it
            sso.Forget(provider.Issuer);
            audit.Record("sso.provider_delete", "OidcProvider", id.ToString(), details: new { provider.DisplayName, provider.Issuer, linksRemoved = links });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        });

        admin.MapPost("/probe", async (SsoProbeRequest request, OidcService sso, CancellationToken ct) =>
        {
            var issuer = ValidIssuer(request.Issuer) ?? throw AppException.BadRequest("Enter the issuer as an https:// URL.", "validation_failed");
            var p = await sso.ProbeAsync(issuer, ct);
            return TypedResults.Ok(new SsoProbeDto(p.Ok, p.Issuer, p.AuthorizationEndpoint, p.TokenEndpoint, p.SigningKeys, p.Message));
        });
    }

    private static async Task<List<SsoProviderDto>> ProvidersAsync(EasyPatchDbContext db, Guid? id, CancellationToken ct) =>
        await db.OidcProviders.AsNoTracking().Where(p => id == null || p.Id == id).OrderBy(p => p.DisplayName)
            .Select(p => new SsoProviderDto(p.Id, p.DisplayName, p.Issuer, p.ClientId, p.ClientSecretProtected != null, p.Scopes, p.Enabled,
                p.TrustEmailClaim, p.ProviderEnforcesMfa, p.AutoProvision, p.DefaultRole, p.AllowedDomains,
                db.ExternalLogins.Count(l => l.ProviderId == p.Id), p.CreatedAt, p.UpdatedAt))
            .ToListAsync(ct);

    private static void Apply(OidcProvider provider, SsoProviderRequest request, NotificationSecrets secrets, DateTimeOffset now)
    {
        var v = new Validator()
            .Required("displayName", request.DisplayName, 64)
            .Required("clientId", request.ClientId, 256);
        var issuer = ValidIssuer(request.Issuer);
        v.Check(issuer is not null, "issuer", "Enter the issuer as an https:// URL without a query, for example https://login.microsoftonline.com/<tenant-id>/v2.0.");
        v.Check(request.ClientSecret is null || request.ClientSecret.Length <= 1024, "clientSecret", "At most 1024 characters.");
        var scopes = string.IsNullOrWhiteSpace(request.Scopes)
            ? OidcService.DefaultScopes
            : string.Join(' ', request.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct());
        v.Check(scopes.Length <= 512 && scopes.Split(' ').All(s => ScopeToken().IsMatch(s)), "scopes", "Scopes are separated by spaces.");
        v.Check(scopes.Split(' ').Contains("openid"), "scopes", "The scopes must include openid.");
        v.Check(Enum.IsDefined(request.DefaultRole), "defaultRole", "Unknown role.");
        v.Check(request.DefaultRole != UserRole.SuperAdmin, "defaultRole", "Accounts created by single sign-on cannot be super administrators.");
        var domains = (request.AllowedDomains ?? []).Select(d => d.Trim().TrimStart('@').ToLowerInvariant()).Where(d => d.Length > 0).Distinct().ToList();
        v.Check(domains.Count <= 50, "allowedDomains", "At most 50 domains.");
        v.Check(domains.All(d => d.Length <= 253 && d.Contains('.', StringComparison.Ordinal) && Uri.CheckHostName(d) == UriHostNameType.Dns),
            "allowedDomains", "Enter domain names such as example.com.");
        v.Check(!request.AutoProvision || domains.Count > 0, "allowedDomains", "List the email domains for which accounts may be created.");
        v.ThrowIfInvalid();

        provider.DisplayName = request.DisplayName.Trim();
        provider.Issuer = issuer!;
        provider.ClientId = request.ClientId.Trim();
        if (request.ClientSecret is not null)
        {
            provider.ClientSecretProtected = request.ClientSecret.Length == 0 ? null : secrets.Protect(request.ClientSecret);
        }

        provider.Scopes = scopes;
        provider.Enabled = request.Enabled;
        provider.TrustEmailClaim = request.TrustEmailClaim;
        provider.ProviderEnforcesMfa = request.ProviderEnforcesMfa;
        provider.AutoProvision = request.AutoProvision;
        provider.DefaultRole = request.DefaultRole;
        provider.AllowedDomains = domains;
        provider.UpdatedAt = now;
    }

    /// <summary>An absolute https URL without query or fragment, at most 512 characters; null otherwise.</summary>
    private static string? ValidIssuer(string? value)
    {
        var issuer = value?.Trim();
        return issuer is { Length: > 0 and <= 512 } && Uri.TryCreate(issuer, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
               uri.Query.Length == 0 && uri.Fragment.Length == 0 && uri.UserInfo.Length == 0
            ? issuer
            : null;
    }

    private static object AuditDetails(OidcProvider p, SsoProviderRequest request) => new
    {
        p.DisplayName,
        p.Issuer,
        p.ClientId,
        SecretChanged = request.ClientSecret is not null,
        p.Scopes,
        p.Enabled,
        p.TrustEmailClaim,
        p.ProviderEnforcesMfa,
        p.AutoProvision,
        p.DefaultRole,
        p.AllowedDomains,
    };

    private static CookieOptions Cookie(DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };

    private static void NoStore(HttpContext http)
    {
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers["Referrer-Policy"] = "no-referrer"; // the callback URL carries the authorization code
    }

    /// <summary>RFC 6749 scope-token characters.</summary>
    [GeneratedRegex(@"^[\x21\x23-\x5B\x5D-\x7E]{1,64}$")]
    private static partial Regex ScopeToken();
}
