using System.Buffers;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Security;

public sealed class AgentAuthenticationOptions : AuthenticationSchemeOptions
{
    public long MaxBodyBytes { get; set; } = 16 * 1024 * 1024;
}

/// <summary>
/// Verifies ECDSA P-256 signed agent requests: timestamp within ±5 minutes, single-use nonce, body SHA-256, and a
/// signature over the canonical request by the credential's registered public key. Credentials starting with
/// <c>r_</c> are pending enrollment requests and may only poll their enrollment status.
/// </summary>
public sealed class AgentAuthenticationHandler(
    IOptionsMonitor<AgentAuthenticationOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    CredentialCache credentials,
    NonceStore nonces,
    TimeProvider clock) : AuthenticationHandler<AgentAuthenticationOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = "Agent";
    public const string KindActive = "active";
    public const string KindPending = "pending";
    private const string FailureCodeKey = "easypatch.agent_auth_failure";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var headers = Request.Headers;
        var credentialId = headers[AgentAuthHeaders.Credential].ToString();
        if (string.IsNullOrEmpty(credentialId))
        {
            return AuthenticateResult.NoResult();
        }

        if (credentialId.Length > 64 || !(credentialId.StartsWith("c_", StringComparison.Ordinal) || credentialId.StartsWith("r_", StringComparison.Ordinal)))
        {
            return Failure(AgentErrorCodes.UnknownCredential);
        }

        if (!long.TryParse(headers[AgentAuthHeaders.Timestamp].ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp))
        {
            return Failure(AgentErrorCodes.InvalidSignature);
        }

        var now = clock.GetUtcNow();
        if (Math.Abs(now.ToUnixTimeSeconds() - timestamp) > (long)RequestSigner.AllowedClockSkew.TotalSeconds)
        {
            return Failure(AgentErrorCodes.ClockSkew);
        }

        var nonce = headers[AgentAuthHeaders.Nonce].ToString();
        var contentHash = headers[AgentAuthHeaders.ContentSha256].ToString();
        var signature = headers[AgentAuthHeaders.Signature].ToString();
        if (!RequestSigner.IsValidNonce(nonce) || contentHash.Length != 64 || string.IsNullOrEmpty(signature) || signature.Length > 200)
        {
            return Failure(AgentErrorCodes.InvalidSignature);
        }

        var bodyHash = await HashBodyAsync();
        if (bodyHash is null)
        {
            return Failure(AgentErrorCodes.ValidationFailed);
        }

        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(bodyHash), Encoding.ASCII.GetBytes(contentHash.ToLowerInvariant())))
        {
            return Failure(AgentErrorCodes.InvalidSignature);
        }

        var pending = credentialId.StartsWith("r_", StringComparison.Ordinal);
        AgentCredentialInfo? active = null;
        PendingRequestInfo? request = null;
        byte[]? publicKey;
        if (pending)
        {
            request = await credentials.GetPendingAsync(credentialId, Context.RequestAborted);
            publicKey = request?.PublicKey;
        }
        else
        {
            active = await credentials.GetAsync(credentialId, Context.RequestAborted);
            publicKey = active?.PublicKey;
        }

        if (publicKey is null)
        {
            return Failure(AgentErrorCodes.UnknownCredential);
        }

        var target = Context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(target) || !target.StartsWith('/'))
        {
            target = Request.PathBase.ToUriComponent() + Request.Path.ToUriComponent() + Request.QueryString.ToUriComponent();
        }

        var canonical = RequestSigner.BuildCanonicalString(Request.Method, target, timestamp, nonce, contentHash.ToLowerInvariant(), credentialId);
        bool valid;
        try
        {
            using var key = AgentKeys.ImportPublicKey(publicKey);
            valid = RequestSigner.Verify(key, canonical, signature);
        }
        catch (CryptographicException)
        {
            valid = false;
        }

        if (!valid)
        {
            return Failure(AgentErrorCodes.InvalidSignature);
        }

        // Only consume nonces for authentic requests so unauthenticated traffic cannot fill the store.
        if (!nonces.TryUse(credentialId, nonce, RequestSigner.AllowedClockSkew * 2))
        {
            return Failure(AgentErrorCodes.ReplayedNonce);
        }

        var claims = new List<Claim> { new(EasyPatchClaims.CredentialId, credentialId) };
        if (active is not null)
        {
            if (active.RevokedAt is not null)
            {
                return Failure(AgentErrorCodes.CredentialRevoked);
            }

            if (active.EndpointStatus != EndpointStatus.Active)
            {
                return Failure(AgentErrorCodes.EndpointRevoked);
            }

            if (active.ExpiresAt <= now)
            {
                return Failure(AgentErrorCodes.CredentialExpired);
            }

            claims.Add(new Claim(EasyPatchClaims.AgentKind, KindActive));
            claims.Add(new Claim(EasyPatchClaims.CredentialDbId, active.CredentialDbId.ToString()));
            claims.Add(new Claim(EasyPatchClaims.EndpointId, active.EndpointId.ToString()));
            claims.Add(new Claim(EasyPatchClaims.OrganizationId, active.OrganizationId.ToString()));
            Context.Items[typeof(AgentCredentialInfo)] = active;
        }
        else
        {
            claims.Add(new Claim(EasyPatchClaims.AgentKind, KindPending));
            Context.Items[typeof(PendingRequestInfo)] = request;
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var code = Context.Items[FailureCodeKey] as string ?? AgentErrorCodes.InvalidSignature;
        var message = code switch
        {
            AgentErrorCodes.ClockSkew => "The request timestamp is outside the allowed window. Synchronize the clock using serverTime.",
            AgentErrorCodes.ReplayedNonce => "The request nonce was already used.",
            AgentErrorCodes.UnknownCredential => "The agent credential is not recognized.",
            AgentErrorCodes.CredentialRevoked => "The agent credential has been revoked.",
            AgentErrorCodes.CredentialExpired => "The agent credential has expired. Re-enroll the agent.",
            AgentErrorCodes.EndpointRevoked => "This endpoint has been revoked or decommissioned.",
            AgentErrorCodes.ValidationFailed => "The request body is too large or could not be read.",
            _ => "The request signature is not valid.",
        };
        var status = code == AgentErrorCodes.ValidationFailed ? StatusCodes.Status413PayloadTooLarge : StatusCodes.Status401Unauthorized;
        return ProblemResults.WriteAsync(Context, status, code, message,
            new Dictionary<string, object?> { ["serverTime"] = clock.GetUtcNow() });
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ProblemResults.WriteAsync(Context, StatusCodes.Status403Forbidden, AgentErrorCodes.EnrollmentInvalid,
            "This credential is not permitted to call this route.");

    private AuthenticateResult Failure(string code)
    {
        Context.Items[FailureCodeKey] = code;
        if (code is not AgentErrorCodes.ClockSkew)
        {
            Logger.LogInformation("Agent authentication failed with {Code} from {Ip}", code, Context.Connection.RemoteIpAddress);
        }

        return AuthenticateResult.Fail(code);
    }

    private async Task<string?> HashBodyAsync()
    {
        var limit = Options.MaxBodyBytes;
        if (Request.ContentLength is { } length && length > limit)
        {
            return null;
        }

        Request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: limit);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long total = 0;
            int read;
            while ((read = await Request.Body.ReadAsync(buffer.AsMemory(0, buffer.Length), Context.RequestAborted)) > 0)
            {
                total += read;
                if (total > limit)
                {
                    return null;
                }

                sha.AppendData(buffer, 0, read);
            }
        }
        catch (IOException)
        {
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        Request.Body.Position = 0;
        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }
}
