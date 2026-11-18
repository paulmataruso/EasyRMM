using System.Net;
using System.Text.Json;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Infrastructure.Services;

public sealed record CreatedToken(EnrollmentToken Token, string PlaintextToken);

/// <summary>Agent enrollment (token and approval flows), credential rotation, revocation and decommissioning.</summary>
public sealed class EnrollmentService(
    EasyPatchDbContext db,
    SettingsService settingsService,
    PolicyService policies,
    CredentialCache credentialCache,
    AuditService audit,
    IActorContext actor,
    TimeProvider clock,
    ILogger<EnrollmentService> logger)
{
    public const string TokenPrefix = "ept_";
    public const string DeploymentCodePrefix = "EPD-";
    public const string Algorithm = "ECDSA_P256";

    // -------------------------------------------------------------------------------------------
    // Administrator: tokens, deployment codes, approval
    // -------------------------------------------------------------------------------------------

    public async Task<IReadOnlyList<CreatedToken>> CreateTokensAsync(Guid organizationId, Guid? siteId, string? description,
        int expiresInHours, int maxUses, int count, CancellationToken ct = default)
    {
        if (expiresInHours is < 1 or > 24 * 30)
        {
            throw AppException.BadRequest("Token lifetime must be between 1 hour and 30 days.", "validation_failed");
        }

        if (maxUses is < 1 or > 1000)
        {
            throw AppException.BadRequest("Max uses must be between 1 and 1000.", "validation_failed");
        }

        if (count is < 1 or > 500)
        {
            throw AppException.BadRequest("Between 1 and 500 tokens can be generated at once.", "validation_failed");
        }

        await EnsureScopeAsync(organizationId, siteId, ct);
        var now = clock.GetUtcNow();
        var created = new List<CreatedToken>();
        for (var i = 0; i < count; i++)
        {
            var plaintext = SecureTokens.Create(TokenPrefix);
            var token = new EnrollmentToken
            {
                Id = Guid.CreateVersion7(now),
                OrganizationId = organizationId,
                SiteId = siteId,
                TokenHash = SecureTokens.Hash(plaintext),
                TokenPrefix = plaintext[..10],
                Description = ScanIngestionService.Truncate(description, 500),
                MaxUses = maxUses,
                CreatedAt = now,
                CreatedByUserId = actor.UserId,
                ExpiresAt = now.AddHours(expiresInHours),
            };
            db.EnrollmentTokens.Add(token);
            created.Add(new CreatedToken(token, plaintext));
        }

        audit.Record("enrollment_token.create", "EnrollmentToken", null, organizationId, null,
            new { count, maxUses, expiresInHours, siteId, description });
        await db.SaveChangesAsync(ct);
        return created;
    }

    public async Task RevokeTokenAsync(Guid tokenId, CancellationToken ct = default)
    {
        var token = await db.EnrollmentTokens.FirstOrDefaultAsync(t => t.Id == tokenId, ct) ?? throw AppException.NotFound("Enrollment token");
        token.RevokedAt ??= clock.GetUtcNow();
        audit.Record("enrollment_token.revoke", "EnrollmentToken", token.Id.ToString(), token.OrganizationId);
        await db.SaveChangesAsync(ct);
    }

    public async Task<DeploymentCode> CreateDeploymentCodeAsync(Guid organizationId, Guid? siteId, string name, int? expiresInDays,
        IReadOnlyList<string> allowedCidrs, int maxPending, CancellationToken ct = default)
    {
        await EnsureScopeAsync(organizationId, siteId, ct);
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200)
        {
            throw AppException.BadRequest("A name (up to 200 characters) is required.", "validation_failed");
        }

        if (expiresInDays is < 1 or > 3650)
        {
            throw AppException.BadRequest("Expiry must be between 1 and 3650 days.", "validation_failed");
        }

        if (maxPending is < 1 or > 10_000)
        {
            throw AppException.BadRequest("Max pending requests must be between 1 and 10000.", "validation_failed");
        }

        foreach (var cidr in allowedCidrs)
        {
            if (!IPNetwork.TryParse(cidr, out _))
            {
                throw AppException.BadRequest($"'{cidr}' is not a valid CIDR range.", "validation_failed");
            }
        }

        var now = clock.GetUtcNow();
        var code = new DeploymentCode
        {
            Id = Guid.CreateVersion7(now),
            Code = SecureTokens.CreateCode(DeploymentCodePrefix, 16),
            Name = name.Trim(),
            OrganizationId = organizationId,
            SiteId = siteId,
            MaxPendingRequests = maxPending,
            AllowedSourceCidrs = allowedCidrs.Select(c => c.Trim()).ToList(),
            CreatedAt = now,
            CreatedByUserId = actor.UserId,
            ExpiresAt = expiresInDays is { } days ? now.AddDays(days) : null,
        };
        db.DeploymentCodes.Add(code);
        audit.Record("deployment_code.create", "DeploymentCode", code.Id.ToString(), organizationId, null, new { name, siteId, expiresInDays });
        await db.SaveChangesAsync(ct);
        return code;
    }

    public async Task RevokeDeploymentCodeAsync(Guid id, CancellationToken ct = default)
    {
        var code = await db.DeploymentCodes.FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Deployment code");
        var now = clock.GetUtcNow();
        code.RevokedAt ??= now;
        await db.EnrollmentRequests.Where(r => r.DeploymentCodeId == id && r.Status == EnrollmentRequestStatus.Pending)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, EnrollmentRequestStatus.Rejected)
                .SetProperty(r => r.RejectReason, "Deployment code revoked")
                .SetProperty(r => r.DecidedAt, now), ct);
        audit.Record("deployment_code.revoke", "DeploymentCode", code.Id.ToString(), code.OrganizationId);
        await db.SaveChangesAsync(ct);
    }

    public async Task<Endpoint> ApproveAsync(Guid requestId, Guid? organizationId, Guid? siteId, CancellationToken ct = default)
    {
        var request = await db.EnrollmentRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct) ?? throw AppException.NotFound("Enrollment request");
        if (request.Status != EnrollmentRequestStatus.Pending)
        {
            throw AppException.Conflict($"The request is already {request.Status}.", "invalid_state");
        }

        var now = clock.GetUtcNow();
        if (request.ExpiresAt <= now)
        {
            request.Status = EnrollmentRequestStatus.Expired;
            await db.SaveChangesAsync(ct);
            throw AppException.Conflict("The enrollment request has expired. Re-run the installer on the endpoint.", "expired");
        }

        var targetOrg = organizationId ?? request.OrganizationId;
        var targetSite = organizationId is not null && organizationId != request.OrganizationId ? siteId : siteId ?? request.SiteId;
        await EnsureScopeAsync(targetOrg, targetSite, ct);
        var device = JsonSerializer.Deserialize<DeviceIdentity>(request.DeviceJson, ContractJson.Options)
                     ?? new DeviceIdentity { Hostname = request.Hostname };
        var settings = await settingsService.GetAsync(ct);
        var (endpoint, _) = await CreateOrReuseEndpointAsync(targetOrg, targetSite, device, request.AgentVersion, request.PublicKey,
            request.KeyFingerprint, settings.CredentialLifetimeDays, null, request.Id, now, ct);
        request.Status = EnrollmentRequestStatus.Approved;
        request.DecidedAt = now;
        request.DecidedByUserId = actor.UserId;
        request.EndpointId = endpoint.Id;
        audit.Record("enrollment_request.approve", "EnrollmentRequest", request.Id.ToString(), targetOrg, endpoint.Id,
            new { request.Hostname, request.KeyFingerprint, request.SourceIp });
        await db.SaveChangesAsync(ct);
        credentialCache.InvalidatePending(request.RequestId);
        return endpoint;
    }

    public async Task RejectAsync(Guid requestId, string? reason, CancellationToken ct = default)
    {
        var request = await db.EnrollmentRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct) ?? throw AppException.NotFound("Enrollment request");
        if (request.Status != EnrollmentRequestStatus.Pending)
        {
            throw AppException.Conflict($"The request is already {request.Status}.", "invalid_state");
        }

        request.Status = EnrollmentRequestStatus.Rejected;
        request.RejectReason = ScanIngestionService.Truncate(reason, 500);
        request.DecidedAt = clock.GetUtcNow();
        request.DecidedByUserId = actor.UserId;
        audit.Record("enrollment_request.reject", "EnrollmentRequest", request.Id.ToString(), request.OrganizationId, null,
            new { request.Hostname, reason });
        await db.SaveChangesAsync(ct);
        credentialCache.InvalidatePending(request.RequestId);
    }

    public async Task RevokeEndpointAsync(Guid endpointId, string reason, EndpointStatus status = EndpointStatus.Revoked, CancellationToken ct = default)
    {
        var endpoint = await db.Endpoints.FirstOrDefaultAsync(e => e.Id == endpointId, ct) ?? throw AppException.NotFound("Endpoint");
        var now = clock.GetUtcNow();
        var credentials = await db.AgentCredentials.Where(c => c.EndpointId == endpointId && c.RevokedAt == null).ToListAsync(ct);
        foreach (var credential in credentials)
        {
            credential.RevokedAt = now;
            credential.RevokedReason = reason;
            credentialCache.Invalidate(credential.CredentialId);
        }

        endpoint.Status = status;
        endpoint.IsOnline = false;
        endpoint.UpdatedAt = now;
        var openJobs = await db.Jobs.Include(j => j.Updates).Where(j => j.EndpointId == endpointId && j.CompletedAt == null).ToListAsync(ct);
        foreach (var job in openJobs.Where(j => !j.Status.IsTerminal()))
        {
            if (status == EndpointStatus.Decommissioned && job.Type == JobType.UninstallAgent)
            {
                // The agent itself reported its removal (the package's uninstall step unenrolls it): the uninstall worked.
                job.Phase = "Completed";
                job.ProgressPercent = 100;
                job.ProgressMessage = "The agent was removed and unenrolled from the server.";
                JobService.Finish(job, JobStatus.Completed, now, null);
                continue;
            }

            JobService.Finish(job, JobStatus.Cancelled, now,
                status == EndpointStatus.Decommissioned ? "The agent was uninstalled." : "Endpoint credentials were revoked.");
        }

        EndpointEvents.Add(db, endpoint, status == EndpointStatus.Revoked ? "CredentialsRevoked" : "Decommissioned", reason, now, EventSeverity.Warning);
        if (actor.IsAdministrator())
        {
            audit.Record("endpoint.revoke", "Endpoint", endpoint.Id.ToString(), endpoint.OrganizationId, endpoint.Id, new { reason });
        }

        await db.SaveChangesAsync(ct);
    }

    // -------------------------------------------------------------------------------------------
    // Agent: enroll, poll, rotate, unenroll
    // -------------------------------------------------------------------------------------------

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, IPAddress? sourceIp, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var now = clock.GetUtcNow();
        ValidateDevice(request);
        if (!AgentKeys.TryParsePublicKey(request.PublicKey, out var spki))
        {
            throw AppException.BadRequest("The public key must be a base64 SubjectPublicKeyInfo for an ECDSA P-256 key.", AgentErrorCodes.EnrollmentInvalid);
        }

        var fingerprint = AgentKeys.Fingerprint(spki);
        var hasToken = !string.IsNullOrWhiteSpace(request.EnrollmentToken);
        var hasCode = !string.IsNullOrWhiteSpace(request.DeploymentCode);
        if (hasToken == hasCode)
        {
            throw AppException.BadRequest("Provide exactly one of enrollmentToken or deploymentCode.", AgentErrorCodes.EnrollmentInvalid);
        }

        // Idempotency: a retry with an already-registered key returns the existing identity.
        var existingCredential = await db.AgentCredentials.AsNoTracking().Include(c => c.Endpoint)
            .Where(c => c.KeyFingerprint == fingerprint && c.RevokedAt == null)
            .ToListAsync(ct);
        var match = existingCredential.FirstOrDefault(c => c.PublicKey.AsSpan().SequenceEqual(spki));
        if (match is not null && match.Endpoint is { Status: EndpointStatus.Active })
        {
            var policy = await policies.ResolveAsync(match.Endpoint, ct);
            return ActiveResponse(match.Endpoint, match, fingerprint, policy.ToAgentConfig(), now);
        }

        return hasToken
            ? await EnrollWithTokenAsync(request, spki, fingerprint, now, ct)
            : await EnrollWithDeploymentCodeAsync(request, spki, fingerprint, sourceIp, now, ct);
    }

    private async Task<EnrollResponse> EnrollWithTokenAsync(EnrollRequest request, byte[] spki, string fingerprint, DateTimeOffset now, CancellationToken ct)
    {
        var hash = SecureTokens.Hash(request.EnrollmentToken!.Trim());
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var token = (await db.EnrollmentTokens.FromSql($"SELECT * FROM enrollment_tokens WHERE token_hash = {hash} FOR UPDATE").ToListAsync(ct))
            .FirstOrDefault();
        if (token is null || token.RevokedAt is not null || token.ExpiresAt <= now || token.UseCount >= token.MaxUses)
        {
            logger.LogWarning("Rejected enrollment with an invalid, expired, revoked or exhausted token (prefix {Prefix})",
                token?.TokenPrefix ?? "unknown");
            throw AppException.Unauthorized(AgentErrorCodes.EnrollmentInvalid, "The enrollment token is invalid, expired, revoked or already used.");
        }

        var organization = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == token.OrganizationId, ct);
        if (organization is not { IsActive: true })
        {
            throw AppException.Unauthorized(AgentErrorCodes.EnrollmentInvalid, "The organization for this token is archived.");
        }

        token.UseCount++;
        token.LastUsedAt = now;
        var settings = await settingsService.GetAsync(ct);
        var (endpoint, credential) = await CreateOrReuseEndpointAsync(token.OrganizationId, token.SiteId, request.Device, request.AgentVersion,
            spki, fingerprint, settings.CredentialLifetimeDays, token.Id, null, now, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        var policy = await policies.ResolveAsync(endpoint, ct);
        logger.LogInformation("Endpoint {EndpointId} ({Hostname}) enrolled with token {Prefix}", endpoint.Id, endpoint.Hostname, token.TokenPrefix);
        return ActiveResponse(endpoint, credential, fingerprint, policy.ToAgentConfig(), now);
    }

    private async Task<EnrollResponse> EnrollWithDeploymentCodeAsync(EnrollRequest request, byte[] spki, string fingerprint, IPAddress? sourceIp,
        DateTimeOffset now, CancellationToken ct)
    {
        var codeValue = request.DeploymentCode!.Trim().ToUpperInvariant();
        var code = await db.DeploymentCodes.AsNoTracking().FirstOrDefaultAsync(c => c.Code == codeValue, ct);
        if (code is null || code.RevokedAt is not null || (code.ExpiresAt is { } exp && exp <= now))
        {
            throw AppException.Unauthorized(AgentErrorCodes.EnrollmentInvalid, "The deployment code is invalid, expired or revoked.");
        }

        if (code.AllowedSourceCidrs.Count > 0 &&
            (sourceIp is null || !code.AllowedSourceCidrs.Any(c => IPNetwork.TryParse(c, out var net) && net.Contains(Normalize(sourceIp)))))
        {
            logger.LogWarning("Deployment-code enrollment from {Ip} rejected by the source allow-list", sourceIp);
            throw AppException.Unauthorized(AgentErrorCodes.EnrollmentInvalid, "Enrollment is not allowed from this network.");
        }

        var settings = await settingsService.GetAsync(ct);
        var existing = await db.EnrollmentRequests.FirstOrDefaultAsync(
            r => r.DeploymentCodeId == code.Id && r.KeyFingerprint == fingerprint && r.Status == EnrollmentRequestStatus.Pending, ct);
        if (existing is null)
        {
            var pending = await db.EnrollmentRequests.CountAsync(r => r.DeploymentCodeId == code.Id && r.Status == EnrollmentRequestStatus.Pending, ct);
            if (pending >= code.MaxPendingRequests)
            {
                throw new AppException(429, AgentErrorCodes.RateLimited, "Too many enrollment requests are awaiting approval for this deployment code.");
            }

            existing = new EnrollmentRequest
            {
                Id = Guid.CreateVersion7(now),
                RequestId = SecureTokens.NewEnrollmentRequestId(),
                DeploymentCodeId = code.Id,
                OrganizationId = code.OrganizationId,
                SiteId = code.SiteId,
                PublicKey = spki,
                KeyFingerprint = fingerprint,
                Hostname = ScanIngestionService.Truncate(request.Device.Hostname, 255)!,
                DeviceJson = JsonSerializer.Serialize(request.Device, ContractJson.Options),
                SerialNumber = ScanIngestionService.Truncate(request.Device.SerialNumber, 255),
                OsCaption = ScanIngestionService.Truncate(request.Device.OsCaption, 255),
                AgentVersion = ScanIngestionService.Truncate(request.AgentVersion, 64)!,
                SourceIp = sourceIp?.ToString(),
                Status = EnrollmentRequestStatus.Pending,
                CreatedAt = now,
                LastSeenAt = now,
                ExpiresAt = now.AddDays(settings.EnrollmentRequestExpiryDays),
            };
            db.EnrollmentRequests.Add(existing);
            logger.LogInformation("Enrollment request {RequestId} from {Hostname} ({Ip}) awaits approval; key fingerprint {Fingerprint}",
                existing.RequestId, existing.Hostname, sourceIp, fingerprint);
        }
        else
        {
            existing.LastSeenAt = now;
        }

        await db.SaveChangesAsync(ct);
        return new EnrollResponse
        {
            State = EnrollmentState.PendingApproval,
            CredentialId = existing.RequestId,
            KeyFingerprint = fingerprint,
            Message = "Enrollment is awaiting administrator approval.",
            ServerTime = now,
        };
    }

    /// <summary>Status poll for a pending enrollment, authenticated by the request's key.</summary>
    public async Task<EnrollResponse> GetPendingStatusAsync(string requestId, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var request = await db.EnrollmentRequests.FirstOrDefaultAsync(r => r.RequestId == requestId, ct)
                      ?? throw AppException.Unauthorized(AgentErrorCodes.UnknownCredential, "Unknown enrollment request.");
        request.LastSeenAt = now;
        if (request.Status == EnrollmentRequestStatus.Pending && request.ExpiresAt <= now)
        {
            request.Status = EnrollmentRequestStatus.Expired;
        }

        await db.SaveChangesAsync(ct);
        switch (request.Status)
        {
            case EnrollmentRequestStatus.Approved when request.EndpointId is { } endpointId:
            {
                var endpoint = await db.Endpoints.AsNoTracking().FirstAsync(e => e.Id == endpointId, ct);
                var credential = await db.AgentCredentials.AsNoTracking()
                    .Where(c => c.EndpointId == endpointId && c.KeyFingerprint == request.KeyFingerprint && c.RevokedAt == null)
                    .OrderByDescending(c => c.CreatedAt).FirstOrDefaultAsync(ct);
                if (credential is null || endpoint.Status != EndpointStatus.Active)
                {
                    return Terminal(EnrollmentState.Rejected, request, "The approved endpoint has since been revoked.", now);
                }

                var policy = await policies.ResolveAsync(endpoint, ct);
                return ActiveResponse(endpoint, credential, request.KeyFingerprint, policy.ToAgentConfig(), now);
            }

            case EnrollmentRequestStatus.Rejected:
                return Terminal(EnrollmentState.Rejected, request, request.RejectReason ?? "Rejected by an administrator.", now);
            case EnrollmentRequestStatus.Expired:
                return Terminal(EnrollmentState.Expired, request, "The enrollment request expired before it was approved.", now);
            default:
                return new EnrollResponse
                {
                    State = EnrollmentState.PendingApproval,
                    CredentialId = request.RequestId,
                    KeyFingerprint = request.KeyFingerprint,
                    Message = "Enrollment is awaiting administrator approval.",
                    ServerTime = now,
                };
        }
    }

    public async Task<RotateCredentialResponse> RotateAsync(Guid endpointId, string currentCredentialId, RotateCredentialRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AgentKeys.TryParsePublicKey(request.PublicKey, out var spki))
        {
            throw AppException.BadRequest("Invalid public key.", AgentErrorCodes.ValidationFailed);
        }

        var now = clock.GetUtcNow();
        var fingerprint = AgentKeys.Fingerprint(spki);
        var settings = await settingsService.GetAsync(ct);
        var current = await db.AgentCredentials.FirstOrDefaultAsync(c => c.CredentialId == currentCredentialId && c.EndpointId == endpointId, ct)
                      ?? throw AppException.Unauthorized(AgentErrorCodes.UnknownCredential, "Unknown credential.");

        // Idempotent: the same new key already registered for this endpoint.
        var already = (await db.AgentCredentials
                .Where(c => c.EndpointId == endpointId && c.KeyFingerprint == fingerprint && c.RevokedAt == null).ToListAsync(ct))
            .FirstOrDefault(c => c.PublicKey.AsSpan().SequenceEqual(spki));
        if (already is not null)
        {
            return new RotateCredentialResponse { CredentialId = already.CredentialId, ExpiresAt = already.ExpiresAt, KeyFingerprint = fingerprint };
        }

        var replacement = NewCredential(endpointId, spki, fingerprint, settings.CredentialLifetimeDays, now);
        db.AgentCredentials.Add(replacement);
        current.ReplacedById = replacement.Id;
        // Keep the old key valid briefly so in-flight requests signed with it still succeed.
        var grace = now.AddHours(1);
        if (current.ExpiresAt > grace)
        {
            current.ExpiresAt = grace;
        }

        var endpoint = await db.Endpoints.FirstAsync(e => e.Id == endpointId, ct);
        EndpointEvents.Add(db, endpoint, "CredentialRotated", $"Agent key rotated (new fingerprint {fingerprint}).", now);
        await db.SaveChangesAsync(ct);
        credentialCache.Invalidate(currentCredentialId);
        return new RotateCredentialResponse { CredentialId = replacement.CredentialId, ExpiresAt = replacement.ExpiresAt, KeyFingerprint = fingerprint };
    }

    public Task UnenrollAsync(Guid endpointId, string? reason, CancellationToken ct = default) =>
        RevokeEndpointAsync(endpointId,
            string.IsNullOrWhiteSpace(reason) || reason.Trim().TrimEnd('.').Equals("Agent uninstalled", StringComparison.OrdinalIgnoreCase)
                ? "Agent uninstalled."
                : $"Agent uninstalled: {ScanIngestionService.Truncate(reason, 200)}",
            EndpointStatus.Decommissioned, ct);

    // -------------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------------

    /// <summary>Creates a new endpoint, or re-associates an existing one in the same organization when the agent was
    /// reinstalled on the same machine (same SMBIOS UUID and hostname). Old credentials of a reused endpoint are revoked.</summary>
    private async Task<(Endpoint Endpoint, AgentCredential Credential)> CreateOrReuseEndpointAsync(
        Guid organizationId, Guid? siteId, DeviceIdentity device, string agentVersion, byte[] spki, string fingerprint,
        int credentialLifetimeDays, Guid? tokenId, Guid? requestId, DateTimeOffset now, CancellationToken ct)
    {
        Endpoint? endpoint = null;
        var uuid = NormalizeUuid(device.SmbiosUuid);
        if (uuid is not null)
        {
            endpoint = await db.Endpoints.FirstOrDefaultAsync(e =>
                e.OrganizationId == organizationId && e.SmbiosUuid == uuid && e.Hostname == device.Hostname &&
                e.Status != EndpointStatus.Decommissioned, ct);
        }

        if (endpoint is not null)
        {
            var oldCredentials = await db.AgentCredentials.Where(c => c.EndpointId == endpoint.Id && c.RevokedAt == null).ToListAsync(ct);
            foreach (var old in oldCredentials)
            {
                old.RevokedAt = now;
                old.RevokedReason = "Endpoint re-enrolled";
                credentialCache.Invalidate(old.CredentialId);
            }

            endpoint.Status = EndpointStatus.Active;
            endpoint.Platform = AgentPlatforms.Normalize(device.Platform) ?? endpoint.Platform;
            endpoint.SiteId = siteId ?? endpoint.SiteId;
            endpoint.AgentVersion = agentVersion;
            endpoint.EnrolledAt = now;
            endpoint.UpdatedAt = now;
            EndpointEvents.Add(db, endpoint, "ReEnrolled", $"Agent re-enrolled (key fingerprint {fingerprint}).", now, EventSeverity.Warning);
        }
        else
        {
            endpoint = new Endpoint
            {
                Id = Guid.CreateVersion7(now),
                OrganizationId = organizationId,
                SiteId = siteId,
                Hostname = ScanIngestionService.Truncate(device.Hostname, 255)!,
                DnsDomain = ScanIngestionService.Truncate(device.DnsDomain, 255),
                SmbiosUuid = uuid,
                SerialNumber = ScanIngestionService.Truncate(device.SerialNumber, 255),
                Manufacturer = ScanIngestionService.Truncate(device.Manufacturer, 255),
                Model = ScanIngestionService.Truncate(device.Model, 255),
                OperatingSystem = ScanIngestionService.Truncate(device.OsCaption, 255),
                Platform = AgentPlatforms.Normalize(device.Platform) ?? AgentPlatforms.Windows,
                OsId = ScanIngestionService.Truncate(device.OsId, 64),
                OsVersion = ScanIngestionService.Truncate(device.OsVersion, 255),
                Architecture = ScanIngestionService.Truncate(device.Architecture, 255),
                AgentVersion = ScanIngestionService.Truncate(agentVersion, 255),
                EnrolledAt = now,
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.Endpoints.Add(endpoint);
            EndpointEvents.Add(db, endpoint, "Enrolled", $"Agent enrolled (key fingerprint {fingerprint}).", now);
        }

        endpoint.EnrollmentTokenId = tokenId ?? endpoint.EnrollmentTokenId;
        endpoint.EnrollmentRequestId = requestId ?? endpoint.EnrollmentRequestId;
        var credential = NewCredential(endpoint.Id, spki, fingerprint, credentialLifetimeDays, now);
        db.AgentCredentials.Add(credential);
        return (endpoint, credential);
    }

    private static AgentCredential NewCredential(Guid endpointId, byte[] spki, string fingerprint, int lifetimeDays, DateTimeOffset now) => new()
    {
        Id = Guid.CreateVersion7(now),
        CredentialId = SecureTokens.NewCredentialId(),
        EndpointId = endpointId,
        PublicKey = spki,
        Algorithm = Algorithm,
        KeyFingerprint = fingerprint,
        CreatedAt = now,
        ExpiresAt = now.AddDays(lifetimeDays),
    };

    private static EnrollResponse ActiveResponse(Endpoint endpoint, AgentCredential credential, string fingerprint, AgentConfig config, DateTimeOffset now) => new()
    {
        State = EnrollmentState.Active,
        CredentialId = credential.CredentialId,
        EndpointId = endpoint.Id,
        OrganizationId = endpoint.OrganizationId,
        CredentialExpiresAt = credential.ExpiresAt,
        Config = config,
        KeyFingerprint = fingerprint,
        ServerTime = now,
    };

    private static EnrollResponse Terminal(EnrollmentState state, EnrollmentRequest request, string message, DateTimeOffset now) => new()
    {
        State = state,
        CredentialId = request.RequestId,
        KeyFingerprint = request.KeyFingerprint,
        Message = message,
        ServerTime = now,
    };

    private async Task EnsureScopeAsync(Guid organizationId, Guid? siteId, CancellationToken ct)
    {
        var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == organizationId, ct) ?? throw AppException.NotFound("Organization");
        if (!org.IsActive)
        {
            throw AppException.Conflict("The organization is archived.", "archived");
        }

        if (siteId is { } s && !await db.Sites.AnyAsync(x => x.Id == s && x.OrganizationId == organizationId && x.IsActive, ct))
        {
            throw AppException.BadRequest("The site does not belong to the organization or is archived.", "validation_failed");
        }
    }

    private static void ValidateDevice(EnrollRequest request)
    {
        if (request.Device is null || string.IsNullOrWhiteSpace(request.Device.Hostname) || request.Device.Hostname.Length > 255)
        {
            throw AppException.BadRequest("A device hostname is required.", AgentErrorCodes.ValidationFailed);
        }

        if (string.IsNullOrWhiteSpace(request.AgentVersion) || request.AgentVersion.Length > 64)
        {
            throw AppException.BadRequest("An agent version is required.", AgentErrorCodes.ValidationFailed);
        }
    }

    internal static string? NormalizeUuid(string? uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid))
        {
            return null;
        }

        var value = uuid.Trim().ToUpperInvariant();
        // Firmware placeholders are not unique.
        return value is "00000000-0000-0000-0000-000000000000" or "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" or "03000200-0400-0500-0006-000700080009"
            ? null
            : ScanIngestionService.Truncate(value, 255);
    }

    private static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
}
