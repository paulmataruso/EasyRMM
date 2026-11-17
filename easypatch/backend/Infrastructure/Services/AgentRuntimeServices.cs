using System.Collections.Concurrent;
using System.Text.Json;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Policy;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace EasyPatch.Infrastructure.Services;

public sealed record AgentCredentialInfo(
    Guid CredentialDbId, string CredentialId, Guid EndpointId, Guid OrganizationId, byte[] PublicKey,
    DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt, EndpointStatus EndpointStatus);

public sealed record PendingRequestInfo(Guid Id, string RequestId, byte[] PublicKey, EnrollmentRequestStatus Status);

/// <summary>Short-lived cache of agent public keys. Revocation evicts entries immediately (single API instance);
/// the TTL bounds staleness otherwise.</summary>
public sealed class CredentialCache(IMemoryCache cache, IServiceScopeFactory scopes)
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);

    public async Task<AgentCredentialInfo?> GetAsync(string credentialId, CancellationToken ct)
    {
        var key = "cred:" + credentialId;
        if (cache.TryGetValue(key, out AgentCredentialInfo? cached))
        {
            return cached;
        }

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<EasyPatchDbContext>();
        var info = await db.AgentCredentials.AsNoTracking()
            .Where(c => c.CredentialId == credentialId)
            .Select(c => new AgentCredentialInfo(c.Id, c.CredentialId, c.EndpointId, c.Endpoint!.OrganizationId, c.PublicKey,
                c.ExpiresAt, c.RevokedAt, c.Endpoint.Status))
            .FirstOrDefaultAsync(ct);
        cache.Set(key, info, Ttl);
        return info;
    }

    public async Task<PendingRequestInfo?> GetPendingAsync(string requestId, CancellationToken ct)
    {
        var key = "req:" + requestId;
        if (cache.TryGetValue(key, out PendingRequestInfo? cached))
        {
            return cached;
        }

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<EasyPatchDbContext>();
        var info = await db.EnrollmentRequests.AsNoTracking()
            .Where(r => r.RequestId == requestId)
            .Select(r => new PendingRequestInfo(r.Id, r.RequestId, r.PublicKey, r.Status))
            .FirstOrDefaultAsync(ct);
        cache.Set(key, info, Ttl);
        return info;
    }

    public void Invalidate(string credentialId) => cache.Remove("cred:" + credentialId);

    public void InvalidatePending(string requestId) => cache.Remove("req:" + requestId);
}

/// <summary>Replay protection: each (credential, nonce) pair is accepted once within the signature validity window.
/// In-memory, so the documented deployment runs a single API replica.</summary>
public sealed class NonceStore(TimeProvider clock)
{
    private const int MaxEntries = 1_000_000;
    private readonly ConcurrentDictionary<string, long> entries = new(StringComparer.Ordinal);
    private long operations;

    public bool TryUse(string credentialId, string nonce, TimeSpan lifetime)
    {
        var now = clock.GetUtcNow().UtcTicks;
        if (Interlocked.Increment(ref operations) % 1024 == 0 || entries.Count > MaxEntries)
        {
            foreach (var (k, expiry) in entries)
            {
                if (expiry <= now)
                {
                    entries.TryRemove(k, out _);
                }
            }
        }

        if (entries.Count > MaxEntries)
        {
            return false; // fail closed under abuse
        }

        return entries.TryAdd(credentialId + "|" + nonce, now + lifetime.Ticks);
    }
}

/// <summary>Buffers agent check-in presence in memory and writes it in batches, so heartbeats do not cost one
/// database write each.</summary>
public sealed class PresenceTracker(IServiceScopeFactory scopes, ILogger<PresenceTracker> logger)
{
    private sealed record Seen(DateTimeOffset At, Guid CredentialDbId, string? Ip, string? Activity);

    private ConcurrentDictionary<Guid, Seen> pending = new();

    public void Record(Guid endpointId, Guid credentialDbId, DateTimeOffset at, string? ip, string? activity) =>
        pending[endpointId] = new Seen(at, credentialDbId, ip, activity is { Length: > 255 } ? activity[..255] : activity);

    public async Task<int> FlushAsync(CancellationToken ct = default)
    {
        var batch = Interlocked.Exchange(ref pending, new ConcurrentDictionary<Guid, Seen>());
        if (batch.IsEmpty)
        {
            return 0;
        }

        var ids = batch.Keys.ToArray();
        var seen = ids.Select(id => batch[id].At).ToArray();
        var ips = ids.Select(id => batch[id].Ip).ToArray();
        var activities = ids.Select(id => batch[id].Activity).ToArray();
        var credentialIds = ids.Select(id => batch[id].CredentialDbId).ToArray();
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<EasyPatchDbContext>();
            await db.Database.ExecuteSqlRawAsync(
                """
                UPDATE endpoints AS e
                SET last_check_in_at = GREATEST(COALESCE(e.last_check_in_at, v.seen), v.seen),
                    last_seen_ip = COALESCE(v.ip, e.last_seen_ip),
                    current_activity = v.activity
                FROM unnest(@ids, @seen, @ips, @activities) AS v(id, seen, ip, activity)
                WHERE e.id = v.id
                """,
                [
                    new NpgsqlParameter("ids", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = ids },
                    new NpgsqlParameter("seen", NpgsqlDbType.Array | NpgsqlDbType.TimestampTz) { Value = seen },
                    new NpgsqlParameter("ips", NpgsqlDbType.Array | NpgsqlDbType.Text) { Value = ips },
                    new NpgsqlParameter("activities", NpgsqlDbType.Array | NpgsqlDbType.Text) { Value = activities },
                ],
                ct);
            await db.Database.ExecuteSqlRawAsync(
                """
                UPDATE agent_credentials AS c SET last_used_at = v.seen
                FROM unnest(@ids, @seen) AS v(id, seen) WHERE c.id = v.id
                """,
                [
                    new NpgsqlParameter("ids", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = credentialIds },
                    new NpgsqlParameter("seen", NpgsqlDbType.Array | NpgsqlDbType.TimestampTz) { Value = seen },
                ],
                ct);
            return ids.Length;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Failed to persist presence for {Count} endpoints; will retry", ids.Length);
            foreach (var (id, value) in batch)
            {
                pending.AddOrUpdate(id, value, (_, current) => current.At >= value.At ? current : value);
            }

            return 0;
        }
    }
}

public sealed class CheckInService(
    EasyPatchDbContext db,
    JobService jobs,
    PolicyService policies,
    SettingsService settingsService,
    PresenceTracker presence,
    AgentPackageService packages,
    TimeProvider clock)
{
    public async Task<CheckInResponse> CheckInAsync(AgentCredentialInfo credential, CheckInRequest request, string? ip, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(request);
        var now = clock.GetUtcNow();
        presence.Record(credential.EndpointId, credential.CredentialDbId, now, ip, request.CurrentActivity);

        var endpoint = await db.Endpoints.FirstOrDefaultAsync(e => e.Id == credential.EndpointId, ct) ?? throw AppException.NotFound("Endpoint");
        var settings = await settingsService.GetAsync(ct);
        var policy = await policies.ResolveAsync(endpoint, ct);

        // Only write when slow-changing state actually changed.
        var version = ScanIngestionService.Truncate(request.AgentVersion, 255);
        if (version is not null && version != endpoint.AgentVersion)
        {
            EndpointEvents.Add(db, endpoint, "AgentVersionChanged", $"Agent version changed from {endpoint.AgentVersion ?? "unknown"} to {version}.", now);
            endpoint.AgentVersion = version;
        }

        if (request.LastBootAt is { } boot && (endpoint.LastBootAt is null || (boot - endpoint.LastBootAt.Value).Duration() > TimeSpan.FromMinutes(2)))
        {
            if (endpoint.LastBootAt is not null && boot > endpoint.LastBootAt)
            {
                EndpointEvents.Add(db, endpoint, "Restarted", $"Endpoint restarted at {boot:u}.", now);
            }

            endpoint.LastBootAt = boot;
        }

        if (ScanIngestionService.ApplyRebootState(db, endpoint, request.RebootPending, request.RebootReasons, now, request.RebootDetails))
        {
            ComplianceService.ReevaluateStatus(endpoint, policy, now);
        }

        ApplyUserExperienceState(db, endpoint, request, now);

        if (!endpoint.IsOnline && endpoint.Status == EndpointStatus.Active)
        {
            // First contact or back from offline (rare transitions): record it now instead of waiting for the presence
            // monitor, and write LastCheckInAt with it so the monitor cannot see a stale timestamp and flip it back.
            endpoint.IsOnline = true;
            endpoint.LastCheckInAt = now;
            EndpointEvents.Add(db, endpoint, "Online", "The agent is checking in.", now);
        }

        if (db.ChangeTracker.HasChanges())
        {
            endpoint.UpdatedAt = now;
            await db.SaveChangesAsync(ct);
        }

        var lease = await jobs.LeaseForCheckInAsync(endpoint, request.ActiveJobIds, policy, settings, ct);
        var latest = AgentUpdatePlanner.PackageFormat(endpoint) is { } format ? packages.GetLatest(endpoint.AgentArchitecture ?? "x64", format) : null;
        return new CheckInResponse
        {
            ServerTime = now,
            Config = policy.ToAgentConfig(),
            Jobs = lease.Jobs,
            CancelJobIds = lease.CancelJobIds,
            RotateCredential = credential.ExpiresAt - now < TimeSpan.FromDays(settings.CredentialRotateBeforeDays),
            LatestAgent = latest is null ? null : new AgentVersionInfo { Version = latest.Version, FileName = latest.FileName, Sha256 = latest.Sha256 },
        };
    }

    /// <summary>Capabilities, signed-in sessions and Windows Update policy status. Writes only on change.</summary>
    internal static void ApplyUserExperienceState(EasyPatchDbContext db, Endpoint endpoint, CheckInRequest request, DateTimeOffset now)
    {
        var capabilities = request.Capabilities
            .Where(c => AgentCapabilities.All.Contains(c, StringComparer.Ordinal))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        if (!capabilities.SequenceEqual(endpoint.AgentCapabilities))
        {
            endpoint.AgentCapabilities = capabilities;
        }

        var architecture = request.AgentArchitecture is { } arch && AgentRelease.Architectures.Contains(arch) ? arch : null;
        if (endpoint.AgentArchitecture != architecture)
        {
            endpoint.AgentArchitecture = architecture;
        }

        var format = AgentRelease.NormalizeFormat(request.AgentPackageFormat);
        if (endpoint.AgentPackageFormat != format)
        {
            endpoint.AgentPackageFormat = format;
        }

        var keyIds = request.ReleaseKeyIds.Where(AgentRelease.IsKeyId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Take(8).ToList();
        if (!keyIds.SequenceEqual(endpoint.AgentReleaseKeyIds))
        {
            endpoint.AgentReleaseKeyIds = keyIds;
        }

        if (request.Winget is { } winget)
        {
            // Agents 1.7.0 and later check (and install) winget themselves; older agents only report it from application checks.
            var version = ScanIngestionService.Truncate(winget.Version?.Trim(), 32);
            var error = ScanIngestionService.Truncate(winget.SetupError?.Trim(), 1000);
            if (endpoint.WingetVersion != version || endpoint.WingetSetupError != error)
            {
                endpoint.WingetVersion = version;
                endpoint.WingetSetupError = error;
            }
        }

        if (request.Sessions is { } sessions)
        {
            var signedIn = Math.Clamp(sessions.SignedInUsers, 0, 10_000);
            var tray = Math.Clamp(sessions.TrayConnected, 0, signedIn);
            if (endpoint.SignedInUsers != signedIn || endpoint.TrayConnectedSessions != tray)
            {
                endpoint.SignedInUsers = signedIn;
                endpoint.TrayConnectedSessions = tray;
            }
        }

        if (request.WindowsUpdatePolicy is { } report && report.Groups.Count <= 16)
        {
            var groups = report.Groups
                .Where(g => Enum.IsDefined(g.Group) && Enum.IsDefined(g.State))
                .GroupBy(g => g.Group).Select(g => g.Last())
                .Select(g => g with
                {
                    Message = ScanIngestionService.Truncate(g.Message, 1000),
                    ConflictingValues = g.ConflictingValues.Take(16).Select(v => ScanIngestionService.Truncate(v, 128) ?? "").ToList(),
                })
                .ToList();
            var json = JsonSerializer.Serialize(report with { Groups = groups }, ContractJson.Options);
            if (json != endpoint.WindowsUpdatePolicyStatus)
            {
                var previous = endpoint.WindowsUpdatePolicyStatus is null
                    ? null
                    : JsonSerializer.Deserialize<WindowsUpdatePolicyReport>(endpoint.WindowsUpdatePolicyStatus, ContractJson.Options);
                foreach (var conflict in groups.Where(g => g.State == WindowsUpdatePolicyState.Conflict &&
                                                           previous?.Groups.FirstOrDefault(p => p.Group == g.Group)?.State != WindowsUpdatePolicyState.Conflict))
                {
                    EndpointEvents.Add(db, endpoint, "WindowsUpdatePolicyConflict",
                        $"Windows Update {conflict.Group} settings were changed by another policy source; EasyPatch stopped re-applying them. {conflict.Message}",
                        now, EventSeverity.Warning);
                }

                endpoint.WindowsUpdatePolicyStatus = json;
                endpoint.WindowsUpdatePolicyReportedAt = now;
            }
        }
    }
}
