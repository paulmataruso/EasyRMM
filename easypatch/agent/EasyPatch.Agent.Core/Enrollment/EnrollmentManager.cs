using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Outbox;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Core.Security;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Enrollment;

public enum EnrollmentOutcome
{
    /// <summary>The agent has an active credential.</summary>
    Active,

    /// <summary>Waiting for an administrator to approve the request (deployment-code flow).</summary>
    PendingApproval,

    /// <summary>No server URL or enrollment credential is configured.</summary>
    NotConfigured,

    /// <summary>The server refused or rejected enrollment; a new token or deployment code is required.</summary>
    Rejected,

    /// <summary>Enrollment failed in a way that may succeed later (e.g. an expired pending request).</summary>
    Failed,
}

/// <summary>Event IDs written to the Windows event log for enrollment milestones.</summary>
public static class AgentEventIds
{
    public static readonly EventId EnrollmentPending = new(1001, "EnrollmentPending");
    public static readonly EventId EnrollmentActive = new(1002, "EnrollmentActive");
    public static readonly EventId EnrollmentRejected = new(1003, "EnrollmentRejected");
    public static readonly EventId CredentialRevoked = new(1004, "CredentialRevoked");
    public static readonly EventId CredentialRotated = new(1005, "CredentialRotated");
    public static readonly EventId RestartStarted = new(1010, "RestartStarted");
    public static readonly EventId WindowsUpdatePolicyChanged = new(1011, "WindowsUpdatePolicyChanged");
    public static readonly EventId WindowsUpdatePolicyConflict = new(1012, "WindowsUpdatePolicyConflict");
    public static readonly EventId AgentUpdateStarted = new(1013, "AgentUpdateStarted");
    public static readonly EventId AgentUpdated = new(1014, "AgentUpdated");
    public static readonly EventId AgentUpdateFailed = new(1015, "AgentUpdateFailed");
    public static readonly EventId AgentUninstallStarted = new(1016, "AgentUninstallStarted");
    public static readonly EventId AgentUninstallFailed = new(1017, "AgentUninstallFailed");
    public static readonly EventId WingetInstalled = new(1018, "WingetInstalled");
    public static readonly EventId WingetSetupFailed = new(1019, "WingetSetupFailed");
    public static readonly EventId UpdateRemoved = new(1020, "UpdateRemoved");
    public static readonly EventId UpdateRemovalFailed = new(1021, "UpdateRemovalFailed");
}

/// <summary>
/// Implements both enrollment flows: an enrollment token (immediately active) and a deployment code
/// (pending until an administrator approves it in the console).
/// </summary>
public sealed class EnrollmentManager
{
    private readonly AgentStateStore _state;
    private readonly AgentKeyStore _keys;
    private readonly AgentPlatform _platform;
    private readonly ApiClientAccessor _api;
    private readonly ReportOutbox _outbox;
    private readonly AgentRuntimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private bool _notConfiguredLogged;

    public EnrollmentManager(
        AgentStateStore state,
        AgentKeyStore keys,
        AgentPlatform platform,
        ApiClientAccessor api,
        ReportOutbox outbox,
        AgentRuntimeOptions options,
        TimeProvider time,
        ILogger<EnrollmentManager> logger)
    {
        _state = state;
        _keys = keys;
        _platform = platform;
        _api = api;
        _outbox = outbox;
        _options = options;
        _time = time;
        _logger = logger;
    }

    public async Task<EnrollmentOutcome> EnsureEnrolledAsync(CancellationToken cancellationToken)
    {
        var snapshot = _state.Snapshot();
        switch (snapshot.Status)
        {
            case AgentEnrollmentStatus.Active when !string.IsNullOrEmpty(snapshot.CredentialId):
                if (_keys.EnsureMatches(snapshot.KeyFingerprint))
                {
                    return EnrollmentOutcome.Active;
                }

                _logger.LogError("The agent's private key is missing or does not match its credential. The agent must enroll again.");
                ResetIdentity();
                break;

            case AgentEnrollmentStatus.PendingApproval when !string.IsNullOrEmpty(snapshot.PendingEnrollmentRequestId):
                return await PollPendingAsync(snapshot, cancellationToken);
        }

        return await EnrollAsync(cancellationToken);
    }

    private async Task<EnrollmentOutcome> EnrollAsync(CancellationToken cancellationToken)
    {
        var bootstrap = _platform.Bootstrap.Read();
        if (string.IsNullOrWhiteSpace(bootstrap.ServerUrl) || !bootstrap.HasEnrollmentCredential)
        {
            if (!_notConfiguredLogged)
            {
                _logger.LogWarning(
                    "The agent is not enrolled and has no {Missing}. {Hint}",
                    string.IsNullOrWhiteSpace(bootstrap.ServerUrl) ? "server URL" : "enrollment token or deployment code", _platform.Bootstrap.SetupHint);
                _notConfiguredLogged = true;
            }

            return EnrollmentOutcome.NotConfigured;
        }

        _notConfiguredLogged = false;
        var status = _state.Read(s => s.Status);
        if (status is AgentEnrollmentStatus.Revoked or AgentEnrollmentStatus.Rejected)
        {
            // A new enrollment credential appeared after revocation/rejection: start over with a fresh identity.
            ResetIdentity();
        }

        string serverUrl;
        try
        {
            serverUrl = ApiClientAccessor.NormalizeServerUrl(bootstrap.ServerUrl, _options.RequireHttps).ToString();
        }
        catch (ArgumentException ex)
        {
            _logger.LogError("Cannot enroll: {Message}", ex.Message);
            return EnrollmentOutcome.NotConfigured;
        }

        var key = _keys.GetOrCreate(); // persisted before the request so retries reuse the same identity
        var fingerprint = AgentKeyStore.Fingerprint(key);
        var device = await CollectDeviceIdentityAsync(cancellationToken);
        var useToken = !string.IsNullOrWhiteSpace(bootstrap.EnrollmentToken);
        var request = new EnrollRequest
        {
            EnrollmentToken = useToken ? bootstrap.EnrollmentToken!.Trim() : null,
            DeploymentCode = useToken ? null : bootstrap.DeploymentCode!.Trim(),
            PublicKey = AgentKeyStore.PublicKeyBase64(key),
            AgentVersion = _options.AgentVersion,
            Device = device,
        };

        _state.Update(s =>
        {
            s.ServerUrl = serverUrl;
            s.KeyFingerprint = fingerprint;
        });

        _logger.LogInformation("Enrolling with {Server} using a {Method} (key fingerprint {Fingerprint}).",
            serverUrl, useToken ? "enrollment token" : "deployment code", fingerprint);

        EnrollResponse response;
        try
        {
            response = await _api.Get(serverUrl).EnrollAsync(request, cancellationToken);
        }
        catch (AgentRejectedException ex)
        {
            _logger.LogError(AgentEventIds.EnrollmentRejected,
                "The server refused enrollment (HTTP {Status}, {Code}): {Message} Provide a new enrollment token or deployment code.",
                (int?)ex.StatusCode, ex.ErrorCode, ex.Message);
            _platform.Bootstrap.ClearEnrollmentSecrets();
            return EnrollmentOutcome.Rejected;
        }

        return Apply(response, fingerprint);
    }

    private async Task<EnrollmentOutcome> PollPendingAsync(AgentState snapshot, CancellationToken cancellationToken)
    {
        if (!_keys.EnsureMatches(snapshot.KeyFingerprint))
        {
            _logger.LogError("The key for the pending enrollment request is missing; submitting a new request.");
            ResetIdentity();
            return EnrollmentOutcome.Failed;
        }

        EnrollResponse response;
        try
        {
            response = await _api.Get(snapshot.ServerUrl!).GetEnrollmentStatusAsync(cancellationToken);
        }
        catch (AgentAuthException ex) when (ex.IsFatal)
        {
            _logger.LogWarning("The server no longer knows the pending enrollment request ({Code}); a new request will be submitted.", ex.ErrorCode);
            ResetIdentity();
            return EnrollmentOutcome.Failed;
        }
        catch (AgentRejectedException ex) when (ex.ErrorCode == AgentErrorCodes.EnrollmentRejected)
        {
            return Apply(new EnrollResponse
            {
                State = EnrollmentState.Rejected,
                CredentialId = snapshot.PendingEnrollmentRequestId!,
                KeyFingerprint = snapshot.KeyFingerprint ?? string.Empty,
                Message = ex.Message,
            }, snapshot.KeyFingerprint ?? string.Empty);
        }

        return Apply(response, snapshot.KeyFingerprint ?? string.Empty);
    }

    private EnrollmentOutcome Apply(EnrollResponse response, string fingerprint)
    {
        if (!string.IsNullOrEmpty(response.KeyFingerprint) && !string.Equals(response.KeyFingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Server-reported key fingerprint {Server} differs from the local fingerprint {Local}.", response.KeyFingerprint, fingerprint);
        }

        var now = _time.GetUtcNow();
        switch (response.State)
        {
            case EnrollmentState.Active:
                _state.Update(s =>
                {
                    s.Status = AgentEnrollmentStatus.Active;
                    s.EndpointId = response.EndpointId;
                    s.OrganizationId = response.OrganizationId;
                    s.CredentialId = response.CredentialId;
                    s.CredentialExpiresAt = response.CredentialExpiresAt;
                    s.PendingEnrollmentRequestId = null;
                    s.KeyFingerprint = fingerprint;
                    s.EnrolledAt = now;
                    s.LastAuthFailureCode = null;
                    s.LastAuthFailureAt = null;
                    if (response.Config is not null)
                    {
                        s.Config = AgentConfigLimits.Normalize(response.Config);
                    }
                });
                _platform.Bootstrap.ClearEnrollmentSecrets();
                _logger.LogInformation(AgentEventIds.EnrollmentActive,
                    "Enrollment complete. Endpoint {EndpointId}, credential {CredentialId}, key fingerprint {Fingerprint}.",
                    response.EndpointId, response.CredentialId, fingerprint);
                return EnrollmentOutcome.Active;

            case EnrollmentState.PendingApproval:
                var firstTime = _state.Read(s => s.Status != AgentEnrollmentStatus.PendingApproval);
                _state.Update(s =>
                {
                    s.Status = AgentEnrollmentStatus.PendingApproval;
                    s.PendingEnrollmentRequestId = response.CredentialId;
                    s.KeyFingerprint = fingerprint;
                });
                if (firstTime)
                {
                    _logger.LogInformation(AgentEventIds.EnrollmentPending,
                        "Enrollment request {RequestId} is waiting for administrator approval in the EasyPatch console. Key fingerprint: {Fingerprint}",
                        response.CredentialId, fingerprint);
                }

                return EnrollmentOutcome.PendingApproval;

            case EnrollmentState.Rejected:
                _logger.LogError(AgentEventIds.EnrollmentRejected,
                    "An administrator rejected this agent's enrollment request. {Message} Reinstall with a new token or deployment code to try again.",
                    response.Message ?? string.Empty);
                _platform.Bootstrap.ClearEnrollmentSecrets();
                _keys.DeleteAll();
                _state.Update(s =>
                {
                    s.Status = AgentEnrollmentStatus.Rejected;
                    s.PendingEnrollmentRequestId = null;
                    s.CredentialId = null;
                });
                return EnrollmentOutcome.Rejected;

            case EnrollmentState.Expired:
            default:
                _logger.LogWarning("The enrollment request expired before it was approved; a new request will be submitted.");
                ResetIdentity();
                return EnrollmentOutcome.Failed;
        }
    }

    /// <summary>Discards the current identity (keys, credential, held jobs and queued reports).</summary>
    public void ResetIdentity()
    {
        _keys.DeleteAll();
        _outbox.Clear();
        _state.Update(s =>
        {
            s.Status = AgentEnrollmentStatus.NotEnrolled;
            s.EndpointId = null;
            s.OrganizationId = null;
            s.CredentialId = null;
            s.CredentialExpiresAt = null;
            s.PendingEnrollmentRequestId = null;
            s.KeyFingerprint = null;
            s.EnrolledAt = null;
            s.Jobs.Clear();
        });
    }

    private async Task<DeviceIdentity> CollectDeviceIdentityAsync(CancellationToken cancellationToken)
    {
        try
        {
            var installedAt = _state.Read(s => s.FirstStartedAt);
            var inventory = await _platform.Inventory.CollectAsync(new InventoryContext(_options.AgentVersion, installedAt), cancellationToken);
            return new DeviceIdentity
            {
                Hostname = inventory.Hostname,
                DnsDomain = inventory.DnsDomain,
                SmbiosUuid = inventory.SmbiosUuid,
                SerialNumber = inventory.SerialNumber,
                Manufacturer = inventory.Manufacturer,
                Model = inventory.Model,
                OsCaption = inventory.OsCaption,
                OsBuild = inventory.OsBuildNumber is { } build
                    ? inventory.OsUbr is { } ubr ? $"{build}.{ubr}" : build.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : null,
                Architecture = inventory.Architecture,
                Platform = inventory.Platform,
                OsId = inventory.OsId,
                OsVersion = inventory.OsVersion,
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Inventory collection failed during enrollment; enrolling with the host name only.");
            return new DeviceIdentity { Hostname = Environment.MachineName };
        }
    }
}

/// <summary>Guards against a misconfigured server driving the agent into excessive polling.</summary>
public static class AgentConfigLimits
{
    public static AgentConfig Normalize(AgentConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config with
        {
            CheckInIntervalSeconds = Math.Clamp(config.CheckInIntervalSeconds, 15, 3600),
            ActiveJobCheckInIntervalSeconds = Math.Clamp(config.ActiveJobCheckInIntervalSeconds, 5, 600),
            ScanIntervalMinutes = Math.Clamp(config.ScanIntervalMinutes, 30, 7 * 24 * 60),
            InventoryIntervalMinutes = Math.Clamp(config.InventoryIntervalMinutes, 60, 7 * 24 * 60),
            JitterPercent = Math.Clamp(config.JitterPercent, 0, 50),
            UserExperience = config.UserExperience ?? new UserExperienceConfig(),
            Applications = config.Applications is { } apps
                ? apps with
                {
                    ApprovedApps = (apps.ApprovedApps ?? []).Where(ApplicationIds.IsValid).Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(ApplicationIds.MaxApproved).ToList(),
                }
                : null,
        };
    }
}
