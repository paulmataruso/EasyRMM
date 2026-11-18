using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Security;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Security;
using Xunit;

namespace EasyPatch.Agent.Tests;

public sealed class EnrollmentTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Token_enrollment_activates_immediately_and_consumes_the_token()
    {
        using var h = new AgentHarness();
        h.Bootstrap.EnrollmentToken = AgentHarness.Token;

        var outcome = await h.Runtime.EnsureEnrolledAsync(Ct);

        Assert.Equal(EnrollmentOutcome.Active, outcome);
        var state = h.Runtime.State.Snapshot();
        Assert.Equal(AgentEnrollmentStatus.Active, state.Status);
        Assert.StartsWith("c_", state.CredentialId, StringComparison.Ordinal);
        Assert.NotNull(state.EndpointId);
        Assert.Equal("https://easypatch.test/", state.ServerUrl);
        Assert.Null(h.Bootstrap.EnrollmentToken);

        var request = Assert.Single(h.Server.EnrollRequests);
        Assert.Equal(AgentHarness.Token, request.EnrollmentToken);
        Assert.Null(request.DeploymentCode);
        Assert.Equal("TEST-PC", request.Device.Hostname);
        Assert.Equal("26100.2605", request.Device.OsBuild);
        Assert.True(AgentKeys.TryParsePublicKey(request.PublicKey, out var spki));
        Assert.Equal(AgentKeys.Fingerprint(spki), state.KeyFingerprint);

        // The private key is persisted only through the secret protector, never as plain PKCS#8.
        var stored = File.ReadAllBytes(Path.Combine(h.DataDirectory, "agent.key"));
        Assert.True(stored.AsSpan(0, TestSecretProtector.Marker.Length).SequenceEqual(TestSecretProtector.Marker));

        // Subsequent calls are idempotent and do not contact the enrollment endpoint again.
        Assert.Equal(EnrollmentOutcome.Active, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Single(h.Server.EnrollRequests);
    }

    [Fact]
    public async Task Identity_survives_a_service_restart()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var credential = h.Runtime.State.Read(s => s.CredentialId);

        var runtime = h.Restart();

        Assert.Equal(EnrollmentOutcome.Active, await runtime.EnsureEnrolledAsync(Ct));
        Assert.NotNull(await runtime.CheckInOnceAsync(Ct));
        Assert.Single(h.Server.EnrollRequests);
        Assert.Equal(credential, runtime.State.Read(s => s.CredentialId));
        Assert.Equal(0, h.Server.RejectedSignatures);
    }

    [Fact]
    public async Task Invalid_token_is_rejected_once_and_never_retried_automatically()
    {
        using var h = new AgentHarness();
        h.Bootstrap.EnrollmentToken = "ept_wrong_token_000000000000";

        Assert.Equal(EnrollmentOutcome.Rejected, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Null(h.Bootstrap.EnrollmentToken);
        Assert.NotEqual(AgentEnrollmentStatus.Active, h.Runtime.State.Read(s => s.Status));

        // Without a new credential the agent does not keep hammering the server.
        Assert.Equal(EnrollmentOutcome.NotConfigured, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Single(h.Server.EnrollRequests);
    }

    [Fact]
    public async Task Missing_configuration_does_not_contact_the_server()
    {
        using var h = new AgentHarness();
        h.Bootstrap.ServerUrl = null;

        Assert.Equal(EnrollmentOutcome.NotConfigured, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Empty(h.Server.Requests);
    }

    [Fact]
    public async Task Plain_http_server_url_is_refused()
    {
        using var h = new AgentHarness();
        h.Bootstrap.ServerUrl = "http://easypatch.test";
        h.Bootstrap.EnrollmentToken = AgentHarness.Token;

        Assert.Equal(EnrollmentOutcome.NotConfigured, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Empty(h.Server.Requests);
    }

    [Fact]
    public async Task Deployment_code_waits_for_approval_then_activates()
    {
        using var h = new AgentHarness();
        h.Bootstrap.DeploymentCode = AgentHarness.DeploymentCode;

        Assert.Equal(EnrollmentOutcome.PendingApproval, await h.Runtime.EnsureEnrolledAsync(Ct));
        var requestId = h.Runtime.State.Read(s => s.PendingEnrollmentRequestId);
        Assert.StartsWith("r_", requestId, StringComparison.Ordinal);
        Assert.Equal(AgentHarness.DeploymentCode, h.Bootstrap.DeploymentCode); // kept until approved

        // Polling is signed with the pending request's key and stays pending until an administrator acts.
        Assert.Equal(EnrollmentOutcome.PendingApproval, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Null(await h.Runtime.CheckInOnceAsync(Ct)); // no check-ins while pending

        h.Server.Approve(requestId!);
        var restarted = h.Restart(); // approval can arrive across a service restart
        Assert.Equal(EnrollmentOutcome.Active, await restarted.EnsureEnrolledAsync(Ct));

        var state = restarted.State.Snapshot();
        Assert.Equal(AgentEnrollmentStatus.Active, state.Status);
        Assert.StartsWith("c_", state.CredentialId, StringComparison.Ordinal);
        Assert.Null(state.PendingEnrollmentRequestId);
        Assert.Null(h.Bootstrap.DeploymentCode);
        Assert.Single(h.Server.EnrollRequests);
        Assert.NotNull(await restarted.CheckInOnceAsync(Ct));
        Assert.Equal(0, h.Server.RejectedSignatures);
    }

    [Fact]
    public async Task Rejected_request_deletes_the_identity_and_the_deployment_code()
    {
        using var h = new AgentHarness();
        h.Bootstrap.DeploymentCode = AgentHarness.DeploymentCode;
        await h.Runtime.EnsureEnrolledAsync(Ct);
        h.Server.Reject(h.Runtime.State.Read(s => s.PendingEnrollmentRequestId)!);

        Assert.Equal(EnrollmentOutcome.Rejected, await h.Runtime.EnsureEnrolledAsync(Ct));

        Assert.Equal(AgentEnrollmentStatus.Rejected, h.Runtime.State.Read(s => s.Status));
        Assert.False(File.Exists(Path.Combine(h.DataDirectory, "agent.key")));
        Assert.Null(h.Bootstrap.DeploymentCode);
        Assert.Equal(EnrollmentOutcome.NotConfigured, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Single(h.Server.EnrollRequests);
    }

    [Fact]
    public async Task Expired_request_is_resubmitted_with_a_new_key()
    {
        using var h = new AgentHarness();
        h.Bootstrap.DeploymentCode = AgentHarness.DeploymentCode;
        await h.Runtime.EnsureEnrolledAsync(Ct);
        var firstFingerprint = h.Runtime.State.Read(s => s.KeyFingerprint);
        h.Server.Expire(h.Runtime.State.Read(s => s.PendingEnrollmentRequestId)!);

        Assert.Equal(EnrollmentOutcome.Failed, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Equal(EnrollmentOutcome.PendingApproval, await h.Runtime.EnsureEnrolledAsync(Ct));

        Assert.Equal(2, h.Server.EnrollRequests.Count);
        Assert.NotEqual(firstFingerprint, h.Runtime.State.Read(s => s.KeyFingerprint));
    }

    [Fact]
    public async Task Server_unreachable_during_enrollment_keeps_the_token_for_retry()
    {
        using var h = new AgentHarness();
        h.Bootstrap.EnrollmentToken = AgentHarness.Token;
        h.Server.NetworkDown = true;

        await Assert.ThrowsAsync<EasyPatch.Communication.AgentTransientException>(() => h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Equal(AgentHarness.Token, h.Bootstrap.EnrollmentToken);
        var fingerprint = h.Runtime.State.Read(s => s.KeyFingerprint);

        h.Server.NetworkDown = false;
        Assert.Equal(EnrollmentOutcome.Active, await h.Runtime.EnsureEnrolledAsync(Ct));
        Assert.Equal(fingerprint, h.Runtime.State.Read(s => s.KeyFingerprint)); // same key reused
    }

    [Fact]
    public async Task Unenroll_notifies_the_server_and_removes_local_identity()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var credential = h.Runtime.State.Read(s => s.CredentialId)!;

        await h.Runtime.UnenrollAsync("test", Ct);

        Assert.Contains(credential, h.Server.Unenrolled);
        Assert.Equal(AgentEnrollmentStatus.NotEnrolled, h.Runtime.State.Read(s => s.Status));
        Assert.False(File.Exists(Path.Combine(h.DataDirectory, "agent.key")));
    }

    [Fact]
    public async Task Unenroll_completes_locally_when_the_server_is_unreachable()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.NetworkDown = true;

        await h.Runtime.UnenrollAsync("test", Ct);

        Assert.Equal(AgentEnrollmentStatus.NotEnrolled, h.Runtime.State.Read(s => s.Status));
        Assert.False(File.Exists(Path.Combine(h.DataDirectory, "agent.key")));
    }

    [Fact]
    public async Task Server_requested_rotation_switches_to_a_new_key()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        var before = h.Runtime.State.Snapshot();
        h.Server.RotateOnNextCheckIn = true;

        await h.Runtime.CheckInOnceAsync(Ct);

        var after = h.Runtime.State.Snapshot();
        Assert.NotEqual(before.CredentialId, after.CredentialId);
        Assert.NotEqual(before.KeyFingerprint, after.KeyFingerprint);
        Assert.False(File.Exists(Path.Combine(h.DataDirectory, "agent.key.pending")));

        // The new credential is used after a restart; the server verifies it against the new key.
        var restarted = h.Restart();
        Assert.NotNull(await restarted.CheckInOnceAsync(Ct));
        Assert.Equal(0, h.Server.RejectedSignatures);
    }

    [Fact]
    public void Interrupted_rotation_is_completed_from_the_pending_key()
    {
        var dir = Path.Combine(Path.GetTempPath(), "easypatch-agent-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var protector = new TestSecretProtector();
            string pendingFingerprint;
            using (var keys = new AgentKeyStore(dir, protector))
            {
                keys.GetOrCreate();
                pendingFingerprint = AgentKeyStore.Fingerprint(keys.GetOrCreatePending());
                // "Crash" here: the state already records the new credential, but the key was never promoted.
            }

            using var reloaded = new AgentKeyStore(dir, protector);
            Assert.True(reloaded.EnsureMatches(pendingFingerprint));
            Assert.Equal(pendingFingerprint, AgentKeyStore.Fingerprint(reloaded.TryGetCurrent()!));
            Assert.False(File.Exists(Path.Combine(dir, "agent.key.pending")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Missing_key_forces_a_fresh_enrollment_instead_of_signing_with_nothing()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        File.Delete(Path.Combine(h.DataDirectory, "agent.key"));

        var runtime = h.Restart();
        h.Bootstrap.EnrollmentToken = AgentHarness.Token;

        Assert.Equal(EnrollmentOutcome.Active, await runtime.EnsureEnrolledAsync(Ct));
        Assert.Equal(2, h.Server.EnrollRequests.Count);
        Assert.NotNull(await runtime.CheckInOnceAsync(Ct));
    }

    [Fact]
    public void Config_limits_clamp_hostile_values()
    {
        var normalized = AgentConfigLimits.Normalize(new AgentConfig
        {
            CheckInIntervalSeconds = 1,
            ActiveJobCheckInIntervalSeconds = 0,
            ScanIntervalMinutes = 1,
            InventoryIntervalMinutes = int.MaxValue,
            JitterPercent = 400,
        });

        Assert.Equal(15, normalized.CheckInIntervalSeconds);
        Assert.Equal(5, normalized.ActiveJobCheckInIntervalSeconds);
        Assert.Equal(30, normalized.ScanIntervalMinutes);
        Assert.Equal(7 * 24 * 60, normalized.InventoryIntervalMinutes);
        Assert.Equal(50, normalized.JitterPercent);
    }
}
