using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Notifications;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Alert rules, alert lifecycle, notification channels and delivery (with a capturing transport).</summary>
public sealed class AlertTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private const string SmtpPassword = "smtp-Secret-Pa55";
    private const string WebhookUrl = "https://hooks.example.com/easypatch/T0K3N-in-path";
    private static readonly Guid OfflineRuleId = Guid.Parse("7c3e1a52-6f0e-4d7b-9a01-000000000001");

    private AdminSession root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
        (org, site) = await CreateOrgAsync(root);
    }

    private static NotificationChannelRequest Webhook(string name, string? url = WebhookUrl, WebhookFormat format = WebhookFormat.Generic) =>
        new(name, NotificationChannelType.Webhook, true, null, format, url);

    private static NotificationChannelRequest Email(string name, params string[] recipients) =>
        new(name, NotificationChannelType.Email, true, recipients, null, null);

    private static AlertRuleRequest OfflineRule(IReadOnlyList<Guid> channels, int hours = 24, Guid? orgId = null) =>
        new("Endpoint offline", AlertRuleType.EndpointOffline, true, AlertSeverity.Warning, hours, orgId, null, channels, NotifyOnResolve: true, 0);

    private async Task ConfigureSmtpAsync() =>
        await root.SendAsync<NotificationSettingsDto>(HttpMethod.Put, "/api/v1/notifications/settings",
            new NotificationSettingsRequest("smtp.example.com", 587, SmtpSecurity.StartTls, "mailer", SmtpPassword, "easypatch@example.com", "EasyPatch",
                false), HttpStatusCode.OK);

    private async Task<SignedAgent> OnlineAgentAsync(string hostname, Guid? orgId = null, Guid? siteId = null)
    {
        var agent = await EnrollAgentAsync(root, orgId ?? org.Id, siteId ?? site.Id, hostname);
        await agent.CheckInAsync();
        await FlushPresenceAsync();
        return agent;
    }

    /// <summary>Moves time on, marks silent endpoints offline and signs the administrator in again (the session expired).</summary>
    private async Task AdvanceAsync(TimeSpan by)
    {
        Clock.Advance(by);
        await RunMaintenanceAsync<PresenceMonitorTask>();
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
    }

    private async Task<List<AlertDto>> AlertsAsync(AdminSession session, string query = "") =>
        (await session.GetAsync<PagedResult<AlertDto>>("/api/v1/alerts" + query)).Items.ToList();

    [Fact]
    public async Task Default_rules_are_seeded_and_only_super_admins_manage_rules_and_channels()
    {
        var rules = await root.GetAsync<List<AlertRuleDto>>("/api/v1/alert-rules");
        Assert.Equal(AlertRuleCatalog.Defaults(DateTimeOffset.UnixEpoch).Count, rules.Count);
        Assert.Equal(9, rules.Count);
        Assert.Equal(AlertSeverity.Critical, rules.Single(r => r.Type == AlertRuleType.KnownExploitedMissing).Severity);
        Assert.All(rules, r => Assert.True(r.Enabled));
        Assert.All(rules, r => Assert.Empty(r.ChannelIds));
        Assert.Equal(24, rules.Single(r => r.Id == OfflineRuleId).Threshold);
        Assert.Equal(AlertSeverity.Critical, rules.Single(r => r.Type == AlertRuleType.SecurityUpdateMissing).Severity);
        Assert.Equal(Enum.GetValues<AlertRuleType>().Length, (await root.GetAsync<List<AlertRuleTypeDto>>("/api/v1/alert-rules/types")).Count);

        var admin = await CreateAndLoginAsync("admin", UserRole.Admin);
        await admin.ExpectAsync(HttpMethod.Get, "/api/v1/alert-rules", null, HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Get, "/api/v1/notifications/channels", null, HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Get, "/api/v1/notifications/settings", null, HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Email("Ops", "ops@example.com"), HttpStatusCode.Forbidden);
        Assert.Empty(await AlertsAsync(admin));

        // Rule validation: thresholds per type, tags not allowed on enrollment rules, unknown channels.
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/alert-rules", OfflineRule([], hours: 0), HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/alert-rules", OfflineRule([Guid.NewGuid()]), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/alert-rules",
            new AlertRuleRequest("Enrollment", AlertRuleType.EnrollmentPending, true, AlertSeverity.Info, null, null, Guid.NewGuid(), null, false, 0),
            HttpStatusCode.BadRequest);
        var created = await root.SendAsync<AlertRuleDto>(HttpMethod.Post, "/api/v1/alert-rules", OfflineRule([], hours: 4, orgId: org.Id), HttpStatusCode.OK);
        Assert.Equal("hours", created.ThresholdUnit);
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/alert-rules/{created.Id}", null, HttpStatusCode.NoContent);
        Assert.Equal(rules.Count, (await root.GetAsync<List<AlertRuleDto>>("/api/v1/alert-rules")).Count);
    }

    [Fact]
    public async Task Channels_are_validated_and_secrets_are_never_returned()
    {
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Webhook("Plain http", "http://hooks.example.com/x"),
            HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Webhook("User info", "https://user:pw@hooks.example.com/x"),
            HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Webhook("No URL", null), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Email("Bad", "not an address"), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Email("Display", "Ops <ops@example.com>"), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/notifications/channels", Email("None"), HttpStatusCode.BadRequest);

        var saved = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post, "/api/v1/notifications/channels", Webhook("PSA"),
            HttpStatusCode.OK);
        Assert.False(string.IsNullOrEmpty(saved.SigningSecret));
        Assert.True(saved.Channel.HasSigningSecret);
        Assert.Equal("hooks.example.com", saved.Channel.WebhookHost);
        var slack = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post, "/api/v1/notifications/channels",
            Webhook("Slack", "https://hooks.slack.com/services/T/B/X", WebhookFormat.Slack), HttpStatusCode.OK);
        Assert.Null(slack.SigningSecret);

        // Updating without a URL keeps the stored one and does not reveal or replace the signing secret.
        var updated = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Put, $"/api/v1/notifications/channels/{saved.Channel.Id}",
            Webhook("PSA tickets", null), HttpStatusCode.OK);
        Assert.Null(updated.SigningSecret);
        Assert.Equal("PSA tickets", updated.Channel.Name);
        var rotated = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post,
            $"/api/v1/notifications/channels/{saved.Channel.Id}/rotate-secret", null, HttpStatusCode.OK);
        Assert.NotEqual(saved.SigningSecret, rotated.SigningSecret);

        await ConfigureSmtpAsync();
        var settings = await root.SendAsync(HttpMethod.Get, "/api/v1/notifications/settings");
        var settingsJson = await settings.Content.ReadAsStringAsync();
        Assert.DoesNotContain(SmtpPassword, settingsJson, StringComparison.Ordinal);
        Assert.True(JsonSerializer.Deserialize<NotificationSettingsDto>(settingsJson, TestJson.Options)!.SmtpPasswordConfigured);

        // A null password keeps the stored one; an empty string removes it.
        await root.SendAsync<NotificationSettingsDto>(HttpMethod.Put, "/api/v1/notifications/settings",
            new NotificationSettingsRequest("smtp.example.com", 587, SmtpSecurity.StartTls, "mailer", null, "easypatch@example.com", null, false),
            HttpStatusCode.OK);
        Assert.True((await root.GetAsync<NotificationSettingsDto>("/api/v1/notifications/settings")).SmtpPasswordConfigured);
        Assert.False((await root.GetAsync<NotificationSettingsDto>("/api/v1/notifications/settings")).SmtpSkipCertificateValidation); // off by default

        // Skipping certificate validation is an explicit choice, kept only for an encrypted connection.
        var skipped = await root.SendAsync<NotificationSettingsDto>(HttpMethod.Put, "/api/v1/notifications/settings",
            new NotificationSettingsRequest("smtp.example.com", 465, SmtpSecurity.SslOnConnect, "mailer", null, "easypatch@example.com", null, false,
                SmtpSkipCertificateValidation: true), HttpStatusCode.OK);
        Assert.True(skipped.SmtpSkipCertificateValidation);
        var plain = await root.SendAsync<NotificationSettingsDto>(HttpMethod.Put, "/api/v1/notifications/settings",
            new NotificationSettingsRequest("smtp.example.com", 25, SmtpSecurity.None, "mailer", null, "easypatch@example.com", null, false,
                SmtpSkipCertificateValidation: true), HttpStatusCode.OK);
        Assert.False(plain.SmtpSkipCertificateValidation);
        Assert.Contains(await WithDbAsync(db => db.AuditLogs.Where(a => a.Action == "notifications.settings_update").Select(a => a.Details).ToListAsync()),
            d => d != null && d.Replace(" ", "", StringComparison.Ordinal).Contains("SkipCertificateValidation\":true", StringComparison.OrdinalIgnoreCase)); // jsonb
        await ConfigureSmtpAsync();

        var channelsJson = await (await root.SendAsync(HttpMethod.Get, "/api/v1/notifications/channels")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("T0K3N", channelsJson, StringComparison.Ordinal);
        Assert.DoesNotContain(rotated.SigningSecret!, channelsJson, StringComparison.Ordinal);

        // Secrets are encrypted at rest.
        var stored = await WithDbAsync(db => db.NotificationChannels.AsNoTracking().SingleAsync(c => c.Id == saved.Channel.Id));
        Assert.DoesNotContain("T0K3N", stored.WebhookUrlProtected, StringComparison.Ordinal);
        Assert.DoesNotContain(rotated.SigningSecret!, stored.SigningSecretProtected, StringComparison.Ordinal);
        var row = await WithDbAsync(db => db.NotificationSettings.AsNoTracking().SingleAsync());
        Assert.DoesNotContain(SmtpPassword, row.SmtpPasswordProtected, StringComparison.Ordinal);

        // Test notifications: sent by the worker, rate limited per channel, failures stored with a safe message.
        var email = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post, "/api/v1/notifications/channels",
            Email("Ops", "ops@example.com", "oncall@example.com"), HttpStatusCode.OK);
        var test = await root.SendAsync<NotificationDeliveryDto>(HttpMethod.Post, $"/api/v1/notifications/channels/{email.Channel.Id}/test", null,
            HttpStatusCode.Accepted);
        Assert.Equal(NotificationKind.Test, test.Kind);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/notifications/channels/{email.Channel.Id}/test", null, (HttpStatusCode)429,
            "test_rate_limited");
        await RunMaintenanceAsync<NotificationDeliveryTask>();
        var sent = Assert.Single(Factory.Transport.Emails);
        Assert.Equal("[EasyPatch] Test notification", sent.Subject);
        Assert.Equal(2, sent.Recipients.Count);
        Assert.Equal(SmtpPassword, sent.Password);

        Factory.Transport.FailWith = "The SMTP server refused the user name or password.";
        Clock.Advance(TimeSpan.FromSeconds(31));
        await root.SendAsync<NotificationDeliveryDto>(HttpMethod.Post, $"/api/v1/notifications/channels/{email.Channel.Id}/test", null,
            HttpStatusCode.Accepted);
        await RunMaintenanceAsync<NotificationDeliveryTask>();
        var deliveries = await root.GetAsync<PagedResult<NotificationDeliveryDto>>($"/api/v1/notifications/deliveries?channelId={email.Channel.Id}");
        var failed = deliveries.Items[0];
        Assert.Equal(DeliveryStatus.Pending, failed.Status); // retried later
        Assert.Equal(1, failed.Attempts);
        Assert.Equal(Factory.Transport.FailWith, failed.LastError);
        var listed = Assert.Single(await root.GetAsync<List<NotificationChannelDto>>("/api/v1/notifications/channels"), c => c.Id == email.Channel.Id);
        Assert.Equal(Factory.Transport.FailWith, listed.LastDelivery?.LastError);

        // The audit log records the changes but never the secrets.
        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action.StartsWith("notifications.")).ToListAsync());
        Assert.Contains(audit, a => a.Action == "notifications.settings_update");
        Assert.All(audit, a => Assert.DoesNotContain("T0K3N", a.Details ?? "", StringComparison.Ordinal));
        Assert.All(audit, a => Assert.DoesNotContain(SmtpPassword, a.Details ?? "", StringComparison.Ordinal));

        // Deleting a channel removes it from rules.
        await root.SendAsync<AlertRuleDto>(HttpMethod.Put, $"/api/v1/alert-rules/{OfflineRuleId}", OfflineRule([email.Channel.Id]), HttpStatusCode.OK);
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/notifications/channels/{email.Channel.Id}", null, HttpStatusCode.NoContent);
        Assert.Empty((await root.GetAsync<List<AlertRuleDto>>("/api/v1/alert-rules")).Single(r => r.Id == OfflineRuleId).ChannelIds);
    }

    [Fact]
    public async Task Offline_endpoints_open_one_digest_per_channel_and_resolve_after_two_clear_evaluations()
    {
        await ConfigureSmtpAsync();
        var hook = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post, "/api/v1/notifications/channels", Webhook("PSA"), HttpStatusCode.OK);
        var mail = await root.SendAsync<NotificationChannelSavedDto>(HttpMethod.Post, "/api/v1/notifications/channels", Email("Ops", "ops@example.com"),
            HttpStatusCode.OK);
        await root.SendAsync<AlertRuleDto>(HttpMethod.Put, $"/api/v1/alert-rules/{OfflineRuleId}",
            OfflineRule([hook.Channel.Id, mail.Channel.Id]), HttpStatusCode.OK);

        var first = await OnlineAgentAsync("PC-OFF-1");
        var second = await OnlineAgentAsync("PC-OFF-2");
        await RunMaintenanceAsync<AlertEvaluationTask>();
        Assert.Empty(await AlertsAsync(root, "?ruleType=EndpointOffline"));

        // Offline, but not yet for the 24 hour threshold.
        await AdvanceAsync(TimeSpan.FromHours(2));
        await RunMaintenanceAsync<AlertEvaluationTask>();
        Assert.Empty(await AlertsAsync(root, "?ruleType=EndpointOffline"));

        await AdvanceAsync(TimeSpan.FromHours(23));
        await RunMaintenanceAsync<AlertEvaluationTask>();
        var alerts = await AlertsAsync(root, "?ruleType=EndpointOffline");
        Assert.Equal(2, alerts.Count);
        Assert.All(alerts, a => Assert.Equal(AlertStatus.Open, a.Status));
        Assert.Contains(alerts, a => a.Hostname == "PC-OFF-1" && a.Title.Contains("offline", StringComparison.Ordinal));
        // Offline endpoints get only the offline alert (no scan-stale or other noise).
        Assert.Equal(2, (await AlertsAsync(root)).Count);
        var summary = await root.GetAsync<AlertSummaryDto>("/api/v1/alerts/summary");
        Assert.Equal(2, summary.Open);
        Assert.Equal(2, summary.Warning);

        // A further evaluation does not notify again.
        await RunMaintenanceAsync<AlertEvaluationTask>();
        await RunMaintenanceAsync<NotificationDeliveryTask>();
        var webhook = Assert.Single(Factory.Transport.Webhooks);
        var email = Assert.Single(Factory.Transport.Emails);
        Assert.Equal("[EasyPatch] 2 new alerts", email.Subject);
        Assert.Contains("PC-OFF-2", email.Text, StringComparison.Ordinal);
        Assert.Contains($"{EasyPatchApiFactory.PublicUrl}/endpoints/{first.EndpointId}", email.Html, StringComparison.Ordinal);

        // The generic webhook is signed with the channel secret: HMAC-SHA256(secret, "t.body").
        Assert.Equal(new Uri(WebhookUrl), webhook.Url);
        Assert.Equal("alerts.opened", webhook.Headers[NotificationRenderer.EventHeader]);
        var signature = webhook.Headers[NotificationRenderer.SignatureHeader];
        var t = signature.Split(',')[0]["t=".Length..];
        var expected = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(hook.SigningSecret!), Encoding.UTF8.GetBytes(t + "." + webhook.Body)));
        Assert.Equal($"t={t},v1={expected}", signature);
        using (var body = JsonDocument.Parse(webhook.Body))
        {
            Assert.Equal("alerts.opened", body.RootElement.GetProperty("event").GetString());
            Assert.Equal(2, body.RootElement.GetProperty("alerts").GetArrayLength());
        }

        // Acknowledge: operators only, scoped to visible alerts.
        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly);
        Assert.Equal(2, (await AlertsAsync(viewer)).Count);
        var alertOne = alerts.Single(a => a.EndpointId == first.EndpointId);
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/alerts/acknowledge", new AcknowledgeAlertsRequest([alertOne.Id]), HttpStatusCode.Forbidden);
        var ack = await root.SendAsync<AcknowledgeAlertsResult>(HttpMethod.Post, "/api/v1/alerts/acknowledge",
            new AcknowledgeAlertsRequest([alertOne.Id]), HttpStatusCode.OK);
        Assert.Equal(1, ack.Acknowledged);
        Assert.Single(await AlertsAsync(root, "?status=open&ruleType=EndpointOffline"));
        Assert.Equal(1, (await root.GetAsync<AlertSummaryDto>("/api/v1/alerts/summary")).Acknowledged);

        // The first endpoint comes back: the alert resolves after two evaluations without a match.
        await first.CheckInAsync();
        await FlushPresenceAsync();
        await RunMaintenanceAsync<AlertEvaluationTask>();
        Assert.Equal(2, (await AlertsAsync(root, "?ruleType=EndpointOffline")).Count);
        await RunMaintenanceAsync<AlertEvaluationTask>();
        var remaining = Assert.Single(await AlertsAsync(root, "?ruleType=EndpointOffline"));
        Assert.Equal(second.EndpointId, remaining.EndpointId);
        var resolvedAlert = Assert.Single(await AlertsAsync(root, "?status=resolved"));
        Assert.Equal(alertOne.Id, resolvedAlert.Id);
        Assert.NotNull(resolvedAlert.ResolvedAt);

        await RunMaintenanceAsync<NotificationDeliveryTask>();
        Assert.Equal(2, Factory.Transport.Emails.Count);
        Assert.Equal("[EasyPatch] Resolved: " + alertOne.Title, Factory.Transport.Emails.Last().Subject);

        // Archiving the organization closes its alerts without notifications.
        var deliveriesBefore = await WithDbAsync(db => db.NotificationDeliveries.CountAsync());
        await WithDbAsync(async db =>
        {
            await db.Organizations.Where(o => o.Id == org.Id).ExecuteUpdateAsync(x => x.SetProperty(o => o.IsActive, false));
        });
        await RunMaintenanceAsync<AlertEvaluationTask>();
        Assert.Empty(await AlertsAsync(root));
        Assert.Equal(deliveriesBefore, await WithDbAsync(db => db.NotificationDeliveries.CountAsync()));
    }

    [Fact]
    public async Task Alerts_are_filtered_by_organization_access_and_rules_by_scope()
    {
        var (otherOrg, otherSite) = await CreateOrgAsync(root, "Fabrikam");
        await OnlineAgentAsync("CONTOSO-1");
        await OnlineAgentAsync("FABRIKAM-1", otherOrg.Id, otherSite.Id);

        // A rule scoped to Fabrikam with a shorter threshold, beside the global default rule.
        var scoped = await root.SendAsync<AlertRuleDto>(HttpMethod.Post, "/api/v1/alert-rules",
            OfflineRule([], hours: 1, orgId: otherOrg.Id) with { Name = "Fabrikam offline", Severity = AlertSeverity.Critical }, HttpStatusCode.OK);
        await AdvanceAsync(TimeSpan.FromHours(2));
        await RunMaintenanceAsync<AlertEvaluationTask>();
        var fabrikam = Assert.Single(await AlertsAsync(root));
        Assert.Equal(scoped.Id, fabrikam.RuleId);
        Assert.Equal(AlertSeverity.Critical, fabrikam.Severity);
        Assert.Equal("Fabrikam", fabrikam.OrganizationName);

        await AdvanceAsync(TimeSpan.FromHours(23));
        await RunMaintenanceAsync<AlertEvaluationTask>();
        Assert.Equal(3, (await AlertsAsync(root)).Count); // the default rule matches both endpoints

        var contosoAdmin = await CreateAndLoginAsync("contoso-admin", UserRole.Admin, org.Id);
        var visible = Assert.Single(await AlertsAsync(contosoAdmin));
        Assert.Equal("CONTOSO-1", visible.Hostname);
        Assert.Equal(1, (await contosoAdmin.GetAsync<AlertSummaryDto>("/api/v1/alerts/summary")).Open);
        Assert.Empty(await AlertsAsync(contosoAdmin, $"?organizationId={otherOrg.Id}"));
        var ack = await contosoAdmin.SendAsync<AcknowledgeAlertsResult>(HttpMethod.Post, "/api/v1/alerts/acknowledge",
            new AcknowledgeAlertsRequest([fabrikam.Id]), HttpStatusCode.OK);
        Assert.Equal(0, ack.Acknowledged);

        // Narrowing the rule's scope closes its alerts silently.
        await root.SendAsync<AlertRuleDto>(HttpMethod.Put, $"/api/v1/alert-rules/{scoped.Id}",
            OfflineRule([], hours: 1, orgId: org.Id) with { Name = "Contoso offline" }, HttpStatusCode.OK);
        Assert.DoesNotContain(await AlertsAsync(root), a => a.RuleId == scoped.Id && a.OrganizationId == otherOrg.Id);
    }

    [Fact]
    public async Task Pending_enrollment_requests_alert_per_organization()
    {
        await root.SendAsync<AlertRuleDto>(HttpMethod.Put, $"/api/v1/alert-rules/{OfflineRuleId}", OfflineRule([]) with { Enabled = false },
            HttpStatusCode.OK);
        var code = await root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, site.Id, "RMM rollout", 30, null, null), HttpStatusCode.Created);
        foreach (var hostname in new[] { "NEW-PC-1", "NEW-PC-2" })
        {
            using var response = await NewAgent().EnrollAsync(null, code.Code, hostname);
            await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
        }

        await RunMaintenanceAsync<AlertEvaluationTask>();
        var alert = Assert.Single(await AlertsAsync(root, "?ruleType=EnrollmentPending"));
        Assert.Null(alert.EndpointId);
        Assert.Contains("2 computers", alert.Title, StringComparison.Ordinal);
        Assert.Equal(AlertSeverity.Info, alert.Severity);
        Assert.Contains(AlertRuleCatalog.Defaults(Clock.GetUtcNow()), r => r.Type == AlertRuleType.EnrollmentPending);
    }
}
