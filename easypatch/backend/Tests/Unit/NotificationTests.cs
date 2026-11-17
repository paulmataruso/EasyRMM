using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Notifications;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class WebhookAddressPolicyTests
{
    private static readonly (IPAddress, int)[] Own = [(IPAddress.Parse("172.30.0.0"), 24), (IPAddress.Parse("172.31.5.0"), 24)];

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("64:ff9b::7f00:1")]
    [InlineData("2002:7f00:1::1")]
    [InlineData("169.254.169.254")]
    [InlineData("fe80::1")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("240.0.0.1")]
    [InlineData("198.18.0.1")]
    [InlineData("172.30.0.7")] // the server's own (Docker) network
    [InlineData("::ffff:172.31.5.9")]
    public void Always_blocked_even_when_private_networks_are_allowed(string address) =>
        Assert.NotNull(WebhookAddressPolicy.Check(IPAddress.Parse(address), allowPrivate: true, Own));

    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.10")]
    [InlineData("192.168.1.20")]
    [InlineData("100.64.0.1")]
    [InlineData("fd12:3456::1")]
    [InlineData("::ffff:10.0.0.1")]
    public void Private_addresses_need_the_setting(string address)
    {
        Assert.NotNull(WebhookAddressPolicy.Check(IPAddress.Parse(address), allowPrivate: false, Own));
        Assert.Null(WebhookAddressPolicy.Check(IPAddress.Parse(address), allowPrivate: true, Own));
    }

    [Theory]
    [InlineData("52.96.0.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("8.8.8.8")]
    public void Public_addresses_are_allowed(string address) =>
        Assert.Null(WebhookAddressPolicy.Check(IPAddress.Parse(address), allowPrivate: false, Own));

    [Fact]
    public void Network_membership_respects_the_prefix()
    {
        Assert.True(WebhookAddressPolicy.InNetwork(IPAddress.Parse("172.31.255.1"), IPAddress.Parse("172.16.0.0"), 12));
        Assert.False(WebhookAddressPolicy.InNetwork(IPAddress.Parse("172.32.0.1"), IPAddress.Parse("172.16.0.0"), 12));
    }
}

public sealed class NotificationRendererTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 9, 30, 0, TimeSpan.Zero);

    private static Alert Alert(string title, AlertSeverity severity = AlertSeverity.Warning, Guid? endpoint = null) => new()
    {
        Id = Guid.NewGuid(),
        DedupeKey = Guid.NewGuid().ToString("N"),
        Title = title,
        Severity = severity,
        OrganizationId = OrgId,
        EndpointId = endpoint ?? Guid.NewGuid(),
        OpenedAt = Now,
        LastSeenAt = Now,
    };

    private static readonly Guid OrgId = Guid.NewGuid();
    private static readonly Dictionary<Guid, string> Orgs = new() { [OrgId] = "Contoso & Co" };

    [Fact]
    public void Digest_is_capped_and_sorted_by_severity()
    {
        var alerts = Enumerable.Range(1, 30).Select(i => Alert($"PC-{i:00} offline")).Append(Alert("SRV-01: 2 security updates missing", AlertSeverity.Critical)).ToList();
        var m = AlertEngine.BuildMessage(NotificationKind.AlertsOpened, alerts, Orgs, "https://patch.example.com/");
        Assert.Equal("[EasyPatch] 31 new alerts", m.Subject);
        Assert.Equal(AlertEngine.MaxItemsPerMessage, m.Items.Count);
        Assert.Equal(6, m.MoreCount);
        Assert.Equal(AlertSeverity.Critical, m.Items[0].Severity);
        Assert.StartsWith("https://patch.example.com/endpoints/", m.Items[0].Url, StringComparison.Ordinal);
        Assert.Equal("https://patch.example.com/alerts", m.ConsoleUrl);
    }

    [Fact]
    public void Single_alert_subject_names_it()
    {
        var m = AlertEngine.BuildMessage(NotificationKind.AlertsResolved, [Alert("PC-01 offline")], Orgs, "https://x.test");
        Assert.Equal("[EasyPatch] Resolved: PC-01 offline", m.Subject);
    }

    [Fact]
    public void Formats_escape_user_controlled_text()
    {
        var m = AlertEngine.BuildMessage(NotificationKind.AlertsOpened, [Alert("<script>alert(1)</script> | [x](y)")], Orgs, "https://x.test");
        Assert.DoesNotContain("<script>", NotificationRenderer.Html(m), StringComparison.Ordinal);
        Assert.Contains("Contoso &amp; Co", NotificationRenderer.Html(m), StringComparison.Ordinal);
        var slack = JsonDocument.Parse(NotificationRenderer.Slack(m)).RootElement.GetProperty("text").GetString()!;
        Assert.DoesNotContain("<script>", slack, StringComparison.Ordinal);

        var teams = JsonDocument.Parse(NotificationRenderer.Teams(m)).RootElement;
        Assert.Equal("message", teams.GetProperty("type").GetString());
        var card = teams.GetProperty("attachments")[0].GetProperty("content");
        Assert.Equal("AdaptiveCard", card.GetProperty("type").GetString());
        Assert.Equal("1.4", card.GetProperty("version").GetString());
    }

    [Fact]
    public void Generic_payload_is_signed_with_hmac_sha256()
    {
        var m = AlertEngine.BuildMessage(NotificationKind.AlertsOpened, [Alert("PC-01 offline")], Orgs, "https://x.test");
        var delivery = Guid.NewGuid();
        var body = NotificationRenderer.Generic(m, delivery, Now);
        var doc = JsonDocument.Parse(body).RootElement;
        Assert.Equal("alerts.opened", doc.GetProperty("event").GetString());
        Assert.Equal(delivery.ToString(), doc.GetProperty("deliveryId").GetString());
        Assert.Equal("Contoso & Co", doc.GetProperty("alerts")[0].GetProperty("organization").GetString());

        var signature = NotificationRenderer.Sign("s3cret", body, Now);
        var t = Now.ToUnixTimeSeconds();
        var expected = Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes("s3cret"), Encoding.UTF8.GetBytes($"{t}.{body}")));
        Assert.Equal($"t={t},v1={expected}", signature);
    }

    [Fact]
    public void Payload_round_trips()
    {
        var m = AlertEngine.BuildMessage(NotificationKind.AlertsReminder, [Alert("A"), Alert("B")], Orgs, "https://x.test");
        var back = NotificationRenderer.Deserialize(NotificationRenderer.Serialize(m));
        Assert.Equal(m.Subject, back.Subject);
        Assert.Equal(m.Items.Count, back.Items.Count);
        Assert.Equal(NotificationKind.AlertsReminder, back.Kind);
    }

    [Fact]
    public void Retries_back_off_to_one_hour() =>
        Assert.Equal([1, 2, 4, 8, 16, 32, 60, 60], Enumerable.Range(1, 8).Select(a => NotificationDispatcher.Backoff(a).TotalMinutes).ToArray());
}

public sealed class AlertRuleCatalogTests
{
    [Fact]
    public void Defaults_are_valid_and_unique()
    {
        var rules = AlertRuleCatalog.Defaults(DateTimeOffset.UnixEpoch);
        Assert.All(rules, r => Assert.Empty(AlertRuleCatalog.Validate(r)));
        Assert.Equal(rules.Count, rules.Select(r => r.Type).Distinct().Count());
    }

    [Fact]
    public void Thresholds_are_validated_per_type()
    {
        Assert.NotEmpty(AlertRuleCatalog.Validate(new AlertRule { Name = "x", Type = AlertRuleType.EndpointOffline, Threshold = 0 }));
        Assert.NotEmpty(AlertRuleCatalog.Validate(new AlertRule { Name = "x", Type = AlertRuleType.InstallFailed, Threshold = 3 }));
        Assert.NotEmpty(AlertRuleCatalog.Validate(new AlertRule { Name = "x", Type = AlertRuleType.EnrollmentPending, TagId = Guid.NewGuid() }));
        Assert.Empty(AlertRuleCatalog.Validate(new AlertRule { Name = "x", Type = AlertRuleType.SecurityUpdateMissing, Threshold = 0 }));
    }
}
