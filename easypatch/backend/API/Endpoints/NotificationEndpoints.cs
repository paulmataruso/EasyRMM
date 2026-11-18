using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MimeKit;

namespace EasyPatch.Api.Endpoints;

/// <summary>Alerts (every console user, tenant-filtered) and notification configuration (SuperAdmin).</summary>
public static class NotificationEndpoints
{
    public const int MaxWebhookUrlLength = 2048;
    public static readonly TimeSpan TestInterval = TimeSpan.FromSeconds(30);

    public static void MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        MapAlerts(app);
        MapSettings(app);
        MapChannels(app);
        MapRules(app);
    }

    private static void MapAlerts(IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/alerts").WithTags("Alerts").RequireAuthorization(Policies.Viewer);

        g.MapGet("/", async (string? status, AlertSeverity? severity, Guid? organizationId, Guid? endpointId, AlertRuleType? ruleType, string? search,
            int? page, int? pageSize, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = Visible(db, tenant);
            query = status?.ToLowerInvariant() switch
            {
                null or "" or "unresolved" => query.Where(a => a.Status != AlertStatus.Resolved),
                "open" => query.Where(a => a.Status == AlertStatus.Open),
                "acknowledged" => query.Where(a => a.Status == AlertStatus.Acknowledged),
                "resolved" => query.Where(a => a.Status == AlertStatus.Resolved),
                "all" => query,
                _ => throw AppException.BadRequest("status must be unresolved, open, acknowledged, resolved or all.", "validation_failed"),
            };
            if (severity is { } sv)
            {
                query = query.Where(a => a.Severity == sv);
            }

            if (organizationId is { } org)
            {
                query = query.Where(a => a.OrganizationId == org);
            }

            if (endpointId is { } ep)
            {
                query = query.Where(a => a.EndpointId == ep);
            }

            if (ruleType is { } rt)
            {
                query = query.Where(a => a.RuleType == rt);
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                var pattern = "%" + OrganizationEndpoints.EscapeLike(search.Trim()) + "%";
                query = query.Where(a => EF.Functions.ILike(a.Title, pattern));
            }

            var rows = query
                .OrderBy(a => a.Status == AlertStatus.Resolved)
                .ThenByDescending(a => a.Severity == AlertSeverity.Critical ? 2 : a.Severity == AlertSeverity.Warning ? 1 : 0)
                .ThenByDescending(a => a.OpenedAt)
                .Select(a => new AlertDto(
                    a.Id, a.RuleId, db.AlertRules.Where(r => r.Id == a.RuleId).Select(r => r.Name).FirstOrDefault(), a.RuleType, a.Severity, a.Status,
                    a.Title, a.Details, a.OrganizationId, db.Organizations.Where(o => o.Id == a.OrganizationId).Select(o => o.Name).FirstOrDefault() ?? "",
                    a.EndpointId, db.Endpoints.Where(e => e.Id == a.EndpointId).Select(e => e.Hostname).FirstOrDefault(), a.OpenedAt, a.LastSeenAt,
                    a.ResolvedAt, a.AcknowledgedAt, a.AcknowledgedBy));
            return TypedResults.Ok(await rows.ToPagedAsync(PageRequest.From(page, pageSize), ct));
        });

        g.MapGet("/summary", async (EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var counts = await Visible(db, tenant).Where(a => a.Status != AlertStatus.Resolved)
                .GroupBy(a => new { a.Status, a.Severity }).Select(x => new { x.Key.Status, x.Key.Severity, Count = x.Count() }).ToListAsync(ct);
            return TypedResults.Ok(new AlertSummaryDto(
                counts.Where(c => c.Status == AlertStatus.Open).Sum(c => c.Count),
                counts.Where(c => c.Status == AlertStatus.Acknowledged).Sum(c => c.Count),
                counts.Where(c => c.Severity == AlertSeverity.Critical).Sum(c => c.Count),
                counts.Where(c => c.Severity == AlertSeverity.Warning).Sum(c => c.Count),
                counts.Where(c => c.Severity == AlertSeverity.Info).Sum(c => c.Count)));
        });

        g.MapPost("/acknowledge", async (AcknowledgeAlertsRequest request, EasyPatchDbContext db, ITenantContext tenant, IActorContext actor,
            AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var ids = (request.AlertIds ?? []).Distinct().ToList();
            if (ids.Count is 0 or > 500)
            {
                throw AppException.BadRequest("Select 1 to 500 alerts.", "validation_failed");
            }

            var alerts = await Visible(db, tenant).Where(a => ids.Contains(a.Id) && a.Status == AlertStatus.Open).ToListAsync(ct);
            var now = clock.GetUtcNow();
            foreach (var alert in alerts)
            {
                alert.Status = AlertStatus.Acknowledged;
                alert.AcknowledgedAt = now;
                alert.AcknowledgedBy = actor.Username;
            }

            if (alerts.Count > 0)
            {
                audit.Record("alert.acknowledge", "Alert", alerts.Count == 1 ? alerts[0].Id.ToString() : null,
                    alerts.Select(a => a.OrganizationId).Distinct().Count() == 1 ? alerts[0].OrganizationId : null,
                    details: new { Alerts = alerts.Count, Ids = alerts.Select(a => a.Id).Take(50).ToList() });
                await db.SaveChangesAsync(ct);
            }

            return TypedResults.Ok(new AcknowledgeAlertsResult(alerts.Count));
        }).RequireAuthorization(Policies.Operator);
    }

    private static IQueryable<Alert> Visible(EasyPatchDbContext db, ITenantContext tenant)
    {
        var query = db.Alerts.AsQueryable();
        if (!tenant.IsUnrestricted)
        {
            var allowed = tenant.AllowedOrganizationIds.ToList();
            query = query.Where(a => allowed.Contains(a.OrganizationId));
        }

        return query;
    }

    private static void MapSettings(IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/notifications").WithTags("Notifications").RequireAuthorization(Policies.SuperAdmin);

        g.MapGet("/settings", async (EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(ToDto(await db.NotificationSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct) ?? new NotificationSettingsRow())));

        g.MapPut("/settings", async (NotificationSettingsRequest request, EasyPatchDbContext db, NotificationSecrets secrets, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            var v = new Validator();
            var host = string.IsNullOrWhiteSpace(request.SmtpHost) ? null : request.SmtpHost.Trim();
            var from = string.IsNullOrWhiteSpace(request.FromAddress) ? null : request.FromAddress.Trim();
            if (host is not null)
            {
                v.Check(host.Length <= 253 && Uri.CheckHostName(host) != UriHostNameType.Unknown, "smtpHost", "Enter a host name or IP address.");
                v.Check(request.SmtpPort is > 0 and <= 65535, "smtpPort", "Port must be between 1 and 65535.");
                v.Check(from is not null && IsEmail(from), "fromAddress", "Enter the sender address.");
            }

            v.Check(Enum.IsDefined(request.SmtpSecurity), "smtpSecurity", "Unknown security mode.");
            v.Check(request.SmtpUsername is null || request.SmtpUsername.Length <= 256, "smtpUsername", "At most 256 characters.");
            v.Check(request.SmtpPassword is null || request.SmtpPassword.Length <= 512, "smtpPassword", "At most 512 characters.");
            v.Check(request.FromName is null || request.FromName.Length <= 100, "fromName", "At most 100 characters.");
            v.ThrowIfInvalid();

            var row = await db.NotificationSettings.FirstOrDefaultAsync(s => s.Id == 1, ct);
            if (row is null)
            {
                row = new NotificationSettingsRow { Id = 1 };
                db.NotificationSettings.Add(row);
            }

            row.SmtpHost = host;
            row.SmtpPort = request.SmtpPort is > 0 and <= 65535 ? request.SmtpPort : 587;
            row.SmtpSecurity = request.SmtpSecurity;
            row.SmtpSkipCertificateValidation = request.SmtpSkipCertificateValidation && request.SmtpSecurity != SmtpSecurity.None;
            row.SmtpUsername = string.IsNullOrWhiteSpace(request.SmtpUsername) ? null : request.SmtpUsername.Trim();
            if (request.SmtpPassword is not null)
            {
                row.SmtpPasswordProtected = request.SmtpPassword.Length == 0 ? null : secrets.Protect(request.SmtpPassword);
            }

            row.FromAddress = from;
            row.FromName = string.IsNullOrWhiteSpace(request.FromName) ? null : request.FromName.Trim();
            row.AllowPrivateNetworkWebhooks = request.AllowPrivateNetworkWebhooks;
            row.UpdatedAt = clock.GetUtcNow();
            audit.Record("notifications.settings_update", "NotificationSettings", null, details: new
            {
                SmtpHost = host,
                row.SmtpPort,
                row.SmtpSecurity,
                row.SmtpSkipCertificateValidation,
                row.SmtpUsername,
                PasswordChanged = request.SmtpPassword is not null,
                FromAddress = from,
                row.AllowPrivateNetworkWebhooks,
            });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(ToDto(row));
        });

        g.MapGet("/deliveries", async (Guid? channelId, DeliveryStatus? status, int? page, int? pageSize, EasyPatchDbContext db, CancellationToken ct) =>
        {
            var query = db.NotificationDeliveries.AsNoTracking();
            if (channelId is { } c)
            {
                query = query.Where(d => d.ChannelId == c);
            }

            if (status is { } s)
            {
                query = query.Where(d => d.Status == s);
            }

            var rows = query.OrderByDescending(d => d.CreatedAt).Select(d => new NotificationDeliveryDto(
                d.Id, d.ChannelId, db.NotificationChannels.Where(x => x.Id == d.ChannelId).Select(x => x.Name).FirstOrDefault() ?? "", d.Kind, d.Subject,
                d.Status, d.Attempts, d.LastError, d.CreatedAt, d.NextAttemptAt, d.SentAt));
            return TypedResults.Ok(await rows.ToPagedAsync(PageRequest.From(page, pageSize), ct));
        });
    }

    private static void MapChannels(IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/notifications/channels").WithTags("Notifications").RequireAuthorization(Policies.SuperAdmin);

        g.MapGet("/", async (EasyPatchDbContext db, CancellationToken ct) =>
        {
            var channels = await db.NotificationChannels.AsNoTracking().OrderBy(c => c.Name).ToListAsync(ct);
            var last = await LastDeliveriesAsync(db, ct);
            return TypedResults.Ok(channels.Select(c => ToDto(c, last.GetValueOrDefault(c.Id))).ToList());
        });

        g.MapPost("/", async (NotificationChannelRequest request, EasyPatchDbContext db, NotificationSecrets secrets, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var channel = new NotificationChannel { Id = Guid.CreateVersion7(now), Name = "", CreatedAt = now, UpdatedAt = now };
            var secret = Apply(channel, request, secrets, creating: true);
            db.NotificationChannels.Add(channel);
            audit.Record("notifications.channel_create", "NotificationChannel", channel.Id.ToString(),
                details: new { channel.Name, channel.Type, channel.WebhookFormat, channel.WebhookHost, Recipients = channel.EmailRecipients.Count });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(new NotificationChannelSavedDto(ToDto(channel, null), secret));
        });

        g.MapPut("/{id:guid}", async (Guid id, NotificationChannelRequest request, EasyPatchDbContext db, NotificationSecrets secrets, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            var channel = await db.NotificationChannels.FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Channel");
            var secret = Apply(channel, request, secrets, creating: false);
            channel.UpdatedAt = clock.GetUtcNow();
            audit.Record("notifications.channel_update", "NotificationChannel", id.ToString(),
                details: new { channel.Name, channel.Type, channel.Enabled, channel.WebhookFormat, channel.WebhookHost, UrlChanged = request.WebhookUrl is not null });
            await db.SaveChangesAsync(ct);
            var last = await LastDeliveriesAsync(db, ct);
            return TypedResults.Ok(new NotificationChannelSavedDto(ToDto(channel, last.GetValueOrDefault(id)), secret));
        });

        g.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, AuditService audit, CancellationToken ct) =>
        {
            var channel = await db.NotificationChannels.FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Channel");
            db.NotificationChannels.Remove(channel); // its deliveries cascade
            foreach (var rule in await db.AlertRules.Where(r => r.ChannelIds.Contains(id)).ToListAsync(ct))
            {
                rule.ChannelIds = rule.ChannelIds.Where(c => c != id).ToList();
            }

            audit.Record("notifications.channel_delete", "NotificationChannel", id.ToString(), details: new { channel.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        });

        g.MapPost("/{id:guid}/rotate-secret", async (Guid id, EasyPatchDbContext db, NotificationSecrets secrets, AuditService audit, TimeProvider clock,
            CancellationToken ct) =>
        {
            var channel = await db.NotificationChannels.FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Channel");
            if (channel.Type != NotificationChannelType.Webhook || channel.WebhookFormat != WebhookFormat.Generic)
            {
                throw AppException.BadRequest("Only generic webhooks have a signing secret.", "validation_failed");
            }

            var secret = NotificationSecrets.NewSigningSecret();
            channel.SigningSecretProtected = secrets.Protect(secret);
            channel.UpdatedAt = clock.GetUtcNow();
            audit.Record("notifications.channel_rotate_secret", "NotificationChannel", id.ToString(), details: new { channel.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(new NotificationChannelSavedDto(ToDto(channel, null), secret));
        });

        // Queues a test message; the worker sends it (same path as real notifications) and the delivery list shows the result.
        g.MapPost("/{id:guid}/test", async (Guid id, EasyPatchDbContext db, IOptions<EasyPatchOptions> options, AuditService audit, TimeProvider clock,
            CancellationToken ct) =>
        {
            var channel = await db.NotificationChannels.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Channel");
            var now = clock.GetUtcNow();
            if (await db.NotificationDeliveries.AnyAsync(d => d.ChannelId == id && d.Kind == NotificationKind.Test && d.CreatedAt > now - TestInterval, ct))
            {
                throw new AppException(429, "test_rate_limited", "A test was sent to this channel less than 30 seconds ago.");
            }

            var message = AlertEngine.TestMessage(channel.Name, options.Value.PublicUrl);
            var delivery = new NotificationDelivery
            {
                Id = Guid.CreateVersion7(now),
                ChannelId = id,
                Kind = NotificationKind.Test,
                Subject = message.Subject,
                Payload = NotificationRenderer.Serialize(message),
                Status = DeliveryStatus.Pending,
                NextAttemptAt = now,
                CreatedAt = now,
            };
            db.NotificationDeliveries.Add(delivery);
            audit.Record("notifications.channel_test", "NotificationChannel", id.ToString(), details: new { channel.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.Accepted((string?)null, new NotificationDeliveryDto(delivery.Id, id, channel.Name, delivery.Kind, delivery.Subject,
                delivery.Status, 0, null, now, now, null));
        });
    }

    private static void MapRules(IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/alert-rules").WithTags("Alerts").RequireAuthorization(Policies.SuperAdmin);

        g.MapGet("/types", () => TypedResults.Ok(Enum.GetValues<AlertRuleType>().Select(t =>
        {
            var spec = AlertRuleCatalog.Threshold(t);
            return new AlertRuleTypeDto(t, spec?.Unit, spec?.Min, spec?.Max, spec?.Default, AlertRuleCatalog.IsEndpointRule(t));
        }).ToList()));

        g.MapGet("/", async (EasyPatchDbContext db, CancellationToken ct) =>
        {
            var rules = await db.AlertRules.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);
            var open = await db.Alerts.AsNoTracking().Where(a => a.Status != AlertStatus.Resolved && a.RuleId != null)
                .GroupBy(a => a.RuleId!.Value).Select(x => new { x.Key, Count = x.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
            return TypedResults.Ok(rules.Select(r => ToDto(r, open.GetValueOrDefault(r.Id))).ToList());
        });

        g.MapPost("/", async (AlertRuleRequest request, EasyPatchDbContext db, AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var rule = new AlertRule { Id = Guid.CreateVersion7(now), Name = "", CreatedAt = now, UpdatedAt = now };
            await ApplyAsync(rule, request, db, ct);
            db.AlertRules.Add(rule);
            audit.Record("alert_rule.create", "AlertRule", rule.Id.ToString(), rule.OrganizationId, details: request);
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(ToDto(rule, 0));
        });

        g.MapPut("/{id:guid}", async (Guid id, AlertRuleRequest request, EasyPatchDbContext db, AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw AppException.NotFound("Alert rule");
            var scopeChanged = rule.Type != request.Type || rule.Threshold != request.Threshold || rule.OrganizationId != request.OrganizationId ||
                               rule.TagId != request.TagId;
            var disabling = rule.Enabled && !request.Enabled;
            await ApplyAsync(rule, request, db, ct);
            rule.UpdatedAt = clock.GetUtcNow();
            audit.Record("alert_rule.update", "AlertRule", id.ToString(), rule.OrganizationId, details: request);
            await db.SaveChangesAsync(ct);
            if (scopeChanged || disabling)
            {
                // Close the rule's alerts without notifications; after a scope change the next evaluation reopens those that still
                // match (also without a notification, because they were resolved less than an hour ago).
                var now = clock.GetUtcNow();
                await db.Alerts.Where(a => a.RuleId == id && a.Status != AlertStatus.Resolved)
                    .ExecuteUpdateAsync(x => x.SetProperty(a => a.Status, AlertStatus.Resolved).SetProperty(a => a.ResolvedAt, now), ct);
            }

            var open = await db.Alerts.CountAsync(a => a.RuleId == id && a.Status != AlertStatus.Resolved, ct);
            return TypedResults.Ok(ToDto(rule, open));
        });

        g.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw AppException.NotFound("Alert rule");
            var now = clock.GetUtcNow();
            await db.Alerts.Where(a => a.RuleId == id && a.Status != AlertStatus.Resolved)
                .ExecuteUpdateAsync(x => x.SetProperty(a => a.Status, AlertStatus.Resolved).SetProperty(a => a.ResolvedAt, now), ct);
            db.AlertRules.Remove(rule); // alerts keep their history (rule_id is set to null)
            audit.Record("alert_rule.delete", "AlertRule", id.ToString(), rule.OrganizationId, details: new { rule.Name, rule.Type });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        });
    }

    private static async Task ApplyAsync(AlertRule rule, AlertRuleRequest request, EasyPatchDbContext db, CancellationToken ct)
    {
        rule.Name = request.Name?.Trim() ?? "";
        rule.Type = request.Type;
        rule.Enabled = request.Enabled;
        rule.Severity = request.Severity;
        rule.Threshold = AlertRuleCatalog.Threshold(request.Type) is null ? null : request.Threshold;
        rule.OrganizationId = request.OrganizationId;
        rule.TagId = request.TagId;
        rule.ChannelIds = (request.ChannelIds ?? []).Distinct().ToList();
        rule.NotifyOnResolve = request.NotifyOnResolve;
        rule.RenotifyHours = request.RenotifyHours;
        var errors = AlertRuleCatalog.Validate(rule).ToList();
        if (!Enum.IsDefined(request.Severity))
        {
            errors.Add("Unknown severity.");
        }

        if (rule.OrganizationId is { } org && !await db.Organizations.AnyAsync(o => o.Id == org, ct))
        {
            errors.Add("Organization not found.");
        }

        if (rule.TagId is { } tag && !await db.Tags.AnyAsync(t => t.Id == tag, ct))
        {
            errors.Add("Tag not found.");
        }

        if (rule.ChannelIds.Count > 0)
        {
            var found = await db.NotificationChannels.CountAsync(c => rule.ChannelIds.Contains(c.Id), ct);
            if (found != rule.ChannelIds.Count)
            {
                errors.Add("Channel not found.");
            }
        }

        if (errors.Count > 0)
        {
            throw AppException.BadRequest(string.Join(" ", errors), "validation_failed");
        }
    }

    /// <summary>Validates and applies a channel request. Returns a new signing secret when one was generated.</summary>
    private static string? Apply(NotificationChannel channel, NotificationChannelRequest request, NotificationSecrets secrets, bool creating)
    {
        var v = new Validator();
        var name = request.Name?.Trim() ?? "";
        v.Check(name.Length is > 0 and <= 100, "name", "Name must be 1-100 characters.");
        v.Check(Enum.IsDefined(request.Type), "type", "Unknown channel type.");
        v.Check(creating || request.Type == channel.Type, "type", "The channel type cannot be changed.");
        var recipients = new List<string>();
        Uri? url = null;
        if (request.Type == NotificationChannelType.Email)
        {
            recipients = (request.EmailRecipients ?? []).Select(r => r.Trim()).Where(r => r.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            v.Check(recipients.Count is > 0 and <= NotificationChannel.MaxRecipients, "emailRecipients",
                $"Enter 1 to {NotificationChannel.MaxRecipients} email addresses.");
            v.Check(recipients.All(IsEmail), "emailRecipients", "One of the email addresses is not valid.");
        }
        else
        {
            v.Check(request.WebhookFormat is { } f && Enum.IsDefined(f), "webhookFormat", "Choose Generic, Slack or Teams.");
            if (request.WebhookUrl is not null || creating)
            {
                var raw = request.WebhookUrl?.Trim() ?? "";
                var valid = raw.Length is > 0 and <= MaxWebhookUrlLength && Uri.TryCreate(raw, UriKind.Absolute, out url) &&
                            url.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(url.UserInfo);
                v.Check(valid, "webhookUrl", "Enter the https:// URL of the webhook.");
            }
        }

        v.ThrowIfInvalid();
        channel.Name = name;
        channel.Type = request.Type;
        channel.Enabled = request.Enabled;
        string? newSecret = null;
        if (request.Type == NotificationChannelType.Email)
        {
            channel.EmailRecipients = recipients;
            channel.WebhookFormat = null;
            channel.WebhookUrlProtected = null;
            channel.WebhookHost = null;
            channel.SigningSecretProtected = null;
            return null;
        }

        channel.EmailRecipients = [];
        channel.WebhookFormat = request.WebhookFormat;
        if (url is not null)
        {
            channel.WebhookUrlProtected = secrets.Protect(url.ToString());
            channel.WebhookHost = url.Host;
        }

        if (request.WebhookFormat == WebhookFormat.Generic && channel.SigningSecretProtected is null)
        {
            newSecret = NotificationSecrets.NewSigningSecret();
            channel.SigningSecretProtected = secrets.Protect(newSecret);
        }
        else if (request.WebhookFormat != WebhookFormat.Generic)
        {
            channel.SigningSecretProtected = null;
        }

        return newSecret;
    }

    internal static bool IsEmail(string value) =>
        value.Length <= 254 && MailboxAddress.TryParse(value, out var mailbox) && mailbox.Address.Contains('@', StringComparison.Ordinal) &&
        string.Equals(mailbox.Address, value, StringComparison.OrdinalIgnoreCase);

    private static async Task<Dictionary<Guid, DeliverySummaryDto>> LastDeliveriesAsync(EasyPatchDbContext db, CancellationToken ct)
    {
        var rows = await db.NotificationDeliveries.AsNoTracking()
            .GroupBy(d => d.ChannelId)
            .Select(g => g.OrderByDescending(d => d.CreatedAt).Select(d => new { d.ChannelId, d.Status, d.CreatedAt, d.LastError }).First())
            .ToListAsync(ct);
        return rows.ToDictionary(r => r.ChannelId, r => new DeliverySummaryDto(r.Status, r.CreatedAt, r.LastError));
    }

    private static NotificationSettingsDto ToDto(NotificationSettingsRow s) => new(
        s.SmtpHost, s.SmtpPort, s.SmtpSecurity, s.SmtpUsername, s.SmtpPasswordProtected is not null, s.FromAddress, s.FromName,
        s.AllowPrivateNetworkWebhooks, s.UpdatedAt, s.SmtpSkipCertificateValidation);

    private static NotificationChannelDto ToDto(NotificationChannel c, DeliverySummaryDto? last) => new(
        c.Id, c.Name, c.Type, c.Enabled, c.EmailRecipients, c.WebhookFormat, c.WebhookHost, c.SigningSecretProtected is not null, c.CreatedAt,
        c.UpdatedAt, last);

    private static AlertRuleDto ToDto(AlertRule r, int unresolved) => new(
        r.Id, r.Name, r.Type, r.Enabled, r.Severity, r.Threshold, AlertRuleCatalog.Threshold(r.Type)?.Unit, r.OrganizationId, r.TagId, r.ChannelIds,
        r.NotifyOnResolve, r.RenotifyHours, unresolved, r.UpdatedAt);
}
