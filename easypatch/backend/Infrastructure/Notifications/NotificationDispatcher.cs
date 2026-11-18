using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Infrastructure.Notifications;

/// <summary>Sends pending notifications from the outbox with retries (1 minute doubling to 1 hour; given up after 24 hours).</summary>
public sealed class NotificationDispatcher(
    EasyPatchDbContext db,
    NotificationSecrets secrets,
    INotificationTransport transport,
    TimeProvider clock,
    ILogger<NotificationDispatcher> logger)
{
    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromHours(24);
    public static readonly TimeSpan RunBudget = TimeSpan.FromSeconds(25);

    public async Task<int> DeliverPendingAsync(CancellationToken ct)
    {
        var started = clock.GetUtcNow();
        var due = await db.NotificationDeliveries
            .Where(d => d.Status == DeliveryStatus.Pending && d.NextAttemptAt <= started)
            .OrderBy(d => d.NextAttemptAt)
            .Take(50)
            .ToListAsync(ct);
        if (due.Count == 0)
        {
            return 0;
        }

        var settings = await db.NotificationSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct) ?? new NotificationSettingsRow();
        var channelIds = due.Select(d => d.ChannelId).Distinct().ToList();
        var channels = await db.NotificationChannels.AsNoTracking().Where(c => channelIds.Contains(c.Id)).ToDictionaryAsync(c => c.Id, ct);
        var sent = 0;
        foreach (var delivery in due)
        {
            if (clock.GetUtcNow() - started > RunBudget)
            {
                break; // the rest waits for the next run
            }

            var now = clock.GetUtcNow();
            if (!channels.TryGetValue(delivery.ChannelId, out var channel) || !channel.Enabled)
            {
                delivery.Status = DeliveryStatus.Failed;
                delivery.LastError = "The channel is disabled.";
                await db.SaveChangesAsync(ct);
                continue;
            }

            try
            {
                await SendAsync(delivery, channel, settings, now, ct);
                delivery.Status = DeliveryStatus.Sent;
                delivery.SentAt = now;
                delivery.LastError = null;
                sent++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Only NotificationException messages are known to be free of URLs and secrets.
                var error = ex is NotificationException ? ex.Message : $"Unexpected error ({ex.GetType().Name}).";
                delivery.Attempts++;
                delivery.LastError = error.Length > 500 ? error[..500] : error;
                if (now - delivery.CreatedAt >= GiveUpAfter || delivery.Kind == NotificationKind.Test && delivery.Attempts >= 3)
                {
                    delivery.Status = DeliveryStatus.Failed;
                }
                else
                {
                    delivery.NextAttemptAt = now + Backoff(delivery.Attempts);
                }

                // The message is sanitized (no URLs, tokens or passwords); the exception itself is not logged.
                logger.LogWarning("Notification {DeliveryId} to channel {Channel} failed (attempt {Attempt}): {Error}",
                    delivery.Id, channel.Name, delivery.Attempts, delivery.LastError);
            }

            await db.SaveChangesAsync(ct);
        }

        return sent;
    }

    public static TimeSpan Backoff(int attempts) => TimeSpan.FromMinutes(Math.Min(60, Math.Pow(2, Math.Max(0, attempts - 1))));

    private async Task SendAsync(NotificationDelivery delivery, NotificationChannel channel, NotificationSettingsRow settings, DateTimeOffset now,
        CancellationToken ct)
    {
        NotificationMessage message;
        try
        {
            message = NotificationRenderer.Deserialize(delivery.Payload);
        }
        catch (System.Text.Json.JsonException)
        {
            throw new NotificationException("The stored notification could not be read.");
        }

        if (channel.Type == NotificationChannelType.Email)
        {
            if (channel.EmailRecipients.Count == 0)
            {
                throw new NotificationException("The channel has no recipients.");
            }

            var password = settings.SmtpPasswordProtected is null ? null : secrets.Unprotect(settings.SmtpPasswordProtected);
            await transport.SendEmailAsync(settings, password, channel.EmailRecipients, delivery.Subject,
                NotificationRenderer.Text(message), NotificationRenderer.Html(message), null, ct);
            return;
        }

        if (channel.WebhookUrlProtected is null)
        {
            throw new NotificationException("The channel has no webhook URL.");
        }

        var url = new Uri(secrets.Unprotect(channel.WebhookUrlProtected));
        var headers = new Dictionary<string, string>();
        string body;
        switch (channel.WebhookFormat ?? WebhookFormat.Generic)
        {
            case WebhookFormat.Slack:
                body = NotificationRenderer.Slack(message);
                break;
            case WebhookFormat.Teams:
                body = NotificationRenderer.Teams(message);
                break;
            default:
                body = NotificationRenderer.Generic(message, delivery.Id, now);
                headers[NotificationRenderer.EventHeader] = NotificationRenderer.EventName(message.Kind);
                if (channel.SigningSecretProtected is not null)
                {
                    headers[NotificationRenderer.SignatureHeader] = NotificationRenderer.Sign(secrets.Unprotect(channel.SigningSecretProtected), body, now);
                }

                break;
        }

        await transport.PostWebhookAsync(url, body, headers, settings.AllowPrivateNetworkWebhooks, ct);
    }
}
