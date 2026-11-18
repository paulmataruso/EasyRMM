using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using EasyPatch.Core.Entities;

namespace EasyPatch.Infrastructure.Notifications;

/// <summary>One line of a notification (an alert). Contains only names, titles and console links: no secrets.</summary>
public sealed record NotificationItem(
    Guid? AlertId, AlertSeverity Severity, string Title, string? Organization, string? Details, string? Url, DateTimeOffset At);

/// <summary>What a notification says, independent of the channel format. Stored as the delivery payload.</summary>
public sealed record NotificationMessage(
    NotificationKind Kind, string Subject, string Intro, IReadOnlyList<NotificationItem> Items, int MoreCount, string ConsoleUrl);

/// <summary>Renders a <see cref="NotificationMessage"/> for email, Slack, Teams and the generic signed webhook.</summary>
public static class NotificationRenderer
{
    public const string SignatureHeader = "X-EasyPatch-Signature";
    public const string EventHeader = "X-EasyPatch-Event";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    public static string Serialize(NotificationMessage message) => JsonSerializer.Serialize(message, PayloadJson.Options);

    public static NotificationMessage Deserialize(string json) =>
        JsonSerializer.Deserialize<NotificationMessage>(json, PayloadJson.Options) ?? throw new InvalidOperationException("Empty notification payload.");

    public static string EventName(NotificationKind kind) => kind switch
    {
        NotificationKind.AlertsOpened => "alerts.opened",
        NotificationKind.AlertsResolved => "alerts.resolved",
        NotificationKind.AlertsReminder => "alerts.reminder",
        NotificationKind.Test => "test",
        _ => kind.ToString().ToLowerInvariant(),
    };

    public static string Text(NotificationMessage m)
    {
        ArgumentNullException.ThrowIfNull(m);
        var sb = new StringBuilder();
        sb.AppendLine(m.Intro).AppendLine();
        foreach (var item in m.Items)
        {
            sb.Append("* [").Append(item.Severity).Append("] ").AppendLine(item.Title);
            if (item.Organization is not null)
            {
                sb.Append("  Organization: ").AppendLine(item.Organization);
            }

            if (item.Details is not null)
            {
                sb.Append("  ").AppendLine(item.Details);
            }

            if (item.Url is not null)
            {
                sb.Append("  ").AppendLine(item.Url);
            }
        }

        if (m.MoreCount > 0)
        {
            sb.Append("…and ").Append(m.MoreCount.ToString(CultureInfo.InvariantCulture)).AppendLine(" more.");
        }

        sb.AppendLine().Append("Open EasyPatch: ").AppendLine(m.ConsoleUrl);
        return sb.ToString();
    }

    public static string Html(NotificationMessage m)
    {
        ArgumentNullException.ThrowIfNull(m);
        static string E(string? s) => WebUtility.HtmlEncode(s ?? string.Empty);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><body style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937\">");
        sb.Append("<p>").Append(E(m.Intro)).Append("</p><ul style=\"padding-left:18px\">");
        foreach (var item in m.Items)
        {
            var color = item.Severity switch { AlertSeverity.Critical => "#b91c1c", AlertSeverity.Warning => "#b45309", _ => "#2563eb" };
            sb.Append("<li style=\"margin-bottom:8px\"><strong style=\"color:").Append(color).Append("\">").Append(E(item.Severity.ToString()))
                .Append("</strong> ");
            sb.Append(item.Url is null ? E(item.Title) : $"<a href=\"{E(item.Url)}\">{E(item.Title)}</a>");
            if (item.Organization is not null)
            {
                sb.Append("<br><span style=\"color:#6b7280\">").Append(E(item.Organization)).Append("</span>");
            }

            if (item.Details is not null)
            {
                sb.Append("<br><span style=\"color:#6b7280\">").Append(E(item.Details)).Append("</span>");
            }

            sb.Append("</li>");
        }

        sb.Append("</ul>");
        if (m.MoreCount > 0)
        {
            sb.Append("<p>…and ").Append(m.MoreCount.ToString(CultureInfo.InvariantCulture)).Append(" more.</p>");
        }

        sb.Append("<p><a href=\"").Append(E(m.ConsoleUrl)).Append("\">Open EasyPatch</a></p></body></html>");
        return sb.ToString();
    }

    public static string Slack(NotificationMessage m)
    {
        ArgumentNullException.ThrowIfNull(m);
        static string Esc(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
        var sb = new StringBuilder();
        sb.Append('*').Append(Esc(m.Subject)).Append("*\n").Append(Esc(m.Intro)).Append('\n');
        foreach (var item in m.Items)
        {
            var icon = item.Severity switch { AlertSeverity.Critical => ":red_circle:", AlertSeverity.Warning => ":large_orange_circle:", _ => ":large_blue_circle:" };
            sb.Append(icon).Append(' ');
            sb.Append(item.Url is null ? Esc(item.Title) : $"<{item.Url}|{Esc(item.Title)}>");
            if (item.Organization is not null)
            {
                sb.Append(" — ").Append(Esc(item.Organization));
            }

            sb.Append('\n');
        }

        if (m.MoreCount > 0)
        {
            sb.Append("…and ").Append(m.MoreCount.ToString(CultureInfo.InvariantCulture)).Append(" more.\n");
        }

        sb.Append('<').Append(m.ConsoleUrl).Append("|Open EasyPatch>");
        return new JsonObject { ["text"] = sb.ToString() }.ToJsonString(Json);
    }

    /// <summary>Microsoft Teams Workflows webhook: a message with an Adaptive Card 1.4 attachment.</summary>
    public static string Teams(NotificationMessage m)
    {
        ArgumentNullException.ThrowIfNull(m);
        var body = new JsonArray
        {
            new JsonObject { ["type"] = "TextBlock", ["text"] = m.Subject, ["weight"] = "Bolder", ["size"] = "Medium", ["wrap"] = true },
            new JsonObject { ["type"] = "TextBlock", ["text"] = m.Intro, ["wrap"] = true, ["spacing"] = "Small" },
        };
        foreach (var item in m.Items)
        {
            var color = item.Severity switch { AlertSeverity.Critical => "Attention", AlertSeverity.Warning => "Warning", _ => "Accent" };
            var text = item.Url is null ? item.Title : $"[{EscapeMarkdown(item.Title)}]({item.Url})";
            var lines = new JsonArray
            {
                new JsonObject { ["type"] = "TextBlock", ["text"] = item.Severity.ToString(), ["color"] = color, ["weight"] = "Bolder", ["size"] = "Small" },
                new JsonObject { ["type"] = "TextBlock", ["text"] = text, ["wrap"] = true, ["spacing"] = "None" },
            };
            if (item.Organization is not null)
            {
                lines.Add(new JsonObject { ["type"] = "TextBlock", ["text"] = item.Organization, ["isSubtle"] = true, ["wrap"] = true, ["spacing"] = "None", ["size"] = "Small" });
            }

            body.Add(new JsonObject { ["type"] = "Container", ["separator"] = true, ["items"] = lines });
        }

        if (m.MoreCount > 0)
        {
            body.Add(new JsonObject { ["type"] = "TextBlock", ["text"] = $"…and {m.MoreCount} more.", ["isSubtle"] = true });
        }

        var card = new JsonObject
        {
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
            ["type"] = "AdaptiveCard",
            ["version"] = "1.4",
            ["body"] = body,
            ["actions"] = new JsonArray { new JsonObject { ["type"] = "Action.OpenUrl", ["title"] = "Open EasyPatch", ["url"] = m.ConsoleUrl } },
        };
        var message = new JsonObject
        {
            ["type"] = "message",
            ["attachments"] = new JsonArray
            {
                new JsonObject { ["contentType"] = "application/vnd.microsoft.card.adaptive", ["contentUrl"] = null, ["content"] = card },
            },
        };
        return message.ToJsonString(Json);
    }

    /// <summary>Generic webhook body: a stable JSON document for PSA/ticketing integrations.</summary>
    public static string Generic(NotificationMessage m, Guid deliveryId, DateTimeOffset sentAt)
    {
        ArgumentNullException.ThrowIfNull(m);
        var alerts = new JsonArray();
        foreach (var item in m.Items)
        {
            alerts.Add(new JsonObject
            {
                ["id"] = item.AlertId?.ToString(),
                ["severity"] = item.Severity.ToString(),
                ["title"] = item.Title,
                ["organization"] = item.Organization,
                ["details"] = item.Details,
                ["url"] = item.Url,
                ["at"] = item.At.ToString("O", CultureInfo.InvariantCulture),
            });
        }

        return new JsonObject
        {
            ["event"] = EventName(m.Kind),
            ["deliveryId"] = deliveryId.ToString(),
            ["sentAt"] = sentAt.ToString("O", CultureInfo.InvariantCulture),
            ["subject"] = m.Subject,
            ["summary"] = m.Intro,
            ["alerts"] = alerts,
            ["moreCount"] = m.MoreCount,
            ["consoleUrl"] = m.ConsoleUrl,
        }.ToJsonString(Json);
    }

    /// <summary>Signature header value <c>t=&lt;unix seconds&gt;,v1=&lt;hex HMAC-SHA256(secret, "t.body")&gt;</c>.</summary>
    public static string Sign(string secret, string body, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(body);
        var t = at.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(t + "." + body));
        return $"t={t},v1={Convert.ToHexStringLower(mac)}";
    }

    private static string EscapeMarkdown(string s) =>
        s.Replace("[", "\\[", StringComparison.Ordinal).Replace("]", "\\]", StringComparison.Ordinal);
}

internal static class PayloadJson
{
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        o.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        return o;
    }
}
