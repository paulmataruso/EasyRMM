using EasyPatch.Core.Entities;

namespace EasyPatch.Api.Contracts;

// Alerts and notifications.

public sealed record AlertDto(
    Guid Id, Guid? RuleId, string? RuleName, AlertRuleType RuleType, AlertSeverity Severity, AlertStatus Status, string Title, string? Details,
    Guid OrganizationId, string OrganizationName, Guid? EndpointId, string? Hostname, DateTimeOffset OpenedAt, DateTimeOffset LastSeenAt,
    DateTimeOffset? ResolvedAt, DateTimeOffset? AcknowledgedAt, string? AcknowledgedBy);

/// <summary>Counts of unresolved alerts the user can see. <c>Open</c> excludes acknowledged alerts.</summary>
public sealed record AlertSummaryDto(int Open, int Acknowledged, int Critical, int Warning, int Info);

public sealed record AcknowledgeAlertsRequest(IReadOnlyList<Guid> AlertIds);

public sealed record AcknowledgeAlertsResult(int Acknowledged);

public sealed record NotificationSettingsDto(
    string? SmtpHost, int SmtpPort, SmtpSecurity SmtpSecurity, string? SmtpUsername, bool SmtpPasswordConfigured, string? FromAddress, string? FromName,
    bool AllowPrivateNetworkWebhooks, DateTimeOffset UpdatedAt, bool SmtpSkipCertificateValidation = false);

/// <param name="SmtpPassword">null keeps the stored password, "" removes it.</param>
/// <param name="SmtpSkipCertificateValidation">Accept any SMTP server certificate (ignored when <paramref name="SmtpSecurity"/> is None).</param>
public sealed record NotificationSettingsRequest(
    string? SmtpHost, int SmtpPort, SmtpSecurity SmtpSecurity, string? SmtpUsername, string? SmtpPassword, string? FromAddress, string? FromName,
    bool AllowPrivateNetworkWebhooks, bool SmtpSkipCertificateValidation = false);

public sealed record DeliverySummaryDto(DeliveryStatus Status, DateTimeOffset CreatedAt, string? LastError);

public sealed record NotificationChannelDto(
    Guid Id, string Name, NotificationChannelType Type, bool Enabled, IReadOnlyList<string> EmailRecipients, WebhookFormat? WebhookFormat,
    string? WebhookHost, bool HasSigningSecret, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, DeliverySummaryDto? LastDelivery);

/// <param name="WebhookUrl">Required when creating a webhook channel; null on update keeps the stored URL.</param>
public sealed record NotificationChannelRequest(
    string Name, NotificationChannelType Type, bool Enabled, IReadOnlyList<string>? EmailRecipients, WebhookFormat? WebhookFormat, string? WebhookUrl);

/// <param name="SigningSecret">Generic webhooks: the HMAC key, shown only in this response.</param>
public sealed record NotificationChannelSavedDto(NotificationChannelDto Channel, string? SigningSecret);

public sealed record NotificationDeliveryDto(
    Guid Id, Guid ChannelId, string ChannelName, NotificationKind Kind, string Subject, DeliveryStatus Status, int Attempts, string? LastError,
    DateTimeOffset CreatedAt, DateTimeOffset NextAttemptAt, DateTimeOffset? SentAt);

public sealed record AlertRuleDto(
    Guid Id, string Name, AlertRuleType Type, bool Enabled, AlertSeverity Severity, int? Threshold, string? ThresholdUnit, Guid? OrganizationId,
    Guid? TagId, IReadOnlyList<Guid> ChannelIds, bool NotifyOnResolve, int RenotifyHours, int UnresolvedAlerts, DateTimeOffset UpdatedAt);

public sealed record AlertRuleRequest(
    string Name, AlertRuleType Type, bool Enabled, AlertSeverity Severity, int? Threshold, Guid? OrganizationId, Guid? TagId,
    IReadOnlyList<Guid>? ChannelIds, bool NotifyOnResolve, int RenotifyHours);

/// <summary>Threshold meaning for a rule type (for the rule editor).</summary>
public sealed record AlertRuleTypeDto(AlertRuleType Type, string? ThresholdUnit, int? ThresholdMin, int? ThresholdMax, int? ThresholdDefault, bool SupportsTag);
