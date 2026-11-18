namespace EasyPatch.Core.Entities;

/// <summary>Monthly compliance report schedule of one organization. Off until someone enables it and adds recipients.</summary>
public sealed class ReportSchedule
{
    public const int MaxRecipients = 20;

    public Guid OrganizationId { get; set; }
    public bool Enabled { get; set; }

    /// <summary>Plain email addresses. There is no default: reports go only to addresses entered here.</summary>
    public List<string> Recipients { get; set; } = [];

    /// <summary>Day of the month (1-28, in the organization's time zone) on which last month's report is sent.</summary>
    public int DayOfMonth { get; set; } = 1;

    /// <summary>Adds a table of every endpoint to the report.</summary>
    public bool IncludeEndpointList { get; set; } = true;

    /// <summary>When the schedule was last switched on. Months that ended before then are not sent automatically.</summary>
    public DateTimeOffset? EnabledAt { get; set; }

    /// <summary>First day of the last month a scheduled report was created for. Deleting that report does not send it again.</summary>
    public DateOnly? LastScheduledPeriod { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>A generated monthly report (PDF) and the state of its email delivery.</summary>
public sealed class GeneratedReport
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }

    /// <summary>First day of the reported month (UTC dates, like the compliance snapshots).</summary>
    public DateOnly PeriodStart { get; set; }

    /// <summary>Last day covered: the end of the month, or the day of generation for the current month.</summary>
    public DateOnly PeriodEnd { get; set; }

    /// <summary>Created by the schedule (one per organization and month) rather than on demand.</summary>
    public bool Scheduled { get; set; }
    public DateTimeOffset GeneratedAt { get; set; }

    /// <summary>User name of the administrator who generated it; null for scheduled reports.</summary>
    public string? GeneratedBy { get; set; }
    public required string FileName { get; set; }
    public required byte[] Content { get; set; }
    public long SizeBytes { get; set; }
    public required string Sha256 { get; set; }

    /// <summary>Null: not emailed. Otherwise the state of the email to <see cref="Recipients"/>.</summary>
    public DeliveryStatus? DeliveryStatus { get; set; }
    public List<string> Recipients { get; set; } = [];
    public int Attempts { get; set; }
    public DateTimeOffset? NextAttemptAt { get; set; }
    public DateTimeOffset? QueuedAt { get; set; }
    public DateTimeOffset? SentAt { get; set; }
    public string? LastError { get; set; }
}
