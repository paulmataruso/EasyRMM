namespace EasyPatch.Core.Domain;

/// <summary>Global, server-wide settings (stored as JSON in server_settings). Policy-level values live in Policy.</summary>
public sealed record ServerSettings
{
    public int GlobalMaxConcurrentInstalls { get; init; } = 50;
    public int JobDefaultExpiryHours { get; init; } = 168;
    public int RunningJobTimeoutHours { get; init; } = 12;
    public int WaitingForRebootExpiryDays { get; init; } = 30;
    public int DeliveryLeaseMinutes { get; init; } = 10;
    public int MaxDeliveryAttempts { get; init; } = 5;
    public int OfflineThresholdMinutes { get; init; } = 10;
    public int CredentialLifetimeDays { get; init; } = 365;
    public int CredentialRotateBeforeDays { get; init; } = 30;
    public int EnrollmentRequestExpiryDays { get; init; } = 7;
    public bool RequireMfa { get; init; } = true;
    public int SessionIdleMinutes { get; init; } = 30;
    public int SessionAbsoluteHours { get; init; } = 12;
    public int RetentionEventsDays { get; init; } = 90;
    public int RetentionAuditDays { get; init; } = 365;
    public int RetentionJobsDays { get; init; } = 180;
    public int RetentionScansDays { get; init; } = 90;
    public int RetentionHistoryDays { get; init; } = 730;

    /// <summary>Download MSRC, CISA KEV and Debian Security Tracker data (worker, outbound HTTPS). Turn off on servers
    /// without internet access.</summary>
    public bool VulnerabilityFeedsEnabled { get; init; } = true;

    /// <summary>Monthly reports are kept this long (months).</summary>
    public int RetentionReportsMonths { get; init; } = 24;

    /// <summary>Optional "Prepared by" line on monthly reports (your company name).</summary>
    public string? ReportBrandName { get; init; }

    /// <summary>The rollout guard holds a Windows update for every organization when its latest installation failed on at least
    /// <see cref="RolloutGuardMinFailedEndpoints"/> endpoints and <see cref="RolloutGuardFailurePercent"/> percent of the endpoints that
    /// tried to install it in the last <see cref="RolloutGuardWindowDays"/> days.</summary>
    public bool RolloutGuardEnabled { get; init; } = true;

    public int RolloutGuardMinFailedEndpoints { get; init; } = 3;
    public int RolloutGuardFailurePercent { get; init; } = 20;
    public int RolloutGuardWindowDays { get; init; } = 7;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        void Range(string name, int value, int min, int max)
        {
            if (value < min || value > max)
            {
                errors.Add($"{name} must be between {min} and {max}.");
            }
        }

        Range(nameof(GlobalMaxConcurrentInstalls), GlobalMaxConcurrentInstalls, 1, 10_000);
        Range(nameof(JobDefaultExpiryHours), JobDefaultExpiryHours, 1, 24 * 90);
        Range(nameof(RunningJobTimeoutHours), RunningJobTimeoutHours, 1, 168);
        Range(nameof(WaitingForRebootExpiryDays), WaitingForRebootExpiryDays, 1, 365);
        Range(nameof(DeliveryLeaseMinutes), DeliveryLeaseMinutes, 2, 120);
        Range(nameof(MaxDeliveryAttempts), MaxDeliveryAttempts, 1, 50);
        Range(nameof(OfflineThresholdMinutes), OfflineThresholdMinutes, 3, 1440);
        Range(nameof(CredentialLifetimeDays), CredentialLifetimeDays, 30, 3650);
        Range(nameof(CredentialRotateBeforeDays), CredentialRotateBeforeDays, 1, 180);
        Range(nameof(EnrollmentRequestExpiryDays), EnrollmentRequestExpiryDays, 1, 90);
        Range(nameof(SessionIdleMinutes), SessionIdleMinutes, 5, 720);
        Range(nameof(SessionAbsoluteHours), SessionAbsoluteHours, 1, 168);
        Range(nameof(RetentionEventsDays), RetentionEventsDays, 7, 3650);
        Range(nameof(RetentionAuditDays), RetentionAuditDays, 30, 3650);
        Range(nameof(RetentionJobsDays), RetentionJobsDays, 7, 3650);
        Range(nameof(RetentionScansDays), RetentionScansDays, 7, 3650);
        Range(nameof(RetentionHistoryDays), RetentionHistoryDays, 30, 3650);
        Range(nameof(RetentionReportsMonths), RetentionReportsMonths, 1, 120);
        Range(nameof(RolloutGuardMinFailedEndpoints), RolloutGuardMinFailedEndpoints, 1, 1000);
        Range(nameof(RolloutGuardFailurePercent), RolloutGuardFailurePercent, 1, 100);
        Range(nameof(RolloutGuardWindowDays), RolloutGuardWindowDays, 1, 90);
        if (ReportBrandName is { } brand && (brand.Length > 100 || brand.Any(char.IsControl)))
        {
            errors.Add("ReportBrandName must be at most 100 characters, without control characters.");
        }

        if (CredentialRotateBeforeDays >= CredentialLifetimeDays)
        {
            errors.Add("CredentialRotateBeforeDays must be less than CredentialLifetimeDays.");
        }

        return errors;
    }
}
