using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Notifications;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace EasyPatch.Infrastructure.Reports;

/// <summary>Generates monthly compliance reports (on demand and on schedule) and emails them.</summary>
public sealed class MonthlyReportService(
    EasyPatchDbContext db,
    MonthlyReportDataBuilder builder,
    SettingsService settings,
    NotificationSecrets secrets,
    INotificationTransport transport,
    TimeProvider clock,
    ILogger<MonthlyReportService> logger)
{
    public const string ContentType = "application/pdf";

    /// <summary>Larger reports are not emailed (many mail servers refuse messages over 20-25 MB); they can be downloaded.</summary>
    public const int MaxEmailBytes = 15 * 1024 * 1024;

    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromHours(24);
    public static readonly TimeSpan RunBudget = TimeSpan.FromSeconds(50);

    /// <summary>Renders and stores the report of <paramref name="org"/> for <paramref name="period"/>. With
    /// <paramref name="emailTo"/>, its email is queued in the same transaction (with any other tracked changes).</summary>
    public async Task<GeneratedReport> GenerateAsync(Organization org, ReportPeriod period, bool includeEndpoints, bool scheduled, string? generatedBy,
        IReadOnlyList<string>? emailTo, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(org);
        ArgumentNullException.ThrowIfNull(period);
        var options = await settings.GetAsync(ct);
        var now = clock.GetUtcNow();
        var data = await builder.BuildAsync(org, period, includeEndpoints, options.ReportBrandName, now, ct);
        var pdf = ReportPdfRenderer.Render(data);
        var report = new GeneratedReport
        {
            Id = Guid.NewGuid(),
            OrganizationId = org.Id,
            PeriodStart = period.Start,
            PeriodEnd = period.End,
            Scheduled = scheduled,
            GeneratedAt = now,
            GeneratedBy = generatedBy,
            FileName = FileName(org.Name, period),
            Content = pdf,
            SizeBytes = pdf.LongLength,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(pdf)),
        };
        if (emailTo is not null)
        {
            QueueDelivery(report, emailTo, now);
        }

        db.GeneratedReports.Add(report);
        await db.SaveChangesAsync(ct);
        return report;
    }

    /// <summary>Queues an email of the report to <paramref name="recipients"/>; the worker sends it.</summary>
    public static void QueueDelivery(GeneratedReport report, IReadOnlyList<string> recipients, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(recipients);
        report.Recipients = [.. recipients];
        report.DeliveryStatus = DeliveryStatus.Pending;
        report.Attempts = 0;
        report.QueuedAt = now;
        report.NextAttemptAt = now;
        report.SentAt = null;
        report.LastError = null;
    }

    /// <summary>The next scheduled report: its due date (in the organization's time zone; today when overdue) and month.
    /// Null when the schedule is off or has no recipients. Months that ended before the schedule was switched on are skipped.</summary>
    public static (DateOnly Due, DateOnly PeriodStart)? NextScheduled(ReportSchedule schedule, string? timeZone, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        if (!schedule.Enabled || schedule.Recipients.Count == 0)
        {
            return null;
        }

        var local = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, MaintenanceWindow.ResolveTimeZone(timeZone)).DateTime);
        var day = Math.Clamp(schedule.DayOfMonth, 1, 28);
        for (var i = 0; i < 3; i++)
        {
            var sendMonth = new DateOnly(local.Year, local.Month, 1).AddMonths(i);
            var period = sendMonth.AddMonths(-1);
            if (schedule.LastScheduledPeriod is { } last && last >= period ||
                schedule.EnabledAt is { } enabledAt && enabledAt >= new DateTimeOffset(sendMonth.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero))
            {
                continue;
            }

            var due = new DateOnly(sendMonth.Year, sendMonth.Month, day);
            return (due < local ? local : due, period);
        }

        return null;
    }

    /// <summary>Creates last month's report for every enabled schedule whose day has come (in the organization's time zone)
    /// and queues its email. Each organization gets at most one scheduled report per month.</summary>
    public async Task<int> GenerateDueAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var todayUtc = DateOnly.FromDateTime(now.UtcDateTime);
        var due = await db.ReportSchedules.AsNoTracking()
            .Where(s => s.Enabled && s.Recipients.Count > 0)
            .Join(db.Organizations.Where(o => o.IsActive && o.ArchivedAt == null), s => s.OrganizationId, o => o.Id, (s, o) => new { Schedule = s, Org = o })
            .ToListAsync(ct);
        var created = 0;
        foreach (var item in due)
        {
            var local = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, MaintenanceWindow.ResolveTimeZone(item.Org.TimeZone)).DateTime);
            // Periods use UTC dates: east of UTC the month may not have ended in UTC yet.
            if (NextScheduled(item.Schedule, item.Org.TimeZone, now) is not { } next || next.Due > local ||
                ReportPeriod.For(next.PeriodStart.Year, next.PeriodStart.Month, todayUtc) is not { MonthToDate: false } period)
            {
                continue;
            }

            var orgId = item.Org.Id;
            try
            {
                var schedule = await db.ReportSchedules.FirstAsync(s => s.OrganizationId == orgId, ct);
                schedule.LastScheduledPeriod = period.Start;
                var report = await GenerateAsync(item.Org, period, schedule.IncludeEndpointList, scheduled: true, generatedBy: null, schedule.Recipients, ct);
                created++;
                logger.LogInformation("Generated the scheduled {Period} report of organization {OrganizationId} ({Bytes} bytes)",
                    period.Start.ToString("yyyy-MM", CultureInfo.InvariantCulture), orgId, report.SizeBytes);
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                // Already generated (e.g. LastScheduledPeriod was reset): record it so it is not attempted again.
                db.ChangeTracker.Clear();
                await db.ReportSchedules.Where(s => s.OrganizationId == orgId)
                    .ExecuteUpdateAsync(x => x.SetProperty(s => s.LastScheduledPeriod, period.Start), ct);
            }
            finally
            {
                db.ChangeTracker.Clear();
            }
        }

        return created;
    }

    /// <summary>Sends queued report emails with retries (1 minute doubling to 1 hour; given up after 24 hours).</summary>
    public async Task<int> DeliverPendingAsync(CancellationToken ct)
    {
        var started = clock.GetUtcNow();
        var due = await db.GeneratedReports.AsNoTracking()
            .Where(r => r.DeliveryStatus == DeliveryStatus.Pending && r.NextAttemptAt <= started)
            .OrderBy(r => r.NextAttemptAt)
            .Select(r => r.Id)
            .Take(20)
            .ToListAsync(ct);
        if (due.Count == 0)
        {
            return 0;
        }

        var smtp = await db.NotificationSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct) ?? new NotificationSettingsRow();
        var sent = 0;
        foreach (var id in due)
        {
            if (clock.GetUtcNow() - started > RunBudget)
            {
                break; // the rest waits for the next run
            }

            // One report (and its PDF) in memory at a time.
            var report = await db.GeneratedReports.FirstOrDefaultAsync(r => r.Id == id && r.DeliveryStatus == DeliveryStatus.Pending, ct);
            var org = report is null ? null : await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == report.OrganizationId, ct);
            if (report is null || org is null)
            {
                continue;
            }

            var now = clock.GetUtcNow();
            try
            {
                await SendAsync(report, org, smtp, ct);
                report.DeliveryStatus = DeliveryStatus.Sent;
                report.SentAt = now;
                report.LastError = null;
                sent++;
                logger.LogInformation("Emailed report {ReportId} to {Count} recipient(s)", report.Id, report.Recipients.Count);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Only NotificationException messages are known to be free of secrets.
                var error = ex is NotificationException ? ex.Message : $"Unexpected error ({ex.GetType().Name}).";
                report.Attempts++;
                report.LastError = error.Length > 1000 ? error[..1000] : error;
                if (ex is ReportNotSendableException || now - (report.QueuedAt ?? now) >= GiveUpAfter)
                {
                    report.DeliveryStatus = DeliveryStatus.Failed;
                    report.NextAttemptAt = null;
                }
                else
                {
                    report.NextAttemptAt = now + NotificationDispatcher.Backoff(report.Attempts);
                }

                logger.LogWarning("Emailing report {ReportId} failed (attempt {Attempt}): {Error}", report.Id, report.Attempts, report.LastError);
            }

            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }

        return sent;
    }

    private async Task SendAsync(GeneratedReport report, Organization org, NotificationSettingsRow smtp, CancellationToken ct)
    {
        if (report.Recipients.Count == 0)
        {
            throw new ReportNotSendableException("The report has no recipients.");
        }

        if (report.Content.Length > MaxEmailBytes)
        {
            throw new ReportNotSendableException("The report is too large to email; download it from the console.");
        }

        // Reports describe the customer's exposure: they are sent only over an encrypted SMTP connection.
        if (smtp.SmtpSecurity == SmtpSecurity.None)
        {
            throw new NotificationException("Reports are emailed only over STARTTLS or TLS; change the SMTP security setting.");
        }

        var password = smtp.SmtpPasswordProtected is null ? null : secrets.Unprotect(smtp.SmtpPasswordProtected);
        var period = PeriodOf(report);
        var orgName = SingleLine(org.Name);
        var subject = $"Patch compliance report: {orgName} – {period.Label}";
        var text =
            $"Attached is the patch compliance report of {orgName} for {period.Label} ({report.FileName}).\n\n" +
            "You receive this email because your address is a recipient of this organization's monthly report. " +
            "Ask your administrator to remove it if you no longer want these reports.\n";
        var html =
            "<!DOCTYPE html><html><body style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2328\">" +
            $"<p>Attached is the patch compliance report of <strong>{WebUtility.HtmlEncode(orgName)}</strong> for {WebUtility.HtmlEncode(period.Label)} " +
            $"({WebUtility.HtmlEncode(report.FileName)}).</p>" +
            "<p style=\"color:#5f6770;font-size:12px\">You receive this email because your address is a recipient of this organization's monthly report. " +
            "Ask your administrator to remove it if you no longer want these reports.</p></body></html>";
        await transport.SendEmailAsync(smtp, password, report.Recipients, subject, text, html,
            [new EmailAttachment(report.FileName, ContentType, report.Content)], ct);
    }

    public static ReportPeriod PeriodOf(GeneratedReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var monthEnd = report.PeriodStart.AddMonths(1).AddDays(-1);
        return new ReportPeriod(report.PeriodStart, report.PeriodEnd, report.PeriodEnd < monthEnd);
    }

    /// <summary>"EasyPatch-acme-corp-2026-10.pdf"; "...-2026-11-to-14.pdf" for a month to date.</summary>
    public static string FileName(string orgName, ReportPeriod period)
    {
        ArgumentNullException.ThrowIfNull(period);
        var slug = new StringBuilder();
        foreach (var c in orgName ?? string.Empty)
        {
            var ascii = Transliterate(char.ToLowerInvariant(c));
            if (ascii is not null)
            {
                slug.Append(ascii);
            }
            else if (slug.Length > 0 && slug[^1] != '-')
            {
                slug.Append('-');
            }

            if (slug.Length >= 60)
            {
                break;
            }
        }

        var name = slug.ToString().Trim('-');
        var month = period.Start.ToString("yyyy-MM", CultureInfo.InvariantCulture);
        var suffix = period.MonthToDate ? $"-to-{period.End.Day:00}" : "";
        return $"EasyPatch-{(name.Length == 0 ? "organization" : name)}-{month}{suffix}.pdf";
    }

    /// <summary>ASCII for letters and digits, including common accented Latin letters (the server runs with invariant
    /// globalization, so Unicode normalization is not available); null for everything else.</summary>
    private static string? Transliterate(char c) => c switch
    {
        _ when char.IsAsciiLetterOrDigit(c) => c.ToString(),
        'à' or 'á' or 'â' or 'ã' or 'ä' or 'å' or 'ā' or 'ą' => "a",
        'ç' or 'ć' or 'č' => "c",
        'ď' or 'đ' or 'ð' => "d",
        'è' or 'é' or 'ê' or 'ë' or 'ē' or 'ę' or 'ě' => "e",
        'ì' or 'í' or 'î' or 'ï' or 'ī' => "i",
        'ł' or 'ľ' => "l",
        'ñ' or 'ń' or 'ň' => "n",
        'ò' or 'ó' or 'ô' or 'õ' or 'ö' or 'ø' or 'ō' or 'ő' => "o",
        'ř' => "r",
        'ś' or 'š' or 'ş' => "s",
        'ť' or 'ţ' => "t",
        'ù' or 'ú' or 'û' or 'ü' or 'ū' or 'ů' or 'ű' => "u",
        'ý' or 'ÿ' => "y",
        'ź' or 'ż' or 'ž' => "z",
        'ß' => "ss",
        'æ' => "ae",
        'œ' => "oe",
        'þ' => "th",
        _ => null,
    };

    private static string SingleLine(string value) =>
        new(value.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
}

/// <summary>A delivery that retrying cannot fix.</summary>
public sealed class ReportNotSendableException(string message) : NotificationException(message);
