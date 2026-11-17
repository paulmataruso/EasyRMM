using System.Net;
using System.Security.Cryptography;
using EasyPatch.Api.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Monthly PDF reports: schedules, on-demand generation, download, email delivery and tenant isolation.</summary>
public sealed class MonthlyReportTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminSession root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
        (org, site) = await CreateOrgAsync(root);
    }

    private async Task ConfigureSmtpAsync(SmtpSecurity security = SmtpSecurity.StartTls) =>
        await root.SendAsync<NotificationSettingsDto>(HttpMethod.Put, "/api/v1/notifications/settings",
            new NotificationSettingsRequest("smtp.example.com", 587, security, "mailer", "smtp-Pa55", "easypatch@example.com", "EasyPatch", false),
            HttpStatusCode.OK);

    private static ReportScheduleRequest Schedule(bool enabled, params string[] recipients) => new(enabled, recipients, 1, true);

    [Fact]
    public async Task Reports_are_generated_on_demand_downloaded_and_emailed_over_tls_only()
    {
        await EnrollAgentAsync(root, org.Id, site.Id, "PC-REPORT-1");
        var today = DateOnly.FromDateTime(Clock.GetUtcNow().UtcDateTime);

        // Month to date.
        var report = await root.SendAsync<MonthlyReportDto>(HttpMethod.Post, "/api/v1/monthly-reports",
            new GenerateReportRequest(org.Id, today.Year, today.Month), HttpStatusCode.Created);
        Assert.True(report.MonthToDate);
        Assert.Equal(today, report.PeriodEnd);
        Assert.Equal($"EasyPatch-contoso-{today:yyyy-MM}-to-{today.Day:00}.pdf", report.FileName);
        Assert.False(report.Scheduled);
        Assert.Equal("root", report.GeneratedBy);
        Assert.Null(report.DeliveryStatus);

        using (var response = await root.Http.GetAsync(new Uri($"/api/v1/monthly-reports/{report.Id}/pdf", UriKind.Relative)))
        {
            await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
            Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);
            Assert.Equal(report.FileName, response.Content.Headers.ContentDisposition?.FileNameStar ?? response.Content.Headers.ContentDisposition?.FileName);
            var pdf = await response.Content.ReadAsByteArrayAsync();
            Assert.Equal("%PDF-"u8.ToArray(), pdf[..5]);
            Assert.Equal(report.Sha256, Convert.ToHexStringLower(SHA256.HashData(pdf)));
            Assert.Equal(report.SizeBytes, pdf.LongLength);
        }

        var future = today.AddMonths(1);
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/monthly-reports", new GenerateReportRequest(org.Id, future.Year, future.Month),
            HttpStatusCode.BadRequest, "invalid_period");

        // Sending needs SMTP with TLS and recipients.
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/monthly-reports/{report.Id}/send", new SendReportRequest(["it@example.com"]),
            HttpStatusCode.Conflict, "smtp_not_configured");
        await ConfigureSmtpAsync(SmtpSecurity.None);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/monthly-reports/{report.Id}/send", new SendReportRequest(["it@example.com"]),
            HttpStatusCode.Conflict, "smtp_not_encrypted");
        await ConfigureSmtpAsync();
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/monthly-reports/{report.Id}/send", new SendReportRequest(), HttpStatusCode.BadRequest,
            "no_recipients");
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/monthly-reports/{report.Id}/send", new SendReportRequest(["not an address"]),
            HttpStatusCode.BadRequest, "validation_failed");

        var queued = await root.SendAsync<MonthlyReportDto>(HttpMethod.Post, $"/api/v1/monthly-reports/{report.Id}/send",
            new SendReportRequest(["it@example.com", "IT@example.com", "owner@example.com"]), HttpStatusCode.OK);
        Assert.Equal(DeliveryStatus.Pending, queued.DeliveryStatus);
        Assert.Equal(2, queued.Recipients.Count);

        // Switching SMTP to plain text after queueing: the worker refuses and retries later.
        await ConfigureSmtpAsync(SmtpSecurity.None);
        await RunMaintenanceAsync<MonthlyReportTask>();
        Assert.Empty(Factory.Transport.Emails);
        var refused = await root.GetAsync<MonthlyReportDto>($"/api/v1/monthly-reports/{report.Id}");
        Assert.Equal(DeliveryStatus.Pending, refused.DeliveryStatus);
        Assert.Contains("STARTTLS", refused.LastError, StringComparison.Ordinal);

        await ConfigureSmtpAsync();
        Clock.Advance(TimeSpan.FromMinutes(2));
        await RunMaintenanceAsync<MonthlyReportTask>();
        var email = Assert.Single(Factory.Transport.Emails);
        Assert.Equal(new[] { "it@example.com", "owner@example.com" }, email.Recipients);
        Assert.StartsWith("Patch compliance report: Contoso – ", email.Subject, StringComparison.Ordinal);
        var attachment = Assert.Single(email.Attachments);
        Assert.Equal(report.FileName, attachment.FileName);
        Assert.Equal("application/pdf", attachment.ContentType);
        Assert.Equal(report.Sha256, Convert.ToHexStringLower(SHA256.HashData(attachment.Content)));
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
        var sent = await root.GetAsync<MonthlyReportDto>($"/api/v1/monthly-reports/{report.Id}");
        Assert.Equal(DeliveryStatus.Sent, sent.DeliveryStatus);
        Assert.NotNull(sent.SentAt);

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.Action.StartsWith("report.")).Select(a => a.Action).ToListAsync());
        Assert.Contains("report.generate", audit);
        Assert.Contains("report.send", audit);

        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/monthly-reports/{report.Id}", null, HttpStatusCode.NoContent);
        await root.ExpectAsync(HttpMethod.Get, $"/api/v1/monthly-reports/{report.Id}/pdf", null, HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Schedules_send_last_month_once_on_the_chosen_day()
    {
        await ConfigureSmtpAsync();
        await EnrollAgentAsync(root, org.Id, site.Id, "PC-REPORT-2");

        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule", Schedule(true), HttpStatusCode.BadRequest,
            "validation_failed");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule",
            Schedule(true, "it@example.com") with { DayOfMonth = 29 }, HttpStatusCode.BadRequest, "validation_failed");
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule",
            Schedule(true, Enumerable.Range(0, 21).Select(i => $"user{i}@example.com").ToArray()), HttpStatusCode.BadRequest, "validation_failed");

        var empty = await root.GetAsync<ReportScheduleDto>($"/api/v1/organizations/{org.Id}/report-schedule");
        Assert.False(empty.Enabled);
        Assert.Null(empty.NextReportDate);

        var schedule = await root.SendAsync<ReportScheduleDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule",
            Schedule(true, "it@example.com"), HttpStatusCode.OK);
        var now = Clock.GetUtcNow();
        var thisMonth = new DateOnly(now.Year, now.Month, 1);
        // Last month ended before the schedule was switched on: the first report is this month's, sent next month.
        Assert.Equal(thisMonth, schedule.NextReportPeriod);
        Assert.Equal(thisMonth.AddMonths(1), schedule.NextReportDate);

        await RunMaintenanceAsync<MonthlyReportTask>();
        Assert.Empty(await WithDbAsync(db => db.GeneratedReports.AsNoTracking().ToListAsync()));

        // Move to 06:00 UTC on the first day of next month.
        var sendAt = new DateTimeOffset(thisMonth.AddMonths(1).ToDateTime(new TimeOnly(6, 0)), TimeSpan.Zero);
        Clock.Advance(sendAt - now);
        await RunMaintenanceAsync<MonthlyReportTask>();
        var report = Assert.Single(await WithDbAsync(db => db.GeneratedReports.AsNoTracking().ToListAsync()));
        Assert.True(report.Scheduled);
        Assert.Equal(thisMonth, report.PeriodStart);
        Assert.Equal(thisMonth.AddMonths(1).AddDays(-1), report.PeriodEnd);
        Assert.Equal(DeliveryStatus.Sent, report.DeliveryStatus);
        var email = Assert.Single(Factory.Transport.Emails);
        Assert.Equal(new[] { "it@example.com" }, email.Recipients);
        Assert.Equal(report.FileName, Assert.Single(email.Attachments).FileName);

        // Once per month, even after the report is deleted.
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/monthly-reports/{report.Id}", null, HttpStatusCode.NoContent);
        Clock.Advance(TimeSpan.FromHours(1));
        await RunMaintenanceAsync<MonthlyReportTask>();
        Assert.Empty(await WithDbAsync(db => db.GeneratedReports.AsNoTracking().ToListAsync()));
        Assert.Single(Factory.Transport.Emails);

        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
        var next = await root.GetAsync<ReportScheduleDto>($"/api/v1/organizations/{org.Id}/report-schedule");
        Assert.Equal(thisMonth, next.LastScheduledPeriod);
        Assert.Equal(thisMonth.AddMonths(1), next.NextReportPeriod);
        Assert.Equal(thisMonth.AddMonths(2), next.NextReportDate);
    }

    [Fact]
    public async Task Reports_are_isolated_per_organization_and_read_only_users_cannot_change_them()
    {
        var (other, _) = await CreateOrgAsync(root, "Fabrikam");
        var today = DateOnly.FromDateTime(Clock.GetUtcNow().UtcDateTime);
        var mine = await root.SendAsync<MonthlyReportDto>(HttpMethod.Post, "/api/v1/monthly-reports",
            new GenerateReportRequest(org.Id, today.Year, today.Month, IncludeEndpointList: false), HttpStatusCode.Created);
        var theirs = await root.SendAsync<MonthlyReportDto>(HttpMethod.Post, "/api/v1/monthly-reports",
            new GenerateReportRequest(other.Id, today.Year, today.Month), HttpStatusCode.Created);

        var contosoAdmin = await CreateAndLoginAsync("contoso-admin", UserRole.Admin, org.Id);
        var listed = await contosoAdmin.GetAsync<PagedResult<MonthlyReportDto>>("/api/v1/monthly-reports");
        Assert.Equal(mine.Id, Assert.Single(listed.Items).Id);
        await contosoAdmin.ExpectAsync(HttpMethod.Get, $"/api/v1/monthly-reports/{theirs.Id}/pdf", null, HttpStatusCode.NotFound);
        await contosoAdmin.ExpectAsync(HttpMethod.Delete, $"/api/v1/monthly-reports/{theirs.Id}", null, HttpStatusCode.NotFound);
        await contosoAdmin.ExpectAsync(HttpMethod.Post, "/api/v1/monthly-reports", new GenerateReportRequest(other.Id, today.Year, today.Month),
            HttpStatusCode.NotFound);
        await contosoAdmin.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{other.Id}/report-schedule", Schedule(false), HttpStatusCode.NotFound);
        await contosoAdmin.SendAsync<ReportScheduleDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule",
            Schedule(false, "it@example.com"), HttpStatusCode.OK);

        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly);
        Assert.Equal(2, (await viewer.GetAsync<PagedResult<MonthlyReportDto>>("/api/v1/monthly-reports")).TotalCount);
        using (var pdf = await viewer.Http.GetAsync(new Uri($"/api/v1/monthly-reports/{mine.Id}/pdf", UriKind.Relative)))
        {
            await AdminSession.EnsureAsync(pdf, HttpStatusCode.OK);
        }

        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/monthly-reports", new GenerateReportRequest(org.Id, today.Year, today.Month),
            HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/monthly-reports/{mine.Id}/send", new SendReportRequest(["it@example.com"]),
            HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Delete, $"/api/v1/monthly-reports/{mine.Id}", null, HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/report-schedule", Schedule(false), HttpStatusCode.Forbidden);
    }
}
