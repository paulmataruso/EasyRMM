using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Reports;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>Monthly compliance reports (PDF): schedules, on-demand generation, download and email.</summary>
public static class MonthlyReportEndpoints
{
    public static void MapMonthlyReportEndpoints(this IEndpointRouteBuilder app)
    {
        var orgs = app.MapGroup("/api/v1/organizations").WithTags("Monthly reports").RequireAuthorization(Policies.Viewer);

        orgs.MapGet("/{id:guid}/report-schedule", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
            var schedule = await db.ReportSchedules.AsNoTracking().FirstOrDefaultAsync(s => s.OrganizationId == id, ct);
            return TypedResults.Ok(ToDto(schedule, org, clock.GetUtcNow()));
        });

        orgs.MapPut("/{id:guid}/report-schedule", async (Guid id, ReportScheduleRequest request, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
            var recipients = ValidRecipients(request.Recipients, required: request.Enabled);
            var v = new Validator();
            v.Check(request.DayOfMonth is >= 1 and <= 28, "dayOfMonth", "Choose a day from 1 to 28.");
            v.ThrowIfInvalid();

            var now = clock.GetUtcNow();
            var schedule = await db.ReportSchedules.FirstOrDefaultAsync(s => s.OrganizationId == id, ct);
            if (schedule is null)
            {
                schedule = new ReportSchedule { OrganizationId = id };
                db.ReportSchedules.Add(schedule);
            }

            if (request.Enabled && !schedule.Enabled)
            {
                schedule.EnabledAt = now;
            }

            schedule.Enabled = request.Enabled;
            schedule.Recipients = recipients;
            schedule.DayOfMonth = request.DayOfMonth;
            schedule.IncludeEndpointList = request.IncludeEndpointList;
            schedule.UpdatedAt = now;
            audit.Record("report_schedule.update", "ReportSchedule", id.ToString(), id,
                details: new { request.Enabled, Recipients = recipients.Count, request.DayOfMonth, request.IncludeEndpointList });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(ToDto(schedule, org, now));
        }).RequireAuthorization(Policies.Operator);

        var reports = app.MapGroup("/api/v1/monthly-reports").WithTags("Monthly reports").RequireAuthorization(Policies.Viewer);

        reports.MapGet("/", async (Guid? organizationId, int? page, int? pageSize, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var size = Math.Clamp(pageSize ?? 50, 1, 200);
            var number = Math.Max(1, page ?? 1);
            var query = db.GeneratedReports.AsNoTracking().ForTenant(tenant, r => r.OrganizationId);
            if (organizationId is { } orgId)
            {
                query = query.Where(r => r.OrganizationId == orgId);
            }

            var total = await query.CountAsync(ct);
            var rows = await Project(db, query.OrderByDescending(r => r.GeneratedAt).Skip((number - 1) * size).Take(size)).ToListAsync(ct);
            return TypedResults.Ok(new PagedResult<MonthlyReportDto>(rows.Select(ToDto).ToList(), number, size, total));
        });

        reports.MapPost("/", async (GenerateReportRequest request, EasyPatchDbContext db, ITenantContext tenant, MonthlyReportService service,
            IActorContext actor, AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(request.OrganizationId);
            var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == request.OrganizationId, ct) ??
                      throw AppException.NotFound("Organization");
            var period = ReportPeriod.For(request.Year, request.Month, DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime)) ??
                         throw AppException.BadRequest("Choose a month that has started and is at most 10 years old.", "invalid_period");
            var includeEndpoints = request.IncludeEndpointList ??
                                   await db.ReportSchedules.Where(s => s.OrganizationId == org.Id).Select(s => (bool?)s.IncludeEndpointList).FirstOrDefaultAsync(ct) ??
                                   true;
            var report = await service.GenerateAsync(org, period, includeEndpoints, scheduled: false, actor.Username, emailTo: null, ct);
            audit.Record("report.generate", "MonthlyReport", report.Id.ToString(), org.Id,
                details: new { Period = period.Start.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture), report.SizeBytes });
            await db.SaveChangesAsync(ct);
            return TypedResults.Created($"/api/v1/monthly-reports/{report.Id}", await LoadAsync(db, report.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        reports.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var dto = await LoadAsync(db, id, ct);
            tenant.EnsureAccess(dto.OrganizationId);
            return TypedResults.Ok(dto);
        });

        reports.MapGet("/{id:guid}/pdf", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var file = await db.GeneratedReports.AsNoTracking().Where(r => r.Id == id)
                           .Select(r => new { r.OrganizationId, r.FileName, r.Content }).FirstOrDefaultAsync(ct) ??
                       throw AppException.NotFound("The report");
            tenant.EnsureAccess(file.OrganizationId);
            return Results.File(file.Content, MonthlyReportService.ContentType, file.FileName);
        });

        reports.MapPost("/{id:guid}/send", async (Guid id, SendReportRequest? request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            var report = await db.GeneratedReports.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw AppException.NotFound("The report");
            tenant.EnsureAccess(report.OrganizationId);
            var recipients = request?.Recipients is { Count: > 0 } given
                ? ValidRecipients(given, required: true)
                : await db.ReportSchedules.AsNoTracking().Where(s => s.OrganizationId == report.OrganizationId).Select(s => s.Recipients).FirstOrDefaultAsync(ct) ?? [];
            if (recipients.Count == 0)
            {
                throw AppException.BadRequest("Enter recipients, or add them to the organization's report schedule.", "no_recipients");
            }

            var smtp = await db.NotificationSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct);
            if (string.IsNullOrWhiteSpace(smtp?.SmtpHost) || string.IsNullOrWhiteSpace(smtp.FromAddress))
            {
                throw AppException.Conflict("Configure SMTP first (Settings → Notifications).", "smtp_not_configured");
            }

            if (smtp.SmtpSecurity == SmtpSecurity.None)
            {
                throw AppException.Conflict("Reports are emailed only over STARTTLS or TLS; change the SMTP security setting.", "smtp_not_encrypted");
            }

            if (report.SizeBytes > MonthlyReportService.MaxEmailBytes)
            {
                throw AppException.Conflict("The report is too large to email; download it instead.", "report_too_large");
            }

            MonthlyReportService.QueueDelivery(report, recipients, clock.GetUtcNow());
            audit.Record("report.send", "MonthlyReport", id.ToString(), report.OrganizationId, details: new { Recipients = recipients.Count });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(await LoadAsync(db, id, ct));
        }).RequireAuthorization(Policies.Operator);

        reports.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, CancellationToken ct) =>
        {
            var report = await db.GeneratedReports.AsNoTracking().Where(r => r.Id == id)
                             .Select(r => new { r.OrganizationId, r.PeriodStart, r.FileName }).FirstOrDefaultAsync(ct) ??
                         throw AppException.NotFound("The report");
            tenant.EnsureAccess(report.OrganizationId);
            await db.GeneratedReports.Where(r => r.Id == id).ExecuteDeleteAsync(ct);
            audit.Record("report.delete", "MonthlyReport", id.ToString(), report.OrganizationId, details: new { report.FileName });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);
    }

    private static List<string> ValidRecipients(IReadOnlyList<string>? input, bool required)
    {
        var recipients = (input ?? []).Select(r => r.Trim()).Where(r => r.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var v = new Validator();
        v.Check(recipients.Count <= ReportSchedule.MaxRecipients, "recipients", $"Enter at most {ReportSchedule.MaxRecipients} email addresses.");
        v.Check(!required || recipients.Count > 0, "recipients", "Enter at least one email address.");
        v.Check(recipients.All(NotificationEndpoints.IsEmail), "recipients", "One of the email addresses is not valid.");
        v.ThrowIfInvalid();
        return recipients;
    }

    private static ReportScheduleDto ToDto(ReportSchedule? schedule, Organization org, DateTimeOffset now)
    {
        var s = schedule ?? new ReportSchedule { OrganizationId = org.Id };
        var next = MonthlyReportService.NextScheduled(s, org.TimeZone, now);
        return new ReportScheduleDto(org.Id, s.Enabled, s.Recipients, s.DayOfMonth, s.IncludeEndpointList, s.EnabledAt, s.LastScheduledPeriod,
            next?.Due, next?.PeriodStart, org.TimeZone, schedule?.UpdatedAt);
    }

    private sealed record ReportRow(GeneratedReport Report, string OrganizationName);

    /// <summary>Every column except the PDF itself.</summary>
    private static IQueryable<ReportRow> Project(EasyPatchDbContext db, IQueryable<GeneratedReport> query) =>
        query.Join(db.Organizations, r => r.OrganizationId, o => o.Id, (r, o) => new ReportRow(new GeneratedReport
        {
            Id = r.Id, OrganizationId = r.OrganizationId, PeriodStart = r.PeriodStart, PeriodEnd = r.PeriodEnd, Scheduled = r.Scheduled,
            GeneratedAt = r.GeneratedAt, GeneratedBy = r.GeneratedBy, FileName = r.FileName, Content = Array.Empty<byte>(), SizeBytes = r.SizeBytes,
            Sha256 = r.Sha256, DeliveryStatus = r.DeliveryStatus, Recipients = r.Recipients, Attempts = r.Attempts, NextAttemptAt = r.NextAttemptAt,
            QueuedAt = r.QueuedAt, SentAt = r.SentAt, LastError = r.LastError,
        }, o.Name));

    private static async Task<MonthlyReportDto> LoadAsync(EasyPatchDbContext db, Guid id, CancellationToken ct) =>
        ToDto(await Project(db, db.GeneratedReports.AsNoTracking().Where(r => r.Id == id)).FirstOrDefaultAsync(ct) ?? throw AppException.NotFound("The report"));

    private static MonthlyReportDto ToDto(ReportRow row)
    {
        var r = row.Report;
        return new MonthlyReportDto(r.Id, r.OrganizationId, row.OrganizationName, r.PeriodStart, r.PeriodEnd, MonthlyReportService.PeriodOf(r).MonthToDate,
            r.Scheduled, r.GeneratedAt, r.GeneratedBy, r.FileName, r.SizeBytes, r.Sha256, r.DeliveryStatus, r.Recipients, r.Attempts, r.QueuedAt, r.SentAt,
            r.LastError);
    }
}
