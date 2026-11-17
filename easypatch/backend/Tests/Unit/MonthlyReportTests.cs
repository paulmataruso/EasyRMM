using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Reports;
using PdfSharp.Pdf.IO;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class MonthlyReportTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 9, 30, 0, TimeSpan.Zero);

    private static MonthlyReportData Sample(int endpoints, bool trend = true, string orgName = "Contoso Ltd")
    {
        var period = ReportPeriod.For(2026, 10, DateOnly.FromDateTime(Now.UtcDateTime))!;
        var points = trend
            ? Enumerable.Range(0, 31).Select(i => new ReportTrendPoint(period.Start.AddDays(i), 40, 20 + i / 2)).ToList()
            : [];
        var rows = Enumerable.Range(0, endpoints).Select(i => new ReportEndpointRow($"PC-{i:0000}", i % 2 == 0 ? "HQ" : "Branch", "Windows 11 24H2",
            i % 3 == 0 ? ComplianceStatus.Compliant : ComplianceStatus.MissingUpdates, i % 4, i % 7 == 0 ? 1 : 0, i % 11 == 0 ? 1 : 0,
            Now.AddHours(-i), i % 5 == 0 ? null : Now.AddDays(-1))).ToList();
        return new MonthlyReportData(
            orgName, "Northwind IT Services", period, Now,
            new ReportSummary(endpoints, endpoints / 3, 33.3, 50, 65, 412, 37, 3, 96, 4, 2, 1, 0),
            points,
            [new ReportSiteRow("Branch", 20, 7, 40, 1, 1, 2), new ReportSiteRow("HQ", 20, 13, 56, 2, 1, 2)],
            [
                new ReportMissingUpdateRow("2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5070001)", "KB5070001", "Critical",
                    true, 61, 30),
                new ReportMissingUpdateRow("openssl", "openssl", null, false, 2, 4),
            ],
            [new ReportOsRow("Windows 11 24H2", OsSupportStatus.Supported, 35), new ReportOsRow("Windows 10 22H2", OsSupportStatus.Unsupported, 5)],
            rows);
    }

    private static PdfSharp.Pdf.PdfDocument Open(byte[] pdf)
    {
        Assert.True(pdf.Length > 1000);
        Assert.Equal("%PDF-"u8.ToArray(), pdf[..5]);
        using var stream = new MemoryStream(pdf);
        return PdfReader.Open(stream, PdfDocumentOpenMode.Import);
    }

    [Fact]
    public void Renders_a_valid_pdf_with_an_endpoint_appendix()
    {
        using var document = Open(ReportPdfRenderer.Render(Sample(300)));
        Assert.True(document.PageCount >= 4, $"{document.PageCount} pages");
        Assert.Equal("Patch compliance report: Contoso Ltd, October 2026", document.Info.Title);
        Assert.Equal("Northwind IT Services", document.Info.Author);
    }

    [Fact]
    public void Renders_an_empty_organization_and_text_in_other_scripts()
    {
        var empty = Sample(0, trend: false, orgName: "Ελληνική Εταιρεία / Компания «Ромашка» / 株式会社") with
        {
            Sites = [], TopMissing = [], OperatingSystems = [], Endpoints = null, BrandName = null,
        };
        using var document = Open(ReportPdfRenderer.Render(empty));
        Assert.Equal(1, document.PageCount);
        Assert.Equal("EasyPatch", document.Info.Author);
    }

    [Fact]
    public void Periods_are_calendar_months_and_the_current_month_is_month_to_date()
    {
        var today = new DateOnly(2026, 11, 14);
        var october = ReportPeriod.For(2026, 10, today)!;
        Assert.Equal(new DateOnly(2026, 10, 1), october.Start);
        Assert.Equal(new DateOnly(2026, 10, 31), october.End);
        Assert.False(october.MonthToDate);
        Assert.Equal("October 2026", october.Label);
        Assert.Equal(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), october.EndExclusiveUtc);

        var november = ReportPeriod.For(2026, 11, today)!;
        Assert.True(november.MonthToDate);
        Assert.Equal(today, november.End);
        Assert.Equal("November 2026 (to 14 November)", november.Label);

        Assert.Null(ReportPeriod.For(2026, 12, today));
        Assert.Null(ReportPeriod.For(2026, 13, today));
        Assert.Null(ReportPeriod.For(2016, 10, today));
        Assert.NotNull(ReportPeriod.For(2016, 12, today));
        Assert.True(ReportPeriod.For(2026, 10, new DateOnly(2026, 10, 31))!.MonthToDate); // the last day is not over yet
    }

    [Theory]
    [InlineData("Contoso Ltd", 10, "EasyPatch-contoso-ltd-2026-10.pdf")]
    [InlineData("  Café & Søn (Århus)  ", 10, "EasyPatch-cafe-son-arhus-2026-10.pdf")]
    [InlineData("株式会社", 10, "EasyPatch-organization-2026-10.pdf")]
    [InlineData("Contoso", 11, "EasyPatch-contoso-2026-11-to-14.pdf")]
    public void File_names_are_ascii_slugs(string org, int month, string expected) =>
        Assert.Equal(expected, MonthlyReportService.FileName(org, ReportPeriod.For(2026, month, new DateOnly(2026, 11, 14))!));

    [Fact]
    public void The_next_scheduled_report_skips_months_that_ended_before_the_schedule_was_enabled()
    {
        var schedule = new ReportSchedule { Enabled = true, Recipients = ["it@example.com"], DayOfMonth = 3, EnabledAt = Now };
        Assert.Equal((new DateOnly(2026, 12, 3), new DateOnly(2026, 11, 1)), MonthlyReportService.NextScheduled(schedule, "UTC", Now));

        // Enabled before October ended: October's report is due on 3 November, i.e. now (overdue).
        schedule.EnabledAt = new DateTimeOffset(2026, 9, 20, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal((new DateOnly(2026, 11, 14), new DateOnly(2026, 10, 1)), MonthlyReportService.NextScheduled(schedule, "UTC", Now));

        // Already sent for October.
        schedule.LastScheduledPeriod = new DateOnly(2026, 10, 1);
        Assert.Equal((new DateOnly(2026, 12, 3), new DateOnly(2026, 11, 1)), MonthlyReportService.NextScheduled(schedule, "UTC", Now));

        // The organization's time zone decides the date: 02:00 UTC on 5 December is still 4 December in Los Angeles.
        var late = new DateTimeOffset(2026, 12, 5, 2, 0, 0, TimeSpan.Zero);
        Assert.Equal((new DateOnly(2026, 12, 5), new DateOnly(2026, 11, 1)), MonthlyReportService.NextScheduled(schedule, "UTC", late));
        Assert.Equal((new DateOnly(2026, 12, 4), new DateOnly(2026, 11, 1)), MonthlyReportService.NextScheduled(schedule, "America/Los_Angeles", late));

        Assert.Null(MonthlyReportService.NextScheduled(new ReportSchedule { Enabled = true, Recipients = [] }, "UTC", Now));
        Assert.Null(MonthlyReportService.NextScheduled(new ReportSchedule { Enabled = false, Recipients = ["it@example.com"] }, "UTC", Now));
    }
}
