using System.Globalization;
using EasyPatch.Core.Entities;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Shapes.Charts;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Fonts;

namespace EasyPatch.Infrastructure.Reports;

/// <summary>Liberation Sans (embedded, SIL OFL 1.1) for every font request: the server needs no installed fonts. It covers
/// Latin, Greek and Cyrillic; other scripts show as missing glyphs.</summary>
public sealed class ReportFontResolver : IFontResolver
{
    private const string Regular = "LiberationSans-Regular";
    private const string Bold = "LiberationSans-Bold";
    private static readonly ReportFontResolver Instance = new();
    private static readonly object Gate = new();
    private static bool registered;

    /// <summary>PDFsharp allows one resolver per process; it is set before the first report is rendered.</summary>
    public static void EnsureRegistered()
    {
        lock (Gate)
        {
            if (!registered)
            {
                GlobalFontSettings.FontResolver = Instance;
                registered = true;
            }
        }
    }

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic) =>
        new(bold ? Bold : Regular, false, italic);

    public byte[]? GetFont(string faceName)
    {
        using var stream = typeof(ReportFontResolver).Assembly.GetManifestResourceStream($"EasyPatch.Fonts.{faceName}.ttf");
        if (stream is null)
        {
            return null;
        }

        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }
}

/// <summary>Renders a <see cref="MonthlyReportData"/> as an A4 PDF (MigraDoc).</summary>
public static class ReportPdfRenderer
{
    private const string Font = "Liberation Sans";
    private static readonly Color Accent = new(0x1F, 0x4E, 0x79);
    private static readonly Color HeaderShade = new(0xE8, 0xEE, 0xF4);
    private static readonly Color ZebraShade = new(0xF7, 0xF8, 0xFA);
    private static readonly Color Muted = new(0x5F, 0x67, 0x70);
    private static readonly Color Danger = new(0xB4, 0x23, 0x18);
    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    public static byte[] Render(MonthlyReportData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ReportFontResolver.EnsureRegistered();
        var document = new Document();
        document.Info.Title = $"Patch compliance report: {data.OrganizationName}, {data.Period.Label}";
        document.Info.Subject = "Monthly patch compliance report";
        document.Info.Author = string.IsNullOrWhiteSpace(data.BrandName) ? "EasyPatch" : data.BrandName;
        ConfigureStyles(document);

        var section = document.AddSection();
        section.PageSetup = document.DefaultPageSetup.Clone();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(1.8);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(1.8);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(1.8);
        section.PageSetup.RightMargin = Unit.FromCentimeter(1.8);
        AddFooter(section, data);

        AddTitle(section, data);
        AddSummary(section, data);
        AddTrend(section, data);
        AddSites(section, data);
        AddTopMissing(section, data);
        AddOperatingSystems(section, data);
        AddNotes(section);
        if (data.Endpoints is { } endpoints)
        {
            AddEndpoints(section, endpoints);
        }

        var renderer = new PdfDocumentRenderer { Document = document };
        renderer.RenderDocument();
        using var output = new MemoryStream();
        renderer.PdfDocument.Save(output, false);
        return output.ToArray();
    }

    private static void ConfigureStyles(Document document)
    {
        var normal = document.Styles[StyleNames.Normal]!;
        normal.Font.Name = Font;
        normal.Font.Size = 9;
        normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);

        var heading = document.Styles[StyleNames.Heading1]!;
        heading.Font.Size = 13;
        heading.Font.Bold = true;
        heading.Font.Color = Accent;
        heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(12);
        heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        heading.ParagraphFormat.KeepWithNext = true;

        var table = document.Styles.AddStyle("TableText", StyleNames.Normal);
        table.Font.Size = 8;
        table.ParagraphFormat.SpaceAfter = Unit.Zero;

        var note = document.Styles.AddStyle("Note", StyleNames.Normal);
        note.Font.Size = 8;
        note.Font.Color = Muted;
    }

    private static void AddFooter(Section section, MonthlyReportData data)
    {
        var footer = section.Footers.Primary.AddParagraph();
        footer.Style = "Note";
        footer.Format.Alignment = ParagraphAlignment.Center;
        footer.AddText($"{data.OrganizationName} · {data.Period.Label} · Page ");
        footer.AddPageField();
        footer.AddText(" of ");
        footer.AddNumPagesField();
    }

    private static void AddTitle(Section section, MonthlyReportData data)
    {
        var title = section.AddParagraph("Patch compliance report");
        title.Format.Font.Size = 20;
        title.Format.Font.Bold = true;
        title.Format.Font.Color = Accent;
        title.Format.SpaceAfter = Unit.FromPoint(2);

        var org = section.AddParagraph(data.OrganizationName);
        org.Format.Font.Size = 14;
        org.Format.SpaceAfter = Unit.FromPoint(2);

        var period = section.AddParagraph(data.Period.Label);
        period.Format.Font.Size = 11;
        period.Format.SpaceAfter = Unit.FromPoint(8);

        var meta = section.AddParagraph();
        meta.Style = "Note";
        if (!string.IsNullOrWhiteSpace(data.BrandName))
        {
            meta.AddText($"Prepared by {data.BrandName}. ");
        }

        meta.AddText($"Generated {data.GeneratedAt.UtcDateTime.ToString("d MMMM yyyy HH:mm", Invariant)} UTC with EasyPatch. ");
        meta.AddText("Period values use UTC dates; values marked \"now\" are as of generation.");
    }

    private static void AddSummary(Section section, MonthlyReportData data)
    {
        section.AddParagraph("Summary", StyleNames.Heading1);
        var s = data.Summary;
        var table = NewTable(section, [("", 10.4, ParagraphAlignment.Left), ("", 7, ParagraphAlignment.Left)], header: false);
        void Row(string label, string value, bool alert = false)
        {
            var row = table.AddRow();
            row.Cells[0].AddParagraph(label);
            var p = row.Cells[1].AddParagraph(value);
            p.Format.Font.Bold = true;
            if (alert)
            {
                p.Format.Font.Color = Danger;
            }
        }

        Row("Compliant endpoints (now)", $"{Percent(s.CompliancePercent)} ({s.Compliant} of {s.Endpoints})");
        Row($"Compliance during {data.Period.Start.ToString("MMMM", Invariant)}",
            s.ComplianceAtStart is { } first && s.ComplianceAtEnd is { } last ? $"{Percent(first)} → {Percent(last)}" : "No daily snapshots in this period");
        Row("Updates installed (confirmed by a scan)", $"{s.UpdatesInstalled} on {s.EndpointsUpdated} endpoint{Plural(s.EndpointsUpdated)}");
        Row("Failed installation attempts", s.FailedInstallations.ToString(Invariant), s.FailedInstallations > 0);
        Row("Required updates outstanding (now)", s.MissingRequiredUpdates.ToString(Invariant));
        Row("Endpoints missing a fix for a known-exploited vulnerability (now)", s.KnownExploitedEndpoints.ToString(Invariant), s.KnownExploitedEndpoints > 0);
        Row("Endpoints waiting for a restart (now)", s.RebootPending.ToString(Invariant));
        Row("Endpoints with an unsupported operating system (now)", s.UnsupportedOs.ToString(Invariant), s.UnsupportedOs > 0);
        Row("Endpoints not seen for more than 7 days (now)", s.OfflineOver7Days.ToString(Invariant), s.OfflineOver7Days > 0);
    }

    private static void AddTrend(Section section, MonthlyReportData data)
    {
        section.AddParagraph("Compliance trend", StyleNames.Heading1);
        if (data.Trend.Count < 2)
        {
            section.AddParagraph("Not enough daily snapshots in this period to show a trend (the server records one per day).").Style = "Note";
            return;
        }

        var chart = section.AddChart(ChartType.Line);
        chart.Width = Unit.FromCentimeter(17.4);
        chart.Height = Unit.FromCentimeter(4.4);
        var series = chart.SeriesCollection.AddSeries();
        series.Name = "Compliant endpoints (%)";
        series.Add(data.Trend.Select(t => Math.Round(t.Percent, 1)).ToArray());
        series.LineFormat.Color = Accent;
        series.LineFormat.Width = Unit.FromPoint(1.5);
        series.MarkerStyle = MarkerStyle.Circle;
        series.MarkerSize = Unit.FromPoint(3);
        series.MarkerBackgroundColor = Accent;
        series.MarkerForegroundColor = Accent;
        var labels = chart.XValues.AddXSeries();
        var every = Math.Max(1, (int)Math.Ceiling(data.Trend.Count / 16.0));
        for (var i = 0; i < data.Trend.Count; i++)
        {
            labels.Add(i % every == 0 || i == data.Trend.Count - 1 ? data.Trend[i].Date.Day.ToString(Invariant) : "");
        }

        chart.XAxis.MajorTickMark = TickMarkType.Outside;
        chart.XAxis.TickLabels.Font.Size = 7;
        chart.YAxis.MinimumScale = 0;
        chart.YAxis.MaximumScale = 100;
        chart.YAxis.MajorTick = 25;
        chart.YAxis.HasMajorGridlines = true;
        chart.YAxis.MajorGridlines.LineFormat.Color = new Color(0xDD, 0xDD, 0xDD);
        chart.YAxis.TickLabels.Font.Size = 7;
        chart.YAxis.TickLabels.Format = "0";
        chart.PlotArea.LineFormat.Visible = false;
        section.AddParagraph($"Share of compliant endpoints per day of {data.Period.Start.ToString("MMMM yyyy", Invariant)} (UTC).").Style = "Note";
    }

    private static void AddSites(Section section, MonthlyReportData data)
    {
        section.AddParagraph("Sites", StyleNames.Heading1);
        if (data.Sites.Count == 0)
        {
            section.AddParagraph("No managed endpoints.").Style = "Note";
            return;
        }

        var table = NewTable(section,
        [
            ("Site", 5.2, ParagraphAlignment.Left), ("Endpoints", 1.8, ParagraphAlignment.Right), ("Compliant", 2.1, ParagraphAlignment.Right),
            ("Required missing", 2.2, ParagraphAlignment.Right), ("Failed", 1.6, ParagraphAlignment.Right), ("Restart pending", 2.2, ParagraphAlignment.Right),
            ("Known exploited", 2.3, ParagraphAlignment.Right),
        ]);
        foreach (var site in data.Sites)
        {
            AddRow(table, site.Name, Number(site.Endpoints), Percent(site.Percent), Number(site.MissingRequired), Number(site.Failed), Number(site.RebootPending),
                Number(site.KnownExploited));
        }
    }

    private static void AddTopMissing(Section section, MonthlyReportData data)
    {
        section.AddParagraph("Most widely missing required updates (now)", StyleNames.Heading1);
        if (data.TopMissing.Count == 0)
        {
            section.AddParagraph("No required updates are missing.").Style = "Note";
            return;
        }

        var table = NewTable(section,
        [
            ("Update", 8.4, ParagraphAlignment.Left), ("KB / package", 2.6, ParagraphAlignment.Left), ("Severity", 1.8, ParagraphAlignment.Left),
            ("CVEs", 1.2, ParagraphAlignment.Right), ("Endpoints", 1.8, ParagraphAlignment.Right), ("", 1.6, ParagraphAlignment.Left),
        ]);
        foreach (var u in data.TopMissing)
        {
            var row = AddRow(table, u.Title, u.Kb ?? "", u.Severity ?? "", u.CveCount > 0 ? Number(u.CveCount) : "", Number(u.Endpoints), u.KnownExploited ? "Exploited" : "");
            if (u.KnownExploited)
            {
                row.Cells[5].Format.Font.Color = Danger;
                row.Cells[5].Format.Font.Bold = true;
            }
        }

        section.AddParagraph("\"Exploited\": fixes a vulnerability in the CISA Known Exploited Vulnerabilities catalog. These are listed first.").Style = "Note";
    }

    private static void AddOperatingSystems(Section section, MonthlyReportData data)
    {
        section.AddParagraph("Operating systems (now)", StyleNames.Heading1);
        if (data.OperatingSystems.Count == 0)
        {
            section.AddParagraph("No managed endpoints.").Style = "Note";
            return;
        }

        var table = NewTable(section, [("Operating system", 10.4, ParagraphAlignment.Left), ("Support", 4.2, ParagraphAlignment.Left), ("Endpoints", 2.8, ParagraphAlignment.Right)]);
        foreach (var os in data.OperatingSystems)
        {
            var row = AddRow(table, os.OperatingSystem, SupportText(os.Support), Number(os.Endpoints));
            if (os.Support == OsSupportStatus.Unsupported)
            {
                row.Cells[1].Format.Font.Color = Danger;
            }
        }
    }

    private static void AddNotes(Section section)
    {
        section.AddParagraph("How to read this report", StyleNames.Heading1);
        section.AddParagraph(
            "An endpoint is compliant when it has no required update missing or failed, no pending restart and a recent successful scan. " +
            "Required updates are those the organization's policy installs; updates still inside a rollout delay are not counted yet. " +
            "An update counts as installed only after a scan of the endpoint confirms it.").Style = "Note";
    }

    private static void AddEndpoints(Section section, IReadOnlyList<ReportEndpointRow> endpoints)
    {
        section.AddPageBreak();
        section.AddParagraph("Endpoints (now)", StyleNames.Heading1);
        var table = NewTable(section,
        [
            ("Endpoint", 3.2, ParagraphAlignment.Left), ("Site", 2.1, ParagraphAlignment.Left), ("Operating system", 2.9, ParagraphAlignment.Left),
            ("Status", 2.6, ParagraphAlignment.Left), ("Missing", 1.3, ParagraphAlignment.Right), ("Failed", 1.1, ParagraphAlignment.Right),
            ("Last seen", 2.0, ParagraphAlignment.Left), ("Last scan", 2.0, ParagraphAlignment.Left),
        ]);
        foreach (var e in endpoints)
        {
            var row = AddRow(table, e.Hostname, e.Site ?? "", e.OperatingSystem ?? "", Humanize(e.Status), Number(e.MissingRequired), Number(e.Failed),
                Date(e.LastCheckIn), Date(e.LastScan));
            if (e.KnownExploited > 0)
            {
                row.Cells[0].Format.Font.Color = Danger;
            }
        }

        if (endpoints.Count >= MonthlyReportDataBuilder.MaxEndpointRows)
        {
            section.AddParagraph($"Only the first {MonthlyReportDataBuilder.MaxEndpointRows} endpoints are listed.").Style = "Note";
        }

        section.AddParagraph("Endpoints in red are missing a fix for a known-exploited vulnerability.").Style = "Note";
    }

    private static Table NewTable(Section section, (string Header, double WidthCm, ParagraphAlignment Align)[] columns, bool header = true)
    {
        var table = section.AddTable();
        table.Style = "TableText";
        table.Borders.Color = new Color(0xD5, 0xDA, 0xE0);
        table.Borders.Width = Unit.FromPoint(0.5);
        table.Borders.Left.Visible = false;
        table.Borders.Right.Visible = false;
        table.LeftPadding = Unit.FromPoint(4);
        table.RightPadding = Unit.FromPoint(4);
        table.TopPadding = Unit.FromPoint(2.5);
        table.BottomPadding = Unit.FromPoint(2.5);
        foreach (var c in columns)
        {
            table.AddColumn(Unit.FromCentimeter(c.WidthCm)).Format.Alignment = c.Align;
        }

        if (header)
        {
            var row = table.AddRow();
            row.HeadingFormat = true;
            row.Shading.Color = HeaderShade;
            row.Format.Font.Bold = true;
            for (var i = 0; i < columns.Length; i++)
            {
                row.Cells[i].AddParagraph(columns[i].Header);
            }
        }

        return table;
    }

    private static Row AddRow(Table table, params string[] values)
    {
        var row = table.AddRow();
        if (table.Rows.Count % 2 == 1)
        {
            row.Shading.Color = ZebraShade;
        }

        for (var i = 0; i < values.Length; i++)
        {
            row.Cells[i].AddParagraph(values[i]);
        }

        return row;
    }

    private static string Percent(double value) => value.ToString("0.0", Invariant) + " %";
    private static string Number(int value) => value.ToString("N0", Invariant);
    private static string Plural(int n) => n == 1 ? "" : "s";
    private static string Date(DateTimeOffset? value) => value?.UtcDateTime.ToString("yyyy-MM-dd", Invariant) ?? "never";

    private static string SupportText(OsSupportStatus status) => status switch
    {
        OsSupportStatus.Supported => "Supported",
        OsSupportStatus.ExtendedSecurityUpdates => "Extended Security Updates",
        OsSupportStatus.Unsupported => "Unsupported",
        _ => "Unknown",
    };

    private static string Humanize(ComplianceStatus status) => status switch
    {
        ComplianceStatus.Compliant => "Compliant",
        ComplianceStatus.MissingUpdates => "Missing updates",
        ComplianceStatus.FailedUpdates => "Failed updates",
        ComplianceStatus.RebootRequired => "Restart required",
        ComplianceStatus.ScanStale => "Scan stale",
        ComplianceStatus.NeverScanned => "Never scanned",
        _ => status.ToString(),
    };
}
