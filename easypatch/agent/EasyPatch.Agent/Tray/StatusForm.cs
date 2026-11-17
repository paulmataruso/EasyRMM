using System.Drawing.Drawing2D;
using System.Globalization;
using System.Text;
using EasyPatch.Agent.Core.Abstractions;

namespace EasyPatch.Agent.Tray;

internal enum StatusLevel
{
    Good,
    Info,
    Busy,
    Warning,
    Error,
}

/// <summary>The one-line summary used by the status window's heading and the icon's tooltip.</summary>
internal sealed record StatusSummary(StatusLevel Level, string Title, string Detail)
{
    /// <summary>Updates count as stale when they have not been checked for this long.</summary>
    private static readonly TimeSpan StaleScan = TimeSpan.FromDays(3);

    public static StatusSummary From(TrayStatus status, RestartPrompt? prompt, bool serviceConnected)
    {
        if (!serviceConnected)
        {
            return new(StatusLevel.Error, "The EasyPatch service is not responding",
                "Updates cannot be checked or installed until the service is running again. If this continues, contact your IT team.");
        }

        switch (status.Connection)
        {
            case TrayConnection.NotEnrolled:
                return new(StatusLevel.Error, "This computer is not connected to EasyPatch",
                    "The agent is installed but has not been enrolled. Contact your IT team.");
            case TrayConnection.Revoked:
                return new(StatusLevel.Error, "This computer was removed from EasyPatch",
                    "The server no longer accepts this computer. Contact your IT team to enroll it again.");
            case TrayConnection.PendingApproval:
                return new(StatusLevel.Warning, "Waiting for approval",
                    "Your IT team needs to approve this computer in the EasyPatch console.");
        }

        if (prompt is not null)
        {
            return new(StatusLevel.Warning, "Restart required",
                prompt.Kind == RestartPromptKind.Countdown
                    ? "Your IT team is restarting this computer. Save your work."
                    : "Your IT team asked you to restart this computer. Open Restart options to restart now or later.");
        }

        if (status.Connection == TrayConnection.Unreachable)
        {
            return new(StatusLevel.Warning, "Can't reach the EasyPatch server",
                $"Last successful check-in: {TimeText.Ago(status.LastContactAt)}. The agent keeps trying automatically.");
        }

        if (status.RebootPending)
        {
            return new(StatusLevel.Warning, "Restart needed to finish installing updates",
                "Windows needs a restart to complete updates. Your IT team schedules restarts, or you can restart when convenient.");
        }

        if (!string.Equals(status.Activity, "Idle", StringComparison.Ordinal))
        {
            return new(StatusLevel.Busy, status.Activity + "…", "This runs in the background. You can keep working.");
        }

        if (status.LastScanError is { Length: > 0 } error)
        {
            return new(StatusLevel.Warning, "The last update check failed", Shorten(error, 160));
        }

        if (status.LastScanAt is not { } lastScan)
        {
            return new(StatusLevel.Info, "Waiting for the first update check", "The agent checks for updates shortly after it starts.");
        }

        if (DateTimeOffset.UtcNow - lastScan > StaleScan)
        {
            return new(StatusLevel.Warning, "Updates have not been checked recently",
                $"Last checked {TimeText.Ago(lastScan)}. Choose Check for updates to check now.");
        }

        if (status.UpdatesAvailable is > 0 and var available)
        {
            return new(StatusLevel.Info, available == 1 ? "1 update available" : $"{available} updates available",
                "Your IT team decides when updates are installed.");
        }

        return new(StatusLevel.Good, "This computer is up to date", $"Last checked for updates {TimeText.Ago(lastScan)}.");
    }

    public static string Shorten(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";
}

/// <summary>
/// The status window opened from the tray icon: health summary, details, "Check in now", "Check for updates" and
/// the recent agent log. It shows only what the service sends; the two buttons send parameterless requests that the
/// service may refuse (they are rate-limited for the whole computer).
/// </summary>
internal sealed class StatusForm : Form
{
    private static readonly TimeSpan AnswerTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan LogRefreshInterval = TimeSpan.FromSeconds(30);

    private readonly StatusBadge _badge = new() { Size = new Size(40, 40), Margin = new Padding(0, 2, 12, 0) };
    private readonly Label _title = new() { AutoSize = true, Margin = new Padding(0) };
    private readonly Label _detail = new() { AutoSize = true, MaximumSize = new Size(500, 0), Margin = new Padding(0, 4, 0, 0) };
    private readonly TableLayoutPanel _details = new() { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top, Margin = new Padding(0, 12, 0, 0) };
    private readonly Dictionary<string, (Label Name, Label Value)> _rows = [];
    private readonly Button _checkIn = new() { Text = "Check in now", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
    private readonly Button _checkUpdates = new() { Text = "Check for updates", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
    private readonly Button _restartOptions = new() { Text = "Restart options…", AutoSize = true, Padding = new Padding(8, 2, 8, 2), Visible = false };
    private readonly Label _result = new() { AutoSize = true, MaximumSize = new Size(560, 0), Margin = new Padding(3, 6, 3, 0), Visible = false };
    private readonly ListView _log = new()
    {
        View = View.Details,
        FullRowSelect = true,
        HeaderStyle = ColumnHeaderStyle.Nonclickable,
        Dock = DockStyle.Fill,
        MultiSelect = true,
        ShowItemToolTips = true,
        AccessibleName = "Recent activity",
    };
    private readonly Button _refreshLog = new() { Text = "Refresh", AutoSize = true };
    private readonly Button _copyLog = new() { Text = "Copy", AutoSize = true };
    private readonly ToolTip _tips = new();
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 1000 };
    private readonly Dictionary<UserRequestKind, DateTime> _awaiting = [];
    private TrayStatus _status = new();
    private RestartPrompt? _prompt;
    private bool _serviceConnected;
    private DateTime _logRequestedAt = DateTime.MinValue;
    private bool _followCheckIn;
    private bool _followUpdateCheck;

    public StatusForm()
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "EasyPatch";
        Icon = AppIcons.Large;
        Font = SystemFonts.MessageBoxFont ?? Font;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = false;
        MinimizeBox = true;
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.Manual;
        ClientSize = new Size(640, 660);
        MinimumSize = new Size(520, 560);
        Padding = new Padding(14);
        _title.Font = new Font(Font.FontFamily, Font.Size + 4, FontStyle.Bold);

        // Heading: badge, title and detail.
        var headingText = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        headingText.Controls.AddRange([_title, _detail]);
        var heading = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0) };
        heading.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        heading.Controls.Add(_badge, 0, 0);
        heading.Controls.Add(headingText, 1, 0);

        // Details.
        _details.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _details.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        foreach (var name in new[]
                 {
                     "Server connection", "Last check-in", "Managed by", "Last update check", "Updates available",
                     "Last updates installed", "Restart needed", "Current activity", "Computer", "Agent version",
                 })
        {
            var label = new Label { Text = name, AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 3, 16, 3) };
            var value = new Label { AutoSize = true, MaximumSize = new Size(420, 0), Margin = new Padding(0, 3, 0, 3), UseMnemonic = false };
            _details.RowCount++;
            _details.Controls.Add(label, 0, _details.RowCount - 1);
            _details.Controls.Add(value, 1, _details.RowCount - 1);
            _rows[name] = (label, value);
        }

        // Actions.
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 12, 0, 0), WrapContents = true };
        actions.Controls.AddRange([_checkIn, _checkUpdates, _restartOptions]);
        _tips.SetToolTip(_checkIn, "Contact the EasyPatch server now. Possible every 30 seconds.");
        _tips.SetToolTip(_checkUpdates, "Look for missing updates now. Nothing is installed; your IT team decides when updates are installed. Possible every 5 minutes.");
        _checkIn.Click += (_, _) => Request(UserRequestKind.CheckIn);
        _checkUpdates.Click += (_, _) => Request(UserRequestKind.CheckForUpdates);
        _restartOptions.Click += (_, _) => RestartOptionsClicked?.Invoke();

        // Log.
        var logTitle = new Label { Text = "Recent activity", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 0, 0) };
        logTitle.Font = new Font(Font, FontStyle.Bold);
        var logButtons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, Margin = new Padding(0), WrapContents = false };
        logButtons.Controls.AddRange([_copyLog, _refreshLog]);
        var logHeader = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 16, 0, 4) };
        logHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        logHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        logHeader.Controls.Add(logTitle, 0, 0);
        logHeader.Controls.Add(logButtons, 1, 0);
        _log.Columns.Add("Time", 130);
        _log.Columns.Add("Level", 70);
        _log.Columns.Add("Message", 400);
        _log.KeyDown += (_, e) =>
        {
            if (e.Control && e.KeyCode == Keys.C)
            {
                CopyLog(selectedOnly: true);
                e.Handled = true;
            }
            else if (e.Control && e.KeyCode == Keys.A)
            {
                foreach (ListViewItem item in _log.Items)
                {
                    item.Selected = true;
                }

                e.Handled = true;
            }
        };
        _refreshLog.Click += (_, _) => RequestLog();
        _copyLog.Click += (_, _) => CopyLog(selectedOnly: _log.SelectedItems.Count > 0);
        _tips.SetToolTip(_copyLog, "Copy the selected entries (or all of them), for example to send to your IT team.");

        // Footer.
        var close = new Button { Text = "Close", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
        close.Click += (_, _) => Hide();
        CancelButton = close;
        var footer = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
        footer.Controls.Add(close);

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Margin = new Padding(0) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 7; i++)
        {
            layout.RowStyles.Add(i == 5 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
        }

        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(_details, 0, 1);
        layout.Controls.Add(actions, 0, 2);
        layout.Controls.Add(_result, 0, 3);
        layout.Controls.Add(logHeader, 0, 4);
        layout.Controls.Add(_log, 0, 5);
        layout.Controls.Add(footer, 0, 6);
        Controls.Add(layout);

        _timer.Tick += (_, _) => Tick();
        ResumeLayout(false);
        PerformLayout();
    }

    /// <summary>The user asked for a check-in or an update check.</summary>
    public event Action<UserRequestKind>? RequestClicked;

    /// <summary>The window needs the recent log.</summary>
    public event Action? LogRequested;

    public event Action? RestartOptionsClicked;

    /// <summary>Shows the window (bottom-right, above the notification area) and brings it to the front.</summary>
    public void Open()
    {
        if (!Visible)
        {
            Show();

            // Placed after Show: the size is final only once the window exists at the screen's DPI.
            var area = Screen.FromControl(this).WorkingArea;
            Location = new Point(Math.Max(area.Left, area.Right - Width - 16), Math.Max(area.Top, area.Bottom - Height - 16));
        }

        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Activate();
        RequestLog();
    }

    public void Display(TrayStatus status, RestartPrompt? prompt, bool serviceConnected)
    {
        _status = status;
        ReportFinishedRequests();
        _prompt = prompt;
        _serviceConnected = serviceConnected;
        Render();
    }

    public void ShowRequestResult(UserRequestKind kind, UserRequestResult result)
    {
        _awaiting.Remove(kind);
        if (result.Accepted)
        {
            if (kind == UserRequestKind.CheckIn)
            {
                _followCheckIn = true;
            }
            else
            {
                _followUpdateCheck = true;
            }
        }

        ShowResult(result.Message, success: result.Accepted ? null : false);
        ReportFinishedRequests(); // in case the request finished before its answer arrived
        Render();
    }

    /// <summary>Reports how an accepted request turned out once the service shows it is no longer waiting. The
    /// service publishes the "requested" status before it answers, so a request is never reported finished early.</summary>
    private void ReportFinishedRequests()
    {
        var status = _status;
        if (_followCheckIn && !status.CheckInRequested)
        {
            _followCheckIn = false;
            var connected = status.Connection == TrayConnection.Connected;
            ShowResult(connected
                ? $"Checked in with the server at {TimeText.At(status.LastContactAt ?? DateTimeOffset.UtcNow)}."
                : "Could not reach the EasyPatch server. The agent keeps trying automatically.", success: connected);
            RequestLog();
        }

        if (_followUpdateCheck && !status.UpdateCheckRequested)
        {
            _followUpdateCheck = false;
            ShowResult(status.LastScanError is { Length: > 0 } error
                ? "The update check failed: " + StatusSummary.Shorten(error, 200)
                : status.UpdatesAvailable switch
                {
                    0 => "Update check finished: no updates are missing.",
                    1 => "Update check finished: 1 update is available.",
                    { } n => $"Update check finished: {n} updates are available.",
                    _ => "Update check finished.",
                }, success: status.LastScanError is null);
            RequestLog();
        }
    }

    public void ShowLog(IReadOnlyList<TrayLogEntry> entries)
    {
        _log.BeginUpdate();
        try
        {
            _log.Items.Clear();
            for (var i = entries.Count - 1; i >= 0; i--) // newest first
            {
                var entry = entries[i];
                var item = new ListViewItem(new[]
                {
                    entry.At.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    LevelText(entry.Level),
                    entry.Message,
                })
                {
                    ToolTipText = entry.Message,
                    ForeColor = entry.Level switch
                    {
                        TrayLogLevel.Error => TrayTheme.ErrorText,
                        TrayLogLevel.Warning => TrayTheme.WarningText,
                        _ => SystemColors.WindowText,
                    },
                };
                _log.Items.Add(item);
            }

            if (entries.Count == 0)
            {
                _log.Items.Add(new ListViewItem(new[] { string.Empty, string.Empty, "No log entries are available." }) { ForeColor = SystemColors.GrayText });
            }
        }
        finally
        {
            _log.EndUpdate();
        }
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        SizeColumns();
        _timer.Start();
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        SizeColumns();
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        SizeColumns();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true; // closing only hides it; the tray icon opens it again
            Hide();
        }

        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
            _tips.Dispose();
        }

        base.Dispose(disposing);
    }

    private void Request(UserRequestKind kind)
    {
        _awaiting[kind] = DateTime.UtcNow;
        ShowResult(kind == UserRequestKind.CheckIn ? "Asking the agent to check in…" : "Asking the agent to check for updates…", success: null);
        Render();
        RequestClicked?.Invoke(kind);
    }

    private void RequestLog()
    {
        _logRequestedAt = DateTime.UtcNow;
        LogRequested?.Invoke();
    }

    private void Tick()
    {
        if (!Visible)
        {
            return;
        }

        foreach (var (kind, since) in _awaiting.ToList())
        {
            if (DateTime.UtcNow - since > AnswerTimeout)
            {
                _awaiting.Remove(kind);
                ShowResult("The EasyPatch service did not answer. Try again in a minute.", success: false);
            }
        }

        if (DateTime.UtcNow - _logRequestedAt > LogRefreshInterval)
        {
            RequestLog();
        }

        Render(); // relative times ("2 minutes ago")
    }

    private void Render()
    {
        var summary = StatusSummary.From(_status, _prompt, _serviceConnected);
        _badge.Level = summary.Level;
        SetText(_title, summary.Title);
        SetText(_detail, summary.Detail);
        _title.ForeColor = summary.Level switch
        {
            StatusLevel.Good => TrayTheme.GoodText,
            StatusLevel.Warning => TrayTheme.WarningText,
            StatusLevel.Error => TrayTheme.ErrorText,
            _ => SystemColors.ControlText,
        };

        var s = _status;
        var enrolled = _serviceConnected && s.Connection is TrayConnection.Connected or TrayConnection.Unreachable;
        Set("Server connection", !_serviceConnected ? "Unknown (the EasyPatch service is not responding)" : s.Connection switch
        {
            TrayConnection.Connected => "Connected",
            TrayConnection.Unreachable => $"Not reachable since {TimeText.At(s.UnreachableSince ?? DateTimeOffset.UtcNow)}",
            TrayConnection.PendingApproval => "Waiting for approval",
            TrayConnection.Revoked => "Removed by the server",
            _ => "Not enrolled",
        });
        Set("Last check-in", TimeText.Ago(s.LastContactAt));
        Set("Managed by", s.ServerHost);
        Set("Last update check", s.LastScanAt is { } scanned
            ? TimeText.Ago(scanned) + (s.LastScanError is { Length: > 0 } ? " (the most recent check failed)" : string.Empty)
            : s.LastScanError is { Length: > 0 } ? "Failed" : "Not yet");
        _tips.SetToolTip(_rows["Last update check"].Value, s.LastScanError ?? string.Empty);
        Set("Updates available", s.UpdatesAvailable switch
        {
            null => "Unknown",
            0 => "None",
            { } n => $"{n} (your IT team decides when updates are installed)",
        });
        Set("Last updates installed", s.LastInstallAt is { } installed
            ? $"{TimeText.Ago(installed)} ({s.LastInstallCount} update{(s.LastInstallCount == 1 ? string.Empty : "s")})"
            : "None recorded by this agent version");
        Set("Restart needed", _prompt is not null ? "Yes, your IT team asked for a restart" : s.RebootPending ? "Yes, to finish installing updates" : "No");
        Set("Current activity", s.Activity == "Idle" ? "None" : s.Activity);
        Set("Computer", Environment.MachineName);
        Set("Agent version", AgentComposition.AgentVersion);

        _checkIn.Enabled = enrolled && !s.CheckInRequested && !_awaiting.ContainsKey(UserRequestKind.CheckIn);
        _checkUpdates.Enabled = enrolled && !s.UpdateCheckRequested && !_awaiting.ContainsKey(UserRequestKind.CheckForUpdates);
        _checkIn.Text = s.CheckInRequested ? "Checking in…" : "Check in now";
        _checkUpdates.Text = s.UpdateCheckRequested ? "Checking for updates…" : "Check for updates";
        _restartOptions.Visible = _prompt is not null && _prompt.Kind != RestartPromptKind.Postponed;
    }

    private void Set(string row, string? value)
    {
        var (name, label) = _rows[row];
        var visible = !string.IsNullOrEmpty(value);
        name.Visible = visible;
        label.Visible = visible;
        SetText(label, value ?? string.Empty);
    }

    /// <summary>Sets the text only when it changed (the window refreshes every second).</summary>
    private static void SetText(Control control, string text)
    {
        if (!string.Equals(control.Text, text, StringComparison.Ordinal))
        {
            control.Text = text;
        }
    }

    private void ShowResult(string text, bool? success)
    {
        _result.Text = text;
        _result.ForeColor = success == false ? TrayTheme.WarningText : success == true ? TrayTheme.GoodText : SystemColors.ControlText;
        _result.Visible = true;
    }

    private void SizeColumns()
    {
        if (_log.Columns.Count < 3)
        {
            return;
        }

        _log.Columns[0].Width = LogicalToDeviceUnits(130);
        _log.Columns[1].Width = LogicalToDeviceUnits(70);
        var rest = _log.ClientSize.Width - _log.Columns[0].Width - _log.Columns[1].Width - SystemInformation.VerticalScrollBarWidth;
        _log.Columns[2].Width = Math.Max(LogicalToDeviceUnits(200), rest);
        var wrap = Math.Max(LogicalToDeviceUnits(240), ClientSize.Width - Padding.Horizontal - LogicalToDeviceUnits(70));
        _detail.MaximumSize = new Size(wrap, 0);
        _result.MaximumSize = new Size(wrap, 0);
        foreach (var (_, value) in _rows.Values)
        {
            value.MaximumSize = new Size(Math.Max(LogicalToDeviceUnits(200), wrap - LogicalToDeviceUnits(150)), 0);
        }
    }

    private void CopyLog(bool selectedOnly)
    {
        var text = new StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"EasyPatch Agent {AgentComposition.AgentVersion} on {Environment.MachineName}");
        IEnumerable<ListViewItem> items = selectedOnly ? _log.SelectedItems.Cast<ListViewItem>() : _log.Items.Cast<ListViewItem>();
        foreach (var item in items)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"{item.SubItems[0].Text}  {item.SubItems[1].Text,-11}  {item.SubItems[2].Text}");
        }

        try
        {
            Clipboard.SetText(text.ToString());
            ShowResult(selectedOnly ? "Copied the selected entries." : "Copied the log.", success: true);
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            ShowResult("The clipboard is in use by another application. Try again.", success: false);
        }
    }

    private static string LevelText(TrayLogLevel level) => level switch
    {
        TrayLogLevel.Error => "Error",
        TrayLogLevel.Warning => "Warning",
        _ => "Info",
    };
}

/// <summary>Status colors that stay readable on the light and the dark (Windows app mode) background.</summary>
internal static class TrayTheme
{
    public static bool Dark => Application.IsDarkModeEnabled;

    public static Color GoodText => Dark ? Color.FromArgb(0x6C, 0xCB, 0x5F) : Color.FromArgb(0x1E, 0x7B, 0x34);

    public static Color WarningText => Dark ? Color.FromArgb(0xFC, 0xC1, 0x5A) : Color.FromArgb(0xA8, 0x5A, 0x00);

    public static Color ErrorText => Dark ? Color.FromArgb(0xFF, 0x99, 0xA4) : Color.FromArgb(0xC0, 0x1C, 0x28);
}

/// <summary>A filled circle with a check mark, exclamation mark, cross, "i" or three dots.</summary>
internal sealed class StatusBadge : Control
{
    public static readonly Color GoodColor = Color.FromArgb(0x1E, 0x7B, 0x34);
    public static readonly Color InfoColor = Color.FromArgb(0x1A, 0x5F, 0xB4);
    public static readonly Color WarningColor = Color.FromArgb(0xE0, 0x8A, 0x00);
    public static readonly Color ErrorColor = Color.FromArgb(0xC0, 0x1C, 0x28);

    private StatusLevel _level = StatusLevel.Info;

    public StatusBadge()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                 ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        TabStop = false;
        AccessibleRole = AccessibleRole.Graphic;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public StatusLevel Level
    {
        get => _level;
        set
        {
            if (_level != value)
            {
                _level = value;
                AccessibleName = value.ToString();
                Invalidate();
            }
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        var size = Math.Min(Width, Height) - 2;
        var circle = new RectangleF(1, 1, size, size);
        var color = _level switch
        {
            StatusLevel.Good => GoodColor,
            StatusLevel.Warning => WarningColor,
            StatusLevel.Error => ErrorColor,
            _ => InfoColor,
        };
        using (var fill = new SolidBrush(color))
        {
            g.FillEllipse(fill, circle);
        }

        using var pen = new Pen(Color.White, Math.Max(2f, size / 9f)) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        float X(float f) => circle.Left + (size * f);
        float Y(float f) => circle.Top + (size * f);
        switch (_level)
        {
            case StatusLevel.Good:
                g.DrawLines(pen, [new PointF(X(0.28f), Y(0.52f)), new PointF(X(0.44f), Y(0.68f)), new PointF(X(0.73f), Y(0.36f))]);
                break;
            case StatusLevel.Error:
                g.DrawLine(pen, X(0.34f), Y(0.34f), X(0.66f), Y(0.66f));
                g.DrawLine(pen, X(0.66f), Y(0.34f), X(0.34f), Y(0.66f));
                break;
            case StatusLevel.Warning:
                g.DrawLine(pen, X(0.5f), Y(0.26f), X(0.5f), Y(0.56f));
                using (var dot = new SolidBrush(Color.White))
                {
                    var r = pen.Width * 0.7f;
                    g.FillEllipse(dot, X(0.5f) - r, Y(0.72f) - r, 2 * r, 2 * r);
                }

                break;
            case StatusLevel.Busy:
                using (var dot = new SolidBrush(Color.White))
                {
                    var r = pen.Width * 0.65f;
                    foreach (var f in new[] { 0.3f, 0.5f, 0.7f })
                    {
                        g.FillEllipse(dot, X(f) - r, Y(0.5f) - r, 2 * r, 2 * r);
                    }
                }

                break;
            default:
                g.DrawLine(pen, X(0.5f), Y(0.45f), X(0.5f), Y(0.74f));
                using (var dot = new SolidBrush(Color.White))
                {
                    var r = pen.Width * 0.7f;
                    g.FillEllipse(dot, X(0.5f) - r, Y(0.28f) - r, 2 * r, 2 * r);
                }

                break;
        }
    }
}
