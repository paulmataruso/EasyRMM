using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Security.Principal;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Ipc;
using EasyPatch.Agent.Platform;
using EasyPatch.Contracts.Agent;
using Microsoft.Win32;

namespace EasyPatch.Agent.Tray;

/// <summary>
/// <c>EasyPatch.Agent.exe tray</c>: the notification-area icon started by the service in each signed-in session. It
/// runs as the user, holds no credentials, reads nothing from the agent's data directory and can only show what the
/// service sends it (status, messages, the restart request and, for the status window, the recent log). The only
/// things it sends back are "restart now" and "postpone" for the restart request on screen, and the status window's
/// parameterless "check in", "check for updates" and "get log" requests.
/// </summary>
internal static class TrayApplication
{
    public static int Run()
    {
        using var current = Process.GetCurrentProcess();
        if (current.SessionId == 0)
        {
            Console.Error.WriteLine("The tray runs in a user's session; the EasyPatch service starts it automatically.");
            return 2;
        }

        using var single = new Mutex(initiallyOwned: false, @"Local\EasyPatchTray", out var created);
        if (!created)
        {
            return 0; // already running in this session
        }

        var thread = new Thread(() =>
        {
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Follow the user's Windows app mode (Settings > Personalization > Colors): dark windows, menus and title
            // bars in dark mode. Must be set before the first window exists.
            Application.SetColorMode(SystemColorMode.System);
            using var context = new TrayContext();
            Application.Run(context);
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return 0;
    }
}

internal sealed class TrayContext : ApplicationContext
{
    private readonly Control _invoker = new();
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu = new();
    private readonly ToolStripMenuItem _statusItem = new() { Enabled = false };
    private readonly ToolStripMenuItem _contactItem = new() { Enabled = false };
    private readonly ToolStripMenuItem _rebootItem = new("A restart is pending to finish installing updates") { Enabled = false, Visible = false };
    private readonly ToolStripMenuItem _openStatusItem = new("Open EasyPatch status");
    private readonly ToolStripMenuItem _restartItem = new("Restart options…") { Visible = false };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 5000 };
    private readonly TrayPipeClient _client;
    private RestartPromptForm? _form;
    private StatusForm? _statusForm;
    private TrayStatus _status = new() { ShowIcon = false };
    private RestartPrompt? _prompt;
    private DateTime _noticeIconUntil;

    public TrayContext()
    {
        _invoker.CreateControl();
        var header = new ToolStripMenuItem($"EasyPatch Agent {AgentComposition.AgentVersion}") { Enabled = false };
        header.Font = new Font(header.Font, FontStyle.Bold);
        _openStatusItem.Font = new Font(_openStatusItem.Font, FontStyle.Bold); // the default action (left click)
        _menu.Items.AddRange([header, _statusItem, _contactItem, _rebootItem, new ToolStripSeparator(), _openStatusItem, _restartItem]);
        _openStatusItem.Click += (_, _) => ShowStatus();
        _restartItem.Click += (_, _) => ShowPrompt(activate: true);

        _icon = new NotifyIcon { Icon = AppIcons.Small, Text = "EasyPatch Agent", ContextMenuStrip = _menu, Visible = false };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowStatus();
            }
        };
        _icon.BalloonTipClicked += (_, _) =>
        {
            if (_prompt is not null)
            {
                ShowPrompt(activate: true);
            }
            else
            {
                ShowStatus();
            }
        };

        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        UpdateMenu();

        _client = new TrayPipeClient(
            message => Post(() => Handle(message)),
            () => Post(ExitThread),
            () => Post(Refresh));
        _client.Start();
    }

    private void Post(Action action)
    {
        try
        {
            _invoker.BeginInvoke(action);
        }
        catch (InvalidOperationException)
        {
            // shutting down
        }
    }

    private void Handle(TrayMessage message)
    {
        switch (message.Type)
        {
            case TrayMessageType.Status when message.Status is { } status:
                _status = status;
                break;
            case TrayMessageType.Notice when message.Notice is { } notice:
                ShowNotice(notice);
                break;
            case TrayMessageType.Prompt:
                _prompt = message.Prompt;
                if (_prompt is null || _prompt.Kind == RestartPromptKind.Postponed)
                {
                    _form?.Hide();
                }
                else
                {
                    ShowPrompt(activate: false);
                }

                break;
            case TrayMessageType.RequestResult when message.Request is { } request && message.Result is { } result:
                _statusForm?.ShowRequestResult(request, result);
                break;
            case TrayMessageType.Log when message.Log is { } entries:
                _statusForm?.ShowLog(entries);
                break;
            case TrayMessageType.Exit:
                ExitThread();
                return;
        }

        Refresh();
    }

    private void ShowNotice(UserNotice notice)
    {
        var title = UserMessages.Title(notice.Preset);
        var body = UserMessages.Body(notice.Preset, notice.ScheduledAt is { } at ? TimeText.At(at) : null);
        _noticeIconUntil = DateTime.UtcNow.AddSeconds(30);
        _icon.Visible = true;
        _icon.ShowBalloonTip(15000, title, body, ToolTipIcon.Info);
    }

    private void ShowStatus()
    {
        if (_statusForm is null || _statusForm.IsDisposed)
        {
            _statusForm = new StatusForm();
            _statusForm.RequestClicked += kind => _client.Send(new TrayMessage
            {
                Type = kind == UserRequestKind.CheckIn ? TrayMessageType.CheckIn : TrayMessageType.CheckForUpdates,
            });
            _statusForm.LogRequested += () => _client.Send(new TrayMessage { Type = TrayMessageType.GetLog });
            _statusForm.RestartOptionsClicked += () => ShowPrompt(activate: true);
        }

        _statusForm.Display(_status, _prompt, _client.IsConnected);
        _statusForm.Open();
    }

    private void ShowPrompt(bool activate)
    {
        if (_prompt is null)
        {
            return;
        }

        if (_form is null || _form.IsDisposed)
        {
            _form = new RestartPromptForm();
            _form.RestartNowClicked += jobId => _client.Send(new TrayMessage { Type = TrayMessageType.RestartNow, JobId = jobId });
            _form.PostponeClicked += (jobId, minutes) => _client.Send(new TrayMessage { Type = TrayMessageType.Postpone, JobId = jobId, Minutes = minutes });
        }

        _form.Display(_prompt);
        if (!_form.Visible)
        {
            _form.Show();
        }

        if (activate)
        {
            _form.Activate();
        }
    }

    private void Refresh()
    {
        UpdateMenu();
        _icon.Visible = _status.ShowIcon || _prompt is not null || DateTime.UtcNow < _noticeIconUntil;

        // The tooltip: "EasyPatch Agent 1.5.0" and the current state (at most 127 characters).
        var summary = StatusSummary.From(_status, _prompt, _client.IsConnected);
        var tip = $"EasyPatch Agent {AgentComposition.AgentVersion}\n{summary.Title}";
        _icon.Text = tip.Length > 127 ? tip[..127] : tip;

        if (_statusForm is { IsDisposed: false, Visible: true })
        {
            _statusForm.Display(_status, _prompt, _client.IsConnected);
        }
    }

    private void UpdateMenu()
    {
        _statusItem.Text = $"Status: {_status.Activity}";
        _contactItem.Text = $"Last check-in: {TimeText.Ago(_status.LastContactAt)}";
        _rebootItem.Visible = _status.RebootPending;
        _restartItem.Visible = _prompt is not null;
    }

    protected override void ExitThreadCore()
    {
        _client.Dispose();
        _timer.Dispose();
        _icon.Visible = false;
        _icon.Dispose();
        _form?.Dispose();
        _statusForm?.Dispose();
        _menu.Dispose();
        _invoker.Dispose();
        base.ExitThreadCore();
    }
}

/// <summary>The connection to the service. Exits the tray when the service has been gone for a minute.</summary>
internal sealed class TrayPipeClient : IDisposable
{
    private static readonly TimeSpan GiveUpAfter = TimeSpan.FromMinutes(1);

    private readonly Action<TrayMessage> _onMessage;
    private readonly Action _onLost;
    private readonly Action _onConnectionChanged;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private volatile NamedPipeClientStream? _pipe;

    public TrayPipeClient(Action<TrayMessage> onMessage, Action onLost, Action onConnectionChanged)
    {
        _onMessage = onMessage;
        _onLost = onLost;
        _onConnectionChanged = onConnectionChanged;
    }

    /// <summary>True while connected to the service.</summary>
    public bool IsConnected => _pipe is not null;

    public void Start() => _ = Task.Run(RunAsync);

    public void Send(TrayMessage message) => _ = SendAsync(message);

    private async Task SendAsync(TrayMessage message)
    {
        var pipe = _pipe;
        if (pipe is null)
        {
            return;
        }

        await _writeLock.WaitAsync(_cts.Token);
        try
        {
            await TrayFrames.WriteAsync(pipe, message, _cts.Token);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task RunAsync()
    {
        var lostSince = DateTime.UtcNow;
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", TrayFrames.PipeName, TrayFrames.ClientAccess, PipeOptions.Asynchronous,
                    TokenImpersonationLevel.Identification, HandleInheritability.None);
                await pipe.ConnectAsync(5000, _cts.Token);
                if (!IsServiceSession(pipe))
                {
                    throw new IOException("The pipe is not served by a Windows service.");
                }

                _pipe = pipe;
                _onConnectionChanged();
                while (await TrayFrames.ReadAsync(pipe, TrayFrames.MaxFrameBytes, _cts.Token) is { } message)
                {
                    _onMessage(message);
                    if (message.Type == TrayMessageType.Exit)
                    {
                        return;
                    }
                }
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or InvalidDataException or UnauthorizedAccessException)
            {
            }
            finally
            {
                if (_pipe is not null)
                {
                    _pipe = null;
                    lostSince = DateTime.UtcNow;
                    _onConnectionChanged();
                }
            }

            if (DateTime.UtcNow - lostSince > GiveUpAfter)
            {
                _onLost();
                return;
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Only a process in session 0 (a service) may serve the tray; a user process cannot create one there.</summary>
    /// <remarks>The session comes from the pipe itself: a signed-in user cannot open the service's process to ask.</remarks>
    private static bool IsServiceSession(NamedPipeClientStream pipe) =>
        NativeMethods.GetNamedPipeServerSessionId(pipe.SafePipeHandle, out var sessionId) && sessionId == 0;

    public void Dispose()
    {
        _cts.Cancel();
        _pipe?.Dispose();
        _cts.Dispose();
    }
}

/// <summary>The restart request window (bottom-right, on top, never steals focus unless the user opens it).</summary>
internal sealed class RestartPromptForm : Form
{
    private readonly Label _heading = new() { AutoSize = true, MaximumSize = new Size(360, 0) };
    private readonly Label _body = new() { AutoSize = true, MaximumSize = new Size(360, 0), Margin = new Padding(3, 8, 3, 3) };
    private readonly Label _when = new() { AutoSize = true, MaximumSize = new Size(360, 0), Margin = new Padding(3, 8, 3, 3) };
    private readonly Button _restartNow = new() { Text = "Restart now", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
    private readonly Button _postpone = new() { Text = "Postpone ▾", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
    private readonly ContextMenuStrip _postponeMenu = new();
    private readonly System.Windows.Forms.Timer _countdown = new() { Interval = 1000 };
    private RestartPrompt? _prompt;

    public RestartPromptForm()
    {
        Text = "EasyPatch";
        Icon = AppIcons.Large;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.Manual;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = SystemFonts.MessageBoxFont ?? Font;
        Padding = new Padding(12);
        _heading.Font = new Font(Font.FontFamily, Font.Size + 3, FontStyle.Bold);

        var picture = new PictureBox { Image = AppIcons.Large.ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(48, 48), Margin = new Padding(3, 3, 12, 3) };
        var text = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        text.Controls.AddRange([_heading, _body, _when]);
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
        buttons.Controls.AddRange([_restartNow, _postpone]);

        var layout = new TableLayoutPanel { ColumnCount = 2, RowCount = 2, AutoSize = true };
        layout.Controls.Add(picture, 0, 0);
        layout.Controls.Add(text, 1, 0);
        layout.Controls.Add(buttons, 0, 1);
        layout.SetColumnSpan(buttons, 2);
        Controls.Add(layout);

        AcceptButton = _restartNow;
        _restartNow.Click += (_, _) => ConfirmRestart();
        _postpone.Click += (_, _) => _postponeMenu.Show(_postpone, new Point(0, _postpone.Height));
        _countdown.Tick += (_, _) => UpdateWhen();
    }

    public event Action<Guid>? RestartNowClicked;

    public event Action<Guid, int>? PostponeClicked;

    protected override bool ShowWithoutActivation => true;

    public void Display(RestartPrompt prompt)
    {
        _prompt = prompt;
        if (prompt.Kind == RestartPromptKind.Countdown)
        {
            _heading.Text = "Your computer will restart soon";
            _body.Text = "Save your work now. Open applications will be closed when the computer restarts.";
        }
        else
        {
            _heading.Text = "Restart required";
            _body.Text = "Your IT team needs to restart this computer. Save your work, then restart now or choose a later time.";
        }

        _postponeMenu.Items.Clear();
        foreach (var minutes in prompt.PostponeOptions)
        {
            var item = new ToolStripMenuItem(minutes switch
            {
                < 120 => $"{minutes / 60} hour",
                < 1440 => $"{minutes / 60} hours",
                _ => $"{minutes / 1440} day" + (minutes >= 2880 ? "s" : string.Empty),
            });
            var chosen = minutes;
            item.Click += (_, _) =>
            {
                PostponeClicked?.Invoke(prompt.JobId, chosen);
                Hide();
            };
            _postponeMenu.Items.Add(item);
        }

        _postpone.Visible = prompt.Kind == RestartPromptKind.Prompt && prompt.PostponeOptions.Count > 0;
        _countdown.Enabled = prompt.Kind == RestartPromptKind.Countdown;
        UpdateWhen();
        PerformLayout();
        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1024, 768);
        Location = new Point(area.Right - Width - 16, area.Bottom - Height - 16);
    }

    private void UpdateWhen()
    {
        if (_prompt is null)
        {
            return;
        }

        if (_prompt.Kind == RestartPromptKind.Countdown && _prompt.RestartAt is { } at)
        {
            var left = at - DateTimeOffset.UtcNow;
            _when.Text = left > TimeSpan.Zero ? $"Restarting in {TimeText.Countdown(left)}." : "Restarting…";
        }
        else if (_prompt.Deadline is { } deadline)
        {
            _when.Text = $"If you do not restart, the computer restarts automatically at {TimeText.At(deadline)}.";
        }
        else
        {
            _when.Text = string.Empty;
        }

        _when.Visible = _when.Text.Length > 0;
    }

    private void ConfirmRestart()
    {
        if (_prompt is null)
        {
            return;
        }

        var answer = MessageBox.Show(this, "Restart now? Open applications will be closed, so save your work first.", "EasyPatch",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (answer == DialogResult.Yes)
        {
            RestartNowClicked?.Invoke(_prompt.JobId);
            Hide();
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true; // closing only hides it; the tray menu and the next reminder bring it back
            Hide();
        }

        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _countdown.Dispose();
            _postponeMenu.Dispose();
        }

        base.Dispose(disposing);
    }
}

internal static class AppIcons
{
    private static readonly Lazy<Icon> LargeIcon = new(() => Load(new Size(48, 48)));
    private static readonly Lazy<Icon> SmallIcon = new(() => Load(SystemInformation.SmallIconSize));

    public static Icon Large => LargeIcon.Value;

    public static Icon Small => SmallIcon.Value;

    private static Icon Load(Size size)
    {
        using var stream = typeof(AppIcons).Assembly.GetManifestResourceStream("EasyPatch.ico");
        return stream is null ? SystemIcons.Application : new Icon(stream, size);
    }
}

/// <summary>Times in the user's local time zone, with the user's short time format (the agent itself is culture-invariant).</summary>
internal static class TimeText
{
    private static readonly Lazy<string> ShortTime = new(ReadShortTimePattern);

    /// <summary>"3:30 PM", "3:30 PM tomorrow", "3:30 PM on Friday" or "3:30 PM on 21 November".</summary>
    public static string At(DateTimeOffset at)
    {
        var local = at.ToLocalTime().DateTime;
        var today = DateTime.Today;
        var time = local.ToString(ShortTime.Value, CultureInfo.InvariantCulture);
        return local.Date == today ? time
            : local.Date == today.AddDays(1) ? $"{time} tomorrow"
            : local.Date < today.AddDays(7) ? $"{time} on {local.ToString("dddd", CultureInfo.InvariantCulture)}"
            : $"{time} on {local.ToString("d MMMM", CultureInfo.InvariantCulture)}";
    }

    public static string Ago(DateTimeOffset? at)
    {
        if (at is not { } value)
        {
            return "not yet";
        }

        var elapsed = DateTimeOffset.UtcNow - value;
        return elapsed.TotalMinutes switch
        {
            < 1 => "just now",
            < 2 => "1 minute ago",
            < 60 => $"{(int)elapsed.TotalMinutes} minutes ago",
            < 120 => "1 hour ago",
            < 1440 => $"{(int)elapsed.TotalHours} hours ago",
            _ => At(value),
        };
    }

    public static string Countdown(TimeSpan left) => left.TotalHours >= 1
        ? $"{(int)left.TotalHours}:{left.Minutes:00}:{left.Seconds:00}"
        : $"{left.Minutes}:{left.Seconds:00}";

    private static string ReadShortTimePattern()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Control Panel\International");
            if (key?.GetValue("sShortTime") is string pattern && pattern.Length is > 0 and <= 16 &&
                pattern.All(c => "hHmst :.".Contains(c, StringComparison.Ordinal)))
            {
                return pattern;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }

        return "HH:mm";
    }
}
