using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Ipc;
using EasyPatch.Agent.Core.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Platform;

/// <summary>Interactive sessions with a signed-in user (console and Remote Desktop, connected or disconnected).</summary>
internal static class WindowsUserSessions
{
    public sealed record SessionInfo(int SessionId, bool Active);

    private static readonly Lock CacheLock = new();
    private static (long At, IReadOnlyList<SessionInfo> Sessions) _cache = (0, []);

    /// <summary>Signed-in sessions (cached for two seconds). Session 0 (services) is never included.</summary>
    public static IReadOnlyList<SessionInfo> SignedIn()
    {
        lock (CacheLock)
        {
            if (_cache.At != 0 && Stopwatch.GetElapsedTime(_cache.At) < TimeSpan.FromSeconds(2))
            {
                return _cache.Sessions;
            }

            _cache = (Stopwatch.GetTimestamp(), Enumerate());
            return _cache.Sessions;
        }
    }

    private static List<SessionInfo> Enumerate()
    {
        if (!NativeMethods.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not enumerate user sessions.");
        }

        var result = new List<SessionInfo>();
        try
        {
            var size = Marshal.SizeOf<NativeMethods.WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<NativeMethods.WtsSessionInfo>(buffer + (i * size));
                if (info.SessionId == 0 || info.State is not (NativeMethods.WtsActive or NativeMethods.WtsDisconnected))
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(UserName(info.SessionId)))
                {
                    result.Add(new SessionInfo(info.SessionId, info.State == NativeMethods.WtsActive));
                }
            }
        }
        finally
        {
            NativeMethods.WTSFreeMemory(buffer);
        }

        return result;
    }

    private static string? UserName(int sessionId)
    {
        if (!NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, NativeMethods.WtsUserName, out var buffer, out _))
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            NativeMethods.WTSFreeMemory(buffer);
        }
    }
}

/// <summary>
/// Starts the EasyPatch tray (<c>EasyPatch.Agent.exe tray</c>) in every active session that does not have one
/// connected. The tray runs as the signed-in user with the user's own token; it is never started with the service's
/// privileges, and no Run key or scheduled task is used.
/// </summary>
internal sealed class TrayLauncher : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan RelaunchDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan WarningInterval = TimeSpan.FromHours(6);

    private readonly TrayBroker _broker;
    private readonly ILogger<TrayLauncher> _logger;
    private readonly Dictionary<int, DateTime> _lastLaunch = [];

    /// <summary>Sessions where a tray was started and has not connected since.</summary>
    private readonly HashSet<int> _awaitingConnection = [];
    private readonly Dictionary<int, DateTime> _lastWarning = [];

    public TrayLauncher(TrayBroker broker, ILogger<TrayLauncher> logger)
    {
        _broker = broker;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Give the pipe server a moment to start listening.
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                LaunchMissing();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not start the EasyPatch tray in user sessions.");
            }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private void LaunchMissing()
    {
        if (_broker.TraysSuspended)
        {
            return; // an agent update is replacing the executable
        }

        var connected = _broker.ConnectedSessions;
        var signedIn = WindowsUserSessions.SignedIn();
        var signedInIds = signedIn.Select(s => s.SessionId).ToHashSet();
        _awaitingConnection.RemoveWhere(id => connected.Contains(id) || !signedInIds.Contains(id));
        foreach (var gone in _lastLaunch.Keys.Where(id => !signedInIds.Contains(id)).ToList())
        {
            _lastLaunch.Remove(gone);
            _lastWarning.Remove(gone);
        }

        var now = DateTime.UtcNow;
        foreach (var session in signedIn.Where(s => s.Active && !connected.Contains(s.SessionId)))
        {
            if (_lastLaunch.TryGetValue(session.SessionId, out var last) && now - last < RelaunchDelay)
            {
                continue;
            }

            var retry = _awaitingConnection.Contains(session.SessionId);
            if (retry && (!_lastWarning.TryGetValue(session.SessionId, out var warned) || now - warned > WarningInterval))
            {
                _lastWarning[session.SessionId] = now;
                _logger.LogWarning(
                    "The EasyPatch tray started in session {SessionId} did not connect to the service; starting it again every {Minutes} minutes. Messages and restart prompts cannot reach this session until it connects.",
                    session.SessionId, RelaunchDelay.TotalMinutes);
            }

            _lastLaunch[session.SessionId] = now;
            if (Launch(session.SessionId, retry))
            {
                _awaitingConnection.Add(session.SessionId);
            }
        }
    }

    private bool Launch(int sessionId, bool retry)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Unknown executable path.");
        if (!NativeMethods.WTSQueryUserToken(sessionId, out var token))
        {
            _logger.LogDebug("No user token for session {SessionId} (error {Error}).", sessionId, Marshal.GetLastPInvokeError());
            return false;
        }

        var environment = IntPtr.Zero;
        var commandLine = Marshal.StringToHGlobalUni($"\"{exe}\" tray");
        var desktop = Marshal.StringToHGlobalUni(@"winsta0\default");
        try
        {
            if (!NativeMethods.CreateEnvironmentBlock(out environment, token, false))
            {
                environment = IntPtr.Zero;
            }

            var startup = new NativeMethods.StartupInfo { Cb = Marshal.SizeOf<NativeMethods.StartupInfo>(), Desktop = desktop };
            if (!NativeMethods.CreateProcessAsUser(token, exe, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    NativeMethods.CreateUnicodeEnvironment | NativeMethods.CreateNoWindow, environment, Path.GetDirectoryName(exe),
                    ref startup, out var process))
            {
                _logger.LogWarning("Could not start the tray in session {SessionId} (error {Error}).", sessionId, Marshal.GetLastPInvokeError());
                return false;
            }

            NativeMethods.CloseHandle(process.Thread);
            NativeMethods.CloseHandle(process.Process);
            _logger.Log(retry ? LogLevel.Debug : LogLevel.Information, "Started the EasyPatch tray in session {SessionId}.", sessionId);
            return true;
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                NativeMethods.DestroyEnvironmentBlock(environment);
            }

            Marshal.FreeHGlobal(commandLine);
            Marshal.FreeHGlobal(desktop);
            NativeMethods.CloseHandle(token);
        }
    }
}

/// <summary>Creates the broker that serves the trays, counting the signed-in sessions with WTS.</summary>
internal static class TrayBrokerFactory
{
    /// <param name="logDirectory">The agent log, shown (first lines, redacted) in the status window.</param>
    public static TrayBroker Create(ILoggerFactory loggerFactory, string logDirectory) =>
        new(() => WindowsUserSessions.SignedIn().Select(s => s.SessionId).ToList(), loggerFactory.CreateLogger<TrayBroker>(),
            () => AgentLogTail.Read(logDirectory));
}

/// <summary>Restarts Windows with InitiateShutdown (planned, operating system: hotfix).</summary>
/// <remarks>SHUTDOWN_FORCE_OTHERS is required: the service is not in the users' sessions, and without it Windows refuses
/// to restart while anyone is signed in.</remarks>
internal sealed class WindowsSystemRestart : ISystemRestart
{
    public void Restart(TimeSpan gracePeriod, string message)
    {
        NativeMethods.EnablePrivilege("SeShutdownPrivilege");
        var flags = NativeMethods.ShutdownRestart | NativeMethods.ShutdownForceOthers;
        var seconds = (int)Math.Clamp(gracePeriod.TotalSeconds, 0, TimeSpan.FromHours(2).TotalSeconds);
        var result = NativeMethods.InitiateShutdown(null, seconds > 0 ? message : null, seconds, flags, NativeMethods.ShutdownReasonPlannedHotfix);
        if (result is not (0 or NativeMethods.ErrorShutdownInProgress))
        {
            throw new Win32Exception(result);
        }
    }

    public bool TryAbort()
    {
        try
        {
            NativeMethods.EnablePrivilege("SeShutdownPrivilege");
            return NativeMethods.AbortSystemShutdown(null);
        }
        catch (Win32Exception)
        {
            return false;
        }
    }
}
