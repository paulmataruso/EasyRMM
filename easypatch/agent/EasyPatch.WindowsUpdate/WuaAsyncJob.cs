using System.Runtime.InteropServices;
using EasyPatch.Contracts.Updates;
using Microsoft.Extensions.Logging;

namespace EasyPatch.WindowsUpdate;

/// <summary>
/// Runs a Windows Update download or installation as an asynchronous WUA job (IUpdateDownloader.BeginDownload /
/// IUpdateInstaller.BeginInstall) so its percentage can be read while it runs. The result comes from EndDownload /
/// EndInstall, exactly as the synchronous call would return it. When WUA does not accept the job (the Begin call fails,
/// so nothing was started), the synchronous Download / Install runs instead and no percentages are reported.
/// </summary>
internal static class WuaAsyncJob
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    /// <summary>Consecutive failed reads of IsCompleted before the wait is left to EndDownload / EndInstall.</summary>
    private const int MaxUnreadableChecks = 30;

    private static int s_fallbackLogged;

    /// <param name="owner">The IUpdateDownloader or IUpdateInstaller, with its Updates set.</param>
    /// <param name="operation">"Download" or "Install".</param>
    /// <param name="abortOnCancel">Request WUA to abort when <paramref name="cancellationToken"/> fires (downloads only:
    /// an installation is never interrupted).</param>
    /// <returns>The IDownloadResult or IInstallationResult.</returns>
    public static object Run(object owner, string operation, IProgress<int>? progress, bool abortOnCancel, ILogger logger,
        CancellationToken cancellationToken)
    {
        if (progress is null)
        {
            return Com.Invoke(owner, operation)!;
        }

        var callbacks = new WuaJobCallbacks();
        object job;
        try
        {
            job = Com.Invoke(owner, "Begin" + operation, new UnknownWrapper(callbacks), new UnknownWrapper(callbacks), null!)
                  ?? throw new COMException($"Begin{operation} returned no job.");
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or ArgumentException or MissingMemberException
                                       or NotSupportedException or InvalidOperationException)
        {
            if (Interlocked.Exchange(ref s_fallbackLogged, 1) == 0)
            {
                logger.LogWarning("Windows Update did not start an asynchronous {Operation} ({Error}); updates are downloaded and installed without progress percentages.",
                    operation.ToLowerInvariant(), ex is COMException com ? WindowsUpdateErrors.Format(com.HResult) : ex.GetType().Name);
            }

            return Com.Invoke(owner, operation)!;
        }

        try
        {
            var lastPercent = -1;
            var unreadable = 0;
            var abortRequested = false;
            while (!callbacks.IsCompleted)
            {
                var completed = TryGetCompleted(job);
                if (completed == true)
                {
                    break;
                }

                if (completed is null && ++unreadable >= MaxUnreadableChecks)
                {
                    logger.LogDebug("The Windows Update {Operation} job state cannot be read; waiting for its result.", operation.ToLowerInvariant());
                    break;
                }

                if (completed is not null)
                {
                    unreadable = 0;
                }

                if (abortOnCancel && !abortRequested && cancellationToken.IsCancellationRequested)
                {
                    abortRequested = true;
                    TryInvoke(job, "RequestAbort", logger);
                }

                ReportPercent(job, progress, ref lastPercent, logger);
                Thread.Sleep(PollInterval);
            }

            return Com.Invoke(owner, "End" + operation, job)!;
        }
        finally
        {
            TryInvoke(job, "CleanUp", logger); // releases WUA's references to the callbacks
            Com.Release(job);
            GC.KeepAlive(callbacks);
        }
    }

    private static bool? TryGetCompleted(object job)
    {
        try
        {
            return Com.Get(job, "IsCompleted") is bool done ? done : null;
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or MissingMemberException or InvalidComObjectException)
        {
            return null;
        }
    }

    private static void ReportPercent(object job, IProgress<int> progress, ref int lastPercent, ILogger logger)
    {
        object? state = null;
        int? percent;
        try
        {
            state = Com.Invoke(job, "GetProgress");
            percent = state is null ? null : Com.TryGetInt(state, "CurrentUpdatePercentComplete") ?? Com.TryGetInt(state, "PercentComplete");
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or MissingMemberException or InvalidComObjectException)
        {
            return;
        }
        finally
        {
            Com.Release(state);
        }

        if (percent is not { } value || value == lastPercent)
        {
            return;
        }

        lastPercent = value;
        try
        {
            progress.Report(Math.Clamp(value, 0, 100));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Reporting must never stop the wait: the job keeps running in Windows Update either way.
            logger.LogDebug(ex, "Could not report Windows Update progress.");
        }
    }

    private static void TryInvoke(object job, string method, ILogger logger)
    {
        try
        {
            Com.Invoke(job, method);
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or MissingMemberException or InvalidComObjectException)
        {
            logger.LogDebug("Windows Update job {Method} failed: {Error}", method, ex.Message);
        }
    }
}

// The WUA job callbacks (wuapi.h). WUA requires them for BeginDownload / BeginInstall and calls them on its own threads;
// they only record completion. The progress itself is read from the job. The arguments are not used, so they stay raw
// pointers (no runtime callable wrappers, nothing to release).

/// <summary>IDownloadProgressChangedCallback.</summary>
[ComImport]
[Guid("8C3F1CDD-6173-4591-AEBD-A56A53CA77C1")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IWuaDownloadProgressChangedCallback
{
    void Invoke(IntPtr downloadJob, IntPtr callbackArgs);
}

/// <summary>IDownloadCompletedCallback.</summary>
[ComImport]
[Guid("77254866-9F5B-4C8E-B9E2-C77A8530D64B")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IWuaDownloadCompletedCallback
{
    void Invoke(IntPtr downloadJob, IntPtr callbackArgs);
}

/// <summary>IInstallationProgressChangedCallback.</summary>
[ComImport]
[Guid("E01402D5-F8DA-43BA-A012-38894BD048F1")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IWuaInstallationProgressChangedCallback
{
    void Invoke(IntPtr installationJob, IntPtr callbackArgs);
}

/// <summary>IInstallationCompletedCallback.</summary>
[ComImport]
[Guid("45F4F6F3-D602-4F98-9A8A-3EFA152AD2D3")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IWuaInstallationCompletedCallback
{
    void Invoke(IntPtr installationJob, IntPtr callbackArgs);
}

/// <summary>Callbacks for one WUA job (exposed to WUA as a COM callable wrapper).</summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class WuaJobCallbacks :
    IWuaDownloadProgressChangedCallback,
    IWuaDownloadCompletedCallback,
    IWuaInstallationProgressChangedCallback,
    IWuaInstallationCompletedCallback
{
    private volatile bool _completed;

    public bool IsCompleted => _completed;

    void IWuaDownloadProgressChangedCallback.Invoke(IntPtr downloadJob, IntPtr callbackArgs)
    {
    }

    void IWuaDownloadCompletedCallback.Invoke(IntPtr downloadJob, IntPtr callbackArgs) => _completed = true;

    void IWuaInstallationProgressChangedCallback.Invoke(IntPtr installationJob, IntPtr callbackArgs)
    {
    }

    void IWuaInstallationCompletedCallback.Invoke(IntPtr installationJob, IntPtr callbackArgs) => _completed = true;
}
