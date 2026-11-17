using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using EasyPatch.Agent.Core.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// The local pipe the trays connect to (<c>\\.\pipe\EasyPatchAgent</c>).
/// <list type="bullet">
/// <item>Created with FirstPipeInstance: if another process already owns the name, the service refuses to serve.</item>
/// <item>ACL: SYSTEM and Administrators full control; interactive users read/write (<see cref="TrayFrames.InteractiveUserAccess"/>:
/// they cannot create instances of the pipe); network logons denied.</item>
/// <item>The caller's session comes from <c>GetNamedPipeClientSessionId</c>, never from the tray; session 0 is refused.</item>
/// </list>
/// </summary>
internal sealed class TrayPipeServer : BackgroundService
{
    private const int MaxInstances = 64;

    private readonly TrayBroker _broker;
    private readonly ILogger<TrayPipeServer> _logger;

    public TrayPipeServer(TrayBroker broker, ILogger<TrayPipeServer> logger)
    {
        _broker = broker;
        _logger = logger;
    }

    public static PipeSecurity CreateSecurity()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), TrayFrames.InteractiveUserAccess, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return security;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var security = CreateSecurity();
        var first = true;
        var clients = new List<Task>();

        // Connections outlive stoppingToken briefly, so every tray receives the Exit message and closes before the
        // service stops: otherwise trays would keep EasyPatch.Agent.exe in use during an MSI upgrade or uninstall.
        using var connections = new CancellationTokenSource();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                NamedPipeServerStream pipe;
                try
                {
                    pipe = NamedPipeServerStreamAcl.Create(TrayFrames.PipeName, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None), 4096, 4096, security);
                }
                catch (UnauthorizedAccessException) when (first)
                {
                    _logger.LogError("Another process owns the EasyPatch tray pipe name; the tray is disabled until the service restarts.");
                    return;
                }
                catch (IOException ex)
                {
                    _logger.LogWarning("Could not create a tray pipe instance: {Message}", ex.Message);
                    await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                    continue;
                }

                first = false;
                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken);
                }
                catch
                {
                    await pipe.DisposeAsync();
                    throw;
                }

                if (!NativeMethods.GetNamedPipeClientSessionId(pipe.SafePipeHandle, out var sessionId) || sessionId == 0)
                {
                    _logger.LogWarning("Refused a tray connection without a user session ({Error}).",
                        sessionId == 0 ? "session 0" : new Win32Exception(Marshal.GetLastPInvokeError()).Message);
                    await pipe.DisposeAsync();
                    continue;
                }

                clients.RemoveAll(t => t.IsCompleted);
                clients.Add(ServeAsync(pipe, (int)sessionId, connections.Token));
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            _broker.DisconnectAll();
            await Task.WhenAny(Task.WhenAll(clients), Task.Delay(TimeSpan.FromSeconds(3), CancellationToken.None));
            await connections.CancelAsync();
            await Task.WhenAny(Task.WhenAll(clients), Task.Delay(TimeSpan.FromSeconds(1), CancellationToken.None));
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, int sessionId, CancellationToken stoppingToken)
    {
        await using (pipe)
        {
            try
            {
                await _broker.ServeAsync(pipe, sessionId, stoppingToken);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
            }
        }
    }
}
