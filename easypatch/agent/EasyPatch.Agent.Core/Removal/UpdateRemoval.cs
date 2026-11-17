using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Core.Removal;

public enum UpdateRemovalStatus
{
    /// <summary>The update was removed, or Windows has queued its removal for the next restart.</summary>
    Removed,

    /// <summary>The update is not installed (nothing to remove).</summary>
    NotInstalled,

    /// <summary>Windows does not allow this update to be removed.</summary>
    NotRemovable,

    Failed,
}

/// <param name="Method">How the removal was attempted ("Windows Update" or "DISM"), for messages.</param>
public sealed record UpdateRemovalResult(UpdateRemovalStatus Status, string Message, bool RebootRequired = false, string? ErrorCode = null,
    string? Method = null);

/// <summary>Removes one installed update for an administrator's uninstall-update job. Implementations never restart the
/// computer and report <see cref="UpdateRemovalStatus.Removed"/> only when Windows confirms the removal.</summary>
public interface IUpdateRemover
{
    Task<UpdateRemovalResult> RemoveAsync(UninstallUpdatePayload update, CancellationToken cancellationToken);
}

public enum WuaUninstallStatus
{
    /// <summary>Windows Update does not list the update as installed.</summary>
    NotInstalled,

    /// <summary>Installed, but Windows Update cannot uninstall it (most cumulative updates).</summary>
    NotUninstallable,

    /// <summary>Windows Update ran its uninstall; see the result.</summary>
    Attempted,
}

public sealed record WuaUninstallResult(WuaUninstallStatus Status, UpdateOperationResult? Result = null);

/// <summary>Windows Update's own uninstall (IUpdateInstaller.Uninstall) for updates that support it.</summary>
public interface IWindowsUpdateUninstaller
{
    Task<WuaUninstallResult> UninstallAsync(Guid updateGuid, CancellationToken cancellationToken);
}

/// <summary>Output of one <c>dism.exe</c> run.</summary>
public sealed record DismResult(int ExitCode, string Output);

/// <summary>Runs Windows' own <c>dism.exe</c> with an argument vector (never through a shell).</summary>
public interface IDismRunner
{
    /// <summary>Where DISM writes its log (passed as <c>/LogPath:</c>).</summary>
    string LogPath { get; }

    /// <exception cref="DismException">DISM could not be started or did not finish within <paramref name="timeout"/>.</exception>
    Task<DismResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

public sealed class DismException : Exception
{
    public DismException()
    {
    }

    public DismException(string message)
        : base(message)
    {
    }

    public DismException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
