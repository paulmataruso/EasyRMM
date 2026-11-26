using System.Diagnostics;

namespace EasyPatch.Agent.Core.Defender;

/// <summary>
/// The folders the EasyPatch agent works out of on Windows (ADR-0070, section 1), under its protected data folder, which is excluded from
/// Defender once it is locked down and verified. Processes the agent starts, and the extraction of its own single file, are pointed here
/// rather than at <c>%TEMP%</c>, which ordinary users can write.
/// </summary>
public static class AgentFolders
{
    /// <summary>The name of the Windows install folder, under Program Files.</summary>
    public const string InstallFolderName = "EasyPatch Agent";

    /// <summary>The name of the agent's program.</summary>
    public const string ProgramName = "EasyPatch.Agent.exe";

    /// <summary>The variable that moves .NET's single-file extraction.</summary>
    public const string BundleExtractVariable = "DOTNET_BUNDLE_EXTRACT_BASE_DIR";

    /// <summary>The extraction folder of the service. Each .NET service or command gets its own, never shared, so one process cannot
    /// plant a library another loads.</summary>
    public const string ServiceBundle = "EasyPatchAgent";

    /// <summary>The extraction folder of the <c>unenroll</c> command that the installer runs on removal.</summary>
    public const string UnenrollBundle = "unenroll";

    /// <summary>The extraction folder of the <c>defender</c> command that the installer runs.</summary>
    public const string DefenderBundle = "defender";

    /// <summary>Every extraction folder the installer creates, locked down with the data folder.</summary>
    public static readonly IReadOnlyList<string> BundleNames = [ServiceBundle, UnenrollBundle, DefenderBundle];

    /// <summary>Where the processes the agent starts (winget, msiexec) keep their temporary files and their working directory.</summary>
    public static string WorkDirectory(string dataDirectory) => Path.Combine(dataDirectory, "work");

    /// <summary>The extraction folder of one .NET service or command.</summary>
    public static string BundleDirectory(string dataDirectory, string name) => Path.Combine(dataDirectory, "bundle", name);

    /// <summary>The program's install folder, fixed from the system's Program Files folder.</summary>
    public static string InstallDirectory(string programFiles) => Path.Combine(programFiles, InstallFolderName);

    /// <summary>The record of what the agent added to Defender.</summary>
    public static string RecordFile(string dataDirectory) => Path.Combine(dataDirectory, "state", DefenderRecord.FileName);

    /// <summary>Points a process the agent starts at the work folder: its working directory, <c>TEMP</c> and <c>TMP</c>.</summary>
    public static void UseWorkDirectory(ProcessStartInfo info, string dataDirectory)
    {
        ArgumentNullException.ThrowIfNull(info);
        var work = WorkDirectory(dataDirectory);
        Directory.CreateDirectory(work);
        info.WorkingDirectory = work;
        info.Environment["TEMP"] = work;
        info.Environment["TMP"] = work;
    }

    /// <summary>Points a process the agent starts at the work folder for <c>TEMP</c> and <c>TMP</c> only (msiexec runs from the system folder).</summary>
    public static void UseWorkAsTemp(ProcessStartInfo info, string dataDirectory)
    {
        ArgumentNullException.ThrowIfNull(info);
        var work = WorkDirectory(dataDirectory);
        Directory.CreateDirectory(work);
        info.Environment["TEMP"] = work;
        info.Environment["TMP"] = work;
    }
}
