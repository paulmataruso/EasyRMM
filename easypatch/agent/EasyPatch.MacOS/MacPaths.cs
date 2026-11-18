namespace EasyPatch.MacOS;

/// <summary>Where the macOS agent package installs things (see agent/Installer/macos). None of these paths contain spaces.</summary>
public static class MacPaths
{
    /// <summary>Program directory (root:wheel 0755), from the package.</summary>
    public const string ProgramDirectory = "/Library/EasyPatch";

    public const string Executable = "/Library/EasyPatch/easypatch-agent";

    /// <summary>Removes the agent; from the package.</summary>
    public const string UninstallScript = "/Library/EasyPatch/uninstall.sh";

    /// <summary>Settings (root-only, 0600), written by the install script or <c>easypatch-agent enroll</c>; not in the package.</summary>
    public const string ConfigPath = "/Library/EasyPatch/agent.conf";

    /// <summary>Identity, state, logs and downloads (root-only, 0700), created by the agent; not in the package.</summary>
    public const string DataDirectory = "/Library/EasyPatch/data";

    /// <summary>launchd label of the agent daemon, and the package identifier.</summary>
    public const string DaemonLabel = "com.dhitechnical.easypatch.agent";

    public const string DaemonPlist = "/Library/LaunchDaemons/com.dhitechnical.easypatch.agent.plist";

    /// <summary>One-shot launchd job that installs an agent update package.</summary>
    public const string UpdateJobLabel = "com.dhitechnical.easypatch.agent-update";

    /// <summary>One-shot launchd job that runs the uninstall script.</summary>
    public const string UninstallJobLabel = "com.dhitechnical.easypatch.agent-uninstall";

    /// <summary>The oldest macOS release the agent runs on.</summary>
    public const int MinimumMajorVersion = 14;
}
