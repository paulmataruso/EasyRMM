namespace EasyPatch.Contracts.Agent;

/// <summary>One file of the pinned winget release (size in bytes, lowercase hex SHA-256).</summary>
public sealed record WingetFile(string Name, long Size, string Sha256);

/// <summary>
/// The winget (App Installer) release that Windows agents install for all users when a computer has no usable winget.
/// It is pinned to one release of Microsoft's <c>microsoft/winget-cli</c> repository. The agent downloads the files from
/// that GitHub release, or from the EasyPatch server (which keeps a copy of the same files) when GitHub cannot be
/// reached, and installs them only when every file's size and SHA-256 match the values here. Windows checks Microsoft's
/// package signatures again when it installs them.
/// </summary>
public static class WingetDistribution
{
    /// <summary>winget-cli release v1.29.380 (published 2026-09-21).</summary>
    public const string Version = "1.29.380";

    public const string Bundle = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle";

    /// <summary>VCLibs and Windows App Runtime packages, in one folder per architecture (x64, arm64, x86).</summary>
    public const string Dependencies = "DesktopAppInstaller_Dependencies.zip";

    public const string License = "e53e159d00e04f729cc2180cffd1c02e_License1.xml";

    /// <summary>Where GitHub serves the release's files (followed by the file name).</summary>
    public const string ReleaseUrl = "https://github.com/microsoft/winget-cli/releases/download/v" + Version + "/";

    /// <summary>Where the EasyPatch server serves its copy (relative to the server URL, followed by the file name).</summary>
    public const string ServerRoute = "downloads/winget/";

    /// <summary>Windows 10 version 1809 / Windows Server 2019 and later (build 17763).</summary>
    public const int MinimumWindowsBuild = 17763;

    public static IReadOnlyList<WingetFile> Files { get; } =
    [
        new(Bundle, 217_276_577, "65dea9c01ce08ee7b763366b27c0e651f97db857c11ca9b9c301826c10092f2e"),
        new(Dependencies, 97_760_717, "ba875afe9d190f61218985ac0292a99d1db710bf93e13c68944ca9d89f0d82d1"),
        new(License, 2_686, "bcb15118ec47df24e3e6013a7006147c3a15b3a8104ed660fe87c8b4ed01f485"),
    ];
}

/// <summary>The computer's machine-wide winget, as the Windows agent last found it (agent 1.7.0 and later).</summary>
public sealed record WingetStatusReport
{
    /// <summary>The version of the machine-wide winget, or null when there is none (or it could not be run).</summary>
    public string? Version { get; init; }

    /// <summary>The agent installed it (the pinned <see cref="WingetDistribution.Version"/>).</summary>
    public bool InstalledByAgent { get; init; }

    /// <summary>Why the agent could not install winget at its last attempt; null when winget is ready.</summary>
    public string? SetupError { get; init; }

    public DateTimeOffset? CheckedAt { get; init; }
}
