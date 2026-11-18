namespace EasyPatch.Agent.Core;

public sealed record AgentRuntimeOptions
{
    /// <summary>Root data directory (C:\ProgramData\EasyPatch on Windows).</summary>
    public required string DataDirectory { get; init; }

    public required string AgentVersion { get; init; }

    /// <summary>Package architecture of this build (<c>x64</c> or <c>arm64</c>); agent updates install the same one.</summary>
    public string? PackageArchitecture { get; init; }

    /// <summary>PEM text with the release public key(s) built into the agent. Agent updates are installed only when
    /// their release signature verifies against one of them; without any, the agent cannot update itself.</summary>
    public string? ReleasePublicKeys { get; init; }

    /// <summary>
    /// Reject non-HTTPS server URLs. Production always leaves this on; only in-process tests (TestServer) turn it off.
    /// This never affects TLS certificate validation, which cannot be disabled.
    /// </summary>
    public bool RequireHttps { get; init; } = true;

    public int MaxOutboxItems { get; init; } = 500;

    public long MaxOutboxBytes { get; init; } = 256L * 1024 * 1024;

    public int MaxHistoryEntriesPerSync { get; init; } = 500;

    /// <summary>A job that has been started this many times without finishing is failed (crash-loop protection).</summary>
    public int MaxJobAttempts { get; init; } = 3;

    /// <summary>Jobs parked waiting for a restart are failed after this long.</summary>
    public TimeSpan WaitingForRebootMaxAge { get; init; } = TimeSpan.FromDays(30);

    /// <summary>A change in boot time larger than this means the computer restarted.</summary>
    public TimeSpan BootTimeTolerance { get; init; } = TimeSpan.FromMinutes(2);

    public TimeSpan WorkLoopInterval { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan NotConfiguredRetryInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Retry interval while the credential is revoked / enrollment was rejected.</summary>
    public TimeSpan RevokedRetryInterval { get; init; } = TimeSpan.FromHours(1);

    public TimeSpan BackoffBase { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How often an agent update checks whether Windows Installer is still busy.</summary>
    public TimeSpan InstallerPollInterval { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan BackoffMax { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Delay between pending-approval status polls (before jitter).</summary>
    public TimeSpan PendingApprovalPollInterval { get; init; } = TimeSpan.FromSeconds(60);

    public string LogDirectory => Path.Combine(DataDirectory, "logs");

    /// <summary>Downloaded agent packages and their installer logs.</summary>
    public string UpdateDirectory => Path.Combine(DataDirectory, "updates");

    /// <summary>Client for downloading winget from GitHub (tests); by default the agent creates its own.</summary>
    public HttpClient? WingetHttpClient { get; init; }

    /// <summary>The winget release to install (tests); by default the pinned <see cref="Contracts.Agent.WingetDistribution"/>.</summary>
    public Applications.WingetRelease? WingetRelease { get; init; }
}
