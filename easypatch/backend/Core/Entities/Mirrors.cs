namespace EasyPatch.Core.Entities;

/// <summary>A copy of third-party files the server keeps for its agents (the pinned winget release), which the worker
/// downloads only after an agent has asked for it.</summary>
public sealed class MirrorState
{
    public required string Name { get; set; }

    /// <summary>The last time an agent asked for a file the server did not have yet.</summary>
    public DateTimeOffset? RequestedAt { get; set; }

    public DateTimeOffset? LastAttemptAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string? LastError { get; set; }

    /// <summary>Failed downloads in a row (spaces the retries out).</summary>
    public int Failures { get; set; }
}

public static class Mirrors
{
    public const string Winget = "winget";
}
