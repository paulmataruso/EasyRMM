namespace EasyPatch.Infrastructure.Services;

/// <summary>Text a caller sent, made safe for a log line.</summary>
public static class LogText
{
    /// <summary>
    /// <paramref name="value"/> with its line breaks escaped: whoever reads the log as plain text must not take a line the
    /// caller wrote for one of the server's.
    /// </summary>
    public static string Safe(string? value) =>
        (value ?? "").Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
}
