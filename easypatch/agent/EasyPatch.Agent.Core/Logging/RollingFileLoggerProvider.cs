using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Logging;

public sealed class RollingFileLoggerOptions
{
    public required string Directory { get; init; }
    public string FileName { get; init; } = "agent.log";
    public long MaxFileBytes { get; init; } = 10L * 1024 * 1024;

    /// <summary>Number of rotated files kept in addition to the active file.</summary>
    public int RetainedFiles { get; init; } = 9;
    public LogLevel MinimumLevel { get; init; } = LogLevel.Information;
}

/// <summary>
/// Size-based rolling file logger (agent.log, agent.1.log … agent.N.log). Writes happen on a background task so
/// logging never blocks Windows Update work. All messages pass through <see cref="LogRedactor"/>.
/// </summary>
[ProviderAlias("RollingFile")]
public sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly RollingFileLoggerOptions _options;
    private readonly Channel<string> _channel = Channel.CreateBounded<string>(new BoundedChannelOptions(10_000)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
    });
    private readonly ConcurrentDictionary<string, RollingFileLogger> _loggers = new(StringComparer.Ordinal);
    private readonly Task _writer;
    private readonly string _path;

    public RollingFileLoggerProvider(RollingFileLoggerOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        System.IO.Directory.CreateDirectory(options.Directory);
        _path = Path.Combine(options.Directory, options.FileName);
        _writer = Task.Run(WriteLoopAsync);
    }

    public LogLevel MinimumLevel => _options.MinimumLevel;

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new RollingFileLogger(name, this));

    internal void Enqueue(string line) => _channel.Writer.TryWrite(line);

    public void Dispose()
    {
        _channel.Writer.TryComplete();
        try
        {
            _writer.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
        }
    }

    private async Task WriteLoopAsync()
    {
        var reader = _channel.Reader;
        while (await reader.WaitToReadAsync().ConfigureAwait(false))
        {
            try
            {
                // Rotate before writing, not after: the newest lines are then always in the current file.
                var current = new FileInfo(_path);
                if (current.Exists && current.Length >= _options.MaxFileBytes)
                {
                    Rotate();
                }

                using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                while (reader.TryRead(out var line))
                {
                    await writer.WriteAsync(line).ConfigureAwait(false);
                    if (stream.Length >= _options.MaxFileBytes)
                    {
                        break;
                    }
                }

                await writer.FlushAsync().ConfigureAwait(false);
            }
            catch (IOException)
            {
                // The disk may be full or the file locked; drop this batch rather than crash the service.
                await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
        }
    }

    private void Rotate()
    {
        var directory = _options.Directory;
        var stem = Path.GetFileNameWithoutExtension(_options.FileName);
        var extension = Path.GetExtension(_options.FileName);
        string Rotated(int index) => Path.Combine(directory, $"{stem}.{index}{extension}");

        var oldest = Rotated(_options.RetainedFiles);
        if (File.Exists(oldest))
        {
            File.Delete(oldest);
        }

        for (var i = _options.RetainedFiles - 1; i >= 1; i--)
        {
            var source = Rotated(i);
            if (File.Exists(source))
            {
                File.Move(source, Rotated(i + 1), overwrite: true);
            }
        }

        if (_options.RetainedFiles >= 1 && File.Exists(_path))
        {
            File.Move(_path, Rotated(1), overwrite: true);
        }
    }

    private sealed class RollingFileLogger : ILogger
    {
        private readonly string _category;
        private readonly RollingFileLoggerProvider _provider;

        public RollingFileLogger(string category, RollingFileLoggerProvider provider)
        {
            _category = category;
            _provider = provider;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None && logLevel >= _provider.MinimumLevel;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            ArgumentNullException.ThrowIfNull(formatter);
            var builder = new StringBuilder(256);
            builder.Append(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture))
                .Append(' ')
                .Append(Level(logLevel))
                .Append(' ')
                .Append(_category)
                .Append(": ")
                .Append(LogRedactor.Redact(formatter(state, exception)));
            if (exception is not null)
            {
                builder.AppendLine().Append(LogRedactor.Redact(exception.ToString()));
            }

            builder.AppendLine();
            _provider.Enqueue(builder.ToString());
        }

        private static string Level(LogLevel level) => level switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Critical => "CRT",
            _ => "???",
        };
    }
}

/// <summary>
/// Last line of defense against secrets reaching log files, and the redaction the repair and log-collection jobs apply before
/// anything leaves the computer (ADR-0069, Part L). The rules are those of the EasyRMM agent and the server (<c>logredact</c>):
/// the value of a field named like a secret (token, password, secret, key, authorization, cookie), anything shaped like an
/// EasyRMM enrollment token (<c>ert_</c>), an EasyPatch token (<c>ept_</c>), a bearer token, or a PEM block. The code never logs
/// secrets intentionally.
/// </summary>
public static partial class LogRedactor
{
    private const string Mask = "***";
    private const int TimeoutMilliseconds = 2000;

    /// <summary>What a line becomes when redacting it took too long: it is withheld, never sent as it was.</summary>
    public const string Withheld = "[line withheld: redaction did not finish]";

    private static readonly string[] SecretWords =
        ["token", "password", "passwd", "secret", "authorization", "cookie", "credential", "passphrase", "signature"];

    public static string Redact(string? message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return message ?? string.Empty;
        }

        try
        {
            message = PemBlock().Replace(message, "-----REDACTED KEY-----");
            message = BearerToken().Replace(message, "$1 " + Mask);
            message = PrefixedToken().Replace(message, "$1" + Mask);
            return Field().Replace(message, m => SecretName(m.Groups[1].Value) ? m.Groups[1].Value + m.Groups[2].Value + MaskLike(m.Groups[3].Value) : m.Value);
        }
        catch (RegexMatchTimeoutException)
        {
            return Withheld;
        }
    }

    /// <summary>Whether a field called <paramref name="name"/> holds a secret: it contains one of the words, or has "key" as a word of
    /// its own (<c>api_key</c>, <c>privateKey</c>, <c>key</c>) or ends with it (<c>apikey</c>).</summary>
    public static bool SecretName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var lower = name.ToLowerInvariant();
        if (SecretWords.Any(w => lower.Contains(w, StringComparison.Ordinal)) ||
            lower.EndsWith("apikey", StringComparison.Ordinal) || lower.EndsWith("privatekey", StringComparison.Ordinal) ||
            lower.EndsWith("secretkey", StringComparison.Ordinal))
        {
            return true;
        }

        return Words(name).Any(w => w == "key");
    }

    private static string MaskLike(string value) =>
        value.Length >= 2 && (value[0] == '"' || value[0] == '\'') && value[^1] == value[0] ? value[0] + Mask + value[0] : Mask;

    /// <summary>Splits a name at punctuation and at camelCase boundaries, in lower case.</summary>
    private static List<string> Words(string name)
    {
        var words = new List<string>();
        var current = new StringBuilder();
        void Flush()
        {
            if (current.Length > 0)
            {
                words.Add(current.ToString().ToLowerInvariant());
                current.Clear();
            }
        }

        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (!char.IsLetterOrDigit(c))
            {
                Flush();
                continue;
            }

            if (char.IsUpper(c) && i > 0 && (char.IsLower(name[i - 1]) || char.IsDigit(name[i - 1])))
            {
                Flush();
            }

            current.Append(c);
        }

        Flush();
        return words;
    }

    // A whole PEM block, or the start of one whose end was cut off (a line or size limit), through the end of the text.
    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|\z)", RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex PemBlock();

    [GeneratedRegex(@"\b(bearer)\s+[A-Za-z0-9._~+/=\-]{6,}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeoutMilliseconds)]
    private static partial Regex BearerToken();

    // The prefixed tokens of EasyRMM (ert_) and EasyPatch (ept_).
    [GeneratedRegex(@"\b(ert_|ept_)[A-Za-z0-9_\-]{6,}", RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex PrefixedToken();

    // name=value, name: value and "name":"value", the value being quoted or running to a delimiter. An authorization value may be
    // a scheme and a credential ("Basic abc", "Bearer abc").
    [GeneratedRegex(
        @"(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]+)([""']?\s*[:=]\s*)(""(?:[^""\\]|\\.)*""|'[^']*'|(?:basic|bearer|digest|negotiate|token)\s+[^\s,;&}\]]+|[^\s,;&}\]""']+)",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeoutMilliseconds)]
    private static partial Regex Field();
}
