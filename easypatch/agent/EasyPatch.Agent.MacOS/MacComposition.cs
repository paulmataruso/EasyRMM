using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using EasyPatch.Agent.Core;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Contracts.Agent;
using EasyPatch.MacOS;
using EasyPatch.MacOS.Platform;
using EasyPatch.MacOS.SoftwareUpdate;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.MacOS;

/// <summary>Wires the platform-independent runtime to the macOS implementations. Experimental: the macOS agent is in
/// development and not for production use.</summary>
internal static class MacComposition
{
    public const string DataDirectory = MacPaths.DataDirectory;

    public const string ConfigPath = MacPaths.ConfigPath;

    private const string ReleaseKeysResource = "EasyPatch.ReleaseKeys.pem";

    public static string AgentVersion { get; } = ReadVersion();

    /// <summary>The package architecture of this build (an Intel build reports x64 even under Rosetta, so it updates to the
    /// Intel package).</summary>
    public static AgentRuntimeOptions CreateOptions() => new()
    {
        DataDirectory = DataDirectory,
        AgentVersion = AgentVersion,
        PackageArchitecture = AgentRelease.ArchitectureOf(RuntimeInformation.ProcessArchitecture),
        ReleasePublicKeys = ReadReleaseKeys(),
    };

    /// <summary>The macOS release, or an exception explaining why it is not supported.</summary>
    public static MacSystemInfo RequireSupportedMacOS(ICommandRunner? commands = null)
    {
        var system = MacSystemInfo.Read(commands ?? new ProcessCommandRunner());
        if (system.Major < MacPaths.MinimumMajorVersion)
        {
            throw new PlatformNotSupportedException($"macOS {system.ProductVersion} is not supported. The agent supports macOS {MacPaths.MinimumMajorVersion} (Sonoma) and later.");
        }

        return system;
    }

    public static AgentPlatform CreatePlatform(ILoggerFactory loggerFactory, IBootstrapConfigSource bootstrap)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        var commands = new ProcessCommandRunner();
        var system = RequireSupportedMacOS(commands);
        var bootTime = new MacBootTimeProvider(commands);
        var updates = new SoftwareUpdateService(commands, system, Path.Combine(DataDirectory, "softwareupdate-ledger.json"), bootTime, TimeProvider.System,
            loggerFactory.CreateLogger<SoftwareUpdateService>());
        var source = new MacUpdateSourceDetector(commands);
        var inventory = new MacInventoryCollector(commands, system, source, bootTime, loggerFactory.CreateLogger<MacInventoryCollector>());
        var jobs = new LaunchdJobRunner(commands, Path.Combine(DataDirectory, "launchd"));

        return new AgentPlatform(updates, inventory, new MacRebootDetector(updates), source, new FilePermissionSecretProtector(), bootstrap, bootTime)
        {
            SystemRestart = new MacSystemRestart(commands),
            AgentInstaller = new MacAgentInstaller(jobs, commands),
            AgentUninstaller = new MacAgentUninstaller(jobs, commands),
            SessionCounter = new MacUserSessions(commands),
        };
    }

    /// <summary>Shown by the command line and logged when the daemon starts.</summary>
    public const string ExperimentalWarning = "Experimental: the macOS agent is in development and not for production use.";

    public static AgentRuntime CreateRuntime(ILoggerFactory loggerFactory)
    {
        loggerFactory.CreateLogger("EasyPatch.Agent.MacOS").LogWarning("EasyPatch Agent {Version} for macOS. {Warning}", AgentVersion, ExperimentalWarning);
        var bootstrap = new ConfFileBootstrapSource(ConfigPath, loggerFactory.CreateLogger<ConfFileBootstrapSource>());
        return new AgentRuntime(CreateOptions(), CreatePlatform(loggerFactory, bootstrap), new MacHttpClientFactory(bootstrap), loggerFactory);
    }

    /// <summary>Optional <c>LogLevel</c> (Trace, Debug, Information, Warning) in agent.conf for the file log.</summary>
    public static LogLevel ReadFileLogLevel()
    {
        var text = new ConfFileBootstrapSource(ConfigPath).ReadValue("LogLevel");
        return Enum.TryParse<LogLevel>(text, ignoreCase: true, out var level) && level is >= LogLevel.Trace and <= LogLevel.Warning
            ? level
            : LogLevel.Information;
    }

    private static string? ReadReleaseKeys()
    {
        using var stream = typeof(MacComposition).Assembly.GetManifestResourceStream(ReleaseKeysResource);
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string ReadVersion()
    {
        var informational = typeof(MacComposition).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus > 0 ? informational[..plus] : informational;
        }

        return typeof(MacComposition).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}

/// <summary>
/// Production HTTP stack. TLS certificates are validated against the macOS trust settings (System keychain and Apple's
/// roots) and validation cannot be disabled or configured. Redirects are not followed (a signed request must reach exactly
/// the URL it was signed for). The proxy is ProxyUrl from agent.conf when set, otherwise the HTTPS_PROXY / HTTP_PROXY /
/// NO_PROXY environment variables of the daemon.
/// </summary>
internal sealed class MacHttpClientFactory : IAgentHttpClientFactory
{
    private readonly IBootstrapConfigSource _bootstrap;

    public MacHttpClientFactory(IBootstrapConfigSource bootstrap)
    {
        _bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
    }

    public HttpClient Create(Uri serverUrl)
    {
        ArgumentNullException.ThrowIfNull(serverUrl);
        if (serverUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The EasyPatch server URL must use HTTPS.", nameof(serverUrl));
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            UseCookies = false,
            UseProxy = true,
            Proxy = CreateProxy(_bootstrap.Read().ProxyUrl),
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = serverUrl,
            Timeout = TimeSpan.FromMinutes(2),
        };
    }

    internal static IWebProxy CreateProxy(string? proxyUrl)
    {
        if (string.IsNullOrWhiteSpace(proxyUrl))
        {
            return HttpClient.DefaultProxy;
        }

        if (!Uri.TryCreate(proxyUrl.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("The proxy must be an absolute http:// or https:// URL without credentials.");
        }

        return new WebProxy(uri, BypassOnLocal: false);
    }
}

/// <summary>Exclusive lock (flock) on a file in the root-only data directory, so the service and CLI commands never
/// change agent state at the same time.</summary>
internal sealed class AgentInstanceLock : IDisposable
{
    private readonly FileStream _stream;

    private AgentInstanceLock(FileStream stream)
    {
        _stream = stream;
    }

    public static AgentInstanceLock? TryAcquire(string dataDirectory, TimeSpan wait)
    {
        var path = Path.Combine(dataDirectory, "agent.lock");
        var deadline = DateTime.UtcNow + wait;
        while (true)
        {
            try
            {
                return new AgentInstanceLock(new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None));
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(500);
            }
            catch (IOException)
            {
                return null;
            }
        }
    }

    public void Dispose() => _stream.Dispose();
}

/// <summary>libc calls the agent needs as root.</summary>
internal static partial class Native
{
    [LibraryImport("libc", SetLastError = true)]
    private static partial uint geteuid();

    [LibraryImport("libc", SetLastError = true)]
    private static partial uint umask(uint mask);

    [LibraryImport("libc", EntryPoint = "chown", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int ChownNative(string path, uint owner, uint group);

    public static bool IsRoot() => geteuid() == 0;

    /// <summary>New files and directories are private to root (0600 / 0700).</summary>
    public static void RestrictUmask() => umask(0x3F); // 077

    /// <summary>Makes the data directory owned by root:wheel and root-only, creating it when needed. Fails closed.</summary>
    public static void SecureDataDirectory(string path)
    {
        const UnixFileMode Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(path, Mode);
        if (ChownNative(path, 0, 0) != 0)
        {
            throw new IOException($"chown root:wheel {path} failed (errno {Marshal.GetLastPInvokeError()}).");
        }

        File.SetUnixFileMode(path, Mode);
    }
}
