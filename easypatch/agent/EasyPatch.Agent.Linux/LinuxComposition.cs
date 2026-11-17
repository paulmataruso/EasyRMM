using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using EasyPatch.Agent.Core;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Contracts.Agent;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Platform;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Linux;

/// <summary>Wires the platform-independent runtime to the Linux implementations.</summary>
internal static class LinuxComposition
{
    public const string ServiceName = "easypatch-agent";
    public const string DataDirectory = "/var/lib/easypatch";

    private const string ReleaseKeysResource = "EasyPatch.ReleaseKeys.pem";

    public static string AgentVersion { get; } = ReadVersion();

    public static string ConfigPath => ConfFileBootstrapSource.DefaultPath;

    public static AgentRuntimeOptions CreateOptions() => new()
    {
        DataDirectory = DataDirectory,
        AgentVersion = AgentVersion,
        PackageArchitecture = AgentRelease.ArchitectureOf(RuntimeInformation.ProcessArchitecture),
        ReleasePublicKeys = ReadReleaseKeys(),
    };

    /// <summary>The distribution, or an exception explaining why it is not supported.</summary>
    public static LinuxDistribution RequireDistribution()
    {
        var distribution = LinuxDistribution.Read() ?? throw new PlatformNotSupportedException("/etc/os-release is missing or has no ID.");
        if (distribution.Family == PackageFamily.Unsupported)
        {
            throw new PlatformNotSupportedException(
                $"{distribution.PrettyName ?? distribution.Id} is not supported. The agent supports Debian, Ubuntu and Enterprise Linux 8+ (RHEL, Rocky, AlmaLinux, Oracle).");
        }

        return distribution;
    }

    public static AgentPlatform CreatePlatform(ILoggerFactory loggerFactory, IBootstrapConfigSource bootstrap)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        var distribution = RequireDistribution();
        var family = distribution.Family;
        var commands = new ProcessCommandRunner();
        var units = new TransientUnitRunner(commands, loggerFactory.CreateLogger<TransientUnitRunner>());
        var workDirectory = Path.Combine(DataDirectory, "packages");
        PackageBackend backend = family == PackageFamily.Debian
            ? new AptBackend(commands, units, workDirectory, loggerFactory.CreateLogger<AptBackend>())
            : new DnfBackend(commands, units, workDirectory, loggerFactory.CreateLogger<DnfBackend>());
        var bootTime = new LinuxBootTimeProvider();
        var reboot = new LinuxRebootDetector(commands, family, loggerFactory.CreateLogger<LinuxRebootDetector>());
        var updates = new PackageUpdateService(backend, distribution, Path.Combine(DataDirectory, "package-ledger.json"), units, reboot,
            TimeProvider.System, loggerFactory.CreateLogger<PackageUpdateService>());
        var source = new LinuxUpdateSourceDetector(commands, family);
        var inventory = new LinuxInventoryCollector(commands, distribution, backend.Name, source, bootTime, loggerFactory.CreateLogger<LinuxInventoryCollector>());

        return new AgentPlatform(updates, inventory, reboot, source, new LinuxSecretProtector(commands, loggerFactory.CreateLogger<LinuxSecretProtector>()),
            bootstrap, bootTime)
        {
            SystemRestart = new LinuxSystemRestart(commands),
            AgentInstaller = new LinuxAgentInstaller(units, family),
            AgentUninstaller = new LinuxAgentUninstaller(units, family),
            SessionCounter = new LinuxUserSessions(commands),
        };
    }

    public static AgentRuntime CreateRuntime(ILoggerFactory loggerFactory)
    {
        var bootstrap = new ConfFileBootstrapSource(ConfigPath, loggerFactory.CreateLogger<ConfFileBootstrapSource>());
        return new AgentRuntime(CreateOptions(), CreatePlatform(loggerFactory, bootstrap), new LinuxHttpClientFactory(bootstrap), loggerFactory);
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
        using var stream = typeof(LinuxComposition).Assembly.GetManifestResourceStream(ReleaseKeysResource);
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string ReadVersion()
    {
        var informational = typeof(LinuxComposition).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus > 0 ? informational[..plus] : informational;
        }

        return typeof(LinuxComposition).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}

/// <summary>
/// Production HTTP stack. TLS certificates are validated against the system trust store (OpenSSL; ca-certificates) and
/// validation cannot be disabled or configured. Redirects are not followed (a signed request must reach exactly the URL
/// it was signed for). The proxy is ProxyUrl from agent.conf when set, otherwise the HTTPS_PROXY / HTTP_PROXY / NO_PROXY
/// environment variables of the service (set them in a systemd drop-in).
/// </summary>
internal sealed class LinuxHttpClientFactory : IAgentHttpClientFactory
{
    private readonly IBootstrapConfigSource _bootstrap;

    public LinuxHttpClientFactory(IBootstrapConfigSource bootstrap)
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

    /// <summary>Makes the data directory root-owned and root-only, creating it when needed. Fails closed.</summary>
    public static void SecureDataDirectory(string path)
    {
        const UnixFileMode Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(path, Mode);
        if (ChownNative(path, 0, 0) != 0)
        {
            throw new IOException($"chown root:root {path} failed (errno {Marshal.GetLastPInvokeError()}).");
        }

        File.SetUnixFileMode(path, Mode);
    }
}
