using System.Reflection;
using System.Runtime.InteropServices;
using EasyPatch.Agent.Core;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Applications;
using EasyPatch.Agent.Core.Removal;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Platform;
using EasyPatch.Contracts.Agent;
using EasyPatch.Inventory;
using EasyPatch.WindowsUpdate;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace EasyPatch.Agent;

/// <summary>Wires the platform-independent runtime to the Windows implementations.</summary>
internal static class AgentComposition
{
    public const string ServiceName = "EasyPatchAgent";
    public const string EventLogSource = "EasyPatch Agent";

    /// <summary>Manifest name of the release public key(s) embedded at build time (see EasyPatchReleasePublicKey in the csproj).</summary>
    private const string ReleaseKeysResource = "EasyPatch.ReleaseKeys.pem";

    public static string AgentVersion { get; } = ReadVersion();

    public static string DataDirectory => SecureStorage.DefaultDataDirectory;

    public static string LogDirectory => Path.Combine(DataDirectory, "logs");

    public static AgentRuntimeOptions CreateOptions() => new()
    {
        DataDirectory = DataDirectory,
        AgentVersion = AgentVersion,
        PackageArchitecture = AgentRelease.ArchitectureOf(RuntimeInformation.ProcessArchitecture),
        ReleasePublicKeys = ReadReleaseKeys(),
    };

    /// <param name="users">The tray broker (service only); CLI commands have no tray.</param>
    public static AgentPlatform CreatePlatform(ILoggerFactory loggerFactory, IBootstrapConfigSource bootstrap, IUserInteraction? users = null)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        var windowsUpdate = new WuaWindowsUpdateService(loggerFactory.CreateLogger<WuaWindowsUpdateService>());
        var updateSource = new RegistryUpdateSourceDetector();
        var winget = new WingetProcessRunner(loggerFactory.CreateLogger<WingetProcessRunner>());
        var rebootDetector = new CompositeRebootDetector(
            [new RegistryRebootDetector(), new WuaRebootDetector(windowsUpdate)],
            loggerFactory.CreateLogger<CompositeRebootDetector>());

        return new AgentPlatform(
            windowsUpdate,
            new WmiInventoryCollector(updateSource, loggerFactory.CreateLogger<WmiInventoryCollector>()),
            rebootDetector,
            updateSource,
            new DpapiSecretProtector(),
            bootstrap,
            new TickCountBootTimeProvider())
        {
            UserInteraction = users,
            SystemRestart = new WindowsSystemRestart(),
            PolicyRegistry = new WindowsPolicyRegistry(),
            AgentInstaller = new WindowsAgentInstaller(),
            AgentUninstaller = new WindowsAgentUninstaller(),
            ApplicationUpdates = new WingetApplicationUpdateService(winget, loggerFactory.CreateLogger<WingetApplicationUpdateService>()),
            WingetRunner = winget,
            WingetProvisioner = new WindowsWingetProvisioner(
                new WindowsDismRunner(Path.Combine(LogDirectory, "winget-setup.log"), loggerFactory.CreateLogger<WindowsDismRunner>())),
            UpdateRemover = new WindowsUpdateRemover(windowsUpdate,
                new WindowsDismRunner(Path.Combine(LogDirectory, "update-removal.log"), loggerFactory.CreateLogger<WindowsDismRunner>()),
                loggerFactory.CreateLogger<WindowsUpdateRemover>()),
        };
    }

    public static AgentRuntime CreateRuntime(ILoggerFactory loggerFactory, IUserInteraction? users = null)
    {
        var bootstrap = new RegistryBootstrapConfigSource();
        return new AgentRuntime(CreateOptions(), CreatePlatform(loggerFactory, bootstrap, users), new AgentHttpClientFactory(bootstrap), loggerFactory);
    }

    /// <summary>Optional <c>LogLevel</c> registry value (Trace, Debug, Information, Warning) for the file log.</summary>
    public static LogLevel ReadFileLogLevel()
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = root.OpenSubKey(RegistryBootstrapConfigSource.KeyPath, writable: false);
            if (key?.GetValue("LogLevel") is string text && Enum.TryParse<LogLevel>(text, ignoreCase: true, out var level) &&
                level is >= LogLevel.Trace and <= LogLevel.Warning)
            {
                return level;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
        }

        return LogLevel.Information;
    }

    private static string? ReadReleaseKeys()
    {
        using var stream = typeof(AgentComposition).Assembly.GetManifestResourceStream(ReleaseKeysResource);
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string ReadVersion()
    {
        var informational = typeof(AgentComposition).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus > 0 ? informational[..plus] : informational;
        }

        return typeof(AgentComposition).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}

/// <summary>
/// Exclusive lock that prevents the service and CLI commands from changing agent state at the same time. It is a file
/// inside the ACL-protected data directory (rather than a named mutex) so unprivileged users cannot squat on it.
/// </summary>
internal sealed class AgentInstanceLock : IDisposable
{
    private readonly FileStream _stream;

    private AgentInstanceLock(FileStream stream)
    {
        _stream = stream;
    }

    public static AgentInstanceLock? TryAcquire(string dataDirectory, TimeSpan wait)
    {
        Directory.CreateDirectory(dataDirectory);
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
