using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Linux;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Systemd;
using Microsoft.Extensions.Logging;

// Everything the agent creates (keys, state, logs, configuration) is private to root.
Native.RestrictUmask();

var command = args.Length == 0 ? "run" : args[0].ToLowerInvariant();
var rest = args.Length == 0 ? [] : args[1..];

try
{
    return command switch
    {
        "run" => await RunAgentAsync(rest),
        "enroll" => await Cli.EnrollAsync(rest),
        "status" => Cli.Status(rest),
        "scan" => await Cli.ScanAsync(rest),
        "unenroll" => await Cli.UnenrollAsync(rest),
        "version" or "--version" or "-v" => Cli.Version(),
        "help" or "--help" or "-h" => Cli.Help(),
        _ => Cli.UnknownCommand(command),
    };
}
catch (CliUsageException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    Console.Error.WriteLine("Run 'easypatch-agent help' for usage.");
    return Cli.ExitUsage;
}

static async Task<int> RunAgentAsync(string[] arguments)
{
    if (arguments.Length > 0)
    {
        throw new CliUsageException($"'run' takes no arguments (got '{arguments[0]}').");
    }

    if (!Native.IsRoot())
    {
        Console.Error.WriteLine("The EasyPatch agent must run as root (systemd service easypatch-agent).");
        return Cli.ExitNotElevated;
    }

    try
    {
        LinuxComposition.RequireDistribution();
    }
    catch (PlatformNotSupportedException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return Cli.ExitFailure;
    }

    var dataDirectory = LinuxComposition.DataDirectory;
    try
    {
        // Fail closed: the agent never writes key material into a directory it could not lock down.
        Native.SecureDataDirectory(dataDirectory);
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
    {
        Console.Error.WriteLine($"Could not restrict access to {dataDirectory}: {ex.Message}");
        return Cli.ExitFailure;
    }

    var isService = SystemdHelpers.IsSystemdService();
    using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, isService ? TimeSpan.FromSeconds(15) : TimeSpan.Zero);
    if (instanceLock is null)
    {
        Console.Error.WriteLine("Another EasyPatch agent process is already running on this computer.");
        return Cli.ExitBusy;
    }

    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        ContentRootPath = AppContext.BaseDirectory,
        DisableDefaults = true,
    });

    builder.Services.AddSystemd();
    builder.Services.Configure<HostOptions>(options =>
    {
        // Give an in-flight package-manager wait time to observe cancellation and the job state time to persist.
        options.ShutdownTimeout = TimeSpan.FromSeconds(60);
    });

    var fileLevel = LinuxComposition.ReadFileLogLevel();
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(fileLevel < LogLevel.Information ? fileLevel : LogLevel.Information);
    builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
    builder.Logging.AddFilter("System", LogLevel.Warning);
    builder.Services.AddSingleton<ILoggerProvider>(_ => new RollingFileLoggerProvider(new RollingFileLoggerOptions
    {
        Directory = Path.Combine(dataDirectory, "logs"),
        MinimumLevel = fileLevel,
    }));

    // The journal (through the console, formatted for journald by AddSystemd) gets information and above.
    builder.Logging.AddConsole();
    builder.Logging.AddFilter<Microsoft.Extensions.Logging.Console.ConsoleLoggerProvider>(null, LogLevel.Warning);
    builder.Logging.AddFilter<Microsoft.Extensions.Logging.Console.ConsoleLoggerProvider>("EasyPatch", LogLevel.Information);

    builder.Services.AddSingleton(sp => LinuxComposition.CreateRuntime(sp.GetRequiredService<ILoggerFactory>()));
    builder.Services.AddHostedService<AgentHostedService>();

    using var host = builder.Build();
    await host.RunAsync();
    return 0;
}
