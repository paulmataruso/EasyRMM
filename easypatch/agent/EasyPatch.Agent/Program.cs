using EasyPatch.Agent;
using EasyPatch.Agent.Core.Ipc;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Platform;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;

var command = args.Length == 0 ? "run" : args[0].ToLowerInvariant();
var rest = args.Length == 0 ? [] : args[1..];

try
{
    return command switch
    {
        "run" => await RunAgentAsync(rest),
        "tray" => EasyPatch.Agent.Tray.TrayApplication.Run(),
        "enroll" => await Cli.EnrollAsync(rest),
        "status" => Cli.Status(rest),
        "unenroll" => await Cli.UnenrollAsync(rest),
        "version" or "--version" or "-v" => Cli.Version(),
        "help" or "--help" or "-h" or "/?" or "-?" => Cli.Help(),
        _ => Cli.UnknownCommand(command),
    };
}
catch (CliUsageException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    Console.Error.WriteLine("Run 'EasyPatch.Agent.exe help' for usage.");
    return Cli.ExitUsage;
}

static async Task<int> RunAgentAsync(string[] arguments)
{
    if (arguments.Length > 0)
    {
        throw new CliUsageException($"'run' takes no arguments (got '{arguments[0]}').");
    }

    var dataDirectory = AgentComposition.DataDirectory;
    var isService = WindowsServiceHelpers.IsWindowsService();
    if (!SecureStorage.IsElevated())
    {
        return Cli.StartupFailure("The EasyPatch agent must run as LocalSystem (Windows service) or from an elevated prompt.", Cli.ExitNotElevated);
    }

    // Fail closed: the agent never writes key material into a directory it could not lock down.
    try
    {
        SecureStorage.SecureDataDirectory(dataDirectory);
        SecureStorage.SecureRegistryKey();
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or System.Security.SecurityException)
    {
        return Cli.StartupFailure($"Could not restrict access to {dataDirectory} or its registry key: {ex.Message}", Cli.ExitFailure);
    }

    using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, isService ? TimeSpan.FromSeconds(15) : TimeSpan.Zero);
    if (instanceLock is null)
    {
        return Cli.StartupFailure("Another EasyPatch agent process is already running on this computer.", Cli.ExitBusy);
    }

    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        ContentRootPath = AppContext.BaseDirectory,
        DisableDefaults = true,
    });

    builder.Services.AddWindowsService(options => options.ServiceName = AgentComposition.ServiceName);
    builder.Services.Configure<HostOptions>(options =>
    {
        // Give an in-flight WUA call time to observe cancellation and the job state time to persist.
        options.ShutdownTimeout = TimeSpan.FromSeconds(60);
    });

    var fileLevel = AgentComposition.ReadFileLogLevel();
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(fileLevel < LogLevel.Information ? fileLevel : LogLevel.Information);
    builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
    builder.Logging.AddFilter("System", LogLevel.Warning);
    builder.Services.AddSingleton<ILoggerProvider>(_ => new RollingFileLoggerProvider(new RollingFileLoggerOptions
    {
        Directory = AgentComposition.LogDirectory,
        MinimumLevel = fileLevel,
    }));
    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = AgentComposition.EventLogSource;
        settings.LogName = "Application";
    });
    builder.Logging.AddFilter<EventLogLoggerProvider>(null, LogLevel.Warning);
    builder.Logging.AddFilter<EventLogLoggerProvider>("EasyPatch", LogLevel.Information);
    if (!isService)
    {
        builder.Logging.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = "HH:mm:ss ";
        });
    }

    if (isService)
    {
        // Trays in the users' sessions (status window, messages and restart prompts). Only the LocalSystem service can start them.
        builder.Services.AddSingleton(sp => TrayBrokerFactory.Create(sp.GetRequiredService<ILoggerFactory>(), AgentComposition.LogDirectory));
        builder.Services.AddSingleton(sp =>
        {
            var broker = sp.GetRequiredService<TrayBroker>();
            var runtime = AgentComposition.CreateRuntime(sp.GetRequiredService<ILoggerFactory>(), broker);
            broker.SetRequestHandler(runtime); // "Check in now" and "Check for updates" in the status window
            return runtime;
        });
        builder.Services.AddHostedService<TrayPipeServer>();
        builder.Services.AddHostedService<TrayLauncher>();
    }
    else
    {
        builder.Services.AddSingleton(sp => AgentComposition.CreateRuntime(sp.GetRequiredService<ILoggerFactory>()));
    }

    builder.Services.AddHostedService<AgentHostedService>();

    using var host = builder.Build();
    await host.RunAsync();
    return 0;
}
