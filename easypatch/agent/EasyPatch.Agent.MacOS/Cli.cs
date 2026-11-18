using System.Globalization;
using System.Text;
using System.Text.Json;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Core.State;
using EasyPatch.Communication;
using EasyPatch.Contracts.Json;
using EasyPatch.MacOS;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.MacOS;

internal sealed class CliUsageException(string message) : Exception(message);

/// <summary>
/// Administrative commands. None of them can execute arbitrary commands or restart the computer. The enrollment token
/// is read from a file, standard input or the environment, never from the command line (where other users could see
/// it in the process list), and is never echoed or logged.
/// </summary>
internal static class Cli
{
    public const int ExitSuccess = 0;
    public const int ExitFailure = 1;
    public const int ExitUsage = 2;
    public const int ExitEnrolledElsewhere = 3;
    public const int ExitRejected = 4;
    public const int ExitNotElevated = 5;
    public const int ExitDeferred = 6;
    public const int ExitBusy = 7;

    private const string TokenEnvironmentVariable = "EASYPATCH_ENROLLMENT_TOKEN";
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromSeconds(90);
    private static readonly JsonSerializerOptions IndentedJson = new(ContractJson.Options) { WriteIndented = true };
    private static readonly ProcessCommandRunner Commands = new();

    // ================================================================== enroll

    public static async Task<int> EnrollAsync(string[] args)
    {
        var options = CliArguments.Parse(args, ["--server", "--token-file", "--deployment-code", "--proxy"], ["--force", "--no-start"]);
        var server = options.Required("--server");
        var code = options.Value("--deployment-code");
        var tokenFile = options.Value("--token-file");
        var force = options.Flag("--force");
        var proxy = options.Value("--proxy");
        if (tokenFile is not null && code is not null)
        {
            throw new CliUsageException("Specify either --token-file or --deployment-code, not both.");
        }

        Uri serverUrl;
        try
        {
            serverUrl = ApiClientAccessor.NormalizeServerUrl(server, requireHttps: true);
            MacHttpClientFactory.CreateProxy(proxy);
        }
        catch (ArgumentException ex)
        {
            throw new CliUsageException(ex.ParamName is null ? ex.Message : ex.Message.Replace($" (Parameter '{ex.ParamName}')", string.Empty, StringComparison.Ordinal));
        }

        if (!Native.IsRoot())
        {
            Console.Error.WriteLine("error: 'enroll' must be run as root (sudo).");
            return ExitNotElevated;
        }

        Console.Error.WriteLine(MacComposition.ExperimentalWarning);
        var token = code is null ? ReadToken(tokenFile) : null;
        if (token is null && code is null)
        {
            throw new CliUsageException($"Specify --token-file <path|-> (or set {TokenEnvironmentVariable}) or --deployment-code <code>.");
        }

        var existing = TryReadState(out _);
        if (existing is { Status: AgentEnrollmentStatus.Active or AgentEnrollmentStatus.PendingApproval } && !force)
        {
            if (SameServer(existing.ServerUrl, serverUrl))
            {
                Console.WriteLine($"This computer is already enrolled with {existing.ServerUrl} (status {existing.Status}). Nothing to do.");
                Console.WriteLine("Use --force to discard the current identity and enroll again.");
                await StartServiceAsync();
                return ExitSuccess;
            }

            Console.Error.WriteLine($"error: this computer is enrolled with {existing.ServerUrl} (status {existing.Status}).");
            Console.Error.WriteLine("Use --force to unenroll from that server and enroll with the new one.");
            return ExitEnrolledElsewhere;
        }

        var dataDirectory = MacComposition.DataDirectory;
        await StopServiceAsync();
        try
        {
            Native.SecureDataDirectory(dataDirectory);
            using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, TimeSpan.FromSeconds(60));
            if (instanceLock is null)
            {
                Console.Error.WriteLine("error: another EasyPatch agent process is running and could not be stopped.");
                return ExitBusy;
            }

            using var loggerFactory = CreateCliLoggerFactory(dataDirectory);
            using var runtime = MacComposition.CreateRuntime(loggerFactory);
            if (force && runtime.State.Read(s => s.Status) != AgentEnrollmentStatus.NotEnrolled)
            {
                using var unenrollTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await runtime.UnenrollAsync("Re-enrolled from the command line (--force).", unenrollTimeout.Token);
            }

            ConfFileBootstrapSource.Write(MacComposition.ConfigPath, new BootstrapConfig(serverUrl.ToString(), token, code, proxy),
                new ConfFileBootstrapSource(MacComposition.ConfigPath).ReadValue("LogLevel"));

            EnrollmentOutcome outcome;
            using (var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3)))
            {
                try
                {
                    outcome = await runtime.EnsureEnrolledAsync(timeout.Token);
                }
                catch (AgentTransientException ex)
                {
                    Console.Error.WriteLine($"warning: could not reach {serverUrl}: {ex.Message}");
                    Console.Error.WriteLine("The settings were saved; the easypatch-agent service will keep retrying enrollment.");
                    return ExitDeferred;
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    Console.Error.WriteLine($"warning: enrollment with {serverUrl} timed out.");
                    Console.Error.WriteLine("The settings were saved; the easypatch-agent service will keep retrying enrollment.");
                    return ExitDeferred;
                }
            }

            var state = runtime.State.Snapshot();
            switch (outcome)
            {
                case EnrollmentOutcome.Active:
                    Console.WriteLine($"Enrolled with {state.ServerUrl}. Endpoint ID: {state.EndpointId}.");
                    return ExitSuccess;

                case EnrollmentOutcome.PendingApproval:
                    Console.WriteLine($"Enrollment request submitted to {state.ServerUrl} and waiting for approval.");
                    Console.WriteLine($"Approve it in the EasyPatch console. Key fingerprint: {state.KeyFingerprint}");
                    return ExitSuccess;

                case EnrollmentOutcome.Rejected:
                    Console.Error.WriteLine("error: the server rejected the enrollment request. Check the token or deployment code and try again.");
                    return ExitRejected;

                case EnrollmentOutcome.NotConfigured:
                    Console.Error.WriteLine("error: the enrollment settings are incomplete or invalid.");
                    return ExitUsage;

                default:
                    Console.Error.WriteLine("error: enrollment did not complete. The service will retry; see the agent log for details.");
                    return ExitFailure;
            }
        }
        finally
        {
            if (!options.Flag("--no-start"))
            {
                await StartServiceAsync();
            }
        }
    }

    /// <summary>The token from <c>--token-file</c> (<c>-</c> reads standard input) or the environment variable.</summary>
    private static string? ReadToken(string? tokenFile)
    {
        string? text;
        if (tokenFile is null)
        {
            text = Environment.GetEnvironmentVariable(TokenEnvironmentVariable);
        }
        else if (tokenFile == "-")
        {
            text = Console.In.ReadToEnd();
        }
        else
        {
            try
            {
                text = File.ReadAllText(tokenFile, Encoding.UTF8);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new CliUsageException($"Could not read the token file: {ex.Message}");
            }
        }

        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return tokenFile is null ? null : throw new CliUsageException("The token file is empty.");
        }

        if (text.Contains('\n', StringComparison.Ordinal) || text.Length > 512)
        {
            throw new CliUsageException("The token file must contain only the enrollment token.");
        }

        return text;
    }

    // ================================================================== status

    public static int Status(string[] args)
    {
        var options = CliArguments.Parse(args, [], ["--json"]);
        var state = TryReadState(out var error);
        var service = ServiceState();
        var outboxCount = CountOutbox();

        if (options.Flag("--json"))
        {
            var payload = new
            {
                agentVersion = MacComposition.AgentVersion,
                experimental = true,
                service,
                status = state?.Status.ToString() ?? (error is null ? "NotEnrolled" : "Unknown"),
                error,
                serverUrl = state?.ServerUrl,
                endpointId = state?.EndpointId,
                credentialId = state?.CredentialId,
                credentialExpiresAt = state?.CredentialExpiresAt,
                keyFingerprint = state?.KeyFingerprint,
                enrolledAt = state?.EnrolledAt,
                lastCheckInAt = state?.LastCheckInAt,
                lastScanAt = state?.LastScanAt,
                lastInventoryAt = state?.LastInventoryAt,
                lastAuthFailureCode = state?.LastAuthFailureCode,
                jobs = state?.Jobs.Select(j => new { jobId = j.Job.JobId, type = j.Job.Type.ToString(), state = j.RunState.ToString(), j.Phase }).ToList(),
                queuedReports = outboxCount,
            };
            Console.WriteLine(JsonSerializer.Serialize(payload, IndentedJson));
            return error is null ? ExitSuccess : ExitFailure;
        }

        Console.WriteLine($"EasyPatch Agent {MacComposition.AgentVersion} for macOS");
        Console.WriteLine(MacComposition.ExperimentalWarning);
        Line("Service", service);
        if (error is not null)
        {
            Line("Status", $"unknown ({error})");
            return ExitFailure;
        }

        if (state is null)
        {
            Line("Status", "NotEnrolled");
            return ExitSuccess;
        }

        Line("Status", state.Status.ToString());
        Line("Server", state.ServerUrl);
        Line("Endpoint ID", state.EndpointId?.ToString());
        Line("Credential", state.CredentialId is null ? null : $"{state.CredentialId} (expires {Format(state.CredentialExpiresAt)})");
        Line("Pending request", state.PendingEnrollmentRequestId);
        Line("Key fingerprint", state.KeyFingerprint);
        Line("Enrolled", Format(state.EnrolledAt));
        Line("Last check-in", Format(state.LastCheckInAt));
        Line("Last scan", Format(state.LastScanAt));
        Line("Last inventory", Format(state.LastInventoryAt));
        Line("Last auth failure", state.LastAuthFailureCode is null ? null : $"{state.LastAuthFailureCode} at {Format(state.LastAuthFailureAt)}");
        Line("Queued reports", outboxCount?.ToString(CultureInfo.InvariantCulture));
        Line("Jobs", state.Jobs.Count == 0 ? "none" : state.Jobs.Count.ToString(CultureInfo.InvariantCulture));
        foreach (var job in state.Jobs)
        {
            Console.WriteLine($"  {job.Job.JobId}  {job.Job.Type}  {job.RunState}  {job.Phase}");
        }

        return ExitSuccess;
    }

    // ================================================================== scan

    /// <summary>Lists the updates the agent would report, without contacting the server or installing anything.</summary>
    public static async Task<int> ScanAsync(string[] args)
    {
        var options = CliArguments.Parse(args, [], ["--json"]);
        if (!Native.IsRoot())
        {
            Console.Error.WriteLine("error: 'scan' must be run as root (sudo).");
            return ExitNotElevated;
        }

        using var loggerFactory = LoggerFactory.Create(builder => builder.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Warning));
        var platform = MacComposition.CreatePlatform(loggerFactory, new ConfFileBootstrapSource(MacComposition.ConfigPath));
        UpdateScanResult result;
        try
        {
            result = await platform.Updates.ScanAsync(includeInstalled: false, CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var (code, message) = platform.Updates.DescribeFailure(ex);
            Console.Error.WriteLine($"error: the {platform.Updates.Name} scan failed ({code}): {message}");
            return ExitFailure;
        }

        using (result)
        {
            var updates = result.Missing.Select(c => c.Update).ToList();
            if (options.Flag("--json"))
            {
                Console.WriteLine(JsonSerializer.Serialize(updates, IndentedJson));
                return ExitSuccess;
            }

            Console.WriteLine($"{updates.Count} update(s) available from {platform.Updates.Name} ({updates.Count(u => u.RebootBehavior == 1)} need a restart):");
            foreach (var update in updates)
            {
                var classification = update.Categories.FirstOrDefault(c => c.Type == "UpdateClassification")?.Name ?? "Updates";
                Console.WriteLine($"  {classification,-17} {update.Title}{(update.RebootBehavior == 1 ? "  [restart]" : string.Empty)}" +
                                  $"{(update.RebootRequired ? "  (installed, waiting for a restart)" : string.Empty)}");
            }

            return ExitSuccess;
        }
    }

    // ================================================================== inventory

    public static async Task<int> InventoryAsync(string[] args)
    {
        var options = CliArguments.Parse(args, [], ["--json"]);
        if (!Native.IsRoot())
        {
            Console.Error.WriteLine("error: 'inventory' must be run as root (sudo).");
            return ExitNotElevated;
        }

        using var loggerFactory = LoggerFactory.Create(builder => builder.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Warning));
        var platform = MacComposition.CreatePlatform(loggerFactory, new ConfFileBootstrapSource(MacComposition.ConfigPath));
        var report = await platform.Inventory.CollectAsync(new InventoryContext(MacComposition.AgentVersion, null), CancellationToken.None);
        if (options.Flag("--json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(report, IndentedJson));
            return ExitSuccess;
        }

        Line("Computer", report.Hostname);
        Line("macOS", $"{report.OsCaption} ({report.OsBuildVersion ?? "?"})");
        Line("Kernel", report.KernelVersion);
        Line("Model", report.Model);
        Line("Processor", $"{report.ProcessorName} ({report.Architecture})");
        Line("Memory", report.TotalMemoryBytes is { } memory ? $"{memory / (1024 * 1024 * 1024)} GB" : null);
        Line("Serial number", report.SerialNumber);
        Line("Virtual machine", report.IsVirtualMachine?.ToString());
        Line("MDM", report.UpdateSource?.ManagedByMdm == true ? "enrolled" : "not enrolled");
        Line("Last boot", Format(report.LastBootAt));
        return ExitSuccess;
    }

    // ================================================================== unenroll

    public static async Task<int> UnenrollAsync(string[] args)
    {
        var options = CliArguments.Parse(args, ["--reason"], []);
        if (!Native.IsRoot())
        {
            Console.Error.WriteLine("error: 'unenroll' must be run as root (sudo).");
            return ExitNotElevated;
        }

        var dataDirectory = MacComposition.DataDirectory;
        await StopServiceAsync();
        Native.SecureDataDirectory(dataDirectory);
        using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, TimeSpan.FromSeconds(60));
        if (instanceLock is null)
        {
            Console.Error.WriteLine("error: another EasyPatch agent process is running and could not be stopped.");
            return ExitBusy;
        }

        using (var loggerFactory = CreateCliLoggerFactory(dataDirectory))
        using (var runtime = MacComposition.CreateRuntime(loggerFactory))
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
        {
            await runtime.UnenrollAsync(options.Value("--reason") ?? "Agent removed from the command line.", timeout.Token);
        }

        ConfFileBootstrapSource.Delete(MacComposition.ConfigPath);
        Console.WriteLine("The agent identity and enrollment settings were removed from this computer.");
        Console.WriteLine($"The daemon stays stopped until the Mac restarts; run 'sudo {MacPaths.UninstallScript}' to remove the agent, or 'enroll' to use it again.");
        return ExitSuccess;
    }

    // ================================================================== misc

    public static int Version()
    {
        Console.WriteLine(MacComposition.AgentVersion);
        Console.Error.WriteLine(MacComposition.ExperimentalWarning);
        return ExitSuccess;
    }

    public static int Help()
    {
        Console.WriteLine($"""
            EasyPatch Agent {MacComposition.AgentVersion} for macOS
            {MacComposition.ExperimentalWarning}

            Usage: easypatch-agent <command> [options]

              run                       Run the agent (default; used by the {MacPaths.DaemonLabel} launchd daemon).
              enroll --server <url> (--token-file <path|-> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
                                        Enroll this computer. A token enrolls immediately; a deployment code
                                        creates a request an administrator must approve in the console.
                                        The token is read from a file, from standard input (--token-file -)
                                        or from {TokenEnvironmentVariable}; it is never accepted as an argument.
              status [--json]           Show enrollment and agent status.
              scan [--json]             List the updates this Mac would report (runs softwareupdate --list;
                                        installs nothing and does not contact the server).
              inventory [--json]        Show the hardware and macOS details this Mac would report (does not
                                        contact the server).
              unenroll [--reason <text>]
                                        Notify the server (best effort) and delete the agent identity.
              version                   Print the agent version.

            Exit codes: 0 success, 1 failure, 2 usage, 3 enrolled with another server (use --force),
                        4 rejected, 5 not root, 6 server unreachable (saved; the service retries), 7 busy.
            """);
        return ExitSuccess;
    }

    public static int UnknownCommand(string command) =>
        throw new CliUsageException($"Unknown command '{command}'.");

    private static ILoggerFactory CreateCliLoggerFactory(string dataDirectory) =>
        LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddFilter("Microsoft", LogLevel.Warning);
            builder.AddFilter("System", LogLevel.Warning);
            builder.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.IncludeScopes = false;
            });
            builder.AddProvider(new RollingFileLoggerProvider(new RollingFileLoggerOptions
            {
                Directory = Path.Combine(dataDirectory, "logs"),
                FileName = "cli.log",
                MaxFileBytes = 2L * 1024 * 1024,
                RetainedFiles = 2,
            }));
        });

    private static AgentState? TryReadState(out string? error)
    {
        error = null;
        try
        {
            var bytes = AtomicFile.TryReadAllBytes(Path.Combine(MacComposition.DataDirectory, "state", "agent-state.json"));
            return bytes is null ? null : JsonSerializer.Deserialize<AgentState>(bytes, ContractJson.Options);
        }
        catch (UnauthorizedAccessException)
        {
            error = "access denied; run as root (sudo)";
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            error = ex.Message;
        }

        return null;
    }

    private static int? CountOutbox()
    {
        try
        {
            var directory = Path.Combine(MacComposition.DataDirectory, "outbox");
            return Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*.json").Count() : 0;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static bool SameServer(string? stored, Uri requested)
    {
        if (string.IsNullOrWhiteSpace(stored))
        {
            return false;
        }

        try
        {
            return ApiClientAccessor.NormalizeServerUrl(stored, requireHttps: true) == requested;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>"active" (running), "loaded" (loaded, not running), "inactive" (not loaded) or "unknown".</summary>
    private static string ServiceState()
    {
        try
        {
            var result = Commands.RunAsync("/bin/launchctl", ["print", "system/" + MacPaths.DaemonLabel], TimeSpan.FromSeconds(30), CancellationToken.None)
                .GetAwaiter().GetResult();
            if (!result.Succeeded)
            {
                return "inactive";
            }

            return result.StandardOutput.Split('\n').Any(l => l.Trim() == "state = running") ? "active" : "loaded";
        }
        catch (CommandException)
        {
            return "unknown";
        }
    }

    /// <summary>Unloads the daemon (launchd would otherwise restart it at once).</summary>
    private static async Task StopServiceAsync()
    {
        if (ServiceState() is "inactive" or "unknown")
        {
            return;
        }

        Console.WriteLine($"Stopping the {MacPaths.DaemonLabel} daemon...");
        await LaunchctlAsync(["bootout", "system/" + MacPaths.DaemonLabel], "stop");
    }

    private static async Task StartServiceAsync()
    {
        if (!File.Exists(MacPaths.DaemonPlist))
        {
            Console.Error.WriteLine($"warning: {MacPaths.DaemonPlist} is missing; reinstall the EasyPatch agent package.");
            return;
        }

        var started = ServiceState() is "active" or "loaded"
            ? await LaunchctlAsync(["kickstart", "-k", "system/" + MacPaths.DaemonLabel], "restart")
            : await LaunchctlAsync(["bootstrap", "system", MacPaths.DaemonPlist], "start");
        if (started)
        {
            Console.WriteLine($"The {MacPaths.DaemonLabel} daemon is running.");
        }
    }

    private static async Task<bool> LaunchctlAsync(IReadOnlyList<string> arguments, string action)
    {
        try
        {
            var result = await Commands.RunAsync("/bin/launchctl", arguments, ServiceTimeout, CancellationToken.None);
            if (!result.Succeeded)
            {
                Console.Error.WriteLine($"warning: could not {action} the {MacPaths.DaemonLabel} daemon (launchctl {arguments[0]}): {result.Combined.Trim()}");
            }

            return result.Succeeded;
        }
        catch (CommandException ex)
        {
            Console.Error.WriteLine($"warning: could not {action} the {MacPaths.DaemonLabel} daemon: {ex.Message}");
            return false;
        }
    }

    private static void Line(string label, string? value) =>
        Console.WriteLine($"{label + ":",-20}{value ?? "-"}");

    private static string? Format(DateTimeOffset? value) =>
        value?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
}

/// <summary>Minimal, strict option parser (<c>--name value</c> and <c>--name=value</c>; unknown options are errors).</summary>
internal sealed class CliArguments
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    public static CliArguments Parse(string[] args, IReadOnlyCollection<string> valued, IReadOnlyCollection<string> flags)
    {
        var result = new CliArguments();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            string name;
            string? inlineValue = null;
            var equals = arg.IndexOf('=', StringComparison.Ordinal);
            if (arg.StartsWith("--", StringComparison.Ordinal) && equals > 2)
            {
                name = arg[..equals];
                inlineValue = arg[(equals + 1)..];
            }
            else
            {
                name = arg;
            }

            if (valued.Contains(name))
            {
                var value = inlineValue ?? (i + 1 < args.Length ? args[++i] : throw new CliUsageException($"Option {name} requires a value."));
                if (!result._values.TryAdd(name, value))
                {
                    throw new CliUsageException($"Option {name} was given more than once.");
                }
            }
            else if (inlineValue is null && flags.Contains(name))
            {
                result._flags.Add(name);
            }
            else if (name == "--token")
            {
                throw new CliUsageException("--token is not accepted (other users could read it from the process list). Use --token-file <path> or --token-file - (standard input).");
            }
            else
            {
                // Do not echo the argument: it may be a mistyped secret.
                throw new CliUsageException($"Unexpected argument at position {i + 1}.");
            }
        }

        return result;
    }

    public string? Value(string name) =>
        _values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

    public string Required(string name) =>
        Value(name) ?? throw new CliUsageException($"Option {name} is required.");

    public bool Flag(string name) => _flags.Contains(name);
}
