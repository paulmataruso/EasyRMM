using System.Diagnostics;
using System.Globalization;
using System.ServiceProcess;
using System.Text.Json;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Core.State;
using EasyPatch.Agent.Platform;
using EasyPatch.Communication;
using EasyPatch.Contracts.Json;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent;

internal sealed class CliUsageException(string message) : Exception(message);

/// <summary>
/// Administrative commands. None of them can execute arbitrary commands, change Windows Update configuration or
/// restart the computer. Secrets passed on the command line are never echoed or logged.
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

    // ================================================================== enroll

    public static async Task<int> EnrollAsync(string[] args)
    {
        var options = CliArguments.Parse(args, ["--server", "--token", "--deployment-code", "--proxy"], ["--force", "--no-start"]);
        var server = options.Required("--server");
        var code = options.Value("--deployment-code");
        var token = options.Value("--token") ?? (code is null ? NullIfEmpty(Environment.GetEnvironmentVariable(TokenEnvironmentVariable)) : null);
        var proxy = options.Value("--proxy");
        var force = options.Flag("--force");

        if ((token is null) == (code is null))
        {
            throw new CliUsageException($"Specify exactly one of --token (or the {TokenEnvironmentVariable} environment variable) or --deployment-code.");
        }

        Uri serverUrl;
        try
        {
            serverUrl = ApiClientAccessor.NormalizeServerUrl(server, requireHttps: true);
            AgentHttpClientFactory.CreateProxy(proxy);
        }
        catch (ArgumentException ex)
        {
            throw new CliUsageException(ex.ParamName is null ? ex.Message : ex.Message.Replace($" (Parameter '{ex.ParamName}')", string.Empty, StringComparison.Ordinal));
        }

        if (!SecureStorage.IsElevated())
        {
            Console.Error.WriteLine("error: 'enroll' must be run from an elevated (Administrator) prompt or as SYSTEM.");
            return ExitNotElevated;
        }

        var existing = TryReadState(out _);
        if (existing is { Status: AgentEnrollmentStatus.Active or AgentEnrollmentStatus.PendingApproval } && !force)
        {
            if (SameServer(existing.ServerUrl, serverUrl))
            {
                Console.WriteLine($"This computer is already enrolled with {existing.ServerUrl} (status {existing.Status}). Nothing to do.");
                Console.WriteLine("Use --force to discard the current identity and enroll again.");
                EnsureServiceRunning();
                return ExitSuccess;
            }

            Console.Error.WriteLine($"error: this computer is enrolled with {existing.ServerUrl} (status {existing.Status}).");
            Console.Error.WriteLine("Use --force to unenroll from that server and enroll with the new one.");
            return ExitEnrolledElsewhere;
        }

        var dataDirectory = AgentComposition.DataDirectory;
        StopServiceIfRunning();
        try
        {
            SecureStorage.SecureDataDirectory(dataDirectory);
            using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, TimeSpan.FromSeconds(60));
            if (instanceLock is null)
            {
                Console.Error.WriteLine("error: another EasyPatch agent process is running and could not be stopped.");
                return ExitBusy;
            }

            using var loggerFactory = CreateCliLoggerFactory(dataDirectory);
            using var runtime = AgentComposition.CreateRuntime(loggerFactory);

            if (force && runtime.State.Read(s => s.Status) != AgentEnrollmentStatus.NotEnrolled)
            {
                using var unenrollTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await runtime.UnenrollAsync("Re-enrolled from the command line (--force).", unenrollTimeout.Token);
            }

            RegistryBootstrapConfigSource.Write(new BootstrapConfig(serverUrl.ToString(), token, code, proxy));

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
                    Console.Error.WriteLine("The settings were saved; the EasyPatch service will keep retrying enrollment.");
                    return ExitDeferred;
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    Console.Error.WriteLine($"warning: enrollment with {serverUrl} timed out.");
                    Console.Error.WriteLine("The settings were saved; the EasyPatch service will keep retrying enrollment.");
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
                EnsureServiceRunning();
            }
        }
    }

    // ================================================================== status

    public static int Status(string[] args)
    {
        var options = CliArguments.Parse(args, [], ["--json"]);
        var state = TryReadState(out var error);
        var service = QueryServiceStatus();
        var outboxCount = CountOutbox();

        if (options.Flag("--json"))
        {
            var payload = new
            {
                agentVersion = AgentComposition.AgentVersion,
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

        Console.WriteLine($"EasyPatch Agent {AgentComposition.AgentVersion}");
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

    // ================================================================== unenroll

    public static async Task<int> UnenrollAsync(string[] args)
    {
        var options = CliArguments.Parse(args, ["--reason"], []);
        if (!SecureStorage.IsElevated())
        {
            Console.Error.WriteLine("error: 'unenroll' must be run from an elevated (Administrator) prompt or as SYSTEM.");
            return ExitNotElevated;
        }

        var dataDirectory = AgentComposition.DataDirectory;
        StopServiceIfRunning();
        using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, TimeSpan.FromSeconds(60));
        if (instanceLock is null)
        {
            Console.Error.WriteLine("error: another EasyPatch agent process is running and could not be stopped.");
            return ExitBusy;
        }

        using (var loggerFactory = CreateCliLoggerFactory(dataDirectory))
        using (var runtime = AgentComposition.CreateRuntime(loggerFactory))
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
        {
            await runtime.UnenrollAsync(options.Value("--reason") ?? "Agent removed from the command line.", timeout.Token);
        }

        RegistryBootstrapConfigSource.DeleteAll();
        Console.WriteLine("The agent identity and enrollment settings were removed from this computer.");
        Console.WriteLine("The service stays stopped; uninstall the EasyPatch Agent MSI or run 'enroll' to use it again.");
        return ExitSuccess;
    }

    // ================================================================== misc

    public static int Version()
    {
        Console.WriteLine(AgentComposition.AgentVersion);
        return ExitSuccess;
    }

    public static int Help()
    {
        Console.WriteLine($"""
            EasyPatch Agent {AgentComposition.AgentVersion}

            Usage: EasyPatch.Agent.exe <command> [options]

              run                       Run the agent (default; used by the Windows service).
              enroll --server <url> (--token <token> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
                                        Enroll this computer. A token enrolls immediately; a deployment code
                                        creates a request an administrator must approve in the console.
                                        The token may be passed in {TokenEnvironmentVariable} instead of --token.
              status [--json]           Show enrollment and agent status.
              unenroll [--reason <text>]
                                        Notify the server (best effort) and delete the agent identity.
              version                   Print the agent version.

            Exit codes: 0 success, 1 failure, 2 usage, 3 enrolled with another server (use --force),
                        4 rejected, 5 not elevated, 6 server unreachable (saved; the service retries), 7 busy.
            """);
        return ExitSuccess;
    }

    public static int UnknownCommand(string command) =>
        throw new CliUsageException($"Unknown command '{command}'.");

    /// <summary>Reports a fatal startup problem on stderr and, when possible, in the Application event log.</summary>
    public static int StartupFailure(string message, int exitCode)
    {
        Console.Error.WriteLine(message);
        try
        {
            if (EventLog.SourceExists(AgentComposition.EventLogSource))
            {
                EventLog.WriteEntry(AgentComposition.EventLogSource, message, EventLogEntryType.Error, 1000);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Security.SecurityException or System.ComponentModel.Win32Exception)
        {
        }

        return exitCode;
    }

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
            var bytes = AtomicFile.TryReadAllBytes(Path.Combine(AgentComposition.DataDirectory, "state", "agent-state.json"));
            return bytes is null ? null : JsonSerializer.Deserialize<AgentState>(bytes, ContractJson.Options);
        }
        catch (UnauthorizedAccessException)
        {
            error = "access denied; run from an elevated prompt";
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
            var directory = Path.Combine(AgentComposition.DataDirectory, "outbox");
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

    private static string QueryServiceStatus()
    {
        try
        {
            using var controller = new ServiceController(AgentComposition.ServiceName);
            return controller.Status.ToString();
        }
        catch (InvalidOperationException)
        {
            return "NotInstalled";
        }
    }

    private static void StopServiceIfRunning()
    {
        try
        {
            using var controller = new ServiceController(AgentComposition.ServiceName);
            if (controller.Status is ServiceControllerStatus.Stopped)
            {
                return;
            }

            Console.WriteLine($"Stopping the {AgentComposition.ServiceName} service...");
            if (controller.Status is not ServiceControllerStatus.StopPending)
            {
                controller.Stop();
            }

            controller.WaitForStatus(ServiceControllerStatus.Stopped, ServiceTimeout);
        }
        catch (InvalidOperationException)
        {
            // Not installed (development) - nothing to stop.
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine($"warning: the {AgentComposition.ServiceName} service did not stop within {ServiceTimeout.TotalSeconds:0} seconds.");
        }
    }

    private static void EnsureServiceRunning()
    {
        try
        {
            using var controller = new ServiceController(AgentComposition.ServiceName);
            if (controller.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            {
                return;
            }

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, ServiceTimeout);
            Console.WriteLine($"The {AgentComposition.ServiceName} service is running.");
        }
        catch (InvalidOperationException)
        {
            Console.WriteLine($"Note: the {AgentComposition.ServiceName} service is not installed or could not be started; install the EasyPatch Agent MSI.");
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine($"warning: the {AgentComposition.ServiceName} service did not start within {ServiceTimeout.TotalSeconds:0} seconds.");
        }
    }

    private static void Line(string label, string? value) =>
        Console.WriteLine($"{label + ":",-20}{value ?? "-"}");

    private static string? Format(DateTimeOffset? value) =>
        value?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}

/// <summary>Minimal, strict option parser (<c>--name value</c> and <c>--name=value</c>; unknown options are errors).</summary>
internal sealed class CliArguments
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

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

            if (valued.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                var value = inlineValue ?? (i + 1 < args.Length ? args[++i] : throw new CliUsageException($"Option {name} requires a value."));
                if (!result._values.TryAdd(name, value))
                {
                    throw new CliUsageException($"Option {name} was given more than once.");
                }
            }
            else if (inlineValue is null && flags.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                result._flags.Add(name);
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
