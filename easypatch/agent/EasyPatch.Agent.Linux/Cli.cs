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
using EasyPatch.Linux.Platform;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Linux;

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
            LinuxHttpClientFactory.CreateProxy(proxy);
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
                await SystemctlAsync("start");
                return ExitSuccess;
            }

            Console.Error.WriteLine($"error: this computer is enrolled with {existing.ServerUrl} (status {existing.Status}).");
            Console.Error.WriteLine("Use --force to unenroll from that server and enroll with the new one.");
            return ExitEnrolledElsewhere;
        }

        var dataDirectory = LinuxComposition.DataDirectory;
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
            using var runtime = LinuxComposition.CreateRuntime(loggerFactory);
            if (force && runtime.State.Read(s => s.Status) != AgentEnrollmentStatus.NotEnrolled)
            {
                using var unenrollTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await runtime.UnenrollAsync("Re-enrolled from the command line (--force).", unenrollTimeout.Token);
            }

            ConfFileBootstrapSource.Write(LinuxComposition.ConfigPath, new BootstrapConfig(serverUrl.ToString(), token, code, proxy),
                new ConfFileBootstrapSource(LinuxComposition.ConfigPath).ReadValue("LogLevel"));

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
                await SystemctlAsync("start");
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
                agentVersion = LinuxComposition.AgentVersion,
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

        Console.WriteLine($"EasyPatch Agent {LinuxComposition.AgentVersion}");
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
        var platform = LinuxComposition.CreatePlatform(loggerFactory, new ConfFileBootstrapSource(LinuxComposition.ConfigPath));
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

            Console.WriteLine($"{updates.Count} update(s) available from {platform.Updates.Name} ({updates.Count(u => u.Package?.Security == true)} security):");
            foreach (var update in updates)
            {
                var package = update.Package!;
                Console.WriteLine($"  {(package.Security ? "security" : "        ")}  {package.Name} ({package.Architecture})  {package.InstalledVersion ?? "?"} -> {package.Version}" +
                                  $"{(update.MsrcSeverity is null ? string.Empty : $"  [{update.MsrcSeverity}]")}{(package.Advisories.Count == 0 ? string.Empty : $"  {string.Join(",", package.Advisories)}")}");
            }

            return ExitSuccess;
        }
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

        var dataDirectory = LinuxComposition.DataDirectory;
        await StopServiceAsync();
        Native.SecureDataDirectory(dataDirectory);
        using var instanceLock = AgentInstanceLock.TryAcquire(dataDirectory, TimeSpan.FromSeconds(60));
        if (instanceLock is null)
        {
            Console.Error.WriteLine("error: another EasyPatch agent process is running and could not be stopped.");
            return ExitBusy;
        }

        using (var loggerFactory = CreateCliLoggerFactory(dataDirectory))
        using (var runtime = LinuxComposition.CreateRuntime(loggerFactory))
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
        {
            await runtime.UnenrollAsync(options.Value("--reason") ?? "Agent removed from the command line.", timeout.Token);
        }

        ConfFileBootstrapSource.Delete(LinuxComposition.ConfigPath);
        Console.WriteLine("The agent identity and enrollment settings were removed from this computer.");
        Console.WriteLine("The service stays stopped; remove the easypatch-agent package or run 'enroll' to use it again.");
        return ExitSuccess;
    }

    // ================================================================== misc

    public static int Version()
    {
        Console.WriteLine(LinuxComposition.AgentVersion);
        return ExitSuccess;
    }

    public static int Help()
    {
        Console.WriteLine($"""
            EasyPatch Agent {LinuxComposition.AgentVersion}

            Usage: easypatch-agent <command> [options]

              run                       Run the agent (default; used by the easypatch-agent systemd service).
              enroll --server <url> (--token-file <path|-> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
                                        Enroll this computer. A token enrolls immediately; a deployment code
                                        creates a request an administrator must approve in the console.
                                        The token is read from a file, from standard input (--token-file -)
                                        or from {TokenEnvironmentVariable}; it is never accepted as an argument.
              status [--json]           Show enrollment and agent status.
              scan [--json]             List the package updates this computer would report (refreshes the package
                                        lists; installs nothing and does not contact the server).
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
            var bytes = AtomicFile.TryReadAllBytes(Path.Combine(LinuxComposition.DataDirectory, "state", "agent-state.json"));
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
            var directory = Path.Combine(LinuxComposition.DataDirectory, "outbox");
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

    private static string ServiceState()
    {
        try
        {
            var result = Commands.RunAsync("systemctl", ["is-active", LinuxComposition.ServiceName + ".service"], TimeSpan.FromSeconds(30), CancellationToken.None)
                .GetAwaiter().GetResult();
            var text = result.StandardOutput.Trim();
            return text.Length == 0 ? "unknown" : text;
        }
        catch (CommandException)
        {
            return "unknown";
        }
    }

    private static async Task StopServiceAsync()
    {
        if (ServiceState() is "inactive" or "failed" or "unknown")
        {
            return;
        }

        Console.WriteLine($"Stopping the {LinuxComposition.ServiceName} service...");
        await SystemctlAsync("stop");
    }

    private static async Task SystemctlAsync(string verb)
    {
        try
        {
            var result = await Commands.RunAsync("systemctl", [verb, LinuxComposition.ServiceName + ".service"], ServiceTimeout, CancellationToken.None);
            if (!result.Succeeded)
            {
                Console.Error.WriteLine($"warning: systemctl {verb} {LinuxComposition.ServiceName} failed: {result.Combined.Trim()}");
            }
            else if (verb == "start")
            {
                Console.WriteLine($"The {LinuxComposition.ServiceName} service is running.");
            }
        }
        catch (CommandException ex)
        {
            Console.Error.WriteLine($"warning: systemctl {verb} {LinuxComposition.ServiceName}: {ex.Message}");
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
