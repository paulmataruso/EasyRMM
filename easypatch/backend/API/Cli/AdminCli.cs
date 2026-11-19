using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Cli;

/// <summary>
/// Operational commands run with the server image: <c>migrate</c>, <c>prepare-import</c> and <c>create-api-token</c>. EasyPatch has
/// no accounts of its own, so there are no account commands. A token is printed to the console once and is never logged.
/// </summary>
public static class AdminCli
{
    /// <summary>The account commands EasyPatch had. They are refused with a message rather than starting the server.</summary>
    private static readonly IReadOnlySet<string> Removed = new HashSet<string>(StringComparer.Ordinal)
    {
        "create-admin", "reset-password", "reset-mfa", "unlock",
    };

    public static readonly IReadOnlySet<string> Commands = new HashSet<string>(StringComparer.Ordinal)
    {
        "migrate", "prepare-import", "create-api-token", "help", "create-admin", "reset-password", "reset-mfa", "unlock",
    };

    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var command = args[0];
        if (command == "help")
        {
            PrintHelp();
            return 0;
        }

        if (Removed.Contains(command))
        {
            await Console.Error.WriteLineAsync($"'{command}' was removed: EasyPatch has no accounts of its own. People sign in to EasyRMM.");
            return 2;
        }

        var options = ParseOptions(args.Skip(1).ToArray());
        var builder = Host.CreateApplicationBuilder([]);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.None); // expected probe failures before first migration
        builder.Services.AddEasyPatchCore(builder.Configuration);
        builder.Services.AddEasyPatchDataProtection(builder.Configuration);
        builder.Services.AddScoped<IActorContext, CliActorContext>();
        builder.Services.AddScoped<ITenantContext, SystemTenantContext>();
        using var host = builder.Build();
        await using var scope = host.Services.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        try
        {
            switch (command)
            {
                case "migrate":
                {
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    var pending = await DatabaseSeeder.MigrateAsync(db, TimeProvider.System);
                    Console.WriteLine(pending.Count == 0 ? "Database schema is up to date." : $"Applied {pending.Count} migration(s): {string.Join(", ", pending)}");
                    return 0;
                }

                case "prepare-import":
                {
                    // A standalone EasyPatch's database, restored for EasyRMM's patching engine (EasyRMM's
                    // deploy/scripts/import-easypatch.sh runs this against the restored copy before it replaces the engine's).
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    ImportPreparationResult r;
                    try
                    {
                        r = await ImportPreparation.PrepareAsync(db, TimeProvider.System);
                    }
                    catch (ImportRefusedException e)
                    {
                        await Console.Error.WriteLineAsync(e.Message);
                        return 3;
                    }

                    Console.WriteLine($"From EasyPatch {r.ReleaseBefore ?? "(last migration " + r.LastMigrationBefore + ")"}; " +
                                      $"{r.Applied.Count} migration(s) applied.");
                    Console.WriteLine($"{r.Organizations} organization(s) ({r.ArchivedOrganizations} archived besides), {r.Sites} site(s), " +
                                      $"{r.ActiveEndpoints} active endpoint(s).");
                    Console.WriteLine($"{r.AccountsDisabled} EasyPatch account(s) disabled: people sign in to EasyRMM." +
                                      (r.EmailsRenamed > 0 ? $" {r.EmailsRenamed} duplicate address(es) renamed." : ""));
                    return 0;
                }

                case "create-api-token":
                {
                    var request = ParseApiTokenOptions(options);
                    var tokens = sp.GetRequiredService<ApiTokenService>();
                    var (token, secret) = await tokens.CreateAsync(request.Name, request.Role, request.OrganizationIds, request.ExpiresInDays);
                    var reach = token.AllOrganizations ? "all organizations" : $"{token.OrganizationIds.Count} organization(s)";
                    var role = token.Role == UserRole.Admin ? "Operator" : "Read only";
                    Console.WriteLine($"Created API token '{token.Name}' ({role}, {reach}, expires {token.ExpiresAt:yyyy-MM-dd}).");
                    Console.WriteLine($"Token (shown once, only its hash is stored): {secret}");
                    return 0;
                }
            }
        }
        catch (AppException ex)
        {
            await Console.Error.WriteLineAsync($"Error: {ex.Message}");
            return 2;
        }
        catch (ArgumentException ex)
        {
            await Console.Error.WriteLineAsync($"Error: {ex.Message}");
            PrintHelp();
            return 2;
        }

        PrintHelp();
        return 2;
    }

    private static void PrintHelp() => Console.WriteLine("""
        EasyPatch administration commands:
          migrate                                         Apply database migrations.
          prepare-import                                  For EasyRMM: check a restored standalone EasyPatch database, migrate it
                                                          and disable its accounts, before it becomes the patching engine's.
          create-api-token --name <name> --role <operator|read-only> --expires-days <1-365> [--organizations <id,id,...>]
                                                          Create an API token for a script or integration and print it once.
                                                          Without --organizations it reaches every organization. The audit log
                                                          records it as created by "cli".
        """);

    private static Dictionary<string, string?> ParseOptions(string[] args)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = args[i][2..];
            result[key] = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
        }

        return result;
    }

    private static string Require(Dictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) && value != "true"
            ? value
            : throw new ArgumentException($"--{key} is required.");

    /// <summary>What <c>create-api-token</c> asks for: a name, a role (never SuperAdmin), a lifetime and optionally organizations.</summary>
    internal sealed record ApiTokenOptions(string Name, UserRole Role, IReadOnlyCollection<Guid> OrganizationIds, int ExpiresInDays);

    internal static ApiTokenOptions ParseApiTokenOptions(Dictionary<string, string?> options)
    {
        var name = Require(options, "name").Trim();
        if (name.Length > ApiTokenService.MaxNameLength || name.Any(char.IsControl))
        {
            throw new ArgumentException($"--name must be at most {ApiTokenService.MaxNameLength} characters, without control characters.");
        }

        var role = Require(options, "role").ToLowerInvariant() switch
        {
            "operator" or "admin" => UserRole.Admin,
            "read-only" or "readonly" => UserRole.ReadOnly,
            _ => throw new ArgumentException("--role must be operator or read-only. A token is never a super administrator."),
        };
        if (!int.TryParse(Require(options, "expires-days"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var days)
            || days < 1 || days > ApiTokenService.MaxLifetimeDays)
        {
            throw new ArgumentException($"--expires-days must be a whole number from 1 to {ApiTokenService.MaxLifetimeDays}.");
        }

        var organizations = new List<Guid>();
        foreach (var part in (Optional(options, "organizations") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            organizations.Add(Guid.TryParse(part, out var id) ? id : throw new ArgumentException($"--organizations: '{part}' is not an organization id."));
        }

        return organizations.Count > 500
            ? throw new ArgumentException("--organizations: at most 500 organizations.")
            : new ApiTokenOptions(name, role, organizations.Distinct().ToList(), days);
    }

    private static string? Optional(Dictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) && value != "true" ? value : null;

    private sealed class CliActorContext : IActorContext
    {
        public Guid? UserId => null;
        public string? Username => "cli";
        public string? IpAddress => null;
        public string? CorrelationId => null;
    }
}
