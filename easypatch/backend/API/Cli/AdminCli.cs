using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Cli;

/// <summary>
/// Operational commands run with the server image: <c>migrate</c> and <c>prepare-import</c>. EasyPatch has no accounts or API tokens
/// of its own, so there are no commands for them.
/// </summary>
public static class AdminCli
{
    /// <summary>The commands EasyPatch had, with why each went. They are refused with a message rather than starting the server.</summary>
    private static readonly IReadOnlyDictionary<string, string> Removed = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["create-admin"] = NoAccounts,
        ["reset-password"] = NoAccounts,
        ["reset-mfa"] = NoAccounts,
        ["unlock"] = NoAccounts,
        ["create-api-token"] = "EasyPatch takes no API tokens. EasyRMM calls its patching engine itself; use EasyRMM's API.",
    };

    private const string NoAccounts = "EasyPatch has no accounts of its own. People sign in to EasyRMM.";

    public static readonly IReadOnlySet<string> Commands = new HashSet<string>(["migrate", "prepare-import", "help", .. Removed.Keys],
        StringComparer.Ordinal);

    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var command = args[0];
        if (command == "help")
        {
            PrintHelp();
            return 0;
        }

        if (Removed.TryGetValue(command, out var reason))
        {
            await Console.Error.WriteLineAsync($"'{command}' was removed: {reason}");
            return 2;
        }

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
            }
        }
        catch (AppException ex)
        {
            await Console.Error.WriteLineAsync($"Error: {ex.Message}");
            return 2;
        }

        PrintHelp();
        return 2;
    }

    private static void PrintHelp() => Console.WriteLine("""
        EasyPatch administration commands:
          migrate                                         Apply database migrations.
          prepare-import                                  For EasyRMM: check a restored standalone EasyPatch database, migrate it,
                                                          disable its accounts and delete its API tokens, before it becomes the
                                                          patching engine's.
        """);

    private sealed class CliActorContext : IActorContext
    {
        public Guid? UserId => null;
        public string? Username => "cli";
        public string? IpAddress => null;
        public string? CorrelationId => null;
    }
}
