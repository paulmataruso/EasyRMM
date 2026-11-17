using System.Security.Cryptography;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Cli;

/// <summary>
/// Operational commands run with the API image, for example <c>docker compose run --rm migrate</c> or
/// <c>docker compose run --rm api create-admin --email admin@example.com</c>. Users are found by their email address, the
/// only name they sign in with.
/// Generated passwords are printed to the console once and are never logged.
/// </summary>
public static class AdminCli
{
    public static readonly IReadOnlySet<string> Commands = new HashSet<string>(StringComparer.Ordinal)
    {
        "migrate", "create-admin", "reset-password", "reset-mfa", "unlock", "help",
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

        var options = ParseOptions(args.Skip(1).ToArray());
        var builder = Host.CreateApplicationBuilder([]);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.None); // expected probe failures before first migration
        builder.Services.AddEasyPatchCore(builder.Configuration);
        builder.Services.AddEasyPatchDataProtection(builder.Configuration);
        builder.Services.AddScoped<IActorContext, CliActorContext>();
        builder.Services.AddScoped<ITenantContext, SystemTenantContext>();
        builder.Services.AddScoped<AuthService>();
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

                case "create-admin":
                {
                    var email = Require(options, "email");
                    // --username is the older name of --name (the account name shown in the console and the audit log).
                    var name = Optional(options, "name") ?? Optional(options, "username") ?? NameFromEmail(email);
                    var auth = sp.GetRequiredService<AuthService>();
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    var (password, generated) = await ReadOrGeneratePasswordAsync(options);
                    var user = await auth.CreateUserAsync(name, email, UserRole.SuperAdmin, password);
                    if (generated)
                    {
                        var tracked = await db.Users.FirstAsync(u => u.Id == user.Id);
                        tracked.MustChangePassword = true;
                        await db.SaveChangesAsync();
                    }

                    Console.WriteLine($"Created SuperAdmin '{user.Username}'. Sign in with {user.Email}.");
                    PrintPassword(password, generated);
                    return 0;
                }

                case "reset-password":
                {
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    var hasher = sp.GetRequiredService<IPasswordHasher>();
                    var auth = sp.GetRequiredService<AuthService>();
                    var user = await FindUserAsync(db, options);
                    var (password, generated) = await ReadOrGeneratePasswordAsync(options);
                    var problem = PasswordPolicy.Validate(password, user.Username);
                    if (problem is not null)
                    {
                        await Console.Error.WriteLineAsync(problem);
                        return 2;
                    }

                    user.PasswordHash = hasher.Hash(password);
                    user.PasswordChangedAt = DateTimeOffset.UtcNow;
                    user.MustChangePassword = generated;
                    user.FailedLoginCount = 0;
                    user.LockoutUntil = null;
                    sp.GetRequiredService<AuditService>().Record("cli.reset_password", "User", user.Id.ToString());
                    await db.SaveChangesAsync();
                    await auth.RevokeSessionsAsync(user.Id, null);
                    Console.WriteLine($"Password for {user.Email} was reset and all sessions were revoked.");
                    PrintPassword(password, generated);
                    return 0;
                }

                case "reset-mfa":
                {
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    var auth = sp.GetRequiredService<AuthService>();
                    var user = await FindUserAsync(db, options);
                    await auth.ResetMfaAsync(user.Id);
                    await auth.RevokeSessionsAsync(user.Id, null);
                    Console.WriteLine($"Multi-factor authentication for {user.Email} was reset. They must enroll again at next sign-in.");
                    return 0;
                }

                case "unlock":
                {
                    var db = sp.GetRequiredService<EasyPatchDbContext>();
                    var user = await FindUserAsync(db, options);
                    user.LockoutUntil = null;
                    user.FailedLoginCount = 0;
                    user.LockoutCount = 0;
                    sp.GetRequiredService<AuditService>().Record("cli.unlock", "User", user.Id.ToString());
                    await db.SaveChangesAsync();
                    Console.WriteLine($"{user.Email} was unlocked.");
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
          create-admin --email <email> [--name <name>] [--password-stdin]
                                                          Create a SuperAdmin who signs in with <email>. <name> is the account
                                                          name shown in the console and the audit log (default: the part of the
                                                          address before '@'). Without --password-stdin a strong temporary
                                                          password is generated, printed once, and must be changed at first sign-in.
          reset-password --email <email> [--password-stdin]
          reset-mfa --email <email>                       Remove MFA (authenticator app, security keys and passkeys) so the
                                                          user enrolls again at next sign-in.
          unlock --email <email>                          Clear a login lockout.
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

    private static async Task<(string Password, bool Generated)> ReadOrGeneratePasswordAsync(Dictionary<string, string?> options)
    {
        if (options.ContainsKey("password-stdin"))
        {
            var line = (await Console.In.ReadLineAsync())?.TrimEnd('\r', '\n');
            return string.IsNullOrEmpty(line) ? throw new ArgumentException("No password was provided on standard input.") : (line, false);
        }

        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        var chars = new char[20];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return (new string(chars), true);
    }

    private static void PrintPassword(string password, bool generated)
    {
        if (generated)
        {
            Console.WriteLine($"Temporary password (shown once, must be changed at first sign-in): {password}");
        }
    }

    private static string? Optional(Dictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) && value != "true" ? value : null;

    /// <summary>The default account name: the part of the address before '@', with characters a username cannot have
    /// replaced by '-'.</summary>
    internal static string NameFromEmail(string email)
    {
        var local = AuthService.NormalizeEmail(email).Split('@')[0];
        var name = new string(local.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '-').ToArray());
        return name.Length > 64 ? name[..64] : name;
    }

    /// <summary>Users are found by email address. <c>--username</c> is refused with a hint instead of being ignored.</summary>
    private static async Task<User> FindUserAsync(EasyPatchDbContext db, Dictionary<string, string?> options)
    {
        if (!options.ContainsKey("email") && options.ContainsKey("username"))
        {
            throw new ArgumentException("Users are now identified by email address: use --email <address> instead of --username.");
        }

        var normalized = AuthService.NormalizeEmail(Require(options, "email"));
        return await db.Users.FirstOrDefaultAsync(u => u.Email == normalized) ?? throw AppException.NotFound($"User with email '{normalized}'");
    }

    private sealed class CliActorContext : IActorContext
    {
        public Guid? UserId => null;
        public string? Username => "cli";
        public string? IpAddress => null;
        public string? CorrelationId => null;
    }
}
