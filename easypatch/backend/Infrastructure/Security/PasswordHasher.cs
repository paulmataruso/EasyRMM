using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace EasyPatch.Infrastructure.Security;

public interface IPasswordHasher
{
    string Hash(string password);

    PasswordVerification Verify(string password, string encodedHash);
}

public enum PasswordVerification
{
    Failed,
    Success,
    SuccessRehashNeeded,
}

/// <summary>Argon2id password hashing (PHC string format). Parameters follow OWASP guidance (m=19 MiB, t=2, p=1).</summary>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    private const int MemoryKib = 19 * 1024;
    private const int Iterations = 2;
    private const int Parallelism = 1;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Compute(password, salt, MemoryKib, Iterations, Parallelism, HashBytes);
        return $"$argon2id$v=19$m={MemoryKib},t={Iterations},p={Parallelism}${B64(salt)}${B64(hash)}";
    }

    public PasswordVerification Verify(string password, string encodedHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (string.IsNullOrEmpty(encodedHash))
        {
            return PasswordVerification.Failed;
        }

        var parts = encodedHash.Split('$');
        // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        if (parts.Length != 6 || parts[1] != "argon2id" || parts[2] != "v=19")
        {
            return PasswordVerification.Failed;
        }

        int m = 0, t = 0, p = 0;
        foreach (var kv in parts[3].Split(','))
        {
            var pair = kv.Split('=');
            if (pair.Length != 2 || !int.TryParse(pair[1], out var value))
            {
                return PasswordVerification.Failed;
            }

            switch (pair[0])
            {
                case "m": m = value; break;
                case "t": t = value; break;
                case "p": p = value; break;
            }
        }

        if (m is < 1024 or > 1024 * 1024 || t is < 1 or > 20 || p is < 1 or > 16)
        {
            return PasswordVerification.Failed;
        }

        byte[] salt, expected;
        try
        {
            salt = FromB64(parts[4]);
            expected = FromB64(parts[5]);
        }
        catch (FormatException)
        {
            return PasswordVerification.Failed;
        }

        var actual = Compute(password, salt, m, t, p, expected.Length);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return PasswordVerification.Failed;
        }

        return m != MemoryKib || t != Iterations || p != Parallelism || expected.Length != HashBytes
            ? PasswordVerification.SuccessRehashNeeded
            : PasswordVerification.Success;
    }

    private static byte[] Compute(string password, byte[] salt, int memoryKib, int iterations, int parallelism, int length)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon.GetBytes(length);
    }

    private static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] FromB64(string value)
    {
        var padded = value.PadRight(value.Length + ((4 - (value.Length % 4)) % 4), '=');
        return Convert.FromBase64String(padded);
    }
}

public static class PasswordPolicy
{
    public const int MinimumLength = 12;
    public const int MaximumLength = 256;

    public static string? Validate(string? password, string? username)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinimumLength)
        {
            return $"Password must be at least {MinimumLength} characters.";
        }

        if (password.Length > MaximumLength)
        {
            return $"Password must be at most {MaximumLength} characters.";
        }

        if (!string.IsNullOrEmpty(username) && password.Contains(username, StringComparison.OrdinalIgnoreCase))
        {
            return "Password must not contain the username.";
        }

        if (password.Distinct().Count() < 4)
        {
            return "Password is too repetitive.";
        }

        return null;
    }
}
