using System.Security.Cryptography;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Platform;

/// <summary>
/// Protects the agent's private key at rest. Where <c>systemd-creds</c> is available (systemd 250+) the key is encrypted
/// with the machine's credential host key (<c>/var/lib/systemd/credential.secret</c>, root-only), so a copy of the agent's
/// data directory alone (a backup, for example) does not reveal it. Otherwise the key relies on file permissions only
/// (root-only directory, mode 0600), which inventory reports as <c>file-permissions</c>.
/// Each blob starts with a marker of the method that wrote it, so a key stays readable if the method changes later.
/// </summary>
public sealed class LinuxSecretProtector : ISecretProtector
{
    public const string SystemdCredsKind = "systemd-creds-host";
    public const string FilePermissionsKind = "file-permissions";

    private const string CredentialName = "easypatch-agent-key";
    private static readonly byte[] CredsMagic = "EPS1"u8.ToArray();
    private static readonly byte[] FileMagic = "EPF1"u8.ToArray();
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly ICommandRunner _commands;
    private readonly ILogger _logger;
    private readonly Lazy<bool> _credsAvailable;

    public LinuxSecretProtector(ICommandRunner commands, ILogger<LinuxSecretProtector> logger)
    {
        _commands = commands;
        _logger = logger;
        _credsAvailable = new Lazy<bool>(Probe);
    }

    public string Kind => _credsAvailable.Value ? SystemdCredsKind : FilePermissionsKind;

    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (_credsAvailable.Value)
        {
            var (exitCode, output, error) = Run(["encrypt", "--with-key=host", "--name=" + CredentialName, "-", "-"], plaintext);
            if (exitCode == 0 && output.Length > 0)
            {
                return [.. CredsMagic, .. output];
            }

            _logger.LogWarning("systemd-creds encrypt failed (exit code {ExitCode}): {Error}. Protecting the key with file permissions only.", exitCode, error.Trim());
        }

        return [.. FileMagic, .. plaintext];
    }

    public byte[] Unprotect(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        if (protectedData.AsSpan().StartsWith(FileMagic))
        {
            return protectedData[FileMagic.Length..];
        }

        if (protectedData.AsSpan().StartsWith(CredsMagic))
        {
            var (exitCode, output, error) = Run(["decrypt", "--name=" + CredentialName, "-", "-"], protectedData[CredsMagic.Length..]);
            if (exitCode != 0)
            {
                throw new CryptographicException($"systemd-creds could not decrypt the agent key (exit code {exitCode}): {error.Trim()}");
            }

            return output;
        }

        throw new CryptographicException("The agent key file has an unknown format.");
    }

    private bool Probe()
    {
        if (_commands.Find("systemd-creds") is null)
        {
            _logger.LogInformation("systemd-creds is not available (systemd older than 250); the agent key is protected by file permissions.");
            return false;
        }

        try
        {
            var probe = RandomNumberGenerator.GetBytes(16);
            var (encryptExit, encrypted, encryptError) = Run(["encrypt", "--with-key=host", "--name=" + CredentialName, "-", "-"], probe);
            if (encryptExit == 0)
            {
                var (decryptExit, decrypted, _) = Run(["decrypt", "--name=" + CredentialName, "-", "-"], encrypted);
                if (decryptExit == 0 && decrypted.AsSpan().SequenceEqual(probe))
                {
                    return true;
                }
            }

            _logger.LogWarning("systemd-creds is installed but did not work ({Error}); the agent key is protected by file permissions.", encryptError.Trim());
        }
        catch (CommandException ex)
        {
            _logger.LogWarning("systemd-creds is installed but did not work ({Message}); the agent key is protected by file permissions.", ex.Message);
        }

        return false;
    }

    private (int ExitCode, byte[] Output, string Error) Run(IReadOnlyList<string> arguments, byte[] input) =>
        _commands.RunBinaryAsync("systemd-creds", arguments, input, Timeout, CancellationToken.None).GetAwaiter().GetResult();
}
