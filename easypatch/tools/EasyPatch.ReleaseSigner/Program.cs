using System.Security.Cryptography;
using System.Text.Json;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;

// easypatch-release: the release key for agent self-update.
//
//   generate-key [--out <private.pem>]              create a key pair (refuses to overwrite)
//   sign --key <private.pem> <package>...            write <package>.sig next to each package
//   verify --public-key <public.pem> <package>...    check packages and their .sig files
//   public-key --key <private.pem>                   print the public key (PEM)
//
// Packages are agent packages: EasyPatchAgent-<version>-<x64|arm64>.<msi|deb|rpm|pkg>.
// The private key must stay on the build machine. Set EASYPATCH_RELEASE_KEY_PASSWORD to encrypt it (generate-key) and
// to read an encrypted key (sign, public-key).

const int ExitOk = 0, ExitFailed = 1;
const string PasswordVariable = "EASYPATCH_RELEASE_KEY_PASSWORD";

var defaultKey = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".easypatch", "easypatch-release-key.pem");
var json = new JsonSerializerOptions(ContractJson.Options) { WriteIndented = true };

try
{
    if (args.Length == 0)
    {
        return Usage();
    }

    var (options, files) = Parse(args[1..]);
    return args[0] switch
    {
        "generate-key" => GenerateKey(options.GetValueOrDefault("out") ?? defaultKey),
        "sign" => Sign(options.GetValueOrDefault("key") ?? defaultKey, files),
        "verify" => Verify(options.GetValueOrDefault("public-key") ?? PublicKeyPath(defaultKey), files),
        "public-key" => PrintPublicKey(options.GetValueOrDefault("key") ?? defaultKey),
        "help" or "--help" or "-h" => Usage(),
        _ => Usage($"unknown command '{args[0]}'"),
    };
}
catch (UsageException ex)
{
    return Usage(ex.Message);
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or JsonException)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return ExitFailed;
}

int GenerateKey(string privatePath)
{
    var publicPath = PublicKeyPath(privatePath);
    if (File.Exists(privatePath) || File.Exists(publicPath))
    {
        Console.Error.WriteLine($"error: {privatePath} or {publicPath} already exists. Agents trust the existing key; move it away first if you really mean to replace it.");
        return ExitFailed;
    }

    var directory = Path.GetDirectoryName(Path.GetFullPath(privatePath))!;
    if (!Directory.Exists(directory))
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var password = Environment.GetEnvironmentVariable(PasswordVariable);
    var privatePem = string.IsNullOrEmpty(password)
        ? key.ExportPkcs8PrivateKeyPem()
        : key.ExportEncryptedPkcs8PrivateKeyPem(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
    WritePrivate(privatePath, privatePem + "\n");
    File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem() + "\n");

    Console.WriteLine($"Release key {AgentRelease.KeyId(key)} created.");
    Console.WriteLine($"  private key: {privatePath}{(string.IsNullOrEmpty(password) ? " (not encrypted: set " + PasswordVariable + " to encrypt it)" : " (encrypted)")}");
    Console.WriteLine($"  public key:  {publicPath}");
    Console.WriteLine("Keep the private key off the EasyPatch server and back it up offline. Agents built with the public key only install updates signed with it.");
    return ExitOk;
}

int Sign(string privatePath, IReadOnlyList<string> packages)
{
    if (packages.Count == 0)
    {
        throw new UsageException("sign needs at least one agent package");
    }

    using var key = LoadPrivateKey(privatePath);
    var keyId = AgentRelease.KeyId(key);
    foreach (var package in packages)
    {
        var manifest = AgentRelease.Describe(package);
        var signature = new AgentReleaseSignature { KeyId = keyId, Manifest = manifest, Signature = AgentRelease.Sign(manifest, key) };
        var output = package + AgentRelease.SignatureExtension;
        File.WriteAllText(output, JsonSerializer.Serialize(signature, json) + "\n");
        Console.WriteLine($"Signed {manifest.FileName} ({manifest.SizeBytes} bytes, SHA-256 {manifest.Sha256}) with release key {keyId}: {output}");
    }

    return ExitOk;
}

int Verify(string publicPath, IReadOnlyList<string> packages)
{
    if (packages.Count == 0)
    {
        throw new UsageException("verify needs at least one agent package");
    }

    var keys = AgentRelease.ParsePublicKeys(File.ReadAllText(publicPath));
    try
    {
        if (keys.Count == 0)
        {
            throw new CryptographicException($"{publicPath} contains no public key.");
        }

        var failed = 0;
        foreach (var package in packages)
        {
            var problem = Check(package, keys);
            Console.WriteLine(problem is null ? $"OK      {Path.GetFileName(package)}" : $"FAILED  {Path.GetFileName(package)}: {problem}");
            failed += problem is null ? 0 : 1;
        }

        return failed == 0 ? ExitOk : ExitFailed;
    }
    finally
    {
        foreach (var key in keys)
        {
            key.Dispose();
        }
    }
}

string? Check(string package, IReadOnlyList<ECDsa> keys)
{
    var sigPath = package + AgentRelease.SignatureExtension;
    if (!File.Exists(sigPath))
    {
        return $"{Path.GetFileName(sigPath)} not found";
    }

    var signature = JsonSerializer.Deserialize<AgentReleaseSignature>(File.ReadAllText(sigPath), ContractJson.Options);
    if (signature is null || signature.Format != AgentRelease.SignatureFormat)
    {
        return "unsupported signature file";
    }

    if (AgentRelease.Describe(package) != signature.Manifest)
    {
        return "the package does not match its signature file (name, version, size or hash differ)";
    }

    var key = keys.FirstOrDefault(k => AgentRelease.KeyId(k) == signature.KeyId);
    if (key is null)
    {
        return $"signed with release key {signature.KeyId}, which is not in the public key file";
    }

    return AgentRelease.Verify(signature.Manifest, signature.Signature, key) ? null : "the signature is not valid";
}

int PrintPublicKey(string privatePath)
{
    using var key = LoadPrivateKey(privatePath);
    Console.Write(key.ExportSubjectPublicKeyInfoPem() + "\n");
    Console.Error.WriteLine($"Release key {AgentRelease.KeyId(key)}");
    return ExitOk;
}

ECDsa LoadPrivateKey(string path)
{
    if (!File.Exists(path))
    {
        throw new IOException($"Release key {path} not found. Create one with: easypatch-release generate-key");
    }

    var pem = File.ReadAllText(path);
    var key = ECDsa.Create();
    try
    {
        if (pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
        {
            var password = Environment.GetEnvironmentVariable(PasswordVariable);
            if (string.IsNullOrEmpty(password))
            {
                throw new CryptographicException($"{path} is encrypted; set {PasswordVariable}.");
            }

            key.ImportFromEncryptedPem(pem, password);
        }
        else
        {
            key.ImportFromPem(pem);
        }

        if (key.KeySize != 256)
        {
            throw new CryptographicException($"{path} is not an ECDSA P-256 key.");
        }

        return key;
    }
    catch
    {
        key.Dispose();
        throw;
    }
}

static string PublicKeyPath(string privatePath) =>
    privatePath.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ? privatePath[..^4] + ".pub.pem" : privatePath + ".pub.pem";

static void WritePrivate(string path, string content)
{
    var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
    if (!OperatingSystem.IsWindows())
    {
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    }

    using var writer = new StreamWriter(path, System.Text.Encoding.ASCII, options);
    writer.Write(content);
}

static (Dictionary<string, string> Options, List<string> Files) Parse(string[] arguments)
{
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    var files = new List<string>();
    for (var i = 0; i < arguments.Length; i++)
    {
        if (arguments[i].StartsWith("--", StringComparison.Ordinal))
        {
            if (i + 1 >= arguments.Length)
            {
                throw new UsageException($"{arguments[i]} needs a value");
            }

            options[arguments[i][2..]] = arguments[++i];
        }
        else
        {
            files.Add(arguments[i]);
        }
    }

    return (options, files);
}

static int Usage(string? error = null)
{
    if (error is not null)
    {
        Console.Error.WriteLine($"error: {error}");
    }

    Console.Error.WriteLine("""
        usage: easypatch-release <command>
          generate-key [--out <private.pem>]              create the release key (default ~/.easypatch/easypatch-release-key.pem)
          sign [--key <private.pem>] <package>...         write <package>.sig for each agent package
          verify [--public-key <public.pem>] <package>... check packages against their .sig files
          public-key [--key <private.pem>]                print the public key
        Agent packages: EasyPatchAgent-<version>-<x64|arm64>.<msi|deb|rpm|pkg>.
        EASYPATCH_RELEASE_KEY_PASSWORD encrypts a new key and unlocks an encrypted one.
        """);
    return error is null ? 0 : 2;
}

internal sealed class UsageException(string message) : Exception(message);
