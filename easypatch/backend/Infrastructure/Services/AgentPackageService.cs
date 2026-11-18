using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Services;

public sealed class EasyPatchOptions
{
    public const string Section = "EasyPatch";

    /// <summary>Public HTTPS base URL agents and installers use, e.g. https://patches.example.com.</summary>
    public string PublicUrl { get; set; } = "https://localhost";

    /// <summary>Directory containing agent packages (EasyPatchAgent-&lt;version&gt;-&lt;arch&gt;.&lt;msi|deb|rpm|pkg&gt;), each
    /// optionally with its release signature (<c>.sig</c>).</summary>
    public string AgentPackagesPath { get; set; } = "/app/agent-packages";

    /// <summary>The worker's copy of the pinned winget release (writable by the worker, read-only for the API). Files an
    /// administrator places in <c>&lt;AgentPackagesPath&gt;/winget</c> are served too.</summary>
    public string WingetCachePath { get; set; } = "/app/winget";

    /// <summary>At most this many automatic agent updates run at the same time (spreads the downloads).</summary>
    public int AutomaticAgentUpdateConcurrency { get; set; } = 25;
}

/// <param name="Release">The release signature file, when present and describing exactly this file. The server never
/// checks the signature itself (it has no release key); agents do.</param>
/// <param name="SignatureProblem">Why a <c>.sig</c> file next to the package was ignored.</param>
/// <param name="Format">msi, deb, rpm or pkg (<see cref="AgentRelease.PackageFormats"/>).</param>
public sealed record AgentPackage(string FileName, string Version, string Architecture, long SizeBytes, string Sha256, DateTimeOffset ModifiedAt,
    AgentReleaseSignature? Release = null, string? SignatureProblem = null, string Format = AgentRelease.FormatMsi);

/// <summary>Lists agent packages (MSI, deb, rpm, and pkg for the experimental macOS agent) placed in the packages directory (mounted
/// read-only into the API container).</summary>
public sealed partial class AgentPackageService(IOptions<EasyPatchOptions> options, TimeProvider clock, ILogger<AgentPackageService> logger)
{
    private readonly ConcurrentDictionary<string, (long Length, DateTime Modified, string Sha256)> hashes = new();
    private readonly ConcurrentDictionary<string, string> reportedProblems = new(StringComparer.Ordinal);
    private IReadOnlyList<AgentPackage> cached = [];
    private DateTimeOffset cachedAt = DateTimeOffset.MinValue;
    private readonly Lock gate = new();

    [GeneratedRegex(@"^EasyPatchAgent-(?<version>\d+\.\d+\.\d+(?:\.\d+)?)-(?<arch>x64|arm64)\.(?<format>msi|deb|rpm|pkg)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FileNamePattern();

    public IReadOnlyList<AgentPackage> List()
    {
        lock (gate)
        {
            if (clock.GetUtcNow() - cachedAt < TimeSpan.FromSeconds(60))
            {
                return cached;
            }

            cached = Scan();
            cachedAt = clock.GetUtcNow();
            return cached;
        }
    }

    /// <summary>The newest package for an architecture and format (by default the x64 MSI).</summary>
    public AgentPackage? GetLatest(string architecture = "x64", string format = AgentRelease.FormatMsi) =>
        List().Where(p => p.Architecture.Equals(architecture, StringComparison.OrdinalIgnoreCase) &&
                          p.Format.Equals(format, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(p => Version.TryParse(p.Version, out var v) ? v : new Version(0, 0))
            .FirstOrDefault();

    /// <summary>The newest agent version among the packages of one format (the version agents of that kind should run).</summary>
    public string? GetLatestVersion(string format = AgentRelease.FormatMsi) =>
        List().Where(p => p.Format.Equals(format, StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Version)
            .OrderByDescending(v => Version.TryParse(v, out var parsed) ? parsed : new Version(0, 0))
            .FirstOrDefault();

    /// <summary>
    /// The listed package with this file name. A package file copied in after the last scan is found too: the worker keeps
    /// its own list and may already have offered it to agents, so a cache miss rescans the folder (at most once a second).
    /// </summary>
    public AgentPackage? Find(string fileName)
    {
        var package = FindIn(List(), fileName);
        if (package is not null || string.IsNullOrEmpty(fileName) || !FileNamePattern().IsMatch(fileName) ||
            !File.Exists(Path.Combine(options.Value.AgentPackagesPath, fileName)))
        {
            return package;
        }

        lock (gate)
        {
            if (clock.GetUtcNow() - cachedAt >= MinimumRescanInterval)
            {
                cached = Scan();
                cachedAt = clock.GetUtcNow();
            }

            return FindIn(cached, fileName);
        }
    }

    private static readonly TimeSpan MinimumRescanInterval = TimeSpan.FromSeconds(1);

    private static AgentPackage? FindIn(IReadOnlyList<AgentPackage> packages, string fileName) =>
        packages.FirstOrDefault(p => p.FileName.Equals(fileName, StringComparison.OrdinalIgnoreCase));

    /// <summary>Resolves a package file path, refusing anything that is not a listed package (no path traversal).</summary>
    public string? GetPath(string fileName)
    {
        var package = Find(fileName);
        return package is null ? null : Path.Combine(options.Value.AgentPackagesPath, package.FileName);
    }

    private List<AgentPackage> Scan()
    {
        var dir = options.Value.AgentPackagesPath;
        var result = new List<AgentPackage>();
        if (!Directory.Exists(dir))
        {
            return result;
        }

        foreach (var path in Directory.EnumerateFiles(dir, "EasyPatchAgent-*"))
        {
            var name = Path.GetFileName(path);
            if (name.EndsWith(AgentRelease.SignatureExtension, StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var match = FileNamePattern().Match(name);
            if (!match.Success)
            {
                logger.LogWarning("Ignoring agent package with unexpected name {FileName}", name);
                continue;
            }

            try
            {
                var info = new FileInfo(path);
                var key = info.FullName;
                if (!hashes.TryGetValue(key, out var entry) || entry.Length != info.Length || entry.Modified != info.LastWriteTimeUtc)
                {
                    using var stream = info.OpenRead();
                    entry = (info.Length, info.LastWriteTimeUtc, Convert.ToHexString(SHA256.HashData(stream)));
                    hashes[key] = entry;
                }

                var (release, problem) = ReadSignature(path, name, info.Length, entry.Sha256);
                result.Add(new AgentPackage(name, match.Groups["version"].Value, match.Groups["arch"].Value.ToLowerInvariant(),
                    info.Length, entry.Sha256, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), release, problem,
                    match.Groups["format"].Value.ToLowerInvariant()));
            }
            catch (IOException ex)
            {
                logger.LogWarning(ex, "Could not read agent package {FileName}", name);
            }
        }

        return result;
    }

    /// <summary>Reads <c>&lt;package&gt;.sig</c> and checks that it describes this exact file.</summary>
    private (AgentReleaseSignature? Release, string? Problem) ReadSignature(string packagePath, string fileName, long size, string sha256)
    {
        var path = packagePath + AgentRelease.SignatureExtension;
        if (!File.Exists(path))
        {
            return (null, null);
        }

        string? problem;
        try
        {
            var info = new FileInfo(path);
            if (info.Length > 16 * 1024)
            {
                problem = "The signature file is too large.";
            }
            else
            {
                var signature = JsonSerializer.Deserialize<AgentReleaseSignature>(File.ReadAllText(path), ContractJson.Options);
                problem = signature switch
                {
                    null => "The signature file is empty.",
                    { Format: not AgentRelease.SignatureFormat } => $"Unsupported signature format {signature.Format}.",
                    _ when !AgentRelease.IsKeyId(signature.KeyId) => "The signature file has no valid key ID.",
                    _ when AgentRelease.Validate(signature.Manifest) is [var error, ..] => error,
                    _ when signature.Manifest.FileName != fileName => "The signature file is for a different package.",
                    _ when signature.Manifest.SizeBytes != size || !signature.Manifest.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase) =>
                        "The package does not match its signature file (it was changed or rebuilt after signing).",
                    _ when string.IsNullOrEmpty(signature.Signature) => "The signature file has no signature.",
                    _ => null,
                };
                if (problem is null)
                {
                    return (signature, null);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            problem = "The signature file could not be read.";
        }

        if (!reportedProblems.TryGetValue(fileName, out var reported) || reported != problem)
        {
            reportedProblems[fileName] = problem;
            logger.LogWarning("Ignoring the release signature of agent package {FileName}: {Problem}", fileName, problem);
        }

        return (null, problem);
    }
}

/// <summary>Builds the tokenless PowerShell installer used by RMM tools. The script verifies the MSI SHA-256 (and,
/// optionally, its Authenticode signature) before installing; the endpoint then waits for approval.
/// <para><paramref name="skipCertificateCheck"/> is for servers whose certificate the endpoint does not trust (a private CA,
/// such as Caddy's internal one in the lab configuration): the one-liner and the script then download without checking the
/// certificate, and the script passes the certificate authority the proxy publishes at <c>/server-ca.crt</c> to the MSI
/// (SERVERCACERT), so the agent trusts that authority for its own connection to EasyPatch only and keeps checking
/// certificates afterwards.</para></summary>
public static class InstallScriptBuilder
{
    /// <summary>Published by the lab proxy (Caddyfile.dev): the root certificate of Caddy's internal CA.</summary>
    public const string ServerCaPath = "/server-ca.crt";

    public static string Build(string publicUrl, AgentPackage package, string deploymentCode, string label, bool requireSignature, DateTimeOffset generatedAt,
        bool skipCertificateCheck = false)
    {
        ArgumentNullException.ThrowIfNull(package);
        var server = publicUrl.TrimEnd('/');
        static string Q(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        var sb = new StringBuilder();
        sb.AppendLine("#Requires -Version 5.1");
        sb.AppendLine($"# EasyPatch agent installer for deployment code {deploymentCode} ({label.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal)})");
        sb.AppendLine($"# Generated {generatedAt:u}. The endpoint will appear under Pending Approvals in the EasyPatch console.");
        sb.AppendLine("# This script contains no secrets: an administrator must approve the endpoint before it is managed.");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");
        sb.AppendLine("try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 -bor 12288 } catch { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 }");
        sb.AppendLine($"$ServerUrl = {Q(server)}");
        sb.AppendLine($"$DeploymentCode = {Q(deploymentCode)}");
        sb.AppendLine($"$PackageUrl = {Q($"{server}/downloads/agent/{Uri.EscapeDataString(package.FileName)}")}");
        sb.AppendLine($"$ExpectedSha256 = {Q(package.Sha256)}");
        sb.AppendLine($"$RequireSignature = ${(requireSignature ? "true" : "false")}");
        sb.AppendLine($"$SkipCertificateCheck = ${(skipCertificateCheck ? "true" : "false")}");
        sb.AppendLine($"$ServerCaUrl = {Q(server + ServerCaPath)}");
        sb.AppendLine("""
            $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script as Administrator or SYSTEM.' }
            if (-not [Environment]::Is64BitOperatingSystem) { throw 'The EasyPatch agent requires 64-bit Windows.' }
            $work = Join-Path $env:TEMP ('EasyPatch-' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $work -Force | Out-Null
            $msi = Join-Path $work 'EasyPatchAgent.msi'
            $log = Join-Path $env:TEMP 'EasyPatchAgent-install.log'
            function Save-EasyPatchFile([string]$Uri, [string]$Path) {
                $download = @{ Uri = $Uri; OutFile = $Path; UseBasicParsing = $true }
                if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $download.SkipCertificateCheck = $true }
                Invoke-WebRequest @download
            }
            try {
                $serverCa = $null
                if ($SkipCertificateCheck) {
                    Write-Warning 'Skip certificate check: the downloads below do not check the server certificate. Use this only on a network you trust.'
                    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    # The certificate authority the agent will trust for its own connection to EasyPatch (and nothing else).
                    $caFile = Join-Path $work 'server-ca.crt'
                    try {
                        Save-EasyPatchFile $ServerCaUrl $caFile
                        $ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $caFile
                        $constraints = @($ca.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] })
                        if ($constraints.Count -eq 0 -or -not $constraints[0].CertificateAuthority) { throw 'it is not a certificate authority certificate' }
                        $serverCa = [Convert]::ToBase64String($ca.RawData)
                        $caHash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($ca.RawData))) -replace '-', ''
                        Write-Output "The agent will trust this certificate authority for its connection to EasyPatch only: $($ca.Subject), SHA-256 $caHash"
                    }
                    catch {
                        Write-Warning "The server does not publish its certificate authority at $ServerCaUrl ($($_.Exception.Message)). The agent will connect only if Windows trusts the server certificate."
                    }
                }
                Write-Output "Downloading $PackageUrl"
                Save-EasyPatchFile $PackageUrl $msi
                $hash = (Get-FileHash -Path $msi -Algorithm SHA256).Hash
                if ($hash -ne $ExpectedSha256) { throw "Package hash $hash does not match the expected $ExpectedSha256. Aborting." }
                if ($RequireSignature) {
                    $sig = Get-AuthenticodeSignature -FilePath $msi
                    if ($sig.Status -ne 'Valid') { throw "Package signature is not valid ($($sig.Status)): $($sig.StatusMessage)" }
                    Write-Output "Package signed by: $($sig.SignerCertificate.Subject)"
                }
                $arguments = @('/i', "`"$msi`"", '/qn', '/norestart', "SERVERURL=$ServerUrl", "DEPLOYMENTCODE=$DeploymentCode", '/l*v', "`"$log`"")
                if ($serverCa) { $arguments += "SERVERCACERT=$serverCa" }
                $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
                if (@(0, 1641, 3010) -notcontains $process.ExitCode) { throw "msiexec failed with exit code $($process.ExitCode). See $log" }
            }
            finally {
                if ($SkipCertificateCheck) { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
                Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
            }
            $agent = Join-Path $env:ProgramFiles 'EasyPatch Agent\EasyPatch.Agent.exe'
            for ($i = 0; $i -lt 12; $i++) {
                Start-Sleep -Seconds 5
                if (Test-Path $agent) {
                    $status = & $agent status 2>&1 | Out-String
                    if ($status -match 'Fingerprint') { Write-Output $status; break }
                }
            }
            Write-Output 'EasyPatch agent installed. Approve this endpoint in the EasyPatch console (Pending Approvals) after comparing the key fingerprint.'
            exit 0
            """);
        return sb.ToString();
    }

    /// <summary>The script's download URL, with the options it was generated for.</summary>
    public static string ScriptUrl(string publicUrl, string deploymentCode, bool requireSignature = false, bool skipCertificateCheck = false)
    {
        var options = new List<string>(2);
        if (requireSignature)
        {
            options.Add("requireSignature=true");
        }

        if (skipCertificateCheck)
        {
            options.Add("skipCertificateCheck=true");
        }

        return $"{publicUrl.TrimEnd('/')}/downloads/install/{deploymentCode}.ps1" + (options.Count == 0 ? string.Empty : "?" + string.Join('&', options));
    }

    /// <summary>
    /// The RMM one-liner. With <paramref name="skipCertificateCheck"/> the download of the script does not check the server
    /// certificate. The callback is <c>{[bool]1}</c> rather than <c>{$true}</c> so that the line also works when it is pasted
    /// into a PowerShell prompt, which would expand <c>$true</c> inside the double quotes.
    /// </summary>
    public static string OneLiner(string publicUrl, string deploymentCode, bool requireSignature = false, bool skipCertificateCheck = false) =>
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
        (skipCertificateCheck ? "[Net.ServicePointManager]::ServerCertificateValidationCallback={[bool]1}; " : string.Empty) +
        $"iex ((New-Object Net.WebClient).DownloadString('{ScriptUrl(publicUrl, deploymentCode, requireSignature, skipCertificateCheck)}'))\"";

    public static string MsiExecCommand(string publicUrl, string token, string? fileName) =>
        $"msiexec /i {fileName ?? "EasyPatchAgent.msi"} /qn /norestart SERVERURL=\"{publicUrl.TrimEnd('/')}\" ENROLLMENTTOKEN=\"{token}\"";
}
