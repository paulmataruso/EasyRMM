using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Platform;

/// <summary>Hardware and operating system inventory from os-release, /proc, /sys and a few read-only commands.</summary>
public sealed class LinuxInventoryCollector : IInventoryCollector
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly ICommandRunner _commands;
    private readonly LinuxDistribution _distribution;
    private readonly string _packageManager;
    private readonly IUpdateSourceDetector _updateSource;
    private readonly IBootTimeProvider _bootTime;
    private readonly ILogger _logger;

    public LinuxInventoryCollector(ICommandRunner commands, LinuxDistribution distribution, string packageManager, IUpdateSourceDetector updateSource,
        IBootTimeProvider bootTime, ILogger<LinuxInventoryCollector> logger)
    {
        _commands = commands;
        _distribution = distribution;
        _packageManager = packageManager;
        _updateSource = updateSource;
        _bootTime = bootTime;
        _logger = logger;
    }

    public async Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var distribution = LinuxDistribution.Read() ?? _distribution;
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var domain = string.IsNullOrWhiteSpace(properties.DomainName) || properties.DomainName == "(none)" ? null : properties.DomainName;
        var (proTitle, proServices) = await UbuntuProAsync(distribution, cancellationToken);
        DriveInfo? root = null;
        try
        {
            root = new DriveInfo("/");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
        }

        return new InventoryReport
        {
            Hostname = Environment.MachineName,
            DnsDomain = domain,
            OsCaption = distribution.PrettyName ?? distribution.ProductName,
            OsDisplayVersion = distribution.VersionId,
            OsProductType = await ProductTypeAsync(cancellationToken),
            Architecture = RuntimeInformation.OSArchitecture.ToString(),
            Manufacturer = Dmi("sys_vendor"),
            Model = Dmi("product_name"),
            SerialNumber = Dmi("product_serial"),
            SmbiosUuid = Dmi("product_uuid"),
            ProcessorName = ProcessorName(),
            TotalMemoryBytes = MemoryBytes(),
            SystemDriveTotalBytes = Safe(() => root?.TotalSize),
            SystemDriveFreeBytes = Safe(() => root?.AvailableFreeSpace),
            LastBootAt = _bootTime.GetLastBootTime(),
            TimeZoneId = TimeZoneInfo.Local.Id,
            IsVirtualMachine = await IsVirtualAsync(cancellationToken),
            EsuLicenseDetected = proTitle is null ? null : proServices.Count > 0,
            EsuLicenseNames = proServices,
            AgentVersion = context.AgentVersion,
            AgentInstalledAt = context.AgentInstalledAt,
            UpdateSource = _updateSource.Detect(),
            Platform = AgentPlatforms.Linux,
            OsId = distribution.Id,
            OsVersion = distribution.VersionId,
            KernelVersion = ReadFile("/proc/sys/kernel/osrelease"),
            PackageManager = _packageManager,
        };
    }

    private async Task<string> ProductTypeAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _commands.RunAsync("systemctl", ["get-default"], Timeout, cancellationToken);
            return result.StandardOutput.Trim() == "graphical.target" ? "Workstation" : "Server";
        }
        catch (CommandException)
        {
            return "Server";
        }
    }

    private async Task<bool?> IsVirtualAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _commands.RunAsync("systemd-detect-virt", ["--quiet"], Timeout, cancellationToken);
            return result.ExitCode == 0;
        }
        catch (CommandException)
        {
            return null;
        }
    }

    /// <summary>Ubuntu Pro: whether the machine is attached and which ESM services are enabled.</summary>
    private async Task<(string? Title, IReadOnlyList<string> Services)> UbuntuProAsync(LinuxDistribution distribution, CancellationToken cancellationToken)
    {
        if (distribution.Id != "ubuntu" || _commands.Find("pro") is null)
        {
            return (null, []);
        }

        try
        {
            var result = await _commands.RunAsync("pro", ["status", "--format", "json"], Timeout, cancellationToken);
            if (!result.Succeeded)
            {
                return (null, []);
            }

            using var json = JsonDocument.Parse(result.StandardOutput);
            var attached = json.RootElement.TryGetProperty("attached", out var a) && a.ValueKind == JsonValueKind.True;
            if (!attached)
            {
                return ("Ubuntu Pro", []);
            }

            var services = new List<string>();
            if (json.RootElement.TryGetProperty("services", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var service in list.EnumerateArray())
                {
                    var name = service.TryGetProperty("name", out var n) ? n.GetString() : null;
                    var status = service.TryGetProperty("status", out var s) ? s.GetString() : null;
                    if (name is not null && status == "enabled" && name.StartsWith("esm-", StringComparison.Ordinal))
                    {
                        services.Add("Ubuntu Pro " + name);
                    }
                }
            }

            return ("Ubuntu Pro", services);
        }
        catch (Exception ex) when (ex is CommandException or JsonException)
        {
            _logger.LogDebug("Could not read the Ubuntu Pro status: {Message}", ex.Message);
            return (null, []);
        }
    }

    private static string? Dmi(string name)
    {
        var value = ReadFile("/sys/class/dmi/id/" + name);
        return value is null or "" or "None" or "Not Specified" or "To Be Filled By O.E.M." or "Default string" ? null : value;
    }

    private static string? ProcessorName()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/cpuinfo"))
            {
                if (line.StartsWith("model name", StringComparison.Ordinal) || line.StartsWith("Hardware", StringComparison.Ordinal))
                {
                    var colon = line.IndexOf(':', StringComparison.Ordinal);
                    if (colon > 0)
                    {
                        return line[(colon + 1)..].Trim();
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    private static long? MemoryBytes()
    {
        try
        {
            var line = File.ReadLines("/proc/meminfo").FirstOrDefault(l => l.StartsWith("MemTotal:", StringComparison.Ordinal));
            var parts = line?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return parts is { Length: >= 2 } && long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var kb) ? kb * 1024 : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? ReadFile(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static long? Safe(Func<long?> read)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

/// <summary>Reports where updates come from (the package manager's repositories) and whether the distribution's own
/// automatic updates (unattended-upgrades, dnf-automatic) are enabled. Never changes either.</summary>
public sealed class LinuxUpdateSourceDetector : IUpdateSourceDetector
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private readonly ICommandRunner _commands;
    private readonly PackageFamily _family;

    public LinuxUpdateSourceDetector(ICommandRunner commands, PackageFamily family)
    {
        _commands = commands;
        _family = family;
    }

    public UpdateSourceInfo Detect() => new()
    {
        Type = UpdateSourceType.PackageRepositories,
        AutomaticUpdatesMode = AutomaticUpdates(),
    };

    private string AutomaticUpdates()
    {
        try
        {
            if (_family == PackageFamily.Debian)
            {
                if (_commands.Find("unattended-upgrade") is null)
                {
                    return "Not installed (unattended-upgrades)";
                }

                var result = Run("apt-config", ["shell", "VALUE", "APT::Periodic::Unattended-Upgrade"]);
                return result.StandardOutput.Contains("VALUE='1'", StringComparison.Ordinal) ? "Enabled (unattended-upgrades)" : "Disabled (unattended-upgrades)";
            }

            if (_family == PackageFamily.RedHat)
            {
                var result = Run("systemctl", ["is-enabled", "dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"]);
                return result.StandardOutput.Split('\n').Any(l => l.Trim() == "enabled") ? "Enabled (dnf-automatic)" : "Disabled (dnf-automatic)";
            }
        }
        catch (CommandException)
        {
        }

        return "Unknown";
    }

    private CommandResult Run(string program, IReadOnlyList<string> arguments) =>
        _commands.RunAsync(program, arguments, Timeout, CancellationToken.None).GetAwaiter().GetResult();
}
