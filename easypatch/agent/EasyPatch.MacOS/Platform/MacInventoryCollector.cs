using System.Net.NetworkInformation;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.MacOS.Platform;

/// <summary>Hardware and macOS details from <c>sw_vers</c>, <c>sysctl</c>, <c>scutil</c> and <c>system_profiler</c>. Read-only.</summary>
public sealed class MacInventoryCollector : IInventoryCollector
{
    private static readonly TimeSpan ProfilerTimeout = TimeSpan.FromMinutes(2);

    private readonly ICommandRunner _commands;
    private readonly MacSystemInfo _system;
    private readonly IUpdateSourceDetector _updateSource;
    private readonly IBootTimeProvider _bootTime;
    private readonly ILogger _logger;

    public MacInventoryCollector(ICommandRunner commands, MacSystemInfo system, IUpdateSourceDetector updateSource, IBootTimeProvider bootTime,
        ILogger<MacInventoryCollector> logger)
    {
        _commands = commands;
        _system = system;
        _updateSource = updateSource;
        _bootTime = bootTime;
        _logger = logger;
    }

    public async Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The release changes after a macOS update and a restart; the agent may have run since before it.
        var version = MacSystemInfo.Run(_commands, "/usr/bin/sw_vers", ["-productVersion"]) ?? _system.ProductVersion;
        var build = MacSystemInfo.Run(_commands, "/usr/bin/sw_vers", ["-buildVersion"]) ?? _system.BuildVersion;
        var current = _system with { ProductVersion = version, BuildVersion = build };
        var hardware = await HardwareAsync(cancellationToken);
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        var domain = string.IsNullOrWhiteSpace(properties.DomainName) ? null : properties.DomainName;
        DriveInfo? root = null;
        try
        {
            root = new DriveInfo("/");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
        }

        var model = hardware?.ModelName is { } name
            ? hardware.ModelIdentifier is { } id ? $"{name} ({id})" : name
            : Sysctl("hw.model");
        return new InventoryReport
        {
            Hostname = MacSystemInfo.Run(_commands, "/usr/sbin/scutil", ["--get", "LocalHostName"]) is { Length: > 0 } local ? local : Environment.MachineName,
            DnsDomain = domain,
            OsCaption = current.Caption,
            OsDisplayVersion = version,
            OsProductType = "Workstation",
            Architecture = _system.AppleSilicon ? "Arm64" : "X64",
            Manufacturer = "Apple Inc.",
            Model = model,
            SerialNumber = hardware?.SerialNumber,
            SmbiosUuid = hardware?.HardwareUuid,
            ProcessorName = MacSystemInfo.ProcessorName(Sysctl("machdep.cpu.brand_string"), hardware?.Chip),
            TotalMemoryBytes = long.TryParse(Sysctl("hw.memsize"), out var memory) ? memory : null,
            SystemDriveTotalBytes = Safe(() => root?.TotalSize),
            SystemDriveFreeBytes = Safe(() => root?.AvailableFreeSpace),
            LastBootAt = _bootTime.GetLastBootTime(),
            TimeZoneId = TimeZoneInfo.Local.Id,
            IsVirtualMachine = Sysctl("kern.hv_vmm_present") switch
            {
                "1" => true,
                "0" => false,
                _ => null,
            },
            AgentVersion = context.AgentVersion,
            AgentInstalledAt = context.AgentInstalledAt,
            UpdateSource = _updateSource.Detect(),
            Platform = AgentPlatforms.MacOS,
            OsId = "macos",
            OsVersion = version,
            OsBuildVersion = build,
            KernelVersion = Sysctl("kern.osrelease"),
            PackageManager = "softwareupdate",
        };
    }

    private async Task<MacSystemInfo.Hardware?> HardwareAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await _commands.RunAsync("/usr/sbin/system_profiler", ["-json", "SPHardwareDataType"], ProfilerTimeout,
                cancellationToken);
            return result.Succeeded ? MacSystemInfo.ParseHardware(result.StandardOutput) : null;
        }
        catch (CommandException ex)
        {
            _logger.LogDebug("system_profiler failed: {Message}", ex.Message);
            return null;
        }
    }

    private string? Sysctl(string name) => MacSystemInfo.Run(_commands, "/usr/sbin/sysctl", ["-n", name]) is { Length: > 0 } value ? value : null;

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
