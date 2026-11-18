using System.Globalization;
using System.Management;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Inventory;

/// <summary>
/// Operating system and hardware inventory from WMI and the registry. Read-only; no software inventory
/// (EasyPatch is a patch manager, not an RMM).
/// </summary>
public sealed class WmiInventoryCollector : IInventoryCollector
{
    private const string CurrentVersionPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(60);

    private readonly IUpdateSourceDetector _updateSource;
    private readonly ILogger<WmiInventoryCollector> _logger;

    public WmiInventoryCollector(IUpdateSourceDetector updateSource, ILogger<WmiInventoryCollector> logger)
    {
        _updateSource = updateSource ?? throw new ArgumentNullException(nameof(updateSource));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Task.Factory.StartNew(() => Collect(context), cancellationToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    private InventoryReport Collect(InventoryContext context)
    {
        var os = QuerySingle("SELECT Caption, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate, ProductType FROM Win32_OperatingSystem");
        var cs = QuerySingle("SELECT Manufacturer, Model, Domain, PartOfDomain, TotalPhysicalMemory FROM Win32_ComputerSystem");
        var bios = QuerySingle("SELECT SerialNumber FROM Win32_BIOS");
        var product = QuerySingle("SELECT UUID FROM Win32_ComputerSystemProduct");
        var cpu = QuerySingle("SELECT Name FROM Win32_Processor");

        var systemDrive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
        var disk = QuerySingle($"SELECT Size, FreeSpace FROM Win32_LogicalDisk WHERE DeviceID = '{systemDrive.Replace("'", string.Empty, StringComparison.Ordinal)}'");

        var buildNumber = Reg.GetString(CurrentVersionPath, "CurrentBuildNumber") ?? Text(os, "BuildNumber");
        var (esuDetected, esuNames) = DetectEsu();
        var (startMode, serviceState) = DetectWindowsUpdateService();

        string? domain = null;
        bool? domainJoined = Bool(cs, "PartOfDomain");
        if (domainJoined == true)
        {
            domain = Text(cs, "Domain");
        }
        else
        {
            try
            {
                var dnsDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
                domain = string.IsNullOrWhiteSpace(dnsDomain) ? null : dnsDomain;
            }
            catch (NetworkInformationException)
            {
            }
        }

        UpdateSourceInfo? source = null;
        try
        {
            source = _updateSource.Detect();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            _logger.LogWarning(ex, "Update source detection failed.");
        }

        return new InventoryReport
        {
            Hostname = Environment.MachineName,
            DnsDomain = domain,
            DomainJoined = domainJoined,
            OsCaption = Text(os, "Caption")?.Trim(),
            OsEdition = Reg.GetString(CurrentVersionPath, "EditionID"),
            OsDisplayVersion = Reg.GetString(CurrentVersionPath, "DisplayVersion") ?? Reg.GetString(CurrentVersionPath, "ReleaseId"),
            OsBuildNumber = int.TryParse(buildNumber, NumberStyles.Integer, CultureInfo.InvariantCulture, out var build) ? build : null,
            OsUbr = Reg.GetInt(CurrentVersionPath, "UBR"),
            OsProductType = UInt(os, "ProductType") switch
            {
                1 => "Workstation",
                2 => "DomainController",
                3 => "Server",
                _ => null,
            },
            OsInstallDate = Date(os, "InstallDate"),
            Architecture = Text(os, "OSArchitecture") ?? System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            Manufacturer = Clean(Text(cs, "Manufacturer")),
            Model = Clean(Text(cs, "Model")),
            SerialNumber = Clean(Text(bios, "SerialNumber")),
            SmbiosUuid = CleanUuid(Text(product, "UUID")),
            ProcessorName = Clean(Text(cpu, "Name")),
            TotalMemoryBytes = Long(cs, "TotalPhysicalMemory"),
            SystemDriveTotalBytes = Long(disk, "Size"),
            SystemDriveFreeBytes = Long(disk, "FreeSpace"),
            LastBootAt = Date(os, "LastBootUpTime"),
            TimeZoneId = TimeZoneInfo.Local.Id,
            IsVirtualMachine = cs is null ? null : IsLikelyVirtualModel(Text(cs, "Model"), Text(cs, "Manufacturer")),
            EsuLicenseDetected = esuDetected,
            EsuLicenseNames = esuNames,
            WindowsUpdateServiceStartMode = startMode,
            WindowsUpdateServiceState = serviceState,
            AgentVersion = context.AgentVersion,
            AgentInstalledAt = context.AgentInstalledAt,
            UpdateSource = source,
        };
    }

    /// <summary>
    /// Best-effort detection of Extended Security Update licenses installed through volume activation (MAK).
    /// Consumer ESU enrollment through a Microsoft account is not visible here.
    /// </summary>
    private (bool? Detected, IReadOnlyList<string> Names) DetectEsu()
    {
        try
        {
            var names = new List<string>();
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\cimv2"),
                new ObjectQuery("SELECT Name, LicenseStatus FROM SoftwareLicensingProduct WHERE Name LIKE '%ESU%' AND LicenseStatus = 1"),
                new System.Management.EnumerationOptions { Timeout = QueryTimeout, ReturnImmediately = true, Rewindable = false });
            foreach (var result in searcher.Get())
            {
                using (result)
                {
                    if (result["Name"] is string name)
                    {
                        names.Add(name);
                    }
                }
            }

            return (names.Count > 0, names);
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            _logger.LogDebug(ex, "ESU license query failed.");
            return (null, []);
        }
    }

    private (string? StartMode, string? State) DetectWindowsUpdateService()
    {
        try
        {
            using var service = new ServiceController("wuauserv");
            return (service.StartType.ToString(), service.Status.ToString());
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _logger.LogDebug(ex, "Could not query the Windows Update service.");
            return (null, null);
        }
    }

    private Dictionary<string, object?>? QuerySingle(string query)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\cimv2"),
                new ObjectQuery(query),
                new System.Management.EnumerationOptions { Timeout = QueryTimeout, ReturnImmediately = true, Rewindable = false });
            foreach (var result in searcher.Get())
            {
                using (result)
                {
                    var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var property in result.Properties)
                    {
                        values[property.Name] = property.Value;
                    }

                    return values;
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            _logger.LogWarning(ex, "WMI query failed: {Query}", query);
        }

        return null;
    }

    private static string? Text(Dictionary<string, object?>? values, string name) =>
        values is not null && values.TryGetValue(name, out var value) && value is not null
            ? Convert.ToString(value, CultureInfo.InvariantCulture)
            : null;

    private static long? Long(Dictionary<string, object?>? values, string name) =>
        values is not null && values.TryGetValue(name, out var value) && value is not null
            ? Convert.ToInt64(value, CultureInfo.InvariantCulture)
            : null;

    private static uint? UInt(Dictionary<string, object?>? values, string name) =>
        values is not null && values.TryGetValue(name, out var value) && value is not null
            ? Convert.ToUInt32(value, CultureInfo.InvariantCulture)
            : null;

    private static bool? Bool(Dictionary<string, object?>? values, string name) =>
        values is not null && values.TryGetValue(name, out var value) && value is bool b ? b : null;

    private static DateTimeOffset? Date(Dictionary<string, object?>? values, string name)
    {
        var text = Text(values, name);
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(text).ToUniversalTime());
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed is "To be filled by O.E.M." or "Default string" or "System Serial Number" or "None" or "0" ? null : trimmed;
    }

    private static string? CleanUuid(string? value)
    {
        var cleaned = Clean(value);
        return cleaned is null || cleaned.All(c => c is 'F' or 'f' or '0' or '-') ? null : cleaned;
    }

    private static bool IsLikelyVirtualModel(string? model, string? manufacturer)
    {
        var text = $"{manufacturer} {model}";
        string[] markers = ["Virtual", "VMware", "KVM", "QEMU", "Xen", "HVM domU", "VirtualBox", "Parallels", "Bochs"];
        return markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }
}
