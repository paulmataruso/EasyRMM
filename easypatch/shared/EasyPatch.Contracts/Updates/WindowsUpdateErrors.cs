using System.Globalization;

namespace EasyPatch.Contracts.Updates;

/// <summary>
/// Human-readable explanations for common Windows Update Agent / servicing HRESULTs, so administrators see
/// an actionable message instead of a bare "Installation Failed".
/// </summary>
public static class WindowsUpdateErrors
{
    private static readonly Dictionary<uint, string> Messages = new()
    {
        [0x80240001] = "Windows Update Agent was unable to provide the service.",
        [0x8024000B] = "The operation was cancelled.",
        [0x8024000E] = "Windows Update received invalid update metadata (XML).",
        [0x80240016] = "Another installation is in progress or the computer must restart before more updates can be installed.",
        [0x80240017] = "The update is not applicable to this computer.",
        [0x8024001E] = "The Windows Update service or the computer was shutting down.",
        [0x80240020] = "The update requires a logged-on interactive user.",
        [0x80240022] = "All updates in the operation failed.",
        [0x80240024] = "There are no updates to install.",
        [0x80240025] = "Access to Windows Update is disabled for this user.",
        [0x8024002E] = "Access to Windows Update (unmanaged server) is disabled by policy.",
        [0x80240032] = "The update search criteria was invalid.",
        [0x80240438] = "The Windows Update service endpoint is unreachable (no network route or blocked by firewall/proxy).",
        [0x80240FFF] = "Windows Update encountered an unexpected error.",
        [0x80244007] = "The update server returned a SOAP fault (check WSUS health).",
        [0x80244010] = "Exceeded the maximum number of round trips to the update server.",
        [0x80244017] = "The update server returned HTTP 401 (access denied).",
        [0x80244018] = "The update server or proxy returned HTTP 403 (forbidden).",
        [0x80244019] = "The update server returned HTTP 404 (not found). For WSUS, check the server URL and content.",
        [0x8024401B] = "The proxy requires authentication (HTTP 407).",
        [0x8024401C] = "The request to the update server timed out (HTTP 408).",
        [0x8024401F] = "The update server returned HTTP 500 (internal server error).",
        [0x80244022] = "The update server is unavailable (HTTP 503).",
        [0x8024402C] = "The update server or proxy name could not be resolved (DNS).",
        [0x8024200D] = "The update needs to be downloaded again.",
        [0x80242016] = "The update was in an unexpected state after its post-restart operation.",
        [0x80246007] = "The update has not been downloaded.",
        [0x80246008] = "Windows Update could not connect to the Background Intelligent Transfer Service (BITS).",
        [0x8024A10A] = "The Windows Update service is shutting down.",
        [0x80070005] = "Access denied.",
        [0x8007000E] = "Out of memory.",
        [0x80070070] = "Not enough free disk space to complete the operation.",
        [0x80070422] = "A required service (Windows Update or BITS) is disabled.",
        [0x80070643] = "A fatal error occurred during installation (MSI-based update).",
        [0x80070BC2] = "A restart is required to complete the operation.",
        [0x80070BC9] = "A previous operation requires a restart before this update can be installed.",
        [0x80072EE2] = "The connection to the update server timed out.",
        [0x80072EE7] = "The update server name could not be resolved (DNS).",
        [0x80072EFD] = "A connection to the update server could not be established.",
        [0x80072EFE] = "The connection to the update server was aborted.",
        [0x80072F8F] = "A secure connection to the update server failed (TLS error or incorrect system clock).",
        [0x80073712] = "The Windows component store is corrupted. Run 'DISM /Online /Cleanup-Image /RestoreHealth'.",
        [0x800F081F] = "Servicing source files could not be found.",
        [0x800F0831] = "The component store is missing a required manifest (store corruption).",
        [0x800F0922] = "Servicing advanced installers failed (often insufficient System Reserved partition space or a VPN interfering).",
    };

    /// <summary>Formats an HRESULT as 0xXXXXXXXX.</summary>
    public static string Format(int hresult) => "0x" + unchecked((uint)hresult).ToString("X8", CultureInfo.InvariantCulture);

    public static string Describe(int hresult) => Describe(unchecked((uint)hresult));

    public static string Describe(uint hresult)
    {
        if (Messages.TryGetValue(hresult, out var message))
        {
            return message;
        }

        if ((hresult & 0xFFFF0000) == 0x80240000)
        {
            return $"Windows Update Agent error 0x{hresult:X8}.";
        }

        return $"Error 0x{hresult:X8}.";
    }

    /// <summary>Parses "0x80240016" or a decimal HRESULT string.</summary>
    public static bool TryParse(string? code, out uint hresult)
    {
        hresult = 0;
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        code = code.Trim();
        if (code.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(code.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out hresult);
        }

        if (int.TryParse(code, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signed))
        {
            hresult = unchecked((uint)signed);
            return true;
        }

        return false;
    }

    public static string DescribeCode(string? code) =>
        TryParse(code, out var value) ? Describe(value) : code ?? string.Empty;
}
