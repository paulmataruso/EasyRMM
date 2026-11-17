using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;

namespace EasyPatch.Infrastructure.Services;

/// <summary>The package an endpoint's agent would update to, or why it cannot update.</summary>
/// <param name="Package">The signed package to install (null when <paramref name="ErrorCode"/> is set).</param>
public sealed record AgentUpdateTarget(AgentPackage? Package, string? ErrorCode, string? Message)
{
    public const string UpgradeRequired = "agent_upgrade_required";
    public const string NoPackage = "no_agent_package";
    public const string UpToDate = "agent_up_to_date";
    public const string NotSigned = "package_not_signed";
    public const string KeyNotTrusted = "release_key_not_trusted";
}

/// <summary>
/// Chooses the agent package for an update: the newest package for the agent's architecture and package format (or the
/// requested version), which must be newer than the installed agent and carry a release signature from a key the agent
/// trusts. The server cannot verify the signature itself; the agent does that before installing.
/// </summary>
public static class AgentUpdatePlanner
{
    /// <summary>The package format the endpoint's agent installs updates from: the one it reported (MSI when it did not say,
    /// see <see cref="AgentRelease.NormalizeFormat"/>), or null when that format does not belong to the endpoint's platform
    /// (MSI for Windows, deb or rpm for Linux, pkg for macOS), so that no agent is ever offered another platform's package.</summary>
    public static string? PackageFormat(Endpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var format = endpoint.AgentPackageFormat ?? AgentRelease.FormatMsi;
        var fits = endpoint.Platform switch
        {
            AgentPlatforms.Windows => format == AgentRelease.FormatMsi,
            AgentPlatforms.Linux => format is AgentRelease.FormatDeb or AgentRelease.FormatRpm,
            AgentPlatforms.MacOS => format == AgentRelease.FormatPkg,
            _ => false,
        };
        return fits ? format : null;
    }

    public static AgentUpdateTarget Resolve(Endpoint endpoint, AgentPackageService packages, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(packages);
        if (!endpoint.AgentCapabilities.Contains(AgentCapabilities.SelfUpdate) || endpoint.AgentArchitecture is null ||
            endpoint.AgentReleaseKeyIds.Count == 0)
        {
            return Fail(AgentUpdateTarget.UpgradeRequired,
                $"The EasyPatch agent on {endpoint.Hostname} (version {endpoint.AgentVersion ?? "unknown"}) cannot update itself: it is older than 1.2.0 " +
                "or was built without a release key. Install a newer agent package on it once; after that it can update itself.");
        }

        if (PackageFormat(endpoint) is not { } format)
        {
            return Fail(AgentUpdateTarget.NoPackage, endpoint.AgentPackageFormat is null
                ? $"The EasyPatch agent on {endpoint.Hostname} did not report its package format, so no {endpoint.Platform} agent package can be chosen."
                : $"The EasyPatch agent on {endpoint.Hostname} reported package format '{endpoint.AgentPackageFormat}', which is not a {endpoint.Platform} package format.");
        }

        if (version is not null && AgentRelease.ParseVersion(version) is null)
        {
            return Fail(AgentUpdateTarget.NoPackage, $"'{version}' is not an agent version.");
        }

        var architecture = endpoint.AgentArchitecture;
        var newest = packages.List()
            .Where(p => p.Architecture == architecture && p.Format == format && (version is null || p.Version == version))
            .OrderByDescending(p => AgentRelease.ParseVersion(p.Version))
            .FirstOrDefault();
        if (newest is null)
        {
            return Fail(AgentUpdateTarget.NoPackage, version is null
                ? $"There is no {architecture} {format} agent package on the server."
                : $"Agent package {version} for {architecture} ({format}) is not on the server.");
        }

        var current = AgentRelease.ParseVersion(endpoint.AgentVersion);
        if (current is not null && AgentRelease.ParseVersion(newest.Version) <= current)
        {
            return Fail(AgentUpdateTarget.UpToDate, version is null
                ? $"{endpoint.Hostname} already runs the newest agent ({endpoint.AgentVersion})."
                : $"{endpoint.Hostname} runs agent {endpoint.AgentVersion}; {version} is not newer (agents are never downgraded).");
        }

        if (newest.Release is not { } release)
        {
            return Fail(AgentUpdateTarget.NotSigned,
                $"{newest.FileName} has no valid release signature{(newest.SignatureProblem is null ? "" : $" ({newest.SignatureProblem.TrimEnd('.')})")}. " +
                "Sign it on the build machine (easypatch-release sign) and copy the .sig file next to it.");
        }

        if (!endpoint.AgentReleaseKeyIds.Contains(release.KeyId))
        {
            return Fail(AgentUpdateTarget.KeyNotTrusted,
                $"{newest.FileName} is signed with release key {release.KeyId}, but the agent on {endpoint.Hostname} only accepts " +
                $"{string.Join(", ", endpoint.AgentReleaseKeyIds)}.");
        }

        return new AgentUpdateTarget(newest, null, null);
    }

    private static AgentUpdateTarget Fail(string code, string message) => new(null, code, message);
}
