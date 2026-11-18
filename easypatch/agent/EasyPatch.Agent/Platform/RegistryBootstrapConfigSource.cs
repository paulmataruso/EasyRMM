using EasyPatch.Agent.Core.Abstractions;
using Microsoft.Win32;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Installer-provided bootstrap settings in <c>HKLM\SOFTWARE\EasyPatch\Agent</c> (64-bit view). The MSI writes them
/// from SERVERURL / ENROLLMENTTOKEN / DEPLOYMENTCODE / PROXYURL / SERVERCACERT; <c>EasyPatch.Agent.exe enroll</c> writes
/// them too.
/// The enrollment token and deployment code are deleted as soon as enrollment completes or is rejected.
/// The key is ACL-restricted to SYSTEM and Administrators (<see cref="SecureStorage"/>).
/// </summary>
internal sealed class RegistryBootstrapConfigSource : IBootstrapConfigSource
{
    public const string KeyPath = @"SOFTWARE\EasyPatch\Agent";

    private const string ServerUrlValue = "ServerUrl";
    private const string EnrollmentTokenValue = "EnrollmentToken";
    private const string DeploymentCodeValue = "DeploymentCode";
    private const string ProxyUrlValue = "ProxyUrl";
    private const string ServerCaCertificateValue = "ServerCaCertificate";

    public BootstrapConfig Read()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(KeyPath, writable: false);
        if (key is null)
        {
            return BootstrapConfig.Empty;
        }

        return new BootstrapConfig(
            ReadString(key, ServerUrlValue),
            ReadString(key, EnrollmentTokenValue),
            ReadString(key, DeploymentCodeValue),
            ReadString(key, ProxyUrlValue),
            ReadString(key, ServerCaCertificateValue));
    }

    public void ClearEnrollmentSecrets()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(KeyPath, writable: true);
        key?.DeleteValue(EnrollmentTokenValue, throwOnMissingValue: false);
        key?.DeleteValue(DeploymentCodeValue, throwOnMissingValue: false);
    }

    /// <summary>Writes new bootstrap settings (CLI <c>enroll</c>). Null proxy removes a previously configured proxy; a null
    /// server certificate authority keeps the one the installer recorded.</summary>
    public static void Write(BootstrapConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        using var key = SecureStorage.CreateOrOpenRegistryKey();
        SetOrDelete(key, ServerUrlValue, config.ServerUrl);
        SetOrDelete(key, EnrollmentTokenValue, config.EnrollmentToken);
        SetOrDelete(key, DeploymentCodeValue, config.DeploymentCode);
        SetOrDelete(key, ProxyUrlValue, config.ProxyUrl);
        if (!string.IsNullOrWhiteSpace(config.ServerCaCertificate))
        {
            SetOrDelete(key, ServerCaCertificateValue, config.ServerCaCertificate);
        }
    }

    /// <summary>Removes all bootstrap settings (CLI <c>unenroll</c>).</summary>
    public static void DeleteAll()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(KeyPath, writable: true);
        if (key is null)
        {
            return;
        }

        foreach (var name in new[] { ServerUrlValue, EnrollmentTokenValue, DeploymentCodeValue, ProxyUrlValue, ServerCaCertificateValue })
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
    }

    private static string? ReadString(RegistryKey key, string name) =>
        key.GetValue(name) is string value && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

    private static void SetOrDelete(RegistryKey key, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(name, value.Trim(), RegistryValueKind.String);
        }
    }
}
