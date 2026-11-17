using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Enforces the access control the agent relies on: the data directory (keys, state, outbox, logs) and the bootstrap
/// registry key are readable and writable only by SYSTEM and the local Administrators group, with inheritance from
/// the parent disabled. Applied by the installer and re-applied on every service start.
/// </summary>
internal static class SecureStorage
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static string DefaultDataDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify), "EasyPatch");

    public static void SecureDataDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            directory.Create();
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { LocalSystem, Administrators })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        security.SetOwner(Administrators);
        directory.SetAccessControl(security);
    }

    public static RegistryKey CreateOrOpenRegistryKey()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var key = root.CreateSubKey(RegistryBootstrapConfigSource.KeyPath, writable: true)
            ?? throw new InvalidOperationException($@"Could not create HKLM\{RegistryBootstrapConfigSource.KeyPath}.");
        try
        {
            key.SetAccessControl(CreateRegistrySecurity());
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public static void SecureRegistryKey()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(
            RegistryBootstrapConfigSource.KeyPath,
            RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);
        key?.SetAccessControl(CreateRegistrySecurity());
    }

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static RegistrySecurity CreateRegistrySecurity()
    {
        var security = new RegistrySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { LocalSystem, Administrators })
        {
            security.AddAccessRule(new RegistryAccessRule(
                sid,
                RegistryRights.FullControl,
                InheritanceFlags.ContainerInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        return security;
    }
}
