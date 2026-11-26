using System.Security.AccessControl;
using System.Security.Principal;
using EasyPatch.Agent.Core.Companion;
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

    public static string DefaultDataDirectory => AdHocMode.Active ? AdHocMode.DataDirectory :
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify), "EasyPatch");

    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    /// <summary>
    /// Makes the data folder what ADR-0070 needs before it is excluded from Defender, and fails closed when it cannot:
    /// (a) a folder that is not trustworthy (a link, an owner that is not SYSTEM or Administrators, an entry that lets someone else
    /// write) is moved aside and made anew with its list set at creation, so there is no moment it is open; (b) the owner and the list
    /// are set; (c) the subtree is walked, links are removed and any entry with a foreign owner or write entry is reset to inherit the
    /// folder's list. A subtree that cannot be made safe throws <see cref="InvalidOperationException"/>.
    /// </summary>
    public static void SecureDataDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        var directory = new DirectoryInfo(full);
        if (directory.Exists && FileTrust.EntryProblemWindows(full, agentSid: null) is { } why)
        {
            MoveAside(directory, why);
            directory = new DirectoryInfo(full);
        }

        if (directory.Exists)
        {
            directory.SetAccessControl(CreateDirectorySecurity(readForUsers: false));
        }
        else
        {
            directory.Create(CreateDirectorySecurity(readForUsers: false));
        }

        MakeSubtreeSafe(full);
    }

    /// <summary>
    /// Locks down the program folder, which the installed folder inherits from Program Files and nothing enforces (ADR-0070): SYSTEM and
    /// Administrators full control and Users read and execute (the tray runs the program in each user's session), inheritance off, and
    /// the same walk of the subtree. Only the agent's own folder: <paramref name="path"/> must be the fixed install folder.
    /// </summary>
    public static void SecureInstallDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        var directory = new DirectoryInfo(full);
        if (!directory.Exists)
        {
            return; // a development build run from a folder: nothing is installed
        }

        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException($"{full} is a link.");
        }

        directory.SetAccessControl(CreateDirectorySecurity(readForUsers: true));
        MakeSubtreeSafe(full);
    }

    private static DirectorySecurity CreateDirectorySecurity(bool readForUsers)
    {
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

        if (readForUsers)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                Users,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        security.SetOwner(Administrators);
        return security;
    }

    /// <summary>Renames a folder that cannot be trusted to a sibling named for the time, so nothing in it stays inside the excluded tree
    /// under its own name. A link is removed, never followed.</summary>
    private static void MoveAside(DirectoryInfo directory, string why)
    {
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            directory.Delete(recursive: false);
            return;
        }

        var target = $"{directory.FullName}.untrusted-{DateTime.UtcNow:yyyyMMddHHmmss}";
        try
        {
            directory.MoveTo(target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"{directory.FullName} cannot be trusted ({why}) and could not be moved aside: {ex.Message}", ex);
        }
    }

    private static void MakeSubtreeSafe(string root)
    {
        var agent = WindowsIdentity.GetCurrent().User?.Value;
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            List<string> children;
            try
            {
                children = Directory.EnumerateFileSystemEntries(directory).ToList();
            }
            catch (DirectoryNotFoundException)
            {
                continue; // removed while the walk was running
            }

            foreach (var child in children)
            {
                try
                {
                    if (FileTrust.EntryProblemWindows(child, agent) is { } why)
                    {
                        Repair(child, why, agent);
                    }
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                {
                    continue; // a temporary file the agent removed meanwhile
                }

                if (FileTrust.IsRealDirectory(child))
                {
                    pending.Push(child);
                }
            }
        }
    }

    private static void Repair(string entry, string why, string? agent)
    {
        var attributes = File.GetAttributes(entry);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            // Removes the link, not what it points to.
            if ((attributes & FileAttributes.Directory) != 0)
            {
                Directory.Delete(entry, recursive: false);
            }
            else
            {
                File.Delete(entry);
            }

            return;
        }

        // Reset to what the folder above passes on: the owner is the Administrators group and the list is inherited.
        if ((attributes & FileAttributes.Directory) != 0)
        {
            var info = new DirectoryInfo(entry);
            var security = info.GetAccessControl(AccessControlSections.Access);
            ResetToInherited(security);
            info.SetAccessControl(security);
            var owner = new DirectorySecurity();
            owner.SetOwner(Administrators);
            info.SetAccessControl(owner);
        }
        else
        {
            var info = new FileInfo(entry);
            var security = info.GetAccessControl(AccessControlSections.Access);
            ResetToInherited(security);
            info.SetAccessControl(security);
            var owner = new FileSecurity();
            owner.SetOwner(Administrators);
            info.SetAccessControl(owner);
        }

        if (FileTrust.EntryProblemWindows(entry, agent) is { } still)
        {
            throw new InvalidOperationException($"{entry} cannot be made safe ({why}; after resetting: {still}).");
        }
    }

    private static void ResetToInherited(FileSystemSecurity security)
    {
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }
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
