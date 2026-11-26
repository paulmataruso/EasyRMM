using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;

namespace EasyPatch.Agent.Core.Companion;

/// <summary>
/// ADR-0069, step 2 of repairing the EasyRMM agent from its recovery copy: the copy is opened without following links or reparse
/// points, its owner is the system (or root), and only the system, administrators or root may write it and every directory above
/// it. The rules are here, apart from the calls that read an access list or a file's owner, so that they are tested on every system.
/// </summary>
internal static class FileTrust
{
    // ---- Windows ---------------------------------------------------------------------------------------------------------------

    /// <summary>The rights to change a file or folder, what it holds, or who may: write data or add a file (0x2), append data or add a
    /// folder (0x4), write extended attributes (0x10), delete what a folder holds (0x40), write attributes (0x100), delete,
    /// change the access list, change the owner, and the generic rights that include these (GENERIC_ALL, GENERIC_WRITE).</summary>
    public const uint WriteRights = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    /// <summary>What lets someone replace what lies below a folder: delete what it holds (0x40), delete it, change its access list or
    /// owner, and GENERIC_ALL. ProgramData and a drive's root let every user add folders, which does not count: it cannot replace the
    /// folder of the agent, which only the system and administrators may change (ADR-0064, the same rule for the folders above a
    /// PowerShell install).</summary>
    public const uint ReplaceRights = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000;

    private const byte InheritOnly = 0x08;

    private static readonly string[] Administration =
    [
        "S-1-5-18", // LocalSystem
        "S-1-5-32-544", // Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
    ];

    // CREATOR OWNER and CREATOR GROUP are replaced, in what a folder passes on, by whoever creates the entry.
    private static readonly string[] Creators = ["S-1-3-0", "S-1-3-1"];

    /// <summary>An entry of a Windows access list.</summary>
    internal readonly record struct AclEntry(bool Allows, byte Flags, uint Mask, string Who);

    /// <summary>The first entry that lets anyone but the administration use any of <paramref name="rights"/>: the SID it names.
    /// <paramref name="passedOn"/> says whether an entry that is only passed on to what a folder holds counts. Null for none.</summary>
    internal static string? Grantee(IEnumerable<AclEntry> acl, uint rights, bool passedOn)
    {
        foreach (var e in acl)
        {
            if (!e.Allows || (e.Mask & rights) == 0 || (!passedOn && (e.Flags & InheritOnly) != 0) ||
                Administration.Contains(e.Who, StringComparer.Ordinal) || Creators.Contains(e.Who, StringComparer.Ordinal))
            {
                continue;
            }

            return e.Who;
        }

        return null;
    }

    /// <summary>Whether a file's owner is the system or the Administrators group. What the agent's service creates belongs to one of
    /// them: Windows makes the Administrators group the default owner of what a process running as the system creates.</summary>
    internal static bool TrustedWindowsOwner(string sid) => sid is "S-1-5-18" or "S-1-5-32-544";

    /// <summary>Whether a directory's owner is the system, the Administrators group or TrustedInstaller. An owner can rewrite the
    /// directory's access list whatever it says, so it counts as much as a write right.</summary>
    internal static bool TrustedDirectoryOwner(string? sid) => sid is "S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// <summary>Checks the copy and every directory above it; the reason it cannot be trusted, null when it can.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static string? CheckWindows(string path, string? stopAt)
    {
        var full = Path.GetFullPath(path);
        var attributes = TryAttributes(full);
        if (attributes is null)
        {
            return $"{full} cannot be read.";
        }

        if ((attributes.Value & FileAttributes.ReparsePoint) != 0)
        {
            return $"{full} is a link or reparse point.";
        }

        if ((attributes.Value & FileAttributes.Directory) != 0)
        {
            return $"{full} is a directory, not a program.";
        }

        var self = ReadAcl(new FileInfo(full).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        if (self.Dacl is null)
        {
            return $"{full} has no access list, so everyone may change it.";
        }

        if (self.Owner is null || !TrustedWindowsOwner(self.Owner))
        {
            return $"{full} is owned by {self.Owner ?? "no one"}, not by the system.";
        }

        if (Grantee(self.Dacl, WriteRights, passedOn: false) is { } writer)
        {
            return $"{full} may be changed by {writer}.";
        }

        return CheckChain(Path.GetDirectoryName(full), folder: true, stopAt);
    }

    /// <summary>ADR-0070, section 2: a folder the agent means to exclude from Defender. The folder is a plain folder (not a link) owned by
    /// the administration, no one else may write it or replace anything above it, and everything below it has an owner that is the
    /// administration or <paramref name="agentSid"/>, entries from the administration alone for writing, and no link or reparse point.
    /// The reason it cannot be trusted, null when it can.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static string? CheckFolderWindows(string folder, string? agentSid)
    {
        var full = Path.GetFullPath(folder);
        var attributes = TryAttributes(full);
        if (attributes is null)
        {
            return $"{full} cannot be read.";
        }

        if ((attributes.Value & FileAttributes.Directory) == 0)
        {
            return $"{full} is not a folder.";
        }

        return CheckChain(full, folder: true, stopAt: null) ?? CheckTree(full, agentSid);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? CheckTree(string root, string? agentSid)
    {
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
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return $"{directory} cannot be read.";
            }

            foreach (var child in children)
            {
                if (EntryProblemWindows(child, agentSid) is { } problem)
                {
                    return problem;
                }

                if (IsRealDirectory(child))
                {
                    pending.Push(child);
                }
            }
        }

        return null;
    }

    /// <summary>Checks one file or folder on its own (not what is above or below it): not a link, an owner that is the administration or
    /// <paramref name="agentSid"/>, and no one else who may write it. The reason, null when it can be trusted.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static string? EntryProblemWindows(string path, string? agentSid)
    {
        var attributes = TryAttributes(path);
        if (attributes is null)
        {
            return $"{path} cannot be read.";
        }

        var reparse = (attributes.Value & FileAttributes.ReparsePoint) != 0;
        string? owner = null;
        List<AclEntry>? dacl = null;
        if (!reparse)
        {
            FileSystemSecurity security = (attributes.Value & FileAttributes.Directory) != 0
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            (owner, dacl) = ReadAcl(security);
        }

        return TreeProblem(path, reparse, owner, dacl, agentSid);
    }

    /// <summary>Whether <paramref name="path"/> is a folder and not a link, so the walk may enter it.</summary>
    public static bool IsRealDirectory(string path) =>
        TryAttributes(path) is { } a && (a & FileAttributes.Directory) != 0 && (a & FileAttributes.ReparsePoint) == 0;

    /// <summary>Whether one file or folder below an excluded folder can be trusted: not a link, a list that exists, an owner that is the
    /// administration or the agent's own account, and no one else who may write it. The reason, null when it can.</summary>
    internal static string? TreeProblem(string path, bool reparse, string? owner, IReadOnlyList<AclEntry>? dacl, string? agentSid)
    {
        if (reparse)
        {
            return $"{path} is a link or reparse point.";
        }

        if (dacl is null)
        {
            return $"{path} has no access list, so everyone may change it.";
        }

        if (owner is null || !(TrustedDirectoryOwner(owner) || (agentSid is not null && owner == agentSid)))
        {
            return $"{path} is owned by {owner ?? "no one"}.";
        }

        return Grantee(dacl, WriteRights, passedOn: true) is { } who ? $"{path} may be changed by {who}." : null;
    }

    /// <summary>Checks <paramref name="start"/> and every directory above it, up to <paramref name="stopAt"/>. <paramref name="folder"/>
    /// says whether <paramref name="start"/> is the agent's own folder, where anything that lets someone add or change what it holds counts.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? CheckChain(string? start, bool folder, string? stopAt)
    {
        var directory = start;
        while (directory is not null)
        {
            var dirAttributes = TryAttributes(directory);
            if (dirAttributes is null)
            {
                return $"{directory} cannot be read.";
            }

            if ((dirAttributes.Value & FileAttributes.ReparsePoint) != 0)
            {
                return $"{directory} is a link or reparse point.";
            }

            var acl = ReadAcl(new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
            if (acl.Dacl is null)
            {
                return $"{directory} has no access list, so everyone may change it.";
            }

            if (!TrustedDirectoryOwner(acl.Owner))
            {
                return $"{directory} is owned by {acl.Owner ?? "no one"}, who may change who can write it.";
            }

            if (Grantee(acl.Dacl, folder ? WriteRights : ReplaceRights, passedOn: folder) is { } who)
            {
                return $"{directory} may be changed by {who}.";
            }

            folder = false;
            if (stopAt is not null && string.Equals(Path.TrimEndingDirectorySeparator(directory), Path.TrimEndingDirectorySeparator(Path.GetFullPath(stopAt)), StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            directory = Path.GetDirectoryName(directory);
        }

        return null;
    }

    private static FileAttributes? TryAttributes(string path)
    {
        try
        {
            return File.GetAttributes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (string? Owner, List<AclEntry>? Dacl) ReadAcl(FileSystemSecurity security)
    {
        var raw = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        var owner = raw.Owner?.Value;
        if (raw.DiscretionaryAcl is null)
        {
            return (owner, null);
        }

        var entries = new List<AclEntry>();
        foreach (var ace in raw.DiscretionaryAcl)
        {
            switch (ace)
            {
                case QualifiedAce { AceQualifier: AceQualifier.AccessAllowed } allowed:
                    entries.Add(new AclEntry(true, (byte)allowed.AceFlags, (uint)allowed.AccessMask, allowed.SecurityIdentifier.Value));
                    break;
                case QualifiedAce:
                    // A denying entry lets no one in, and a system-audit entry is not an access entry.
                    break;
                default:
                    // An entry of a kind this does not read: count it as letting everyone write rather than trust what it cannot see.
                    entries.Add(new AclEntry(true, (byte)ace.AceFlags, uint.MaxValue, "S-1-1-0"));
                    break;
            }
        }

        return (owner, entries);
    }

    // ---- Linux -----------------------------------------------------------------------------------------------------------------

    /// <summary>What <c>stat</c> says about one path.</summary>
    internal readonly record struct UnixEntry(string Path, int Uid, int Mode, int Links, string Kind);

    /// <summary>Reads <c>stat -c '%u %a %h %F'</c> output for <paramref name="paths"/>, one line each, in order.</summary>
    internal static List<UnixEntry>? ParseStat(IReadOnlyList<string> paths, string output)
    {
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != paths.Count)
        {
            return null;
        }

        var list = new List<UnixEntry>();
        for (var i = 0; i < lines.Length; i++)
        {
            var parts = lines[i].Split(' ', 4);
            if (parts.Length != 4 || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
                !TryOctal(parts[1], out var mode) || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var links))
            {
                return null;
            }

            list.Add(new UnixEntry(paths[i], uid, mode, links, parts[3].Trim()));
        }

        return list;
    }

    private static bool TryOctal(string text, out int value)
    {
        value = 0;
        if (text.Length is 0 or > 5)
        {
            return false;
        }

        foreach (var c in text)
        {
            if (c is < '0' or > '7')
            {
                return false;
            }

            value = (value * 8) + (c - '0');
        }

        return true;
    }

    /// <summary>Every path from the root down to the copy: the directories above it, then the copy.</summary>
    internal static List<string> UnixChain(string path)
    {
        // Split at '/' itself: the rule is about Unix paths and is tested on every system.
        var chain = new List<string> { "/" };
        var current = "";
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            current += "/" + part;
            chain.Add(current);
        }

        return chain;
    }

    /// <summary>The reason the entries cannot be trusted, null when they can. The last entry is the copy.</summary>
    internal static string? EvaluateUnix(IReadOnlyList<UnixEntry> chain, int trustedUid)
    {
        for (var i = 0; i < chain.Count; i++)
        {
            var e = chain[i];
            var isCopy = i == chain.Count - 1;
            if (e.Kind == "symbolic link")
            {
                return $"{e.Path} is a link.";
            }

            if (isCopy && e.Kind != "regular file")
            {
                return $"{e.Path} is a {e.Kind}, not a program.";
            }

            if (!isCopy && e.Kind != "directory")
            {
                return $"{e.Path} is a {e.Kind}, not a directory.";
            }

            if (isCopy && e.Links != 1)
            {
                return $"{e.Path} has {e.Links.ToString(CultureInfo.InvariantCulture)} hard links.";
            }

            if (e.Uid != trustedUid)
            {
                return $"{e.Path} is owned by user {e.Uid.ToString(CultureInfo.InvariantCulture)}, not by root.";
            }

            if ((e.Mode & 0b000_010_010) != 0)
            {
                return $"{e.Path} may be changed by its group or by others (mode {Convert.ToString(e.Mode, 8)}).";
            }
        }

        return null;
    }
}
