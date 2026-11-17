# Test-AdminOnly is true when only administrators can change $Path: it and
# each folder above it, up to and including $Top, are plain files and
# folders (not links) owned by SYSTEM, Administrators or TrustedInstaller,
# and grant no one else the right to write, add, delete, or change their
# permissions or owner. The agent runs what it finds as LocalSystem, so a
# program that a standard user could replace would run their code as
# LocalSystem. (Prepended to the Windows software scripts.)
function Test-AdminOnly([string]$Path, [string]$Top) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # WriteData/AddFile, AppendData/AddSubdirectory, DeleteChild, Delete,
    # WriteDAC, WriteOwner, GenericAll, GenericWrite.
    $unsafe = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    try {
        $stop = (Get-Item -LiteralPath $Top -Force -ErrorAction Stop).FullName.TrimEnd('\')
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        while ($item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            # .NET, not Get-Acl: its module fails to load when PSModulePath
            # names PowerShell 7's modules, and every check would then fail.
            $acl = $item.GetAccessControl()
            if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne 'Allow') { continue }
                if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                if ($trusted -contains $rule.IdentityReference.Value) { continue }
                if (([int64]$rule.FileSystemRights -band $unsafe) -ne 0) { return $false }
            }
            if ($item.FullName.TrimEnd('\') -eq $stop) { return $true }
            $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
        }
    } catch {
        return $false
    }
    return $false
}

