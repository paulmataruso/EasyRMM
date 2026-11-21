package host

import (
	"cmp"
	"slices"
)

// The rule for Windows access lists that checkState applies is kept here,
// apart from the Windows calls that read them, so that it is tested on
// every system. The values are Windows' own (winnt.h).

// Kinds of access list entry, and the flag of an entry that is only passed
// on to what a folder holds.
const (
	aceAllowed              = 0x0 // ACCESS_ALLOWED_ACE_TYPE
	aceDenied               = 0x1 // ACCESS_DENIED_ACE_TYPE
	aceDeniedObject         = 0x6 // ACCESS_DENIED_OBJECT_ACE_TYPE
	aceAllowedCallback      = 0x9 // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
	aceDeniedCallback       = 0xA // ACCESS_DENIED_CALLBACK_ACE_TYPE
	aceDeniedCallbackObject = 0xC // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE

	aceInheritOnly = 0x8 // INHERIT_ONLY_ACE
)

// writeRights are the rights to change a file or folder, what it holds, or
// who may: write data or add a file (0x2), append data or add a folder
// (0x4), write extended attributes (0x10), delete what a folder holds
// (0x40), write attributes (0x100), delete (DELETE), change the access list
// (WRITE_DAC) or the owner (WRITE_OWNER), and the generic rights that
// include these (GENERIC_ALL, GENERIC_WRITE).
const writeRights uint32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// trustedInstaller is the NT SERVICE\TrustedInstaller account, which owns
// many of Windows' own folders.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// administration is the system, the Administrators group and
// TrustedInstaller, as SIDs: the only accounts that may change the agent's
// state on Windows.
var administration = []string{"S-1-5-18", "S-1-5-32-544", trustedInstaller}

// aclEntry is an entry of a Windows access list: its kind, flags and
// rights, and the SID it names. who is "" for a kind that keeps its SID
// elsewhere than a plain allowing entry does.
type aclEntry struct {
	kind, flags uint8
	mask        uint32
	who         string
}

// othersMayWrite reports whether an access list lets anyone but the
// administration change what it protects: an allowing entry that grants a
// write right (writeRights) to anyone else, or to someone it does not name
// plainly. Denying entries let no one in. An entry that is only passed on
// to what a folder holds counts on a folder, since what the folder holds
// later gets it, and grants nothing on a file.
func othersMayWrite(acl []aclEntry, folder bool) bool {
	for _, e := range acl {
		switch {
		case e.kind == aceDenied, e.kind == aceDeniedObject, e.kind == aceDeniedCallback, e.kind == aceDeniedCallbackObject:
		case e.mask&writeRights == 0:
		case !folder && e.flags&aceInheritOnly != 0:
		case (e.kind == aceAllowed || e.kind == aceAllowedCallback) && slices.Contains(administration, e.who):
		default:
			return true
		}
	}
	return false
}

// sameEntries reports whether two access lists hold the same entries, in
// any order: Windows may store them in another order than they were set.
func sameEntries(a, b []aclEntry) bool {
	order := func(x, y aclEntry) int {
		return cmp.Or(cmp.Compare(x.who, y.who), cmp.Compare(x.kind, y.kind), cmp.Compare(x.flags, y.flags), cmp.Compare(x.mask, y.mask))
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, order)
	slices.SortFunc(b, order)
	return slices.Equal(a, b)
}
