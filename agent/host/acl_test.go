package host

import "testing"

// TestOthersMayWrite: an access list lets others change the agent's state
// only by allowing someone besides the system, the Administrators group
// and TrustedInstaller a right to write, delete, or change the list or the
// owner. Reading, denying, and what only passes on to a file, do not.
func TestOthersMayWrite(t *testing.T) {
	const (
		system, admins, users = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"
		owner                 = "S-1-5-21-1-2-3-1001" // an administrator's own account
		inherit               = 0x1 | 0x2             // to files and folders
		inherited             = 0x10
		fullControl           = 0x1f01ff
		read                  = 0x120089
		readExecute           = 0x1200a9
	)
	protected := []aclEntry{
		{kind: aceAllowed, flags: inherit, mask: fullControl, who: system},
		{kind: aceAllowed, flags: inherit, mask: fullControl, who: admins},
	}
	with := func(e ...aclEntry) []aclEntry { return append(append([]aclEntry{}, protected...), e...) }
	harmless := map[string][]aclEntry{
		"the protected list": protected,
		"no entries":         {},
		"Administrators twice, with generic rights": with(
			aclEntry{kind: aceAllowed, mask: 0x10000000, who: admins},
			aclEntry{kind: aceAllowed, flags: inherit | aceInheritOnly, mask: 0x10000000, who: system}),
		"TrustedInstaller":            with(aclEntry{kind: aceAllowed, flags: inherited, mask: fullControl, who: trustedInstaller}),
		"Users may read":              with(aclEntry{kind: aceAllowed, flags: inherit, mask: read, who: users}),
		"Users may read and run":      with(aclEntry{kind: aceAllowed, mask: readExecute | 0x80000000 | 0x20000000, who: users}),
		"Users are denied everything": with(aclEntry{kind: aceDenied, mask: fullControl, who: users}),
		"a denying entry of every kind": with(
			aclEntry{kind: aceDeniedObject, mask: fullControl},
			aclEntry{kind: aceDeniedCallback, mask: fullControl, who: users},
			aclEntry{kind: aceDeniedCallbackObject, mask: fullControl}),
		"a condition that allows the system": with(aclEntry{kind: aceAllowedCallback, mask: fullControl, who: system}),
		// Program Files as Windows sets it up: whoever creates something in
		// it owns that, and only administrators may create.
		"Program Files": with(
			aclEntry{kind: aceAllowed, flags: inherit | aceInheritOnly, mask: 0x10000000, who: "S-1-3-0"},
			aclEntry{kind: aceAllowed, flags: inherit | aceInheritOnly, mask: 0x10000000, who: "S-1-3-1"},
			aclEntry{kind: aceAllowed, flags: inherit, mask: readExecute, who: users},
			aclEntry{kind: aceAllowed, flags: inherit, mask: readExecute, who: "S-1-15-2-1"}),
	}
	for name, acl := range harmless {
		for _, folder := range []bool{false, true} {
			if othersMayWrite(acl, folder) {
				t.Errorf("%s (folder %v): others may write", name, folder)
			}
		}
	}

	// Each write right on its own, to Users or to an administrator's own
	// account, lets others change the state.
	for _, right := range []uint32{0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x120116, fullControl} {
		for _, who := range []string{users, owner, ""} {
			acl := with(aclEntry{kind: aceAllowed, mask: right, who: who})
			if !othersMayWrite(acl, false) || !othersMayWrite(acl, true) {
				t.Errorf("right %#x for %q: others may not write", right, who)
			}
		}
	}
	// writer names who may.
	if who, ok := writer(with(aclEntry{kind: aceAllowed, mask: 0x2, who: users}), false); !ok || who != users {
		t.Errorf("writer = %q %v", who, ok)
	}
	if who, ok := writer(protected, true); ok || who != "" {
		t.Errorf("the protected list's writer = %q %v", who, ok)
	}
	for name, e := range map[string]aclEntry{
		"inherited":                      {kind: aceAllowed, flags: inherited, mask: 0x2, who: users},
		"passed on and applying here":    {kind: aceAllowed, flags: inherit, mask: 0x2, who: users},
		"under a condition":              {kind: aceAllowedCallback, mask: 0x2, who: users},
		"in an entry kept elsewhere":     {kind: 0x5, mask: 0x2}, // ACCESS_ALLOWED_OBJECT_ACE_TYPE
		"in an entry of an unknown kind": {kind: 0x4, mask: 0x40000, who: system},
	} {
		if !othersMayWrite(with(e), false) {
			t.Errorf("a write right %s: others may not write", name)
		}
	}

	// What is only passed on counts on a folder, where what it holds later
	// gets it, and not on a file.
	passedOn := with(aclEntry{kind: aceAllowed, flags: inherit | aceInheritOnly, mask: 0x120116, who: users})
	if othersMayWrite(passedOn, false) {
		t.Error("a file: what is only passed on lets others write")
	}
	if !othersMayWrite(passedOn, true) {
		t.Error("a folder: what it passes on does not let others write")
	}
}

// TestSameEntries: the order of an access list's entries does not matter;
// anything else about them does.
func TestSameEntries(t *testing.T) {
	a := []aclEntry{{kind: aceAllowed, flags: 3, mask: 0x1f01ff, who: "S-1-5-18"}, {kind: aceAllowed, flags: 3, mask: 0x1f01ff, who: "S-1-5-32-544"}}
	b := []aclEntry{a[1], a[0]}
	if !sameEntries(a, b) || !sameEntries(a, a) || !sameEntries(nil, []aclEntry{}) {
		t.Error("the same entries differ")
	}
	if a[0].who != "S-1-5-18" {
		t.Error("sameEntries reordered what it was given")
	}
	for _, c := range []aclEntry{
		{kind: aceAllowed, flags: 3, mask: 0x1f01ff, who: "S-1-5-32-545"},
		{kind: aceDenied, flags: 3, mask: 0x1f01ff, who: "S-1-5-18"},
		{kind: aceAllowed, flags: 3 | 0x10, mask: 0x1f01ff, who: "S-1-5-18"},
		{kind: aceAllowed, flags: 3, mask: 0x10000000, who: "S-1-5-18"},
	} {
		if sameEntries(a, []aclEntry{c, a[1]}) {
			t.Errorf("%+v counts as %+v", c, a[0])
		}
	}
	if sameEntries(a, a[:1]) || sameEntries(a, append(b, a[0])) {
		t.Error("lists of other lengths are the same")
	}
}
