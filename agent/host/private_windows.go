package host

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// PrivateFile is a file opened for reading by OpenPrivate, with what was
// found on the open handle.
type PrivateFile struct {
	*os.File
	// Meta describes the file's size, access list and times, to tell that it
	// changed.
	Meta string
}

// Problem is why OpenPrivate refused a file.
type Problem struct {
	Reason string
	// Readable says that someone other than the administration may read it.
	Readable bool
}

func (p *Problem) Error() string { return p.Reason }

// OpenPrivate opens path for reading without following links, and checks it
// on the open handle (ADR-0056, the enrollment file): a file, not a reparse
// point, with one link, owned by SYSTEM, Administrators or TrustedInstaller,
// whose access list's allowing entries name only those three. Every folder
// from top down to the file's own must be a plain folder, with such an
// owner, in which only those three may create, change or delete: others may
// read. Inherit-only entries apply to what is created later, not to what
// holds them, and are ignored. A *Problem says what failed.
func OpenPrivate(path, top string) (*PrivateFile, error) {
	// The folders, from the top down: a folder the check passes cannot be
	// replaced by anyone who may not change it.
	top = filepath.Clean(top)
	dir := filepath.Dir(filepath.Clean(path))
	var chain []string
	for d := dir; ; d = filepath.Dir(d) {
		chain = append(chain, d)
		if strings.EqualFold(d, top) || d == filepath.Dir(d) {
			break
		}
	}
	slices.Reverse(chain)
	for _, d := range chain {
		why, err := entryProblem(d, false, false)
		if err != nil {
			return nil, err
		}
		if why != "" {
			return nil, &Problem{Reason: "its folder " + d + " " + why}
		}
	}
	// Opened sharing it for reading only: while it stays open, no one else may
	// write or delete it.
	h, why, err := inspect(path, false, true)
	if err != nil {
		return nil, err
	}
	if why != "" {
		return nil, &Problem{Reason: why, Readable: strings.Contains(why, "can be changed by")}
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	acl, ok, err := accessList(sd)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if !ok {
		_ = windows.CloseHandle(h)
		return nil, &Problem{Reason: "has no access list, so everyone can read it", Readable: true}
	}
	for _, e := range acl {
		if who, bad := reader(e); bad {
			_ = windows.CloseHandle(h)
			return nil, &Problem{Reason: "can be read by " + nameOf(who), Readable: true}
		}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	return &PrivateFile{File: f, Meta: fmt.Sprintf("%d|%s|%d|%d", info.FileSizeLow, sd.String(), info.LastWriteTime.Nanoseconds(), info.CreationTime.Nanoseconds())}, nil
}

// reader reports whether an access list entry lets anyone but the
// administration read the file, and whom it names ("" for an entry it does
// not read plainly). Denying entries and inherit-only ones let no one in.
func reader(e aclEntry) (who string, bad bool) {
	switch e.kind {
	case aceDenied, aceDeniedObject, aceDeniedCallback, aceDeniedCallbackObject:
		return "", false
	}
	if e.flags&aceInheritOnly != 0 {
		return "", false
	}
	if (e.kind == aceAllowed || e.kind == aceAllowedCallback) && slices.Contains(administration, e.who) {
		return "", false
	}
	return e.who, true
}
