//go:build windows

package host

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func systemDescription() string {
	v, err := WindowsVersion()
	if err != nil {
		return "Windows"
	}
	return v.Name
}

// WindowsInfo is the Windows release, from the registry.
type WindowsInfo struct {
	// Name is the release as people know it: Windows 11 Pro 23H2.
	Name string
	// Version is major.minor.build: 10.0.22631.
	Version string
	// Build is the build with its update revision: 22631.4460.
	Build string
	// Server is true on Windows Server.
	Server bool
}

// WindowsVersion reads the Windows release from the registry.
func WindowsVersion() (WindowsInfo, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return WindowsInfo{}, err
	}
	defer func() { _ = k.Close() }()
	str := func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	}
	num := func(name string) (uint64, bool) {
		v, _, err := k.GetIntegerValue(name)
		return v, err == nil
	}
	build, _ := strconv.Atoi(str("CurrentBuildNumber"))
	display := str("DisplayVersion")
	if display == "" {
		display = str("ReleaseId")
	}
	major, ok := num("CurrentMajorVersionNumber")
	minor, _ := num("CurrentMinorVersionNumber")
	version := str("CurrentVersion") // 6.3 before Windows 10
	if ok {
		version = fmt.Sprintf("%d.%d", major, minor)
	}
	info := WindowsInfo{
		Name:    WindowsName(str("ProductName"), display, build),
		Version: fmt.Sprintf("%s.%d", version, build),
		Build:   strconv.Itoa(build),
		Server:  str("InstallationType") == "Server",
	}
	if ubr, ok := num("UBR"); ok {
		info.Build += "." + strconv.FormatUint(ubr, 10)
	}
	return info, nil
}

// IsAdmin reports whether the agent runs elevated, as an administrator or
// as the system.
func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// ServicesAvailable reports whether the agent can install itself as a
// service; Windows always can.
func ServicesAvailable() bool { return true }

// SystemServices returns the Windows service manager.
func SystemServices(Paths) Services { return WindowsServices{} }

// protectedDACL grants full control to SYSTEM and Administrators only, for
// everything below, and drops what the parent grants: ProgramData and
// Program Files let every user read.
const protectedDACL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Protect creates dir if needed and makes it reachable by SYSTEM and
// Administrators only.
//
// Any user may create folders under ProgramData. There, every folder from
// ProgramData down to dir must also be a plain folder (not a link) owned by
// the system, the Administrators group, TrustedInstaller or the account the
// agent runs as. A folder someone else made beforehand is moved aside and
// made anew rather than used: whatever access list we set, its owner could
// change it again, or could hold it open to add files later, and then
// replace the agent's settings and key. Folders are created with their
// access list, so there is no moment when other users can reach them.
func Protect(dir string) error {
	return protect(dir, cmp.Or(os.Getenv("ProgramData"), `C:\ProgramData`))
}

func protect(dir, shared string) error {
	dir, shared = filepath.Clean(dir), filepath.Clean(shared)
	rel, err := filepath.Rel(shared, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// Not below ProgramData: Program Files, where only administrators
		// create folders.
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { //nolint:gosec // only the last folder is the agent's own
			return err
		}
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			return mkdirProtected(dir)
		}
		return setProtected(dir)
	}
	p := shared
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		if _, _, err := trustedFolder(p, false); err != nil {
			return err
		}
	}
	return nil
}

// checkState makes dir, the agent's state folder below shared (ProgramData),
// safe to read before anything in it is read or written:
//   - every folder from shared down to dir is made a protected folder that
//     only administrators made, as Protect does;
//   - dir's access list must also let no one but the system, the
//     Administrators group and TrustedInstaller change it or what it holds
//     (othersMayChange). Another list that lets no one else in is set back
//     to the protected one; a list that does let someone else in means what
//     dir holds may have been changed in place;
//   - a folder that fails is moved aside, with all it holds, and made anew;
//   - in a folder that passes, the entries named must be plain files with a
//     single link, or plain folders, that a trusted account owns and no one
//     else may change. An entry that fails moves aside with the rest of its
//     group, into a folder beside dir, and is not read.
//
// Entries are checked in order, so a folder must come before the entries
// in it. Nothing else in dir is checked: the agent reads nothing else.
func checkState(dir, shared string, entries [][]string) (StateCheck, error) {
	var c StateCheck
	dir, shared = filepath.Clean(dir), filepath.Clean(shared)
	rel, err := filepath.Rel(shared, dir)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return c, fmt.Errorf("the agent's state folder %s is not below %s", dir, shared)
	}
	// ProgramData is always there; a test's root needs one made.
	if err := os.MkdirAll(shared, 0o755); err != nil { //nolint:gosec // ProgramData, or a test's
		return c, err
	}
	// Protecting a folder above rewrites what dir and its files inherit, so
	// whether others could change them is read first, as it stands. A list
	// that cannot be read counts as letting them.
	others, err := othersMayChangeFolder(dir)
	if errors.Is(err, fs.ErrNotExist) {
		others = false
	} else if err != nil {
		others = true
	}
	p := shared
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		p = filepath.Join(p, part)
		// What was below a folder moved aside went with it, and is made anew.
		moved, reprotected, err := trustedFolder(p, i == len(parts)-1 && others)
		if moved != "" {
			c.Aside = append(c.Aside, moved)
		}
		if reprotected {
			c.Reprotected = append(c.Reprotected, p)
		}
		if err != nil {
			return c, err
		}
	}
	moved, err := trustedEntries(dir, entries)
	c.Aside = append(c.Aside, moved...)
	return c, err
}

// trustedFolder makes p a protected folder that only administrators made,
// creating it, or replacing one that someone else made. A folder of theirs
// with another access list gets the protected one, unless others could
// change it: then it is replaced too. It returns where it moved a folder it
// replaced, and whether it set a folder's access list back.
func trustedFolder(p string, others bool) (aside string, reprotected bool, err error) {
	fi, err := os.Lstat(p) //nolint:gosec // below ProgramData, from the system's environment
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, mkdirProtected(p)
	}
	if err != nil {
		return "", false, err
	}
	if plainFolder(fi) {
		ok, err := trustedOwner(p)
		if err != nil {
			return "", false, err
		}
		if ok {
			// Setting an access list rewrites the lists of everything below,
			// so a folder that has the protected one keeps it as it is.
			protected, err := protectedACL(p)
			if err != nil || protected {
				return "", false, err
			}
			if !others {
				if err := setProtected(p); err != nil {
					return "", false, err
				}
				return "", true, nil
			}
		}
	}
	aside = fmt.Sprintf("%s.untrusted-%d", p, time.Now().UnixNano())
	if err := os.Rename(p, aside); err != nil { //nolint:gosec // below ProgramData, from the system's environment
		return "", false, fmt.Errorf("%s was not made by an administrator, or others could change it, so the agent will not use it, and moving it aside failed: %w; delete it and try again", p, err)
	}
	return aside, false, mkdirProtected(p)
}

// trustedEntries checks the entries of dir that entries name (checkState),
// and moves aside each group with an entry that fails.
func trustedEntries(dir string, entries [][]string) ([]string, error) {
	var aside []string
	away := "" // the folder beside dir that what fails moves to
	for _, group := range entries {
		var found []string
		ok := true
		for _, name := range group {
			matches, err := match(dir, name)
			if err != nil {
				return aside, err
			}
			for _, m := range matches {
				good, err := trustedEntry(m)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return aside, err
				}
				found, ok = append(found, m), ok && good
			}
		}
		if ok {
			continue
		}
		if away == "" {
			away = fmt.Sprintf("%s.untrusted-%d", dir, time.Now().UnixNano())
			if err := mkdirProtected(away); err != nil {
				return aside, err
			}
		}
		for _, m := range found {
			rel, err := filepath.Rel(dir, m)
			if err != nil {
				return aside, err
			}
			to := filepath.Join(away, rel)
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return aside, err
			}
			if err := os.Rename(m, to); err != nil {
				return aside, fmt.Errorf("the agent cannot trust %s, and moving it aside failed: %w; delete it and try again", m, err)
			}
			aside = append(aside, to)
		}
	}
	return aside, nil
}

// match lists what name, relative to dir, names. Only its last element may
// be a pattern; its folder is read as it is, so it must have been checked.
func match(dir, name string) ([]string, error) {
	folder, pattern := filepath.Split(filepath.Join(dir, name))
	folder = filepath.Clean(folder)
	if !strings.ContainsAny(pattern, `*?[`) {
		return []string{filepath.Join(folder, pattern)}, nil
	}
	list, err := os.ReadDir(folder)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range list {
		if ok, err := filepath.Match(pattern, e.Name()); err != nil {
			return nil, err
		} else if ok {
			out = append(out, filepath.Join(folder, e.Name()))
		}
	}
	return out, nil
}

// trustedEntry reports whether p is a plain file with a single link, or a
// plain folder, that a trusted account owns and no one else may change
// (entryProblem).
func trustedEntry(p string) (bool, error) {
	why, err := entryProblem(p, false, false)
	return why == "" && err == nil, err
}

// entryProblem says why p fails the test of trustedEntry, or "" when it
// passes (inspect). exclusive is inspect's.
func entryProblem(p string, links, exclusive bool) (string, error) {
	h, why, err := inspect(p, links, exclusive)
	if h != 0 {
		_ = windows.CloseHandle(h)
	}
	return why, err
}

// The storage reparse points that leave a file a plain file, which Windows
// reads as it would without them: files compressed by its overlay filter
// (compact /exe, IO_REPARSE_TAG_WOF) and by data deduplication
// (IO_REPARSE_TAG_DEDUP). Every other tag is a link, a junction, a
// placeholder or something the agent does not know (ADR-0064). Where the
// overlay filter runs, as on CI's runners, it hides its reparse point, and
// a compressed file reads as a plain file before its tag is looked at.
const (
	reparseWOF   = 0x80000017
	reparseDedup = 0x80000013
)

// reparseRefused reports whether a reparse point with tag makes an entry
// fail the check: always for a folder, and for a file unless the tag is
// one of the two above.
func reparseRefused(tag uint32, folder bool) bool {
	return folder || (tag != reparseWOF && tag != reparseDedup)
}

const (
	inspectAccess = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL
	inspectFlags  = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS
	shareAll      = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
)

// openEntry opens p itself, never through a link, to check it. Not
// exclusive, it opens p sharing everything, as the agent's own state is
// checked: the agent may hold its own files open. Exclusive, it opens p to
// read it, sharing it for reading only. That open fails while anyone else
// holds p open to write or delete it, or without sharing it; while it
// stays open, no one else may open p to write or delete it. Where it fails
// so, busy is true and p is opened sharing everything, which checks a
// folder as well: what holds a folder open does not change what the folder
// allows.
func openEntry(p string, exclusive bool) (h windows.Handle, busy bool, err error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, false, err
	}
	if !exclusive {
		h, err = windows.CreateFile(name, inspectAccess, shareAll, nil, windows.OPEN_EXISTING, inspectFlags, 0)
		return h, false, err
	}
	h, err = windows.CreateFile(name, windows.FILE_READ_DATA|inspectAccess, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, inspectFlags, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		busy = true
		h, err = windows.CreateFile(name, inspectAccess, shareAll, nil, windows.OPEN_EXISTING, inspectFlags, 0)
	}
	return h, busy, err
}

// inspect checks p as trustedEntry does: it must be a plain file with a
// single link (any number, with links) or a plain folder, that a trusted
// account owns and no one else may change (writer). Exclusive, a file must
// also not be open in another program that may write it (openEntry): an
// access list fixed afterwards does not close what was opened before it
// was (ADR-0064). A file compressed by
// Windows or by deduplication is a plain file. It looks at p itself,
// never through a link. What it may not look at fails: only its owner can
// have kept the system and administrators out. Where p passes, the handle
// it checked p through is returned open, for the caller to close: for a
// file, no one else may write or delete it while that stays open.
func inspect(p string, links, exclusive bool) (windows.Handle, string, error) {
	h, busy, err := openEntry(p, exclusive)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return 0, "cannot be read by the agent", nil
	}
	if err != nil {
		return 0, "", &fs.PathError{Op: "open", Path: p, Err: err}
	}
	why, err := handleProblem(h, p, links, busy)
	if why != "" || err != nil {
		_ = windows.CloseHandle(h)
		return 0, why, err
	}
	return h, "", nil
}

// handleProblem is inspect's test of the entry h is open to.
func handleProblem(h windows.Handle, p string, links, busy bool) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", &fs.PathError{Op: "stat", Path: p, Err: err}
	}
	folder := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		tag, err := reparseTag(h)
		if err != nil {
			return "", &fs.PathError{Op: "read the reparse tag of", Path: p, Err: err}
		}
		if reparseRefused(tag, folder) {
			return "is a link, junction or other reparse point", nil
		}
	}
	if !folder && !links && info.NumberOfLinks != 1 {
		return fmt.Sprintf(linksReason, info.NumberOfLinks), nil
	}
	acl, why, err := ownerAndList(h, p)
	if why != "" || err != nil {
		return why, err
	}
	if who, ok := writer(acl, folder); ok {
		return "can be changed by " + nameOf(who), nil
	}
	if busy && !folder {
		return busyReason, nil
	}
	return "", nil
}

// busyReason is why a file that passes but is open in another program,
// to write it or without sharing it, fails an exclusive check (openEntry).
const busyReason = "is open in another program that may write to it"

// linksReason is why a file with more than one hard link fails a check
// that allows it one only (handleProblem), with how many it has.
const linksReason = "has %d hard links"

// reparseTag is the tag of the reparse point h is open to.
func reparseTag(h windows.Handle) (uint32, error) {
	var info struct{ FileAttributes, ReparseTag uint32 }
	err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))) //nolint:gosec // a small struct's size
	return info.ReparseTag, err
}

// ownerAndList reads the access list of what h is open to, and says why
// that fails where its owner is not trusted or it has no list.
func ownerAndList(h windows.Handle, p string) ([]aclEntry, string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, "", &fs.PathError{Op: "read the owner and access list of", Path: p, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, "", err
	}
	if owner == nil {
		return nil, "has no owner", nil
	}
	if !trusted(owner) {
		return nil, "is owned by " + accountName(owner), nil
	}
	acl, ok, err := accessList(sd)
	if err != nil {
		return nil, "", &fs.PathError{Op: "read the access list of", Path: p, Err: err}
	}
	if !ok {
		return nil, "can be changed by everyone: it has no access list", nil
	}
	return acl, "", nil
}

// nameOf names the SID an access list entry names, or says that the entry
// names one in a way the agent does not read.
func nameOf(who string) string {
	if who == "" {
		return "someone an access list entry names in a way the agent does not read"
	}
	sid, err := windows.StringToSid(who)
	if err != nil {
		return who
	}
	return accountName(sid)
}

// accountName names an account as Windows does (BUILTIN\Users), or by its
// SID when it has no name.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil || account == "":
		return sid.String()
	case domain == "":
		return account
	}
	return domain + `\` + account
}

// Untrusted is an entry that fails the test of trustedEntry, and why.
type Untrusted struct {
	Path string
	// Reason completes a sentence about the entry: "can be changed by
	// BUILTIN\Users".
	Reason string
	// Busy says the entry failed only for being open in another program
	// that may write to it, or that let no one else open it (openEntry):
	// anyone who may read a file can do that, so it says nothing of who
	// may change the file.
	Busy bool
	// Linked says the entry failed only for having more than one hard link.
	// Which Windows builds let a user who may only read a file link to it
	// is not confirmed, so neither does that say who may change the file.
	Linked bool
}

func (u *Untrusted) Error() string { return u.Path + " " + u.Reason }

func untrusted(p, why string) *Untrusted {
	var n uint32
	_, err := fmt.Sscanf(why, linksReason, &n)
	linked := err == nil && why == fmt.Sprintf(linksReason, n)
	return &Untrusted{Path: p, Reason: why, Busy: why == busyReason, Linked: linked}
}

// CheckTree checks root and everything in it at any depth as trustedEntry
// checks an entry of the agent's state, each before what it holds, and
// never through a link (ADR-0064: a PowerShell install and its module
// folders). links allows files more than one link: in System32 Windows
// keeps many of its own files as hard links into its component store. It
// returns an *Untrusted for the first entry that fails, or another error
// when one could not be read.
func CheckTree(root string, links bool) error {
	held, err := CheckTreeHolding(root, links, nil)
	held.Close()
	return err
}

// Held is files a check keeps open: until it is closed no one else may
// write or delete them.
type Held struct{ handles []windows.Handle }

// Close lets the files go. A nil Held holds nothing.
func (h *Held) Close() {
	if h == nil {
		return
	}
	for _, x := range h.handles {
		_ = windows.CloseHandle(x)
	}
	h.handles = nil
}

// CheckTreeHolding checks root as CheckTree does, and keeps open the files
// hold names, through the handles they were checked through, so that
// nothing changes them between their check and their use: ADR-0064 holds a
// PowerShell install's program and libraries until the run's process is
// created. On failure nothing is held.
func CheckTreeHolding(root string, links bool, hold func(path string) bool) (*Held, error) {
	held := &Held{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		h, why, err := inspect(p, links, true)
		if err != nil {
			return err
		}
		if why != "" {
			return untrusted(p, why)
		}
		if hold != nil && !d.IsDir() && hold(p) {
			held.handles = append(held.handles, h)
			return nil
		}
		return windows.CloseHandle(h)
	})
	if err != nil {
		held.Close()
		return nil, err
	}
	return held, nil
}

// CheckSubtree checks root and everything in it as CheckTree does, without
// the exclusive open: the agent's own files may be open, and an open file
// does not change who may write it (ADR-0070: the folders the agent
// excludes from Defender are verified before it does).
func CheckSubtree(root string) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		why, err := entryProblem(p, false, false)
		if err != nil {
			return err
		}
		if why != "" {
			return untrusted(p, why)
		}
		return nil
	})
}

// CheckEntry checks one entry as CheckTree does, without what it holds.
func CheckEntry(p string, links bool) error {
	why, err := entryProblem(p, links, true)
	if err != nil {
		return err
	}
	if why != "" {
		return untrusted(p, why)
	}
	return nil
}

// CheckAbove checks p and the folders above it, up to its drive's root,
// for what would let anyone but the administration put another folder in
// p's place (ADR-0064: a PowerShell install and each module folder). Each
// folder on the way that exists, p included, must not be a link or
// junction, must have a trusted owner, and must not let others delete or
// rename it, nor change its access list or owner (replaceRights); each
// folder above p must not let others delete what it holds (replaceInRights).
// Where p, or a folder on the way to it, does not exist, the nearest one
// that does must not let others add a folder to it (createInRights),
// unless it is the drive's root, which lets every user add a folder; a
// drive's root is held only to replaceInRights. What p holds is not
// checked here. It returns an *Untrusted for the first folder that fails.
func CheckAbove(p string) error {
	p = filepath.Clean(p)
	child, childExists := p, false
	if _, err := os.Lstat(p); err == nil {
		childExists = true
		if why, err := folderProblem(p, replaceRights); why != "" || err != nil {
			return untrustedOr(p, why, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for {
		parent := filepath.Dir(child)
		if parent == child {
			return nil
		}
		if _, err := os.Lstat(parent); errors.Is(err, fs.ErrNotExist) {
			child = parent
			continue
		} else if err != nil {
			return err
		}
		rights := replaceInRights
		if filepath.Dir(parent) != parent {
			rights |= replaceRights
			if !childExists {
				rights |= createInRights
			}
		}
		if why, err := folderProblem(parent, rights); why != "" || err != nil {
			return untrustedOr(parent, why, err)
		}
		child, childExists = parent, true
	}
}

func untrustedOr(p, why string, err error) error {
	if err != nil {
		return err
	}
	return &Untrusted{Path: p, Reason: why}
}

// folderProblem says why the folder p fails CheckAbove's test for rights,
// or "" when it passes.
func folderProblem(p string, rights uint32) (string, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, inspectAccess, shareAll, nil, windows.OPEN_EXISTING, inspectFlags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return "cannot be read by the agent", nil
	}
	if err != nil {
		return "", &fs.PathError{Op: "open", Path: p, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", &fs.PathError{Op: "stat", Path: p, Err: err}
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return "is a link, junction or other reparse point", nil
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return "is not a folder", nil
	}
	acl, why, err := ownerAndList(h, p)
	if why != "" || err != nil {
		return why, err
	}
	if who, ok := grantee(acl, rights&^createInRights, false); ok {
		return "can be replaced, or what it holds deleted, by " + nameOf(who), nil
	}
	if who, ok := grantee(acl, rights&createInRights, false); ok {
		return "lets " + nameOf(who) + " create folders in it", nil
	}
	return "", nil
}

// plainFolder reports whether fi is a folder and not a link, junction or
// other reparse point.
func plainFolder(fi fs.FileInfo) bool {
	if fi.Mode().Type() != fs.ModeDir {
		return false
	}
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// trustedOwner reports whether p's owner is trusted.
func trustedOwner(p string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	return trusted(owner), nil
}

// trusted reports whether owner is the system, the Administrators group,
// TrustedInstaller, or the account the agent runs as. What an elevated
// administrator creates, files and folders alike, belongs to the
// Administrators group: Windows makes it the default owner of an elevated
// administrator's token. (The "Default owner for objects created by members
// of the Administrators group" policy that could make it the administrator's
// own account is ignored since Windows Vista, KB 947721.) What the agent's
// service creates belongs to the system or to the Administrators group.
func trusted(owner *windows.SID) bool {
	if slices.Contains(administration, owner.String()) {
		return true
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && owner.Equals(u.User.Sid)
}

// protectedACL reports whether p's access list is the protected one: not
// inherited, full control for SYSTEM and Administrators, and nothing for
// anyone else, in any order.
func protectedACL(p string) (bool, error) {
	got, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	want, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return false, err
	}
	control, _, err := got.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false, err
	}
	a, ok, err := accessList(got)
	if err != nil || !ok {
		return false, err
	}
	b, _, err := accessList(want)
	return err == nil && sameEntries(a, b), err
}

// othersMayChangeFolder reports whether the folder p's access list lets
// anyone but the administration change it, or what it holds
// (othersMayChange).
func othersMayChangeFolder(p string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	return othersMayChange(sd, true)
}

// othersMayChange reports whether sd's access list lets anyone but the
// system, the Administrators group and TrustedInstaller change what it
// protects (othersMayWrite), folder telling whether that is a folder. A
// missing access list lets everyone.
func othersMayChange(sd *windows.SECURITY_DESCRIPTOR, folder bool) (bool, error) {
	acl, ok, err := accessList(sd)
	if err != nil {
		return false, err
	}
	return !ok || othersMayWrite(acl, folder), nil
}

// accessList reads the entries of sd's access list. ok is false when it
// has none at all, which lets everyone do everything; an empty one lets no
// one do anything.
func accessList(sd *windows.SECURITY_DESCRIPTOR) (acl []aclEntry, ok bool, err error) {
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil || dacl == nil {
		return nil, false, err
	}
	acl = []aclEntry{}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, false, err
		}
		e := aclEntry{kind: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch e.kind {
		case aceAllowed, aceDenied, aceAllowedCallback, aceDeniedCallback:
			// These keep the SID they name at SidStart; the object kinds
			// keep theirs after the objects' GUIDs.
			e.who = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		acl = append(acl, e)
	}
	return acl, true, nil
}

// mkdirProtected creates a folder with the protected access list from the
// start.
func mkdirProtected(p string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa)) //nolint:gosec // a small struct's size
	if err := windows.CreateDirectory(name, &sa); err != nil {
		return &fs.PathError{Op: "mkdir", Path: p, Err: err}
	}
	return nil
}

// setProtected replaces an existing folder's access list.
func setProtected(p string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// RemoveExecutable deletes an installed program. A running program cannot
// be deleted on Windows: it is then deleted at the next restart, and later
// is true.
func RemoveExecutable(path string) (later bool, err error) {
	err = os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	p, perr := windows.UTF16PtrFromString(path)
	if perr != nil {
		return false, err
	}
	if merr := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); merr != nil {
		return false, fmt.Errorf("%w; scheduling its removal at restart failed too: %w", err, merr)
	}
	return true, nil
}

// replaceFile moves src over dst. A running program cannot be overwritten
// on Windows, but it can be renamed: the old one moves aside and is deleted
// once it no longer runs.
func replaceFile(src, dst string) error {
	if _, err := os.Stat(dst); err != nil {
		return os.Rename(src, dst)
	}
	old := dst + ".old"
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		old = fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())
	}
	if err := os.Rename(dst, old); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Rename(old, dst)
		return err
	}
	_, _ = RemoveExecutable(old)
	return nil
}

// WindowsServices installs and removes Windows services. Services run as
// LocalSystem, start at boot and are restarted by Windows when they fail.
type WindowsServices struct{}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connecting to the Windows service manager: %w", err)
	}
	return m, nil
}

// commandLine quotes a service's program and arguments as mgr.CreateService
// does.
func commandLine(binary string, args []string) string {
	s := syscall.EscapeArg(binary)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// Install creates or updates the service and starts it unless it runs.
func (WindowsServices) Install(_ context.Context, s Service) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	service, err := m.OpenService(s.Name)
	if err != nil {
		service, err = m.CreateService(s.Name, s.Binary, mgr.Config{
			DisplayName:  s.DisplayName,
			Description:  s.Description,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, s.Args...)
		if err != nil {
			return fmt.Errorf("creating the %s service: %w", s.Name, err)
		}
	} else {
		cfg, err := service.Config()
		if err != nil {
			_ = service.Close()
			return fmt.Errorf("reading the %s service: %w", s.Name, err)
		}
		cfg.BinaryPathName = commandLine(s.Binary, s.Args)
		cfg.DisplayName, cfg.Description, cfg.StartType = s.DisplayName, s.Description, mgr.StartAutomatic
		if err := service.UpdateConfig(cfg); err != nil {
			_ = service.Close()
			return fmt.Errorf("updating the %s service: %w", s.Name, err)
		}
	}
	defer func() { _ = service.Close() }()
	delay := max(s.RestartDelay, time.Second)
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: delay}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("setting the %s service's recovery: %w", s.Name, err)
	}
	// An exit with an error code counts as a failure too, not only a crash.
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("setting the %s service's recovery: %w", s.Name, err)
	}
	st, err := service.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		if err := service.Start(); err != nil {
			return fmt.Errorf("starting the %s service: %w", s.Name, err)
		}
	}
	return nil
}

// stopService stops a service and waits up to 30 seconds for it.
func stopService(ctx context.Context, s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st, err = s.Query(); err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("the service did not stop within 30 seconds")
}

// Restart stops a service if it runs, then starts it.
func (WindowsServices) Restart(ctx context.Context, name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	if err := stopService(ctx, s); err != nil {
		return fmt.Errorf("stopping the %s service: %w", name, err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("starting the %s service: %w", name, err)
	}
	return nil
}

// Stop stops a service and waits for it.
func (WindowsServices) Stop(ctx context.Context, name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	if err := stopService(ctx, s); err != nil {
		return fmt.Errorf("stopping the %s service: %w", name, err)
	}
	return nil
}

// Remove stops and deletes a service.
func (WindowsServices) Remove(ctx context.Context, name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	stopErr := stopService(ctx, s)
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("deleting the %s service: %w", name, err)
	}
	if stopErr != nil {
		return fmt.Errorf("the %s service was deleted but did not stop: %w", name, stopErr)
	}
	return nil
}

// State is the service's state: running, stopped, starting, stopping,
// paused, or "not installed".
func (WindowsServices) State(_ context.Context, name string) string {
	m, err := connect()
	if err != nil {
		return "unknown"
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "not installed"
	}
	if err != nil {
		return "unknown"
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	switch st.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return "paused"
	}
	return "unknown"
}
