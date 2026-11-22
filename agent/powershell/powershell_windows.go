//go:build windows

package powershell

import (
	"cmp"
	"debug/pe"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Roots are the folders installs are looked for in: Program Files and
// Program Files (x86), from Windows' known folders, never from environment
// variables. Below them the agent looks in PowerShell\<name>\pwsh.exe,
// <name> a major version with or without -preview, and in WindowsApps for
// Store packages.
func Roots() ([]string, error) {
	var out []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT)
		if err != nil {
			return nil, fmt.Errorf("finding Program Files: %w", err)
		}
		if !containsFold(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// Discover lists Windows PowerShell and every PowerShell 7 install found in
// roots, at most agentproto.MaxPowerShell, as the inventory reports them:
// each one a run could choose is checked as a run checks it (check), so
// the inventory says what a run would do.
func Discover(roots []string) []agentproto.PowerShellInstall {
	native := nativeArch()
	found, _ := candidates(roots, native)
	list := append([]agentproto.PowerShellInstall{Desktop()}, found...)
	for i := range list {
		if list[i].Edition == agentproto.EditionCore && list[i].Usable {
			c, _ := check(&list[i], false)
			c.release()
		}
	}
	order(list, native)
	return list[:min(len(list), agentproto.MaxPowerShell)]
}

// Desktop is Windows PowerShell 5.1 as the inventory lists it: its version
// from the registry, its architecture from its program's header.
func Desktop() agentproto.PowerShellInstall {
	p := agentproto.PowerShellInstall{Edition: agentproto.EditionDesktop, Path: DesktopPath()}
	if _, err := os.Stat(p.Path); err != nil {
		p.Reason = "Not found: " + err.Error()
		return p
	}
	p.Usable = true
	var errs []string
	v, err := desktopVersion()
	if err != nil {
		errs = append(errs, "its version could not be read: "+err.Error())
	}
	arch, err := peArch(p.Path)
	if err != nil {
		errs = append(errs, "its architecture could not be read: "+err.Error())
	}
	p.Version, p.Arch = v, arch
	if len(errs) > 0 {
		p.Reason = capitalize(strings.Join(errs, "; ")) + "."
	}
	return p
}

// DesktopPath is Windows PowerShell 5.1's program, in System32.
func DesktopPath() string {
	return filepath.Join(system32(), `WindowsPowerShell\v1.0\powershell.exe`)
}

// DesktopInterpreter is Windows PowerShell as a run's result reports it.
func DesktopInterpreter() agentproto.Interpreter {
	d := Desktop()
	return agentproto.Interpreter{Edition: d.Edition, Version: d.Version, Arch: d.Arch, Path: d.Path}
}

// desktopVersion is Windows PowerShell's version as its $PSVersionTable
// prints it: the version the registry names (PowerShellVersion, 5.1.26100.1)
// with the build and revision of its engine's file, which Windows' updates
// change and the registry's value does not follow.
func desktopVersion() (string, error) {
	v, err := registryVersion()
	if err != nil {
		return "", err
	}
	engine, err := fixedFileVersion(desktopEngine())
	if err != nil {
		return "", fmt.Errorf("reading its engine's version: %w", err)
	}
	return withEngine(v, engine)
}

// registryVersion is the version Windows PowerShell's setup recorded.
func registryVersion() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("PowerShellVersion")
	return v, err
}

// desktopEngine is Windows PowerShell's engine, System.Management.Automation
// in the .NET Framework's assembly cache.
func desktopEngine() string {
	win, err := windows.GetWindowsDirectory()
	if err != nil {
		win = `C:\Windows`
	}
	return filepath.Join(win, `Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`)
}

// fixedFileVersion reads the file version of a program or library's
// version resource, as four numbers.
func fixedFileVersion(path string) ([4]uint16, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return [4]uint16{}, err
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return [4]uint16{}, err
	}
	var (
		p *windows.VS_FIXEDFILEINFO
		n uint32
	)
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&p), &n); err != nil || n < uint32(unsafe.Sizeof(*p)) {
		return [4]uint16{}, errors.New("it has no file version")
	}
	return [4]uint16{uint16(p.FileVersionMS >> 16), uint16(p.FileVersionMS), uint16(p.FileVersionLS >> 16), uint16(p.FileVersionLS)}, nil //nolint:gosec // halves of 32 bits
}

func system32() string {
	if d, err := windows.GetSystemDirectory(); err == nil {
		return d
	}
	return `C:\Windows\System32`
}

// candidates lists the PowerShell 7 installs in roots with what their files
// say of them, those a run may choose marked usable before anything is
// checked (assess), in the order a run prefers them. What could not be
// read, a version that is not one included, is listed blocked (unread,
// assess), and the error a run fails with is put in blocked by its path.
func candidates(roots []string, native string) (list []agentproto.PowerShellInstall, blocked map[string]error) {
	blocked = map[string]error{}
	for _, root := range roots {
		list = append(list, installsIn(root, blocked)...)
		list = append(list, storeInstallsIn(root)...)
	}
	for i := range list {
		if list[i].Reason != "" {
			continue
		}
		if err := assess(&list[i], native); err != nil {
			blocked[list[i].Path] = err
		}
	}
	order(list, native)
	return list, blocked
}

// installsIn lists the installs in root\PowerShell, with what their files
// say of them. Only a folder that is not there is not looked in, and only
// an install folder without pwsh.exe is not listed (notThere). A folder
// that cannot be listed, or a pwsh.exe that cannot be read, is listed
// blocked (unread), with the error a run fails with put in blocked by its
// path: anyone who may read a file can keep the agent from reading it,
// holding it open or locking it, and would otherwise choose where pwsh
// scripts run (ADR-0064).
func installsIn(root string, blocked map[string]error) []agentproto.PowerShellInstall {
	folder := filepath.Join(root, "PowerShell")
	entries, err := os.ReadDir(folder)
	if notThere(err) {
		return nil
	}
	if err != nil {
		p := agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Path: folder}
		blocked[folder] = unread(&p, err)
		return []agentproto.PowerShellInstall{p}
	}
	var out []agentproto.PowerShellInstall
	for _, e := range entries {
		preview, ok := installFolder(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(folder, e.Name(), "pwsh.exe")
		if _, err := os.Lstat(path); notThere(err) {
			continue
		}
		p, err := read(path, preview, false)
		if err != nil {
			blocked[path] = unread(&p, err)
		}
		out = append(out, p)
	}
	return out
}

// notThere reports whether err says that a file or folder is not there,
// and nothing else: ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND.
func notThere(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

// unread marks p, an install or the folder installs are in, that could not
// be read or checked, blocked (uncheckedReason), and returns the error a
// run fails with: a run does not fall back from it (ADR-0064).
func unread(p *agentproto.PowerShellInstall, err error) error {
	p.Usable, p.Blocked, p.Reason = false, true, uncheckedReason(err)
	return notChecked(p.Path, err)
}

// storeInstallsIn lists the Store packages of PowerShell in
// root\WindowsApps, which only administrators and the system may list.
func storeInstallsIn(root string) []agentproto.PowerShellInstall {
	entries, err := os.ReadDir(filepath.Join(root, "WindowsApps"))
	if err != nil {
		return nil
	}
	var out []agentproto.PowerShellInstall
	for _, e := range entries {
		v, arch, preview, ok := storePackage(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(root, "WindowsApps", e.Name(), "pwsh.exe")
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		// A Store install is never used, read or not.
		p, _ := read(path, preview, true)
		if p.Version == "" {
			p.Version = v
		}
		if p.Arch == "" {
			p.Arch = arch
		}
		p.Reason = reasonStore
		out = append(out, p)
	}
	return out
}

// read reads an install's version, from its program's version resource,
// and its architecture, from the program's header, without starting it.
// What it could read is filled in, and an error returned for what it could
// not: the header's first, since Windows' version functions name a file
// they could not open as one without a resource section, as CI's runners
// showed.
func read(path string, preview, store bool) (agentproto.PowerShellInstall, error) {
	p := agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Path: path, Preview: preview, Store: store}
	v, verr := fileProductVersion(path)
	p.Version = productVersion(v)
	if strings.Contains(p.Version, "-") {
		p.Preview = true
	}
	arch, aerr := peArch(path)
	p.Arch = arch
	return p, cmp.Or(aerr, verr)
}

// peArch reads a program's architecture from its PE header.
func peArch(path string) (string, error) {
	f, err := pe.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return agentproto.ArchX64, nil
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return agentproto.ArchARM64, nil
	case pe.IMAGE_FILE_MACHINE_I386:
		return agentproto.ArchX86, nil
	}
	return "", fmt.Errorf("an unknown machine type %#x", f.Machine)
}

// fileProductVersion reads the ProductVersion of a program's version
// resource, in the first language it lists.
func fileProductVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", err
	}
	var (
		p unsafe.Pointer
		n uint32
	)
	tables := []string{"040904b0", "040904e4", "000004b0"}
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&p), &n); err == nil && n >= 4 {
		t := unsafe.Slice((*uint16)(p), n/2)
		var listed []string
		for i := 0; i+1 < len(t); i += 2 {
			listed = append(listed, fmt.Sprintf("%04x%04x", t[i], t[i+1]))
		}
		tables = append(listed, tables...)
	}
	for _, table := range tables {
		if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\StringFileInfo\`+table+`\ProductVersion`, unsafe.Pointer(&p), &n); err == nil && n > 0 {
			return windows.UTF16PtrToString((*uint16)(p)), nil
		}
	}
	return "", errors.New("it has no product version")
}

// nativeArch is the computer's own architecture, whatever the agent's.
func nativeArch() string {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err == nil {
		switch native {
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return agentproto.ArchARM64
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return agentproto.ArchX64
		case pe.IMAGE_FILE_MACHINE_I386:
			return agentproto.ArchX86
		}
	}
	switch runtime.GOARCH {
	case "arm64":
		return agentproto.ArchARM64
	case "386":
		return agentproto.ArchX86
	}
	return agentproto.ArchX64
}

// checked is what a run uses of an install that passed its check: the
// install's program and libraries, held open, and the PSModulePath the run
// is given (givenPath).
type checked struct {
	held *host.Held
	path string
}

func (c *checked) release() {
	if c != nil {
		c.held.Close()
	}
}

// check checks an install a run could choose, as a run does (ADR-0064):
// the install itself (checkInstall), then what a run of it loads from
// outside it (checkModules). An install whose own check finds an entry that
// others may change, that no trusted account owns, that is a link, or whose
// access list keeps the agent out is marked not used (host.Untrusted), and
// nil is returned: a run tries the next one, or falls back to Windows
// PowerShell where the script allows it. Every other failure marks it
// blocked, not usable, and is returned: a run tries the next install, and
// fails, without the fallback, where none passes. That is a file of the
// install open in another program (host.Untrusted.Busy), which anyone who
// may read it can cause; one with a second hard link
// (host.Untrusted.Linked), which some Windows builds may let them make; an
// install that could not be checked, which they can cause too: each would
// otherwise let them choose where scripts run. So are module folders or a
// configuration that fail, since Windows PowerShell loads from Windows
// PowerShell's folders too. hold keeps the install's program and libraries
// open while the result is used (checkInstall).
func check(p *agentproto.PowerShellInstall, hold bool) (*checked, error) {
	held, err := checkInstall(p.Path, hold)
	var u *host.Untrusted
	switch {
	case errors.As(err, &u) && u.Busy:
		p.Usable, p.Blocked, p.Reason = false, true, u.Path+" "+u.Reason+busySuffix
		return nil, err
	case errors.As(err, &u) && u.Linked:
		p.Usable, p.Blocked, p.Reason = false, true, u.Path+" "+u.Reason+linkedSuffix
		return nil, err
	case errors.As(err, &u):
		p.Usable, p.Reason = false, u.Path+" "+u.Reason+": not used, since what it runs and loads must be changeable by administrators only."
		return nil, nil
	case err != nil:
		return nil, unread(p, err)
	}
	path, err := checkModules(filepath.Dir(p.Path))
	if err != nil {
		held.Close()
		p.Usable, p.Blocked, p.Reason = false, true, blockedReason(err)
		return nil, err
	}
	return &checked{held: held, path: path}, nil
}

// checkInstall checks what a PowerShell 7 install is and runs: Program
// Files and its PowerShell folder themselves, the folders above the install
// (host.CheckAbove), and the install's folder and everything in it, its
// own module folder included. With hold, its program and libraries (.dll)
// stay open, through the handles they were checked through, until the
// returned Held is closed: no one may write them meanwhile (ADR-0064).
func checkInstall(pwsh string, hold bool) (*host.Held, error) {
	install := filepath.Dir(pwsh)
	parent := filepath.Dir(install) // <Program Files>\PowerShell
	root := filepath.Dir(parent)    // <Program Files>
	for _, p := range []string{root, parent} {
		if err := host.CheckEntry(p, false); err != nil {
			return nil, err
		}
	}
	if err := host.CheckAbove(install); err != nil {
		return nil, err
	}
	var which func(string) bool
	if hold {
		which = func(p string) bool {
			return strings.EqualFold(p, pwsh) || strings.EqualFold(filepath.Ext(p), ".dll")
		}
	}
	return host.CheckTreeHolding(install, false, which)
}

// checkModules checks what a run of the PowerShell 7 in psHome loads from
// outside its install: its configuration, and the folders it may load
// modules from (moduleFolders), each with the folders above it
// (host.CheckAbove) and, where it exists, everything in it, and the folders
// of the Windows PowerShell session it starts for a module only Windows
// PowerShell can load (windowsPowerShellFolders). It returns the
// PSModulePath a run is given, which names Windows PowerShell's two
// (givenPath).
func checkModules(psHome string) (string, error) {
	all, windowsPS, path, err := moduleFolders(psHome)
	if err != nil {
		return "", err
	}
	_, own, err := windowsPowerShellFolders()
	if err != nil {
		return "", err
	}
	for _, m := range append(slices.Clone(all), own) {
		if within(m, psHome) {
			continue // checked with the install
		}
		if err := checkFolder(m, windowsPS); err != nil {
			return "", fmt.Errorf("PowerShell 7 would load modules from %s, and %w", m, err)
		}
	}
	return path, nil
}

// checkFolder checks a module folder with the folders above it
// (host.CheckAbove) and, where it exists, everything in it. Windows keeps
// the modules it puts in Windows PowerShell's two folders as hard links into
// its component store (WinSxS), as seen on CI's runners; nowhere else are
// hard links allowed.
func checkFolder(m string, windowsPS []string) error {
	links := slices.ContainsFunc(windowsPS, func(w string) bool { return strings.EqualFold(filepath.Clean(m), filepath.Clean(w)) })
	if err := host.CheckAbove(m); err != nil {
		return err
	}
	return checkIfThere(m, links)
}

// windowsPowerShellFolders are the module folders of a Windows PowerShell
// 5.1 process the agent starts, as the fallback of a pwsh script or as
// PowerShell 7's compatibility session: Program Files' and System32's,
// which its PSModulePath names (given), and the account's own
// (Documents\WindowsPowerShell\Modules), which Windows PowerShell may add to
// what it is given (ADR-0064).
func windowsPowerShellFolders() (given []string, own string, err error) {
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return nil, "", fmt.Errorf("finding the account's Documents folder: %w", err)
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, "", fmt.Errorf("finding Program Files: %w", err)
	}
	given = []string{filepath.Join(programFiles, "WindowsPowerShell", "Modules"), filepath.Join(system32(), `WindowsPowerShell\v1.0\Modules`)}
	return given, filepath.Join(docs, "WindowsPowerShell", "Modules"), nil
}

// Fallback is what a pwsh script that allows it runs in where no PowerShell
// 7 is usable: Windows PowerShell 5.1, with the module folders it may load
// from checked as a pwsh run's are (ADR-0064): the account's own and the
// two its PSModulePath names.
type Fallback struct {
	// Env sets PSModulePath to Windows PowerShell's two folders (givenPath),
	// as for PowerShell 7's compatibility session, so that the system
	// environment's PSModulePath and what it names are not used.
	Env []string
}

// ForFallback checks the module folders of Windows PowerShell as the
// fallback of a pwsh script, and returns them with the environment that
// limits it to them. A folder that fails is an error, and so is a
// PSModulePath the agent cannot spell for it (givenPath); the script does
// not run.
func ForFallback() (*Fallback, error) {
	given, own, err := windowsPowerShellFolders()
	if err != nil {
		return nil, err
	}
	all := append([]string{own}, given...)
	for _, m := range all {
		if err := checkFolder(m, given); err != nil {
			return nil, fmt.Errorf("Windows PowerShell would load modules from %s, and %w", m, err) //nolint:staticcheck // ST1005: a name
		}
	}
	path, err := givenPath(given)
	if err != nil {
		return nil, err
	}
	return &Fallback{Env: []string{"PSModulePath=" + path}}, nil
}

// givenPath is the PSModulePath a run gives Windows PowerShell's two
// folders (given), spelled (spell) unlike every value Windows PowerShell 5.1
// compares it with (compared), so that it keeps it as it is and adds no
// folder: the computer's PSModulePath and the system account's, read from
// the registry as they are held.
func givenPath(given []string) (string, error) {
	machine, err := registryModulePath(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	if err != nil {
		return "", err
	}
	account, err := registryModulePath(registry.CURRENT_USER, "Environment")
	if err != nil {
		return "", err
	}
	taken, err := compared(machine, account, os.LookupEnv)
	if err != nil {
		return "", err
	}
	return spell(given, taken), nil
}

// registryModulePath is the PSModulePath a registry key holds, or nil where
// the key or the value is missing or the value is not text, which Windows
// PowerShell reads as not set. Any other error is returned: the agent could
// not tell what Windows PowerShell compares.
func registryModulePath(root registry.Key, path string) (*registryPath, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the registry key %s: %w", path, err)
	}
	defer func() { _ = k.Close() }()
	v, typ, err := k.GetStringValue("PSModulePath")
	switch {
	case errors.Is(err, registry.ErrNotExist), errors.Is(err, registry.ErrUnexpectedType):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("reading PSModulePath in the registry key %s: %w", path, err)
	}
	return &registryPath{value: v, expandable: typ == registry.EXPAND_SZ}, nil
}

// checkIfThere checks a folder and what it holds when it exists.
func checkIfThere(p string, links bool) error {
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return host.CheckTree(p, links)
}

// uncheckedReason says why an install, or the folder installs are in, that
// could not be read or checked blocks a run.
func uncheckedReason(err error) string {
	return "Could not be checked: " + strings.TrimSuffix(err.Error(), ".") + ". Not used until it can be, since anyone who may read a file can keep the agent from reading it. Scripts that allow Windows PowerShell 5.1 do not run in it instead."
}

// notChecked is the error a run fails with where path, an install or the
// folder installs are in, could not be read or checked: Windows' messages
// end with a period, which the run's error does not.
func notChecked(path string, err error) error {
	return errors.New(path + " could not be checked: " + strings.TrimSuffix(err.Error(), "."))
}

// busySuffix ends the reason of an install with a file open in another
// program.
const busySuffix = ": not used while it is, since anyone who may read the file can hold it so. Close that program or restart the computer. Scripts that allow Windows PowerShell 5.1 do not run in it instead."

// linkedSuffix ends the reason of an install with a file that has more
// than one hard link.
const linkedSuffix = ": not used while it has, since some Windows builds may let anyone who may read the file link to it. List its links with fsutil hardlink list and delete the others. Scripts that allow Windows PowerShell 5.1 do not run in it instead."

// blockedReason says why an install whose own files pass is not used:
// what a run of it would load does not.
func blockedReason(err error) string {
	return capitalize(err.Error()) + ": not used, since what it loads must be changeable by administrators only. Scripts that allow Windows PowerShell 5.1 do not run in it instead."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Run is what a pwsh run starts: the PowerShell 7 chosen, what its result
// reports of it, and what its environment adds, with the module folders it
// may load from checked (ADR-0064).
type Run struct {
	Interpreter agentproto.Interpreter
	// Env sets PSModulePath to Windows PowerShell's two folders, which
	// PowerShell 7 puts its own three before, and turns off its telemetry
	// and update check.
	Env []string

	held *host.Held
}

// Release lets go of the install's program and libraries, held open since
// their check so that no one changes them before the run's process is
// created. Call it once that process is created, or will not be.
func (r *Run) Release() { r.held.Close() }

// ForRun chooses the PowerShell 7 a pwsh run uses from roots: the first, in
// the order a run prefers them, that passes check, its program and
// libraries held open until Release. An install that is blocked (check,
// candidates) is passed over for the next one that passes every check;
// where none does, the run fails with the error of the blocked install the
// inventory lists first (order: by path), which a script may not fall back
// from. Where none is blocked either, it returns a *NotFound, which a
// script may fall back from (ForFallback).
func ForRun(roots []string) (*Run, error) {
	native := nativeArch()
	list, blocked := candidates(roots, native)
	for i := range list {
		if !list[i].Usable {
			continue
		}
		c, err := check(&list[i], true)
		if err != nil {
			blocked[list[i].Path] = err
			continue
		}
		if c == nil {
			continue
		}
		p := list[i]
		return &Run{
			Interpreter: agentproto.Interpreter{Edition: p.Edition, Version: p.Version, Arch: p.Arch, Path: p.Path},
			Env:         runEnv(c.path),
			held:        c.held,
		}, nil
	}
	order(list, native)
	for _, p := range list {
		if err := blocked[p.Path]; err != nil {
			return nil, fmt.Errorf("%w; the script was not run", err)
		}
	}
	looked := make([]string, len(roots))
	for i, r := range roots {
		looked[i] = filepath.Join(r, "PowerShell")
	}
	return nil, &NotFound{Looked: looked, Found: list}
}

// within reports whether p is dir or below it, ignoring case as Windows
// does.
func within(p, dir string) bool {
	rel, err := filepath.Rel(strings.ToLower(dir), strings.ToLower(p))
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}

// moduleFolders lists the folders a pwsh run may load modules from, in
// PowerShell 7's order: the account's own (Documents\PowerShell\Modules, or
// what the account's powershell.config.json names), the shared one (Program
// Files\PowerShell\Modules, or what $PSHOME's powershell.config.json
// names), $PSHOME\Modules, then Windows PowerShell's two, in Program Files
// and in System32, which are also returned alone with the PSModulePath a
// run is given (givenPath). Each configuration file is checked before it is
// read.
func moduleFolders(psHome string) (all, windowsPS []string, path string, err error) {
	// The system account's Documents folder need not exist.
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return nil, nil, "", fmt.Errorf("finding the account's Documents folder: %w", err)
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, nil, "", fmt.Errorf("finding Program Files: %w", err)
	}
	windowsPS, _, err = windowsPowerShellFolders()
	if err != nil {
		return nil, nil, "", err
	}
	path, err = givenPath(windowsPS)
	if err != nil {
		return nil, nil, "", err
	}
	lookup := runLookup(runEnv(path), os.LookupEnv)
	user, err := configured(filepath.Join(docs, "PowerShell", "powershell.config.json"), filepath.Join(docs, "PowerShell", "Modules"), lookup)
	if err != nil {
		return nil, nil, "", err
	}
	shared, err := configured(filepath.Join(psHome, "powershell.config.json"), filepath.Join(programFiles, "PowerShell", "Modules"), lookup)
	if err != nil {
		return nil, nil, "", err
	}
	all = append(append(append(user, shared...), filepath.Join(psHome, "Modules")), windowsPS...)
	return all, windowsPS, path, nil
}

// configured is the module folders a powershell.config.json names, or def
// when there is no such file or it names none. Whoever could put the file
// there could name any folder, so its folder and those above it are
// checked whether it exists or not, and the file before it is read. A
// folder the file names must exist: one that does not could be made later
// by whoever may (ADR-0064). Its variables are expanded from lookup, a
// run's environment (runLookup), as PowerShell 7 expands them in the run.
func configured(file, def string, lookup func(string) (string, bool)) ([]string, error) {
	fail := func(err error) error {
		return fmt.Errorf("PowerShell 7 would read its configuration from %s, and %w", file, err)
	}
	dir := filepath.Dir(file)
	if err := host.CheckAbove(dir); err != nil {
		return nil, fail(err)
	}
	if _, err := os.Lstat(dir); err == nil {
		if err := host.CheckEntry(dir, false); err != nil {
			return nil, fail(err)
		}
	} else if !notThere(err) {
		return nil, fail(err)
	}
	if _, err := os.Lstat(file); notThere(err) {
		return []string{def}, nil
	} else if err != nil {
		return nil, err
	}
	if err := host.CheckEntry(file, false); err != nil {
		return nil, fail(err)
	}
	b, err := os.ReadFile(file) //nolint:gosec // checked above: only administrators may change it
	if err != nil {
		return nil, err
	}
	p, err := configModulePath(b)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	if p == "" {
		return []string{def}, nil
	}
	p, err = expand(p, lookup)
	if err != nil {
		return nil, fmt.Errorf("%s names a module folder with %w", file, err)
	}
	var out []string
	for f := range strings.SplitSeq(p, ";") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if !filepath.IsAbs(f) {
			return nil, fmt.Errorf("%s names the module folder %q, which is not a full path", file, f)
		}
		f = filepath.Clean(f)
		if _, err := os.Lstat(f); errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s names the module folder %s, which does not exist", file, f)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return []string{def}, nil
	}
	return out, nil
}
