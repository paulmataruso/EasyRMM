//go:build windows

package powershell

import (
	"debug/pe"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
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
// the inventory says what a run would do, and took is how long the checks
// took.
func Discover(roots []string) (list []agentproto.PowerShellInstall, took time.Duration) {
	native := nativeArch()
	list = append([]agentproto.PowerShellInstall{Desktop()}, candidates(roots, native)...)
	start := time.Now()
	for i := range list {
		if list[i].Edition == agentproto.EditionCore && list[i].Usable {
			c, _ := check(&list[i], false)
			c.release()
		}
	}
	took = time.Since(start)
	order(list, native)
	return list[:min(len(list), agentproto.MaxPowerShell)], took
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
// checked (assess), in the order a run prefers them.
func candidates(roots []string, native string) []agentproto.PowerShellInstall {
	var list []agentproto.PowerShellInstall
	for _, root := range roots {
		list = append(list, installsIn(root)...)
		list = append(list, storeInstallsIn(root)...)
	}
	for i := range list {
		if list[i].Reason == "" {
			assess(&list[i], native)
		}
	}
	order(list, native)
	return list
}

// installsIn lists the installs in root\PowerShell, with what their files
// say of them.
func installsIn(root string) []agentproto.PowerShellInstall {
	entries, err := os.ReadDir(filepath.Join(root, "PowerShell"))
	if err != nil {
		return nil
	}
	var out []agentproto.PowerShellInstall
	for _, e := range entries {
		_, preview, ok := installFolder(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(root, "PowerShell", e.Name(), "pwsh.exe")
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		out = append(out, read(path, preview, false))
	}
	return out
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
		p := read(path, preview, true)
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
func read(path string, preview, store bool) agentproto.PowerShellInstall {
	p := agentproto.PowerShellInstall{Edition: agentproto.EditionCore, Path: path, Preview: preview, Store: store}
	v, err := fileProductVersion(path)
	if err != nil {
		p.Reason = "Could not be read: " + err.Error() + "."
	}
	p.Version = productVersion(v)
	if strings.Contains(p.Version, "-") {
		p.Preview = true
	}
	arch, err := peArch(path)
	if err != nil && p.Reason == "" {
		p.Reason = "Could not be read: " + err.Error() + "."
	}
	p.Arch = arch
	return p
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
// install's program and libraries, held open, and the module folders.
type checked struct {
	held               *host.Held
	modules, windowsPS []string
}

func (c *checked) release() {
	if c != nil {
		c.held.Close()
	}
}

// check checks an install a run could choose, as a run does (ADR-0064):
// the install itself (checkInstall), then what a run of it loads from
// outside it (checkModules). An install that fails its own check is marked
// not usable, and a run tries the next one, or falls back to Windows
// PowerShell where the script allows it; nil is returned. One whose own
// files pass but whose module folders or configuration fail is marked
// blocked, not usable, and that failure is returned: a run that would have
// used it fails, without the fallback, since Windows PowerShell loads from
// Windows PowerShell's folders too. So is one with a file open in another
// program (host.Untrusted.Busy): anyone who may read a file can hold it so,
// and could otherwise choose where scripts run. hold keeps the install's
// program and libraries open while the result is used (checkInstall).
func check(p *agentproto.PowerShellInstall, hold bool) (*checked, error) {
	held, err := checkInstall(p.Path, hold)
	var u *host.Untrusted
	if errors.As(err, &u) && u.Busy {
		p.Usable, p.Blocked, p.Reason = false, true, u.Path+" "+u.Reason+busySuffix
		return nil, err
	}
	if err != nil {
		p.Usable, p.Reason = false, untrustedReason(err)
		return nil, nil
	}
	mods, windowsPS, err := checkModules(filepath.Dir(p.Path))
	if err != nil {
		held.Close()
		p.Usable, p.Blocked, p.Reason = false, true, blockedReason(err)
		return nil, err
	}
	return &checked{held: held, modules: mods, windowsPS: windowsPS}, nil
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
// PowerShell can load (windowsPowerShellFolders). It returns PowerShell 7's
// folders, and Windows PowerShell's two, which a run's PSModulePath names.
func checkModules(psHome string) (all, windowsPS []string, err error) {
	all, windowsPS, err = moduleFolders(psHome)
	if err != nil {
		return nil, nil, err
	}
	_, own, err := windowsPowerShellFolders()
	if err != nil {
		return nil, nil, err
	}
	for _, m := range append(slices.Clone(all), own) {
		if within(m, psHome) {
			continue // checked with the install
		}
		if err := checkFolder(m, windowsPS); err != nil {
			return nil, nil, fmt.Errorf("PowerShell 7 would load modules from %s, and %w", m, err)
		}
	}
	return all, windowsPS, nil
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
// from checked as a pwsh run's are (ADR-0064).
type Fallback struct {
	// Modules are the folders checked: the account's own and the two its
	// PSModulePath names.
	Modules []string
	// Env sets PSModulePath to Windows PowerShell's two folders (givenPath),
	// as for PowerShell 7's compatibility session, so that the system
	// environment's PSModulePath and what it names are not used.
	Env []string
}

// ForFallback checks the module folders of Windows PowerShell as the
// fallback of a pwsh script, and returns them with the environment that
// limits it to them; a folder that fails is an error, and the script does
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
	return &Fallback{Modules: all, Env: []string{"PSModulePath=" + givenPath(given)}}, nil
}

// givenPath is the PSModulePath a run gives Windows PowerShell's two
// folders (given), spelled (spell) unlike every value Windows PowerShell 5.1
// compares it with, so that it keeps it as it is and adds no folder.
func givenPath(given []string) string {
	machine, isMachine := registryModulePath(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	account, isAccount := registryModulePath(registry.CURRENT_USER, "Environment")
	var taken []string
	if isMachine {
		taken = append(taken, machine)
	}
	if isAccount {
		taken = append(taken, account)
	}
	if isMachine && isAccount {
		taken = append(taken, account+";"+machine)
	}
	return spell(given, taken)
}

// registryModulePath reads a PSModulePath as Windows PowerShell 5.1 reads
// the computer's and the account's: an expandable value expanded, as .NET's
// registry read does, then expanded once more. Windows PowerShell expands
// them with the run's environment and the agent with its own, which differ
// only in what each run sets for itself (PerRun) and in runEnv's
// variables: a value naming one of those is compared as the agent expands
// it, a limit ADR-0064 records. A value that is missing, or cannot be
// read, is not compared; Windows PowerShell reads a missing one as not set.
func registryModulePath(root registry.Key, path string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = k.Close() }()
	v, typ, err := k.GetStringValue("PSModulePath")
	if err != nil {
		return "", false
	}
	if typ == registry.EXPAND_SZ {
		v = expandOnce(v)
	}
	return expandOnce(v), true
}

// expandOnce expands the variables in s as Windows does, or leaves s.
func expandOnce(s string) string {
	if e, err := registry.ExpandString(s); err == nil {
		return e
	}
	return s
}

// checkIfThere checks a folder and what it holds when it exists.
func checkIfThere(p string, links bool) error {
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return host.CheckTree(p, links)
}

// untrustedReason says why an install is not used after its check.
func untrustedReason(err error) string {
	var u *host.Untrusted
	if errors.As(err, &u) {
		return u.Path + " " + u.Reason + ": not used, since what it runs and loads must be changeable by administrators only."
	}
	return "Could not be checked: " + err.Error() + "."
}

// busySuffix ends the reason of an install with a file open in another
// program.
const busySuffix = ": not used while it is, since anyone who may read the file can hold it so. Close that program or restart the computer. Scripts that allow Windows PowerShell 5.1 do not run in it instead."

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
// reports of it, the module folders it may load from, all checked, and
// what its environment adds (ADR-0064).
type Run struct {
	Interpreter agentproto.Interpreter
	// Modules are the module folders PowerShell 7 builds its module path
	// from, in its order: the system account's, the shared one, its own,
	// and Windows PowerShell's two.
	Modules []string
	// Env sets PSModulePath to Windows PowerShell's two folders, which
	// PowerShell 7 puts its own three before, and turns off its telemetry
	// and update check.
	Env []string
	// Took is how long the checks took.
	Took time.Duration

	held *host.Held
}

// Release lets go of the install's program and libraries, held open since
// their check so that no one changes them before the run's process is
// created. Call it once that process is created, or will not be.
func (r *Run) Release() { r.held.Close() }

// ForRun chooses the PowerShell 7 a pwsh run uses from roots: the first, in
// the order a run prefers them, that passes check, its program and
// libraries held open until Release. It returns a *NotFound when no
// install is usable, which a script may fall back from (ForFallback), and
// another error when an install whose own files pass would load from a
// folder, or read a configuration, that fails, or has a file open in another
// program, which it may not.
func ForRun(roots []string) (*Run, error) {
	start := time.Now()
	list := candidates(roots, nativeArch())
	var blocked error
	for i := range list {
		if !list[i].Usable {
			continue
		}
		c, err := check(&list[i], true)
		if err != nil {
			if blocked == nil {
				blocked = err
			}
			continue
		}
		if c == nil {
			continue
		}
		p := list[i]
		return &Run{
			Interpreter: agentproto.Interpreter{Edition: p.Edition, Version: p.Version, Arch: p.Arch, Path: p.Path},
			Modules:     c.modules,
			Env:         runEnv(givenPath(c.windowsPS)),
			Took:        time.Since(start),
			held:        c.held,
		}, nil
	}
	if blocked != nil {
		return nil, fmt.Errorf("%w; the script was not run", blocked)
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
// and in System32, which are also returned alone. Each configuration file
// is checked before it is read.
func moduleFolders(psHome string) (all, windowsPS []string, err error) {
	// The system account's Documents folder need not exist.
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return nil, nil, fmt.Errorf("finding the account's Documents folder: %w", err)
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, nil, fmt.Errorf("finding Program Files: %w", err)
	}
	windowsPS, _, err = windowsPowerShellFolders()
	if err != nil {
		return nil, nil, err
	}
	lookup := runLookup(runEnv(givenPath(windowsPS)), os.LookupEnv)
	user, err := configured(filepath.Join(docs, "PowerShell", "powershell.config.json"), filepath.Join(docs, "PowerShell", "Modules"), lookup)
	if err != nil {
		return nil, nil, err
	}
	shared, err := configured(filepath.Join(psHome, "powershell.config.json"), filepath.Join(programFiles, "PowerShell", "Modules"), lookup)
	if err != nil {
		return nil, nil, err
	}
	all = append(append(append(user, shared...), filepath.Join(psHome, "Modules")), windowsPS...)
	return all, windowsPS, nil
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
	}
	if _, err := os.Lstat(file); errors.Is(err, fs.ErrNotExist) {
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
