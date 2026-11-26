package quickassist

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// BaseFor is where a session's folder goes: under ProgramData when the
// runner is elevated, under the user's own local data otherwise (ADR-0080).
func BaseFor(elevated bool) string {
	root := os.Getenv("ProgramData")
	if !elevated || root == "" {
		if l := os.Getenv("LOCALAPPDATA"); l != "" {
			root = l
		}
	}
	if root == "" {
		root = os.TempDir()
	}
	return filepath.Join(root, "EasyRMM", "QuickAssist")
}

// askWindow is the consent window the user clicks: Yes or No, always on top.
// It returns handled true on Windows; the terminal text stays visible beside
// it with the session code.
func askWindow(server, code string) (yes, handled bool) {
	text := "Allow remote support?\n\nRequested by the server: " + server +
		"\n\nThis lets the technician see and control your screen, run programs, see your computer's details and installed updates, and transfer files, until you close this program.\n\nYour session code: " + code +
		"\nRead it to the technician on the phone. Only they can accept the session, by typing it.\n\nNothing is installed, and everything is removed when the session ends."
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("EasyRMM remote support")
	const mbYesNo, mbIconQuestion, mbTopmost, mbSetForeground, idYes = 0x4, 0x20, 0x40000, 0x10000, 6
	r, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), mbYesNo|mbIconQuestion|mbTopmost|mbSetForeground)
	return r == idYes, true
}

// Relaunch starts this program again with administrator rights through UAC
// and reports whether it did; the caller then exits. A user who declines
// UAC gets false and continues without elevation (screen and inventory only).
func Relaunch(self string, args []string) bool {
	verb, _ := syscall.UTF16PtrFromString("runas")
	exe, _ := syscall.UTF16PtrFromString(self)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoteAll(args), " "))
	return windows.ShellExecute(0, verb, exe, params, nil, windows.SW_NORMAL) == nil
}

func quoteAll(a []string) []string {
	out := make([]string, len(a))
	for i, s := range a {
		out[i] = syscall.EscapeArg(s)
	}
	return out
}

// removeNodeKeys deletes the registry keys MeshAgent made for this
// session's service name, by that exact name only: never "Mesh Agent" or any
// other (ADR-0071).
func removeNodeKeys(name string) []string {
	var left []string
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
			path := `SOFTWARE\Open Source\` + name
			k, err := registry.OpenKey(root, path, registry.READ|view)
			if err != nil {
				continue
			}
			_ = k.Close()
			if err := registry.DeleteKey(root, path); err != nil {
				left = append(left, path)
			}
		}
	}
	return left
}

func askWindowAvailable() (bool, bool) { return false, true }
