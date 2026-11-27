//go:build windows

package roles

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// localBudget bounds the registry and service reads together; the Defender
// query has its own deadline (ADR-0073).
const (
	localBudget    = 2 * time.Second
	defenderBudget = 10 * time.Second
)

// Read collects what Evaluate decides from. The registry and service
// reads are local; the one WMI call for Defender runs in a child process
// that is killed after defenderBudget, and a failure of it is reported as
// an unknown Defender, not as an error.
func Read(ctx context.Context) (Inputs, error) {
	local, cancel := context.WithTimeout(ctx, localBudget)
	defer cancel()
	in := Inputs{Services: map[string]Service{}}
	pt, err := regString(`SYSTEM\CurrentControlSet\Control\ProductOptions`, "ProductType")
	if err != nil {
		return Inputs{}, err
	}
	in.ProductType = pt
	m, err := mgr.Connect()
	if err != nil {
		return Inputs{}, err
	}
	defer func() { _ = m.Disconnect() }()
	for _, name := range []string{"NTDS", "CertSvc", "DNS", "DHCPServer", "LanmanServer", "Spooler", "wbengine", "WinDefend", "fhsvc"} {
		if local.Err() != nil {
			return Inputs{}, local.Err()
		}
		in.Services[name] = serviceState(m, name)
	}
	in.CAConfigured = regHasSubKey(`SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`)
	in.DHCPParameters = regKeyExists(`SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters`)
	// The shares the server holds are the values of one key; administrative
	// shares (C$, ADMIN$) and IPC$ are not stored there, and Print$ is
	// told apart for the print role.
	for _, share := range regValueNames(`SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`) {
		switch {
		case strings.EqualFold(share, "Print$"):
			in.PrintShared = true
		case !strings.HasSuffix(share, "$"):
			in.Shares++
		}
	}
	in.PrintShared, in.PrintQueue = printerState()
	in.GroupPolicyModule = groupPolicyModuleInstalled()
	if in.Services["WinDefend"].Installed() {
		in.Defender = queryDefender(ctx)
	}
	return in, nil
}

// serviceState opens the service for reading its status only: the default
// access, all of it, is refused for a protected service such as WinDefend,
// which then looked as if it were not installed.
func serviceState(m *mgr.Mgr, name string) Service {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Missing
	}
	h, err := windows.OpenService(m.Handle, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return Missing
		}
		// The service is there; what it is doing cannot be read.
		return Stopped
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return Stopped
	}
	if st.State == svc.Running {
		return Running
	}
	return Stopped
}

func regString(path, name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(name)
	return v, err
}

func regKeyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

func regHasSubKey(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	names, err := k.ReadSubKeyNames(1)
	return err == nil && len(names) > 0
}

func regValueNames(path string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	names, _ := k.ReadValueNames(-1)
	return names
}

// printerShared is the PRINTER_ATTRIBUTE_SHARED bit of a printer's
// Attributes value.
const printerShared = 0x8

// printerState reads the printer queues: whether one is shared, and whether
// one is on a real port. It is only a guess at what an admin set up, so a
// queue that cannot be read is skipped.
func printerState() (shared, queue bool) {
	const path = `SYSTEM\CurrentControlSet\Control\Print\Printers`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false, false
	}
	defer func() { _ = k.Close() }()
	names, _ := k.ReadSubKeyNames(-1)
	for _, n := range names {
		p, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, aerr := p.GetIntegerValue("Attributes")
		port, _, perr := p.GetStringValue("Port")
		_ = p.Close()
		if aerr == nil && v&printerShared != 0 {
			shared = true
		}
		if perr == nil && realPrintPort(port) {
			queue = true
		}
	}
	return shared, queue
}

const defenderScript = `$ErrorActionPreference='Stop'; Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpComputerStatus | Select-Object -First 1 AMRunningMode,AMProductVersion | ConvertTo-Json -Compress`

func queryDefender(ctx context.Context) Defender {
	ctx, cancel := context.WithTimeout(ctx, defenderBudget)
	defer cancel()
	exe, err := windows.KnownFolderPath(windows.FOLDERID_System, 0)
	if err != nil {
		return Defender{}
	}
	cmd := exec.CommandContext(ctx, exe+`\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", defenderScript) //nolint:gosec // fixed command
	out, err := cmd.Output()
	if err != nil {
		return Defender{}
	}
	d, err := ParseDefender(out)
	if err != nil {
		return Defender{}
	}
	return d
}

// groupPolicyModuleInstalled says whether the GroupPolicy PowerShell module (the Group Policy Management tools) is
// on this computer.
func groupPolicyModuleInstalled() bool {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, "WindowsPowerShell", "v1.0", "Modules", "GroupPolicy", "GroupPolicy.psd1"))
	return err == nil
}
