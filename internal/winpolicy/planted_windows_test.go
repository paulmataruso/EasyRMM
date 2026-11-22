//go:build windows

package winpolicy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Owners the tests plant on a runner made for the job, each as the owner
// itself leaves its sign (registry keys, files, a service, the filtering
// platform's objects), and the reader's answer with and without it. Like
// TestQueryAsSystem, they run as LocalSystem in CI's job "Windows hardening
// as LocalSystem", and remove what they plant.

func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return !errors.Is(err, registry.ErrNotExist)
	}
	_ = k.Close()
	return true
}

// plant makes a key under HKLM that does not exist yet, with values, and
// removes it, and the parents it made, when the test ends.
func plant(t *testing.T, path string, values map[string]any) {
	t.Helper()
	if keyExists(path) {
		t.Fatalf(`HKLM\%s exists already`, path)
	}
	top := path
	for p := path; strings.Contains(p, `\`); {
		p = p[:strings.LastIndex(p, `\`)]
		if keyExists(p) {
			break
		}
		top = p
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	t.Cleanup(func() { deleteTree(t, top) })
	for name, v := range values {
		switch v := v.(type) {
		case uint32:
			err = k.SetDWordValue(name, v)
		case string:
			err = k.SetStringValue(name, v)
		default:
			t.Fatalf("value %s: %T", name, v)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// deleteTree deletes a key under HKLM and its subkeys. A key SYSTEM may not
// read (denyRead) has no subkeys here, and SYSTEM may still delete it.
func deleteTree(t *testing.T, path string) {
	t.Helper()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, n := range names {
			deleteTree(t, path+`\`+n)
		}
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		t.Errorf(`delete HKLM\%s: %v`, path, err)
	}
}

// denyRead lets no one, SYSTEM included, read a key under HKLM.
func denyRead(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(D;;KR;;;SY)(D;;KR;;;BA)(A;;KA;;;BA)(A;;KA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(`MACHINE\`+path, windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// client: whether the computer is a workstation (InstallationType Client).
func client(t *testing.T) bool {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue("InstallationType")
	if err != nil {
		t.Fatal(err)
	}
	return v == "Client"
}

// tamperOwned: whether the answer is real-time protection's, owned by
// Tamper Protection, which comes before every reason.
func tamperOwned(a answer) bool {
	return a.Result == ResultOwner && a.Owner == OwnerTamperProtection
}

// allCannotTell checks that each answer is cannot_tell with the reason
// (Tamper Protection's real-time protection apart).
func allCannotTell(t *testing.T, what string, a *answers, reason string) {
	t.Helper()
	for i, x := range a.all() {
		if !tamperOwned(x) && (x.Result != ResultCannotTell || !slices.Contains(x.Reasons, reason)) {
			t.Errorf("%s, answer %d: %v, want cannot_tell with %s", what, i, x, reason)
		}
	}
}

// noReason checks that no answer gives the reason.
func noReason(t *testing.T, what string, a *answers, reason string) {
	t.Helper()
	for i, x := range a.all() {
		if slices.Contains(x.Reasons, reason) {
			t.Errorf("%s, answer %d: %v, want no %s", what, i, x, reason)
		}
	}
}

// TestQueryMDMAsSystem: an enrolment as an MDM leaves it (Intune's
// provider, enrolled, with the discovery service it was found through)
// makes every answer cannot_tell (mdm), with the Policy CSP policy beside
// security settings and audit subcategories; an enrolment of Windows' own,
// without a discovery service, does not; enrolments that cannot be read make
// every answer cannot_tell (unreadable).
func TestQueryMDMAsSystem(t *testing.T) {
	systemTest(t)
	key := `SOFTWARE\Microsoft\Enrollments\{5E0F1E4B-3C1A-4E2B-9A61-EA5E7C0DE001}`
	plant(t, key, map[string]any{
		"ProviderID":              "MS DM Server",
		"EnrollmentState":         uint32(1),
		"DiscoveryServiceFullURL": "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
		"UPN":                     "test@example.invalid",
	})
	code, a := ask(t, baseRequest)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	allCannotTell(t, "enrolled", a, ReasonMDM)
	for i, want := range map[int]string{0: "DeviceLock/MinDevicePasswordLength", 1: "DeviceLock/AccountLockoutPolicy"} {
		if m := a.Security[i].MDM; m == nil || m.CSP != want {
			t.Errorf("security %d: %v, want the MDM's %s", i, a.Security[i], want)
		}
	}
	if m := a.Audit[0].MDM; m == nil || m.CSP != "Audit/AccountLogonLogoff_AuditLogon" {
		t.Errorf("Logon: %v, want the MDM's Audit/AccountLogonLogoff_AuditLogon", a.Audit[0])
	}

	// Windows' own enrolments record no discovery service.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	err = k.DeleteValue("DiscoveryServiceFullURL")
	_ = k.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	noReason(t, "Windows' own enrolment", a, ReasonMDM)

	denyRead(t, key)
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	allCannotTell(t, "an enrolment that cannot be read", a, ReasonUnreadable)
	if !slices.ContainsFunc(a.Notes, func(n string) bool { return strings.Contains(n, "could not be read") }) {
		t.Errorf("notes %q", a.Notes)
	}
}

// TestQueryAuditHistoryAsSystem: the audit policy extension's history lists
// a policy; with its copy of the audit policy, the subcategories in the
// copy are that policy's; without the copy, or with a history that cannot
// be read, every audit subcategory is cannot_tell (unreadable).
func TestQueryAuditHistoryAsSystem(t *testing.T) {
	systemTest(t)
	history := `SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{F3CCC681-B74C-4060-9F26-CD84525DCA2A}`
	copyFile := filepath.Join(os.Getenv("SystemRoot"), `security\audit\audit.csv`)
	if keyExists(history) {
		t.Skip("the audit policy extension has a history here")
	}
	if _, err := os.Stat(copyFile); err == nil {
		t.Skip("the audit policy extension has a copy here")
	}
	plant(t, history+`\0`, map[string]any{"DisplayName": "EasyRMM test audit policy", "GPOName": "{5E0F1E4B-3C1A-4E2B-9A61-EA5E7C0DE002}"})

	code, a := ask(t, baseRequest)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for i, x := range a.Audit {
		if x.Result != ResultCannotTell || strings.Join(x.Reasons, ",") != ReasonUnreadable {
			t.Errorf("audit %d without the copy: %v", i, x)
		}
	}
	for i, x := range slices.Concat(a.Registry[2:], a.Security) {
		if x.Result != ResultNone {
			t.Errorf("answer %d, not audit: %v", i, x)
		}
	}

	if err := os.MkdirAll(filepath.Dir(copyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(copyFile) })
	if err := os.WriteFile(copyFile, []byte("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"+
		",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if l := a.Audit[0]; l.Result != ResultOwner || l.Owner != OwnerGroupPolicy || l.Policy != "EasyRMM test audit policy" || l.Value != "success_failure" {
		t.Errorf("Logon, in the copy: %v", l)
	}
	if p := a.Audit[1]; p.Result != ResultNone {
		t.Errorf("Process Creation, not in the copy: %v", p)
	}

	denyRead(t, history+`\0`)
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for i, x := range a.Audit {
		if x.Result != ResultCannotTell || strings.Join(x.Reasons, ",") != ReasonUnreadable {
			t.Errorf("audit %d with a history that cannot be read: %v", i, x)
		}
	}
}

// TestQueryLocalGpoAsSystem: the local Group Policy object's Registry.pol
// owns the values it sets and deletes; one that cannot be read makes every
// registry value cannot_tell (unreadable).
func TestQueryLocalGpoAsSystem(t *testing.T) {
	systemTest(t)
	const key = `Software\Policies\EasyRMM-winpolicy-lgpo`
	file := filepath.Join(os.Getenv("SystemRoot"), `System32\GroupPolicy\Machine\Registry.pol`)
	saved, err := os.ReadFile(file)
	switch {
	case err == nil:
		t.Cleanup(func() {
			if err := os.WriteFile(file, saved, 0o600); err != nil {
				t.Errorf("restore %s: %v", file, err)
			}
		})
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(file) })
	default:
		t.Fatal(err)
	}
	// Group Policy may apply the file while the test runs.
	t.Cleanup(func() { deleteTree(t, key) })
	if err := os.WriteFile(file, testPol(key), 0o600); err != nil {
		t.Fatal(err)
	}

	request := `{"registry": [`
	for i, w := range polWant {
		if i > 0 {
			request += ","
		}
		request += `{"path": "HKLM\\` + strings.ReplaceAll(key+w.key, `\`, `\\`) + `", "name": "` + w.name + `"}`
	}
	request += `], "security": ["MinimumPasswordLength"], "audit": ["` + logonGUID + `"]}`
	code, a := ask(t, request)
	if code != 0 || len(a.Registry) != len(polWant) {
		t.Fatalf("exit code %d, answers %+v", code, a)
	}
	for i, w := range polWant {
		x := a.Registry[i]
		if w.value == "" && x.Result != ResultNone ||
			w.value != "" && (x.Result != ResultOwner || x.Owner != OwnerGroupPolicy || x.Policy != "Local Group Policy" || x.Value != w.value) {
			t.Errorf(`%s%s\%s: %v, want %q`, key, w.key, w.name, x, w.value)
		}
	}

	if err := os.WriteFile(file, []byte("PReg\x01\x00\x00\x00[\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, a = ask(t, request); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	for i, x := range a.Registry {
		if x.Result != ResultCannotTell || strings.Join(x.Reasons, ",") != ReasonUnreadable {
			t.Errorf("registry %d with a Registry.pol that cannot be read: %v", i, x)
		}
	}
	for i, x := range slices.Concat(a.Security, a.Audit) {
		if x.Result != ResultNone {
			t.Errorf("security or audit %d: %v", i, x)
		}
	}
}

// The filtering platform's structures (fwpmtypes.h), as 64-bit Windows lays
// them out; TestQueryOtherFirewallAsSystem checks the sizes.
type fwpmDisplayData struct{ Name, Description *uint16 }

type fwpByteBlob struct {
	Size uint32
	Data *byte
}

type fwpmSession struct {
	Key            windows.GUID
	DisplayData    fwpmDisplayData
	Flags          uint32
	TxnWaitTimeout uint32
	ProcessID      uint32
	SID            *windows.SID
	Username       *uint16
	KernelMode     int32
}

type fwpmProvider struct {
	Key          windows.GUID
	DisplayData  fwpmDisplayData
	Flags        uint32
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

// fwpValue: FWP_VALUE0, a type and a union of 8 bytes.
type fwpValue struct {
	Type  uint32
	_     uint32
	Value uint64
}

// fwpmAction: FWPM_ACTION0, a type and a GUID.
type fwpmAction struct {
	Type uint32
	Key  windows.GUID
}

type fwpmFilter struct {
	Key             windows.GUID
	DisplayData     fwpmDisplayData
	Flags           uint32
	ProviderKey     *windows.GUID
	ProviderData    fwpByteBlob
	LayerKey        windows.GUID
	SubLayerKey     windows.GUID
	Weight          fwpValue
	NumConditions   uint32
	Conditions      uintptr
	Action          fwpmAction
	Context         [2]uint64 // rawContext or providerContextKey
	Reserved        *windows.GUID
	FilterID        uint64
	EffectiveWeight fwpValue
}

var (
	fwpuclnt         = windows.NewLazySystemDLL("fwpuclnt.dll")
	fwpmEngineOpen0  = fwpuclnt.NewProc("FwpmEngineOpen0")
	fwpmEngineClose0 = fwpuclnt.NewProc("FwpmEngineClose0")
	fwpmProviderAdd0 = fwpuclnt.NewProc("FwpmProviderAdd0")
	fwpmFilterAdd0   = fwpuclnt.NewProc("FwpmFilterAdd0")
	// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: connections accepted.
	aleAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
)

// plantFirewall adds, as another firewall does, a provider with a filter
// at an inbound layer (permitting connections accepted on IPv4, which
// Windows Defender Firewall's own filters still block where it blocks),
// in a dynamic session: the filtering platform removes both when the
// session ends, which the returned function does.
func plantFirewall(t *testing.T, name string) func() {
	t.Helper()
	if s := unsafe.Sizeof(fwpmFilter{}); s != 200 || unsafe.Offsetof(fwpmFilter{}.Context) != 152 ||
		unsafe.Sizeof(fwpmProvider{}) != 64 || unsafe.Sizeof(fwpmSession{}) != 72 {
		t.Fatalf("the structures are not laid out as fwpmtypes.h has them (filter %d bytes)", s)
	}
	session := fwpmSession{Flags: 1} // FWPM_SESSION_FLAG_DYNAMIC
	var engine windows.Handle
	// RPC_C_AUTHN_WINNT
	if r, _, _ := fwpmEngineOpen0.Call(0, 10, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine))); r != 0 {
		t.Fatalf("FwpmEngineOpen0: %#x", r)
	}
	closeEngine := func() { _, _, _ = fwpmEngineClose0.Call(uintptr(engine)) }
	providerKey, err := windows.GenerateGUID()
	if err != nil {
		closeEngine()
		t.Fatal(err)
	}
	provider := fwpmProvider{Key: providerKey, DisplayData: fwpmDisplayData{Name: windows.StringToUTF16Ptr(name)}}
	if r, _, _ := fwpmProviderAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&provider)), 0); r != 0 {
		closeEngine()
		t.Fatalf("FwpmProviderAdd0: %#x", r)
	}
	filter := fwpmFilter{
		DisplayData: fwpmDisplayData{Name: windows.StringToUTF16Ptr(name + " inbound")},
		ProviderKey: &providerKey,
		LayerKey:    aleAuthRecvAcceptV4,
		Action:      fwpmAction{Type: 0x1002}, // FWP_ACTION_PERMIT
	}
	var id uint64
	if r, _, _ := fwpmFilterAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id))); r != 0 {
		closeEngine()
		t.Fatalf("FwpmFilterAdd0: %#x", r)
	}
	runtime.KeepAlive(&provider)
	runtime.KeepAlive(&filter)
	runtime.KeepAlive(&providerKey)
	return closeEngine
}

// TestQueryOtherFirewallAsSystem: on a server, another vendor's provider
// that filters inbound traffic makes the firewall's values cannot_tell
// (other_firewall); on a workstation, Security Center names other
// firewalls instead, and the filtering platform is not read.
func TestQueryOtherFirewallAsSystem(t *testing.T) {
	systemTest(t)
	const name = "EasyRMM test firewall"
	request := `{"registry": [
		{"path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", "name": "EnableFirewall", "defender": true, "product": "firewall"},
		{"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "name": "UseLogonCredential"}]}`
	code, a := ask(t, request)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	noReason(t, "the runner's own providers", a, ReasonOtherFirewall)

	closeEngine := plantFirewall(t, name)
	defer closeEngine()
	if code, a = ask(t, request); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	t.Logf("answers %+v", a)
	if client(t) {
		noReason(t, "a workstation", a, ReasonOtherFirewall)
		return
	}
	if f := a.Registry[0]; f.Result != ResultCannotTell || !slices.Contains(f.Reasons, ReasonOtherFirewall) {
		t.Errorf("the firewall's value with another firewall's filters: %v", f)
	}
	if w := a.Registry[1]; slices.Contains(w.Reasons, ReasonOtherFirewall) {
		t.Errorf("a value no firewall sets: %v", w)
	}
	if !slices.ContainsFunc(a.Notes, func(n string) bool { return strings.Contains(n, name) }) {
		t.Errorf("notes %q do not name %s", a.Notes, name)
	}
}

// TestQueryAzureAsSystem: Azure machine configuration's sign is its
// service. The guest configuration extension's folder, which a standard
// user may make where C:\Packages is missing, is not one.
func TestQueryAzureAsSystem(t *testing.T) {
	systemTest(t)
	for _, s := range []string{"GCService", "GCArcService"} {
		if exec.Command("sc.exe", "query", s).Run() == nil {
			t.Skipf("the computer has %s", s)
		}
	}
	folder := filepath.Join(os.Getenv("SystemDrive")+`\`, `Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows`)
	if _, err := os.Stat(folder); err == nil {
		t.Skipf("the computer has %s", folder)
	}
	top := folder
	for p := filepath.Dir(folder); ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			break
		}
		top = p
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(top) })
	code, a := ask(t, baseRequest)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	noReason(t, "the extension's folder", a, ReasonAzureMachineConfiguration)

	// A service that is never started: cmd.exe is no service.
	cmd := filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)
	if out, err := exec.Command("sc.exe", "create", "GCService", "binPath=", cmd+" /c exit", "start=", "demand").CombinedOutput(); err != nil {
		t.Fatalf("sc create: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("sc.exe", "delete", "GCService").CombinedOutput(); err != nil {
			t.Errorf("sc delete: %v %s", err, out)
		}
	})
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	allCannotTell(t, "the guest configuration service", a, ReasonAzureMachineConfiguration)
}

// The stand-in for OSConfig's module: it leaves a mark where it is
// imported, and lists an active security baseline, or with
// EASYRMM_TEST_OSCONFIG=secured-core only the read-only Secured-core
// scenario.
const (
	osconfigManifest = `@{ ModuleVersion = '1.0.0'; RootModule = 'Microsoft.OSConfig.psm1'; FunctionsToExport = @('Get-OSConfigMetadata') }`
	osconfigModule   = `Set-Content -LiteralPath (Join-Path $env:SystemRoot 'Temp\easyrmm-osconfig-stand-in') -Value 'imported'
function Get-OSConfigMetadata {
    $s = @([pscustomobject]@{ Name = 'SecuredCoreState'; Status = 'Active' })
    if ($env:EASYRMM_TEST_OSCONFIG -ne 'secured-core') { $s += [pscustomobject]@{ Name = 'SecurityBaseline/EasyRMMTest'; Status = 'Active' } }
    $s
}
`
)

// standIn writes the stand-in module under dir\Microsoft.OSConfig\1.0.0.
func standIn(t *testing.T, dir string) string {
	t.Helper()
	folder := filepath.Join(dir, "Microsoft.OSConfig", "1.0.0")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(dir, "Microsoft.OSConfig")) })
	for name, text := range map[string]string{"Microsoft.OSConfig.psd1": osconfigManifest, "Microsoft.OSConfig.psm1": osconfigModule} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return folder
}

// TestQueryOSConfigAsSystem: the reader imports OSConfig's module only from
// Program Files or System32, only where no one but SYSTEM, Administrators
// and TrustedInstaller can change it, and by its path; a module elsewhere,
// one that fails the check, or OSConfig's record of a scenario without the
// module, makes every answer cannot_tell (osconfig).
func TestQueryOSConfigAsSystem(t *testing.T) {
	systemTest(t)
	programFiles := filepath.Join(os.Getenv("ProgramFiles"), `WindowsPowerShell\Modules`)
	system32 := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\Modules`)
	for _, d := range append([]string{programFiles, system32}, filepath.SplitList(os.Getenv("PSModulePath"))...) {
		if _, err := os.Stat(filepath.Join(d, "Microsoft.OSConfig")); err == nil {
			t.Skipf("OSConfig's module is installed in %s", d)
		}
	}
	const metadata = `SOFTWARE\Microsoft\OSConfig\Metadata`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, metadata, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		if len(names) > 0 {
			t.Skipf("OSConfig recorded scenarios here: %q", names)
		}
	}
	mark := filepath.Join(os.Getenv("SystemRoot"), `Temp\easyrmm-osconfig-stand-in`)
	t.Cleanup(func() { _ = os.Remove(mark) })
	imported := func() bool {
		_, err := os.Stat(mark)
		_ = os.Remove(mark)
		return err == nil
	}
	_ = os.Remove(mark)

	// In Program Files, where only the trusted accounts may change it.
	folder := standIn(t, programFiles)
	code, a := ask(t, baseRequest)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !imported() {
		t.Error("the module in Program Files was not imported")
	}
	allCannotTell(t, "an active baseline", a, ReasonOSConfig)
	code, a = askWith(t, baseRequest, []string{"EASYRMM_TEST_OSCONFIG=secured-core"})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	_ = imported()
	noReason(t, "only the Secured-core scenario", a, ReasonOSConfig)

	// Users may change it.
	if out, err := exec.Command("icacls.exe", folder, "/grant", "*S-1-5-32-545:(OI)(CI)M").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if imported() {
		t.Error("a module Users may change was imported")
	}
	allCannotTell(t, "a module Users may change", a, ReasonOSConfig)
	if err := os.RemoveAll(filepath.Join(programFiles, "Microsoft.OSConfig")); err != nil {
		t.Fatal(err)
	}

	// Only in another folder of PSModulePath.
	other := filepath.Join(os.Getenv("SystemDrive")+`\`, "EasyRMM-test-modules")
	t.Cleanup(func() { _ = os.RemoveAll(other) })
	standIn(t, other)
	code, a = askWith(t, baseRequest, []string{"PSModulePath=" + other + ";" + programFiles + ";" + system32})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if imported() {
		t.Error("a module outside Program Files and System32 was imported")
	}
	allCannotTell(t, "a module outside Program Files and System32", a, ReasonOSConfig)
	if err := os.RemoveAll(other); err != nil {
		t.Fatal(err)
	}

	// OSConfig's record of a scenario, without the module.
	plant(t, metadata+`\EasyRMMTest`, map[string]any{"Description": "EasyRMM test"})
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	allCannotTell(t, "OSConfig's record without the module", a, ReasonOSConfig)
}
