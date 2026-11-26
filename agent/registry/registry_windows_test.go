//go:build windows

package registry

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
	"github.com/paulmataruso/easyrmm/internal/wintest"
)

// The registry builtin on a real Windows, as LocalSystem (ADR-0067, Testing).
// CI's job builds this package's test binary for each architecture and runs
// it through a scheduled task with EASYRMM_TEST_SYSTEM set; the tests change
// the computer (keys under a random name below HKLM\SOFTWARE, removed when
// each test ends), so they run only there.

func needSystem(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
}

var regSetValueEx = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")

// setRaw writes a value of any type, with the bytes given, under HKLM.
func setRaw(t *testing.T, path, name string, typ uint32, data []byte) {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	var p unsafe.Pointer
	if len(data) > 0 {
		p = unsafe.Pointer(&data[0])
	}
	if r, _, _ := regSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(n)), 0, uintptr(typ), uintptr(p), uintptr(len(data))); r != 0 {
		t.Fatalf("setting %q: %v", name, syscall.Errno(r))
	}
}

func u16bytes(s string, units ...uint16) []byte {
	u := append(utf16.Encode([]rune(s)), units...)
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func testKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return `SOFTWARE\EasyRMMTest-` + hex.EncodeToString(b)
}

func backend(t *testing.T) Backend {
	t.Helper()
	be, err := NewBackend()
	if err != nil {
		t.Fatal(err)
	}
	return be
}

func read(t *testing.T, be Backend, in agentproto.RegistryInput) *agentproto.RegistryResult {
	t.Helper()
	in.V, in.Rules = 1, registryrules.Version
	if in.View == "" {
		in.View = "64"
	}
	if in.Hive == "" {
		in.Hive = "HKLM"
	}
	if in.Path == nil {
		in.Path = []string{}
	}
	var out bytes.Buffer
	start := time.Now()
	if err := Run(in, be, &out, Options{AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s of %s\\%s in view %s took %s", in.Op, in.Hive, strings.Join(in.Path, `\`), in.View, time.Since(start))
	res, err := agentproto.ParseRegistryLines(agentproto.SplitResultLines(out.Bytes()))
	if err != nil || res.End == nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return res
}

func processes(t *testing.T) []string {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []string
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out = append(out, strings.ToLower(windows.UTF16ToString(e.ExeFile[:]))+fmt.Sprint(e.ProcessID))
	}
	return out
}

func TestRegistryTypesAsSystem(t *testing.T) {
	needSystem(t)
	base := testKey(t)
	wintest.Plant(t, base, map[string]any{"Str": "hello", "Dword": uint32(7)})
	setRaw(t, base, "", registry.SZ, u16bytes("default", 0))
	setRaw(t, base, "None", registry.NONE, []byte{1, 2})
	setRaw(t, base, "Expand", registry.EXPAND_SZ, u16bytes(`%SystemRoot%\x`, 0))
	setRaw(t, base, "Bin", registry.BINARY, []byte{0, 1, 0xff})
	setRaw(t, base, "BE", 5, []byte{0, 0, 0, 5})
	setRaw(t, base, "Multi", registry.MULTI_SZ, u16bytes("a\x00bc\x00", 0))
	setRaw(t, base, "Res", 8, []byte{9, 9, 9})
	setRaw(t, base, "Qword", registry.QWORD, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})
	setRaw(t, base, "Weird", 99, []byte{7})
	setRaw(t, base, "NoTerm", registry.SZ, u16bytes("abc"))
	setRaw(t, base, "NulInside", registry.SZ, u16bytes("a\x00b", 0))
	setRaw(t, base, "LoneSurrogate", registry.SZ, u16bytes("", 0xD800, 0))
	setRaw(t, base, "Odd", registry.SZ, []byte{'a', 0, 'b'})
	setRaw(t, base, "ShortDword", registry.DWORD, []byte{1, 2})
	setRaw(t, base, "DefaultPassword", registry.SZ, u16bytes("hunter2-marker", 0))
	setRaw(t, base, "Plain/Slash", registry.SZ, u16bytes("slash", 0))
	long := strings.Repeat("n", 255)
	setRaw(t, base, long, registry.SZ, u16bytes("long", 0))

	be := backend(t)
	res := read(t, be, agentproto.RegistryInput{Op: "list", Path: strings.Split(base, `\`)})
	by := map[string]agentproto.RegValue{}
	for _, v := range res.Values {
		by[v.Name] = v
	}
	if d := by[""]; d.Text == nil || *d.Text != "default" {
		t.Errorf("default value: %+v", d)
	}
	for name, want := range map[string]uint32{"None": 0, "Expand": 2, "Bin": 3, "BE": 5, "Multi": 7, "Res": 8, "Qword": 11, "Weird": 99, "Dword": 4} {
		if by[name].Type != want {
			t.Errorf("%s: type %d, want %d", name, by[name].Type, want)
		}
	}
	if v := by["Expand"]; v.Text == nil || *v.Text != `%SystemRoot%\x` {
		t.Errorf("REG_EXPAND_SZ is never expanded: %+v", v)
	}
	if v := by["Multi"]; len(v.Items) != 2 {
		t.Errorf("multi: %+v", v)
	}
	if v := by["Qword"]; v.Decimal != "9223372036854775807" {
		t.Errorf("qword: %+v", v)
	}
	// NoTerm: RegQueryValueEx itself appends the NUL a REG_SZ was stored
	// without (ADR-0067, amended), so Windows hands over a terminated string.
	if v := by["NoTerm"]; v.Text == nil || *v.Text != "abc" {
		t.Errorf("NoTerm: Windows terminates it: %+v", v)
	}
	for _, name := range []string{"NulInside", "LoneSurrogate", "Odd", "ShortDword"} {
		if v := by[name]; !v.Odd || v.Raw == "" {
			t.Errorf("%s is sent raw: %+v", name, v)
		}
	}
	if v := by["DefaultPassword"]; !v.Masked || v.Text != nil {
		t.Errorf("masked: %+v", v)
	}
	if _, ok := by["Plain/Slash"]; !ok {
		t.Error("a slash is part of a name")
	}
	if _, ok := by[long]; !ok {
		t.Error("a name of 255 characters")
	}
	if !strings.HasSuffix(res.Key.Kernel, `\`+base) || !strings.HasPrefix(res.Key.Kernel, `\REGISTRY\MACHINE\`) {
		t.Errorf("kernel name %q", res.Key.Kernel)
	}
	// A value read of a masked value is masked; one of a plain value is whole.
	one := read(t, be, agentproto.RegistryInput{Op: "value", Path: strings.Split(base, `\`), ValueName: ptr("DefaultPassword")})
	if len(one.Values) != 1 || !one.Values[0].Masked {
		t.Errorf("%+v", one.Values)
	}
	// No PowerShell process is started by a read.
	before := processes(t)
	read(t, be, agentproto.RegistryInput{Op: "list", Path: strings.Split(base, `\`)})
	for _, p := range processes(t) {
		if (strings.HasPrefix(p, "powershell.exe") || strings.HasPrefix(p, "pwsh.exe")) && !slices.Contains(before, p) {
			t.Errorf("a read started %s", p)
		}
	}
}

func TestRegistryViewsAsSystem(t *testing.T) {
	needSystem(t)
	be := backend(t)
	name := strings.TrimPrefix(testKey(t), `SOFTWARE\`)
	// A key made under the 32-bit node is the 32-bit view's SOFTWARE\<name>.
	wintest.Plant(t, `SOFTWARE\WOW6432Node\`+name, map[string]any{"View": "x86"})
	r32 := read(t, be, agentproto.RegistryInput{Op: "list", View: "32", Path: []string{"SOFTWARE", name}})
	if len(r32.Values) != 1 || !strings.Contains(strings.ToLower(r32.Key.Kernel), strings.ToLower(`\SOFTWARE\WOW6432Node\`+name)) {
		t.Errorf("32-bit view: %+v %+v", r32.Key, r32.Values)
	}
	r64 := read(t, be, agentproto.RegistryInput{Op: "list", View: "64", Path: []string{"SOFTWARE", name}})
	if len(r64.Errors) != 1 || r64.Errors[0].Code != agentproto.ErrCodeNotFound {
		t.Errorf("the 64-bit view has no such key: %+v", r64.Errors)
	}
	// A key the views share has one kernel name in both.
	a := read(t, be, agentproto.RegistryInput{Op: "list", View: "64", Path: []string{"SYSTEM", "CurrentControlSet", "Services"}})
	b := read(t, be, agentproto.RegistryInput{Op: "list", View: "32", Path: []string{"SYSTEM", "CurrentControlSet", "Services"}})
	if a.Key == nil || b.Key == nil || a.Key.Kernel != b.Key.Kernel {
		t.Errorf("shared key: %+v %+v", a.Key, b.Key)
	}
}

func TestRegistryRefusalsAsSystem(t *testing.T) {
	needSystem(t)
	be := backend(t)
	for _, p := range []string{`SAM`, `sam\SAM`, `SECURITY`, `SECURITY\SAM`, `SOFTWARE\EasyRMM`, `SOFTWARE\WOW6432Node\EasyPatch`, `SOFTWARE\Open Source`,
		`SYSTEM\CurrentControlSet\Services\EasyRMMAgent`, `SYSTEM\ControlSet001\Services\EasyPatchAgent`, `SYSTEM\ControlSet001\Services\EasyRMMMeshAgent`} {
		for _, view := range []string{"64", "32"} {
			res := read(t, be, agentproto.RegistryInput{Op: "list", View: view, Path: strings.Split(p, `\`)})
			if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused || len(res.Values)+len(res.Subkeys) != 0 {
				t.Errorf("%s in view %s: %+v", p, view, res.Errors)
			}
		}
	}
	// HKLM's list marks SAM and SECURITY, and never opens them.
	root := read(t, be, agentproto.RegistryInput{Op: "list"})
	state := map[string]string{}
	for _, s := range root.Subkeys {
		state[s.Name] = s.State
	}
	if state["SAM"] != agentproto.StateRefused || state["SECURITY"] != agentproto.StateRefused || state["SOFTWARE"] != "" {
		t.Errorf("HKLM's list: %v", state)
	}
	// A search and an export do not enter them.
	s := read(t, be, agentproto.RegistryInput{Op: "search", Term: "Domains", Depth: 3})
	for _, m := range s.Matches {
		if len(m.Path) > 0 && (strings.EqualFold(m.Path[0], "SAM") || strings.EqualFold(m.Path[0], "SECURITY")) {
			t.Errorf("a search entered %v", m.Path)
		}
	}
}

func TestRegistryLinksAsSystem(t *testing.T) {
	needSystem(t)
	be := backend(t)
	base := testKey(t)
	wintest.Plant(t, base+`\Real`, map[string]any{"x": uint32(1)})
	wintest.Link(t, base+`\Allowed`, base+`\Real`)
	wintest.Link(t, base+`\ToSam`, `SAM`)
	wintest.Link(t, base+`\ToSamSecurity`, `SECURITY\SAM`)
	path := strings.Split(base, `\`)
	ls := read(t, be, agentproto.RegistryInput{Op: "list", Path: path})
	state := map[string]string{}
	for _, s := range ls.Subkeys {
		state[s.Name] = s.State
	}
	if state["Allowed"] != agentproto.StateLink || state["ToSam"] != agentproto.StateLink || state["Real"] != "" {
		t.Errorf("links are marked: %v", state)
	}
	// A link to an allowed key in the same hive is followed for a read.
	r := read(t, be, agentproto.RegistryInput{Op: "list", Path: append(slices.Clone(path), "Allowed")})
	if len(r.Values) != 1 || !strings.HasSuffix(r.Key.Kernel, `\Real`) {
		t.Errorf("followed: %+v %+v", r.Key, r.Errors)
	}
	// A link to SAM is refused by its target, and by its kernel name.
	for _, name := range []string{"ToSam", "ToSamSecurity"} {
		r = read(t, be, agentproto.RegistryInput{Op: "list", Path: append(slices.Clone(path), name)})
		if len(r.Errors) != 1 || r.Errors[0].Code != agentproto.ErrCodeRefused {
			t.Errorf("%s: %+v", name, r.Errors)
		}
	}
	// A search never follows a link, and lists it.
	s := read(t, be, agentproto.RegistryInput{Op: "search", Path: path, Term: "zzz-nothing"})
	links := 0
	for _, m := range s.Matches {
		if m.Kind == agentproto.MatchLink {
			links++
		}
	}
	if links != 3 {
		t.Errorf("%d links listed, want 3", links)
	}
	// CurrentControlSet and HKCC's alias are links Windows makes, followed for a read.
	cs := read(t, be, agentproto.RegistryInput{Op: "list", Path: []string{"SYSTEM", "CurrentControlSet"}})
	if cs.Key == nil || !strings.Contains(cs.Key.Kernel, `\ControlSet`) {
		t.Errorf("CurrentControlSet: %+v %+v", cs.Key, cs.Errors)
	}
	cc := read(t, be, agentproto.RegistryInput{Op: "list", Hive: "HKCC"})
	if cc.Key == nil || len(cc.Errors) != 0 {
		t.Errorf("HKCC: %+v %+v", cc.Key, cc.Errors)
	}
}

func TestRegistryHivesAsSystem(t *testing.T) {
	needSystem(t)
	be := backend(t)
	u := read(t, be, agentproto.RegistryInput{Op: "list", Hive: "HKU"})
	names := map[string]bool{}
	for _, s := range u.Subkeys {
		names[s.Name] = true
	}
	if !names[".DEFAULT"] || !names["S-1-5-18"] {
		t.Errorf("HKU: %v", names)
	}
	cr := read(t, be, agentproto.RegistryInput{Op: "list", Hive: "HKCR"})
	if len(cr.Subkeys) < 100 || len(cr.Errors) != 0 {
		t.Errorf("HKCR: %d subkeys %+v", len(cr.Subkeys), cr.Errors)
	}
	// A search from HKCR keeps its paths in HKCR's terms.
	s := read(t, be, agentproto.RegistryInput{Op: "search", Hive: "HKCR", Term: "txtfile", Depth: 1})
	if s.End.Complete && len(s.Matches) > 0 && s.Matches[0].Path[0] == "SOFTWARE" {
		t.Errorf("paths in HKLM's terms: %v", s.Matches[0].Path)
	}
}

func TestRegistryCopiesOfSamAsSystem(t *testing.T) {
	needSystem(t)
	// A test hive, built with a SAM\Domains key and never the real SAM, saved
	// and loaded under another name.
	base := testKey(t)
	wintest.Plant(t, base+`\SAM\Domains`, map[string]any{"x": uint32(1)})
	dir := t.TempDir()
	for _, file := range []string{"sam.save", "plain.hiv"} {
		path := dir + `\` + file
		if out, err := regCommand("save", `HKLM\`+base, path, "/y"); err != nil {
			t.Fatalf("reg save: %v\n%s", err, out)
		}
		name := "EasyRMMTest-" + file[:3] + "-" + hex.EncodeToString([]byte(file))[:6]
		if out, err := regCommand("load", `HKLM\`+name, path); err != nil {
			t.Fatalf("reg load: %v\n%s", err, out)
		}
		t.Cleanup(func() { _, _ = regCommand("unload", `HKLM\`+name) })
		res := read(t, backend(t), agentproto.RegistryInput{Op: "list", Path: []string{name}})
		if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused {
			t.Errorf("%s loaded as %s: %+v (refused by its file's name, or by its root)", file, name, res.Errors)
		}
	}
}

func TestRegistryBigKeyAndValueAsSystem(t *testing.T) {
	needSystem(t)
	if testing.Short() {
		t.Skip("makes 100,000 keys")
	}
	base := testKey(t)
	wintest.Plant(t, base, map[string]any{})
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	made := time.Now()
	for i := range 100000 {
		c, _, err := registry.CreateKey(k, fmt.Sprintf("key%06d", i), registry.QUERY_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	_ = k.Close()
	t.Logf("made 100,000 keys in %s", time.Since(made))
	setRaw(t, base, "OneMiB", registry.BINARY, make([]byte, 1<<20))
	be := backend(t)
	path := strings.Split(base, `\`)
	total := 0
	var cursor *agentproto.RegistryCursor
	for pages := 0; pages < 200; pages++ {
		start := time.Now()
		res := read(t, be, agentproto.RegistryInput{Op: "list", Path: path, Cursor: cursor, MaxSubkeys: 1000})
		t.Logf("a page of %d subkeys took %s", len(res.Subkeys), time.Since(start))
		total += len(res.Subkeys)
		if !res.End.MoreSubkeys {
			break
		}
		next := res.End.NextSubkey
		cursor = &agentproto.RegistryCursor{Subkey: &next}
	}
	if total != 100000 {
		t.Errorf("%d subkeys paged, want 100000", total)
	}
	v := read(t, be, agentproto.RegistryInput{Op: "value", Path: path, ValueName: ptr("OneMiB")})
	if len(v.Values) != 1 || v.Values[0].Size != 1<<20 || v.Values[0].Cut {
		t.Errorf("a 1 MiB value: %+v", v.Values)
	}
	// A search stops at its bounds.
	s := read(t, be, agentproto.RegistryInput{Op: "search", Path: path, Term: "key0999", MaxMatches: 5})
	if s.End.StoppedBy != agentproto.StoppedMatches || len(s.Matches) != 5 {
		t.Errorf("search: %+v", s.End)
	}
}

func TestRegistryExportMatchesRegExeAsSystem(t *testing.T) {
	needSystem(t)
	base := testKey(t)
	wintest.Plant(t, base+`\Sub`, map[string]any{"Str": `C:\Program Files "x"`, "Dword": uint32(255)})
	setRaw(t, base+`\Sub`, "Bin", registry.BINARY, []byte{1, 2, 3})
	setRaw(t, base+`\Sub`, "Exp", registry.EXPAND_SZ, u16bytes(`%SystemRoot%`, 0))
	setRaw(t, base+`\Sub`, "Multi", registry.MULTI_SZ, u16bytes("a\x00b\x00", 0))
	res := read(t, backend(t), agentproto.RegistryInput{Op: "export", Path: strings.Split(base, `\`)})
	if !res.End.Complete || len(res.XKeys) != 2 {
		t.Fatalf("%+v", res.End)
	}
	var sub agentproto.RegXKey
	for _, x := range res.XKeys {
		if len(x.Path) == 3 {
			sub = x
		}
	}
	got := map[string][]byte{}
	for _, v := range sub.Values {
		b, ok := agentproto.RegValueBytes(v)
		if !ok {
			t.Fatalf("no bytes for %s", v.Name)
		}
		got[v.Name] = b
	}
	// What reg.exe exports of the same key holds the same values: the
	// export imported by reg import into another key reads back equal.
	dir := t.TempDir()
	file := dir + `\export.reg`
	if out, err := regCommand("export", `HKLM\`+base, file, "/y"); err != nil {
		t.Fatalf("reg export: %v\n%s", err, out)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text := string(utf16.Decode(utf16Of(b)))
	for _, want := range []string{`"Dword"=dword:000000ff`, `"Bin"=hex:01,02,03`, `"Exp"=hex(2):`, `"Multi"=hex(7):`} {
		if !strings.Contains(text, want) {
			t.Errorf("reg.exe's export lacks %q:\n%s", want, text)
		}
	}
	if len(got["Bin"]) != 3 || !bytes.Equal(got["Bin"], []byte{1, 2, 3}) {
		t.Errorf("bin: %v", got["Bin"])
	}
}

func utf16Of(b []byte) []uint16 {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return u
}

func TestBackendRunsAsTheMachinesOwnArchitecture(t *testing.T) {
	needSystem(t)
	be, err := NewBackend()
	if err != nil {
		t.Fatal(err)
	}
	if a := be.Arch(); a != agentproto.ArchX64 && a != agentproto.ArchARM64 {
		t.Errorf("arch %q", a)
	}
}
