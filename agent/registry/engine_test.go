package registry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// A registry in memory, for the engine's tests: the logic that opens paths,
// refuses keys, follows links and pages does not depend on Windows. What
// does is tested on the Windows runners, in registry_windows_test.go.

type fval struct {
	typ  uint32
	data []byte
}

type fnode struct {
	name      string
	kernel    string
	subs      map[string]*fnode
	vals      map[string]fval
	link      string
	denied    bool
	lastWrite time.Time
}

type fake struct {
	roots    map[registryrules.Hive]*fnode
	opened   []string
	hivelist []HiveFile
	labels   map[string]string
}

func newFake() *fake {
	return &fake{roots: map[registryrules.Hive]*fnode{
		registryrules.HKLM: {name: "", kernel: `\REGISTRY\MACHINE`, subs: map[string]*fnode{}, vals: map[string]fval{}},
		registryrules.HKU:  {name: "", kernel: `\REGISTRY\USER`, subs: map[string]*fnode{}, vals: map[string]fval{}},
	}, labels: map[string]string{}}
}

// add makes the keys of a path under a hive and returns the last.
func (f *fake) add(h registryrules.Hive, path ...string) *fnode {
	n := f.roots[h]
	for _, name := range path {
		c := n.subs[name]
		if c == nil {
			c = &fnode{name: name, kernel: n.kernel + `\` + name, subs: map[string]*fnode{}, vals: map[string]fval{}, lastWrite: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
			n.subs[name] = c
		}
		n = c
	}
	return n
}

func (n *fnode) set(name string, typ uint32, data []byte) *fnode {
	n.vals[name] = fval{typ, data}
	return n
}

func str(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func dword(n uint32) []byte { return binary.LittleEndian.AppendUint32(nil, n) }

type fkey struct {
	f *fake
	n *fnode
}

func (f *fake) Root(h registryrules.Hive, _ registryrules.View) (Key, error) {
	return &fkey{f, f.roots[h]}, nil
}
func (f *fake) Hivelist() ([]HiveFile, error) { return f.hivelist, nil }
func (f *fake) SIDLabel(s string) string      { return f.labels[s] }
func (f *fake) Arch() string                  { return agentproto.ArchX64 }

func (k *fkey) Kernel() string { return k.n.kernel }
func (k *fkey) Info() (Info, error) {
	return Info{Subkeys: len(k.n.subs), Values: len(k.n.vals), LastWrite: k.n.lastWrite}, nil
}
func (k *fkey) SubkeyNames() ([]string, error) {
	var out []string
	for n := range k.n.subs {
		out = append(out, n)
	}
	return out, nil
}
func (k *fkey) ValueNames() ([]string, error) {
	var out []string
	for n := range k.n.vals {
		out = append(out, n)
	}
	return out, nil
}
func (k *fkey) ValueInfo(name string) (uint32, int, error) {
	v, ok := k.n.vals[name]
	if !ok {
		return 0, 0, ErrNotFound
	}
	return v.typ, len(v.data), nil
}
func (k *fkey) ReadValue(name string) (uint32, []byte, error) {
	v, ok := k.n.vals[name]
	if !ok {
		return 0, nil, ErrNotFound
	}
	return v.typ, v.data, nil
}
func (k *fkey) OpenChild(name string) (Key, error) {
	found := k.n.subs[name]
	if found == nil {
		for n, c := range k.n.subs {
			if strings.EqualFold(n, name) {
				found = c
			}
		}
	}
	if found == nil {
		return nil, ErrNotFound
	}
	k.f.opened = append(k.f.opened, found.kernel)
	if found.denied {
		return nil, ErrDenied
	}
	return &fkey{k.f, found}, nil
}
func (k *fkey) LinkTarget() (string, bool) { return k.n.link, k.n.link != "" }
func (k *fkey) Close()                     {}

// run reads and decodes the lines.
func run(t *testing.T, f *fake, in agentproto.RegistryInput, o Options) (*agentproto.RegistryResult, []byte) {
	t.Helper()
	in.V, in.Rules = 1, 1
	if in.View == "" {
		in.View = "64"
	}
	if in.Hive == "" {
		in.Hive = "HKLM"
	}
	if in.Path == nil {
		in.Path = []string{}
	}
	if err := in.Check(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	o.AgentVersion = "1.5.0"
	if err := Run(in, f, &out, o); err != nil {
		t.Fatal(err)
	}
	res, err := agentproto.ParseRegistryLines(agentproto.SplitResultLines(out.Bytes()))
	if err != nil {
		t.Fatalf("the result does not decode: %v\n%s", err, out.Bytes())
	}
	for _, l := range agentproto.SplitResultLines(out.Bytes()) {
		if !agentproto.ValidRegistryText(l) {
			t.Fatalf("a line cannot go into jsonb: %s", l)
		}
	}
	if res.End == nil {
		t.Fatalf("no end line:\n%s", out.Bytes())
	}
	return res, out.Bytes()
}

func names(subs []agentproto.RegSubkey) []string {
	var out []string
	for _, s := range subs {
		out = append(out, s.Name)
	}
	return out
}

func TestListMarksRefusedKeysAndNeverOpensThem(t *testing.T) {
	f := newFake()
	f.add(registryrules.HKLM, "SAM", "SAM", "Domains")
	f.add(registryrules.HKLM, "SECURITY", "Policy", "Secrets")
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor")
	f.add(registryrules.HKLM, "SYSTEM")
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list"}, Options{})
	if got := names(res.Subkeys); !slices.Equal(got, []string{"SAM", "SECURITY", "SOFTWARE", "SYSTEM"}) {
		t.Fatalf("subkeys %v", got)
	}
	for _, s := range res.Subkeys[:2] {
		if s.State != agentproto.StateRefused || s.Rule == "" {
			t.Errorf("%s: %+v", s.Name, s)
		}
	}
	if res.Subkeys[2].State != "" || res.Subkeys[2].Subkeys != 1 {
		t.Errorf("SOFTWARE: %+v", res.Subkeys[2])
	}
	for _, o := range f.opened {
		if strings.Contains(o, "SAM") || strings.Contains(o, "SECURITY") {
			t.Errorf("a refused key was opened: %s", o)
		}
	}
	if res.Key == nil || res.Key.Kernel != `\REGISTRY\MACHINE` || res.Key.Subkeys != 4 || res.Key.ReadAt == "" {
		t.Errorf("key line %+v", res.Key)
	}
	if res.Begin.AgentVersion != "1.5.0" || res.Begin.Rules != registryrules.Version || res.Begin.Arch != "x64" {
		t.Errorf("begin %+v", res.Begin)
	}
}

func TestEveryRefusedSpellingIsRefusedByTheAgentWithoutTheServer(t *testing.T) {
	f := newFake()
	f.add(registryrules.HKLM, "SAM", "SAM")
	f.add(registryrules.HKLM, "SECURITY", "SAM")
	f.add(registryrules.HKLM, "SOFTWARE", "EasyRMM")
	f.add(registryrules.HKLM, "SOFTWARE", "WOW6432Node", "EasyPatch")
	f.add(registryrules.HKLM, "SOFTWARE", "Open Source")
	f.add(registryrules.HKLM, "SYSTEM", "ControlSet001", "Services", "EasyRMMAgent")
	for _, p := range [][]string{{"SAM"}, {"sam", "SAM"}, {"SECURITY", "SAM"}, {"SOFTWARE", "EasyRMM"}, {"SOFTWARE", "WOW6432Node", "EasyPatch"},
		{"SOFTWARE", "Open Source"}, {"SYSTEM", "ControlSet001", "Services", "EasyRMMAgent"}, {"SOFTWARE", "EaſyRMM"}} {
		for _, view := range []string{"64", "32"} {
			f.opened = nil
			res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: p, View: view}, Options{})
			if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused || len(res.Refused) != 1 {
				t.Errorf("%v in view %s: %+v %+v", p, view, res.Errors, res.Refused)
			}
			if len(f.opened) != 0 {
				t.Errorf("%v: opened %v", p, f.opened)
			}
		}
	}
}

func TestAKeyThatResolvesIntoARefusedKeyIsRefusedByItsKernelName(t *testing.T) {
	f := newFake()
	disguised := f.add(registryrules.HKLM, "SOFTWARE", "Innocent")
	disguised.kernel = `\REGISTRY\MACHINE\SECURITY\Policy`
	disguised.set("x", 1, str("secret"))
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Innocent"}}, Options{})
	if len(res.Refused) != 1 || res.Refused[0].Kernel != `\REGISTRY\MACHINE\SECURITY\Policy` || len(res.Values) != 0 {
		t.Fatalf("refused %+v values %+v errors %+v", res.Refused, res.Values, res.Errors)
	}
	// Listed as a subkey it is marked refused, and its data is never read.
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE"}}, Options{})
	if len(res.Subkeys) != 1 || res.Subkeys[0].State != agentproto.StateRefused {
		t.Errorf("%+v", res.Subkeys)
	}
}

func TestValuesAreRawMaskedAndBounded(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "V")
	k.set("", 1, str("default"))
	k.set("Dword", 4, dword(255))
	k.set("DefaultPassword", 1, str("hunter2"))
	k.set("ApiToken", 3, []byte{1, 2, 3})
	k.set("PasswordExpiryWarning", 4, dword(14))
	k.set("Big", 3, make([]byte, 5000))
	k.set("Expand", 2, str("%SystemRoot%\\x"))
	k.set("NoTerm", 1, []byte{'a', 0, 'b', 0})
	k.set("Lnk", 6, []byte{1})
	res, out := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "V"}}, Options{})
	by := map[string]agentproto.RegValue{}
	for _, v := range res.Values {
		by[v.Name] = v
	}
	if d := by[""]; d.Text == nil || *d.Text != "default" {
		t.Errorf("default value: %+v", d)
	}
	if v := by["DefaultPassword"]; !v.Masked || v.Text != nil || v.Size != 16 {
		t.Errorf("masked: %+v", v)
	}
	if v := by["ApiToken"]; !v.Masked || v.Base64 != "" {
		t.Errorf("masked binary: %+v", v)
	}
	if v := by["PasswordExpiryWarning"]; v.Masked || v.Number == nil || *v.Number != 14 {
		t.Errorf("a number named like a secret is a setting: %+v", v)
	}
	if v := by["Big"]; !v.NoData || v.Size != 5000 {
		t.Errorf("larger than a page: %+v", v)
	}
	if v := by["Expand"]; v.Text == nil || *v.Text != `%SystemRoot%\x` {
		t.Errorf("never expanded: %+v", v)
	}
	if v := by["NoTerm"]; !v.Odd || v.Raw == "" {
		t.Errorf("no terminator: %+v", v)
	}
	if v := by["Lnk"]; v.Type != 6 || v.Base64 == "" {
		t.Errorf("an unknown type is bytes: %+v", v)
	}
	if bytes.Contains(out, []byte("hunter2")) || bytes.Contains(out, []byte("aAB1AG4AdABlAHIAMgA")) {
		t.Error("masked data is in the result")
	}
	// A value read of a masked value is masked too.
	one, _ := run(t, f, agentproto.RegistryInput{Op: "value", Path: []string{"SOFTWARE", "V"}, ValueName: ptr("DefaultPassword")}, Options{})
	if len(one.Values) != 1 || !one.Values[0].Masked || one.Values[0].Text != nil {
		t.Errorf("value read of a masked value: %+v", one.Values)
	}
	// A value read gets the whole value, up to 1 MiB, then cuts.
	f.add(registryrules.HKLM, "SOFTWARE", "V").set("Huge", 3, make([]byte, 2<<20))
	cut, _ := run(t, f, agentproto.RegistryInput{Op: "value", Path: []string{"SOFTWARE", "V"}, ValueName: ptr("Huge")}, Options{})
	if len(cut.Values) != 1 || !cut.Values[0].Cut || cut.Values[0].Size != 2<<20 {
		t.Errorf("huge: %+v", cut.Values)
	}
	// Value that is not there.
	nf, _ := run(t, f, agentproto.RegistryInput{Op: "value", Path: []string{"SOFTWARE", "V"}, ValueName: ptr("None")}, Options{})
	if len(nf.Errors) != 1 || nf.Errors[0].Code != agentproto.ErrCodeNotFound {
		t.Errorf("not found: %+v", nf.Errors)
	}
}

func ptr(s string) *string { return &s }

func TestPagesByNameInOrdinalIgnoreCaseOrder(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "Many")
	var want []string
	for i := range 2500 {
		n := fmt.Sprintf("%c%04d", "aBcD"[i%4], i)
		k.subs[n] = &fnode{name: n, kernel: k.kernel + `\` + n, subs: map[string]*fnode{}, vals: map[string]fval{}}
		want = append(want, n)
	}
	for i := range 700 {
		k.set(fmt.Sprintf("v%04d", i), 4, dword(uint32(i)))
	}
	var got, gotVals []string
	var cursor *agentproto.RegistryCursor
	pages := 0
	for {
		res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Many"}, Cursor: cursor}, Options{})
		pages++
		got = append(got, names(res.Subkeys)...)
		for _, v := range res.Values {
			gotVals = append(gotVals, v.Name)
		}
		if len(res.Subkeys) > 1000 || len(res.Values) > 500 {
			t.Fatalf("a page of %d subkeys and %d values", len(res.Subkeys), len(res.Values))
		}
		if !res.End.MoreSubkeys && !res.End.MoreValues {
			break
		}
		cursor = &agentproto.RegistryCursor{}
		if res.End.MoreSubkeys {
			cursor.Subkey = &res.End.NextSubkey
		} else {
			cursor.Subkey = ptr(got[len(got)-1])
		}
		if res.End.MoreValues {
			cursor.Value = &res.End.NextValue
		} else if len(gotVals) > 0 {
			cursor.Value = ptr(gotVals[len(gotVals)-1])
		}
		if pages > 10 {
			t.Fatal("paging does not end")
		}
	}
	order(want)
	if !slices.Equal(got, want) {
		t.Errorf("the pages hold %d subkeys, want %d, in order", len(got), len(want))
	}
	if len(gotVals) != 700 {
		t.Errorf("%d values", len(gotVals))
	}
	// Ordinal ignore-case: a before B before c before D.
	if !slices.IsSortedFunc(got, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) }) {
		t.Error("not in ignore-case order")
	}
}

func TestResultFileNeverPassesItsBound(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "Fat")
	for i := range 500 {
		k.set(fmt.Sprintf("v%03d", i), 3, bytes.Repeat([]byte{byte(i)}, 4000))
	}
	res, out := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Fat"}}, Options{})
	if len(out) > agentproto.MaxResultFile {
		t.Errorf("%d bytes", len(out))
	}
	if !res.End.MoreValues || len(res.Values) == 0 || len(res.Values) == 500 {
		t.Errorf("a page ends at its bound: %d values, more=%v", len(res.Values), res.End.MoreValues)
	}
}

func TestLinks(t *testing.T) {
	f := newFake()
	real := f.add(registryrules.HKLM, "SOFTWARE", "Real")
	real.set("x", 4, dword(1))
	f.add(registryrules.HKLM, "SOFTWARE", "Real", "Child")
	f.add(registryrules.HKLM, "SOFTWARE", "Link").link = `\Registry\Machine\SOFTWARE\Real`
	f.add(registryrules.HKLM, "SOFTWARE", "ToSam").link = `\REGISTRY\MACHINE\SAM`
	f.add(registryrules.HKLM, "SOFTWARE", "ToUsers").link = `\REGISTRY\USER\S-1-5-18`
	f.add(registryrules.HKLM, "SAM", "SAM")
	f.add(registryrules.HKU, "S-1-5-18", "Software")
	f.add(registryrules.HKLM, "SOFTWARE", "Loop").link = `\REGISTRY\MACHINE\SOFTWARE\Loop`

	// A link inside the hive that passes the refusals is followed for a read.
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Link"}}, Options{})
	if len(res.Values) != 1 || res.Key == nil || res.Key.Kernel != `\REGISTRY\MACHINE\SOFTWARE\Real` || len(res.Subkeys) != 1 {
		t.Errorf("followed: %+v %+v", res.Key, res.Values)
	}
	// Listed as a subkey it is marked, with its target.
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE"}}, Options{})
	for _, s := range res.Subkeys {
		if strings.HasPrefix(s.Name, "To") || s.Name == "Link" || s.Name == "Loop" {
			if s.State != agentproto.StateLink || s.Target == "" {
				t.Errorf("%s: %+v", s.Name, s)
			}
		}
	}
	// To a refused key: refused by its target, and SAM never opened.
	f.opened = nil
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "ToSam"}}, Options{})
	if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused {
		t.Errorf("a link to SAM: %+v", res.Errors)
	}
	for _, o := range f.opened {
		if strings.Contains(o, `\SAM`) {
			t.Errorf("opened %s", o)
		}
	}
	// To another hive, and a loop: not followed, with the target said.
	for _, name := range []string{"ToUsers", "Loop"} {
		res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", name}}, Options{})
		if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Message, "does not follow") {
			t.Errorf("%s: %+v", name, res.Errors)
		}
	}
	// A search never follows a link and lists it.
	s, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE"}, Term: "zzz"}, Options{})
	links := 0
	for _, m := range s.Matches {
		if m.Kind == agentproto.MatchLink {
			links++
		}
	}
	if links != 4 {
		t.Errorf("%d links listed by the search, want 4", links)
	}
}

func TestSearch(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "Vendor")
	k.set("MarkerName", 4, dword(1))
	k.set("Plain", 1, str("has a MARKER inside"))
	k.set("Multi", 7, append(append(str("one"), str("marker two")...), 0, 0))
	k.set("Bin", 3, []byte("marker"))
	k.set("DbPassword", 1, str("marker-secret"))
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor", "marker key", "Deep", "Deeper")
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor", "A")
	f.add(registryrules.HKLM, "SOFTWARE", "EasyRMM", "marker")
	f.add(registryrules.HKLM, "SECURITY", "marker")
	res, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{}, Term: "Marker"}, Options{})
	kinds := map[string]int{}
	for _, m := range res.Matches {
		kinds[m.Kind]++
		if len(m.Path) > 0 && (m.Path[0] == "SECURITY" || len(m.Path) > 1 && m.Path[1] == "EasyRMM") {
			t.Errorf("a refused key was entered: %v", m.Path)
		}
		if m.Name == "DbPassword" {
			t.Error("a match inside masked data")
		}
		if m.Kind == "data" && m.Name == "Bin" {
			t.Error("a match in binary data")
		}
	}
	if kinds["valueName"] != 1 || kinds["data"] != 2 || kinds["key"] != 1 {
		t.Errorf("matches %v", kinds)
	}
	for _, o := range f.opened {
		if strings.Contains(o, "SECURITY") || strings.Contains(o, "EasyRMM") {
			t.Errorf("opened %s", o)
		}
	}
	if !res.End.Complete || res.End.Visited == 0 {
		t.Errorf("end %+v", res.End)
	}
	// Bounds: matches, depth, keys visited, time, each naming the first key not visited.
	m, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE"}, Term: "marker", MaxMatches: 2}, Options{})
	if m.End.StoppedBy != agentproto.StoppedMatches || len(m.Matches) != 2 || m.End.Complete {
		t.Errorf("matches bound: %+v", m.End)
	}
	d, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE"}, Term: "deeper", Depth: 2}, Options{})
	if len(d.Matches) != 0 {
		t.Errorf("depth 2 reaches Deeper: %+v", d.Matches)
	}
	d, _ = run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE"}, Term: "deeper", Depth: 4}, Options{})
	if len(d.Matches) != 1 {
		t.Errorf("depth 4: %+v", d.Matches)
	}
	now := time.Unix(0, 0)
	ticking := func() time.Time { now = now.Add(10 * time.Second); return now }
	tm, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE"}, Term: "marker"}, Options{Now: ticking, SearchBudget: 25 * time.Second})
	if tm.End.StoppedBy != agentproto.StoppedTime || len(tm.End.FirstUnvisited) == 0 {
		t.Errorf("time bound: %+v", tm.End)
	}
}

func TestSearchStopsAtTheKeyLimit(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "Wide")
	for i := range agentproto.RegMaxVisited + 5 {
		n := fmt.Sprintf("k%06d", i)
		k.subs[n] = &fnode{name: n, kernel: k.kernel + `\` + n, subs: map[string]*fnode{}, vals: map[string]fval{}}
	}
	res, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{"SOFTWARE", "Wide"}, Term: "zzzz"}, Options{SearchBudget: time.Hour})
	if res.End.StoppedBy != agentproto.StoppedKeys || res.End.Visited != agentproto.RegMaxVisited || len(res.End.FirstUnvisited) != 3 {
		t.Errorf("%+v", res.End)
	}
}

func TestExport(t *testing.T) {
	f := newFake()
	root := f.add(registryrules.HKLM, "SOFTWARE", "Vendor")
	root.set("", 1, str("d")).set("N", 4, dword(7)).set("Token", 1, str("secret")).set("B", 3, []byte{1, 2, 3})
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor", "Sub").set("x", 7, append(str("a"), str("")...))
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor", "Denied").denied = true
	f.add(registryrules.HKLM, "SOFTWARE", "Vendor", "Lnk").link = `\Registry\Machine\SOFTWARE\Vendor`
	f.add(registryrules.HKLM, "SOFTWARE", "EasyRMM")
	res, out := run(t, f, agentproto.RegistryInput{Op: "export", Path: []string{"SOFTWARE"}}, Options{})
	if !res.End.Complete || len(res.XKeys) != 6 {
		t.Fatalf("%d keys, end %+v", len(res.XKeys), res.End)
	}
	state := map[string]string{}
	for _, x := range res.XKeys {
		state[x.Path[len(x.Path)-1]] = x.State
	}
	if state["Denied"] != agentproto.StateDenied || state["Lnk"] != agentproto.StateLink || state["EasyRMM"] != agentproto.StateRefused || state["Sub"] != "" {
		t.Errorf("states %v", state)
	}
	if bytes.Contains(out, []byte("c2VjcmV0")) {
		t.Error("masked data in the export")
	}
	seen := false
	for _, x := range res.XKeys {
		for _, v := range x.Values {
			if v.Name == "N" {
				seen = true
				if v.Number == nil || v.Raw == "" {
					t.Errorf("an export carries the bytes: %+v", v)
				}
			}
		}
	}
	if !seen {
		t.Error("the value was not exported")
	}
	// Bounds: 5,000 keys, and the size.
	g := newFake()
	k := g.add(registryrules.HKLM, "SOFTWARE", "Wide")
	for i := range agentproto.RegMaxExportKeys + 5 {
		n := fmt.Sprintf("k%05d", i)
		k.subs[n] = &fnode{name: n, kernel: k.kernel + `\` + n, subs: map[string]*fnode{}, vals: map[string]fval{}}
	}
	big, _ := run(t, g, agentproto.RegistryInput{Op: "export", Path: []string{"SOFTWARE", "Wide"}}, Options{SearchBudget: time.Hour})
	if big.End.StoppedBy != agentproto.StoppedExported || big.End.Complete {
		t.Errorf("5,000 keys: %+v", big.End)
	}
	h := newFake()
	hk := h.add(registryrules.HKLM, "SOFTWARE", "Heavy")
	for i := range 60 {
		n := fmt.Sprintf("k%02d", i)
		c := &fnode{name: n, kernel: hk.kernel + `\` + n, subs: map[string]*fnode{}, vals: map[string]fval{}}
		c.set("blob", 3, bytes.Repeat([]byte{7}, 60000))
		hk.subs[n] = c
	}
	heavy, out2 := run(t, h, agentproto.RegistryInput{Op: "export", Path: []string{"SOFTWARE", "Heavy"}}, Options{SearchBudget: time.Hour})
	if heavy.End.StoppedBy != agentproto.StoppedSize || len(out2) > agentproto.MaxResultFile {
		t.Errorf("size: %+v %d bytes", heavy.End, len(out2))
	}
}

func TestLoadedCopiesOfSamAndSecurityAreRefusedWhereverTheyAreMounted(t *testing.T) {
	f := newFake()
	f.hivelist = []HiveFile{
		{Key: `\REGISTRY\MACHINE\SOFTWARE`, File: `\Device\HarddiskVolume3\Windows\System32\config\SOFTWARE`},
		{Key: `\REGISTRY\MACHINE\Copy1`, File: `\Device\HarddiskVolume3\temp\sam.save`},
		{Key: `\REGISTRY\MACHINE\Copy2`, File: `C:\x\SECURITY.hiv`},
		{Key: `\REGISTRY\MACHINE\Copy3`, File: `C:\x\Security`},
		{Key: `\REGISTRY\MACHINE\Fine`, File: `C:\x\mydata.dat`},
	}
	f.add(registryrules.HKLM, "Copy1", "a")
	f.add(registryrules.HKLM, "Copy2", "a")
	f.add(registryrules.HKLM, "Copy3", "a")
	f.add(registryrules.HKLM, "Fine", "a")
	// A copy under any name: its root holds SAM\Domains or Policy\Secrets.
	f.add(registryrules.HKLM, "Renamed", "SAM", "Domains")
	f.add(registryrules.HKLM, "Renamed2", "Policy", "Secrets")
	f.add(registryrules.HKU, "TempCopy", "SAM", "Domains")
	f.add(registryrules.HKU, "S-1-5-21-1", "Software")
	for _, p := range []string{"Copy1", "Copy2", "Copy3", "Renamed", "Renamed2"} {
		f.opened = nil
		res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{p}}, Options{})
		if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused {
			t.Errorf("%s: %+v", p, res.Errors)
		}
	}
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"Fine"}}, Options{})
	if len(res.Errors) != 0 {
		t.Errorf("an ordinary hive refused: %+v", res.Errors)
	}
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"TempCopy"}, Hive: "HKU"}, Options{})
	if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeRefused {
		t.Errorf("HKU copy: %+v", res.Errors)
	}
	// Listing the root marks them too.
	root, _ := run(t, f, agentproto.RegistryInput{Op: "list"}, Options{})
	state := map[string]string{}
	for _, s := range root.Subkeys {
		state[s.Name] = s.State
	}
	for _, n := range []string{"Copy1", "Copy2", "Copy3", "Renamed", "Renamed2"} {
		if state[n] != agentproto.StateRefused {
			t.Errorf("%s listed as %q", n, state[n])
		}
	}
	if state["Fine"] != "" {
		t.Errorf("Fine listed as %q", state["Fine"])
	}
	// Searches and exports skip them as well.
	s, _ := run(t, f, agentproto.RegistryInput{Op: "search", Path: []string{}, Term: "a"}, Options{})
	for _, m := range s.Matches {
		if len(m.Path) > 0 && strings.HasPrefix(m.Path[0], "Copy") {
			t.Errorf("entered %v", m.Path)
		}
	}
}

func TestHKUListsLoadedHivesWithTheirUsers(t *testing.T) {
	f := newFake()
	f.add(registryrules.HKU, "S-1-5-21-1-2-3-1001", "Software")
	f.add(registryrules.HKU, "S-1-5-21-1-2-3-1001_Classes")
	f.add(registryrules.HKU, ".DEFAULT")
	f.labels["S-1-5-21-1-2-3-1001"] = `LAB\ana`
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Hive: "HKU"}, Options{})
	got := map[string]string{}
	for _, s := range res.Subkeys {
		got[s.Name] = s.Label
	}
	if got["S-1-5-21-1-2-3-1001"] != `LAB\ana` || got[".DEFAULT"] != "" || len(got) != 3 {
		t.Errorf("%v", got)
	}
}

func TestHKCRAndHKCCAreRead(t *testing.T) {
	f := newFake()
	f.add(registryrules.HKLM, "SOFTWARE", "Classes", ".txt").set("", 1, str("txtfile"))
	cc := f.add(registryrules.HKLM, "SYSTEM", "ControlSet001", "Hardware Profiles", "Current")
	cc.set("x", 4, dword(1))
	f.add(registryrules.HKLM, "SYSTEM", "CurrentControlSet").link = `\Registry\Machine\SYSTEM\ControlSet001`
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Hive: "HKCR"}, Options{})
	if got := names(res.Subkeys); !slices.Equal(got, []string{".txt"}) || res.Begin.Hive != "HKCR" {
		t.Errorf("HKCR: %v %+v", got, res.Begin)
	}
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Hive: "HKCC"}, Options{})
	if len(res.Values) != 1 || res.Key == nil || !strings.HasSuffix(res.Key.Kernel, `ControlSet001\Hardware Profiles\Current`) {
		t.Errorf("HKCC through its alias: %+v %+v", res.Key, res.Values)
	}
	// A search from HKCR keeps paths in HKCR's own terms.
	s, _ := run(t, f, agentproto.RegistryInput{Op: "search", Hive: "HKCR", Path: []string{}, Term: "txt"}, Options{})
	if len(s.Matches) == 0 || s.Matches[0].Path[0] != ".txt" {
		t.Errorf("%+v", s.Matches)
	}
}

func TestAccessDeniedAndNotFound(t *testing.T) {
	f := newFake()
	f.add(registryrules.HKLM, "SOFTWARE", "Locked").denied = true
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Locked"}}, Options{})
	if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeDenied {
		t.Errorf("%+v", res.Errors)
	}
	res, _ = run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Gone"}}, Options{})
	if len(res.Errors) != 1 || res.Errors[0].Code != agentproto.ErrCodeNotFound {
		t.Errorf("%+v", res.Errors)
	}
	sub, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE"}}, Options{})
	if len(sub.Subkeys) != 1 || sub.Subkeys[0].State != agentproto.StateDenied {
		t.Errorf("a denied subkey: %+v", sub.Subkeys)
	}
}

func TestTimeBudgetListsNamesWithUnknownCounts(t *testing.T) {
	f := newFake()
	k := f.add(registryrules.HKLM, "SOFTWARE", "Slow")
	for i := range 5 {
		n := fmt.Sprintf("k%d", i)
		k.subs[n] = &fnode{name: n, kernel: k.kernel + `\` + n, subs: map[string]*fnode{}, vals: map[string]fval{}}
	}
	now := time.Unix(0, 0)
	res, _ := run(t, f, agentproto.RegistryInput{Op: "list", Path: []string{"SOFTWARE", "Slow"}}, Options{Now: func() time.Time { now = now.Add(20 * time.Second); return now }})
	if len(res.Subkeys) != 5 {
		t.Fatalf("%d", len(res.Subkeys))
	}
	unknown := 0
	for _, s := range res.Subkeys {
		if s.Subkeys == -1 {
			unknown++
		}
	}
	if unknown == 0 {
		t.Error("no counts were given up when the time ran out")
	}
}

func TestRunFiles(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "input.json"), filepath.Join(dir, "result.jsonl")
	f := newFake()
	f.add(registryrules.HKLM, "SOFTWARE", "V")
	if err := os.WriteFile(in, []byte(`{"v":1,"op":"list","hive":"HKLM","view":"64","path":["SOFTWARE"],"rules":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunFiles(in, out, "9.9", f); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	res, err := agentproto.ParseRegistryLines(agentproto.SplitResultLines(b))
	if err != nil || res.End == nil || res.Begin.AgentVersion != "9.9" || names(res.Subkeys)[0] != "V" {
		t.Errorf("%+v %v", res, err)
	}
	// An input that does not decode is refused, and writes no result.
	_ = os.Remove(out)
	if err := os.WriteFile(in, []byte(`{"v":1,"op":"set","hive":"HKLM","view":"64","path":[],"rules":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunFiles(in, out, "9.9", f); !errors.Is(err, agentproto.ErrRegistryInput) {
		t.Errorf("%v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a result was written for a bad input")
	}
	t.Setenv("EASYRMM_JOB_INPUT", "")
	if err := Main("x"); err == nil {
		t.Error("Main without its files")
	}
}
