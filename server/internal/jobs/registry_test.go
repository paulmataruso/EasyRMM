package jobs

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func u32(n uint32) *uint32 { return &n }
func sp(s string) *string  { return &s }

func TestKindsTable(t *testing.T) {
	q, c := Kinds[KindRegistryQuery], Kinds[KindRegistryChange]
	if q.Executor != ExecBuiltin || !q.AskerOnly || !q.Quick || q.Listed || q.keepResult(nil) != 3600e9 || q.WaitDefault.Minutes() != 2 {
		t.Errorf("registry_query %+v", q)
	}
	if c.AskerOnly || c.RecordRead != "registry.change_view" || !c.ChangeLock || c.WaitDefault.Minutes() != 15 {
		t.Errorf("registry_change %+v", c)
	}
	if got := strings.Join(q.needs(), ","); got != "job.structured,builtin.registry.v1" {
		t.Errorf("needs %s", got)
	}
	if !isStructured(KindRegistryChange) || isStructured(KindScript) || isStructured("nothing") {
		t.Error("isStructured")
	}
	if len(builtinKinds()) != 2 || builtinKinds()[0].Name != KindRegistryChange {
		t.Errorf("%+v", builtinKinds())
	}
	s := &Service{outputRetention: 1e9, retention: 2e9}
	if Kinds[KindScript].keepResult(s) != 1e9 || Kinds[KindScript].keepJob(s) != 2e9 || q.keepJob(s) != 7*24*3600e9 {
		t.Error("retention")
	}
}

func TestNormalizeRegistryInput(t *testing.T) {
	in, err := normalizeRegistryInput(RegistryQueryInput{Op: "list", Text: `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\a/b`})
	if err != nil || in.Hive != "HKLM" || len(in.Path) != 2 || in.Path[1] != "a/b" || in.View != "64" || in.MaxSubkeys != 1000 || in.MaxValues != 500 || in.Rules != 1 {
		t.Errorf("%+v %v", in, err)
	}
	in, err = normalizeRegistryInput(RegistryQueryInput{Op: "search", Hive: "HKU", View: "32", Term: "x"})
	if err != nil || in.Depth != agentproto.RegDefaultDepth || in.MaxMatches != agentproto.RegMaxMatches || in.Path == nil {
		t.Errorf("%+v %v", in, err)
	}
	for _, bad := range []RegistryQueryInput{{Op: "list", Text: `HKCU\Software`}, {Op: "list", Text: `nonsense`}, {Op: "set", Hive: "HKLM"}} {
		if _, err := normalizeRegistryInput(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	d := registryAudit(agentproto.RegistryInput{Op: "search", Hive: "HKLM", View: "64", Path: []string{"A"}, Term: "secret", Depth: 3, MaxMatches: 9})
	if d["termLength"] != 6 || strings.Contains(strings.Join(mapStrings(d), " "), "secret") {
		t.Errorf("%v", d)
	}
	long := registryAudit(agentproto.RegistryInput{Op: "list", Path: []string{strings.Repeat("x", 3000)}})
	if len([]rune(long["path"].(string))) != 2048 {
		t.Error("the path is cut at 2,048 characters")
	}
}

func mapStrings(m map[string]any) []string {
	var out []string
	for _, v := range m {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestStateAndReasonText(t *testing.T) {
	for code, want := range map[string]string{agentproto.ErrCodeDenied: "unavailable", agentproto.ErrCodeNotFound: "not_found", agentproto.ErrCodeRefused: "refused", agentproto.ErrCodeFailed: "unknown"} {
		if s, r := stateOfErrors([]agentproto.RegError{{Code: code, Message: "m"}}); s != want || r != "m" {
			t.Errorf("%s: %s %s", code, s, r)
		}
	}
	if s, _ := stateOfErrors(nil); s != "" {
		t.Error("no error")
	}
	for status, want := range map[string]string{StatusSucceeded: "no result", StatusTimedOut: "timed out", StatusCanceled: "canceled", StatusExpired: "did not answer", StatusFailed: "did not finish"} {
		if got := emptyReason(status, ""); !strings.Contains(got, want) {
			t.Errorf("%s: %q", status, got)
		}
	}
	if emptyReason(StatusExpired, "held") != "held" || emptyReason(StatusFailed, "why") != "why" {
		t.Error("the run's own error is kept")
	}
}

func parse(t *testing.T, lines ...string) *agentproto.RegistryResult {
	t.Helper()
	var b [][]byte
	for _, l := range lines {
		b = append(b, []byte(l))
	}
	r, err := agentproto.ParseRegistryLines(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCheckRegistryResultAgainstItsInput(t *testing.T) {
	begin := func(op string, path string) string {
		return `{"t":"begin","v":1,"op":"` + op + `","hive":"HKLM","view":"64","path":[` + path + `],"rules":1,"agentVersion":"1"}`
	}
	in := func(op string) agentproto.RegistryInput {
		i := agentproto.RegistryInput{V: 1, Op: op, Hive: "HKLM", View: "64", Path: []string{"A"}, Rules: 1, MaxSubkeys: 1, MaxValues: 1, MaxMatches: 1}
		if op == "value" {
			i.ValueName = sp("x")
		}
		return i
	}
	sub := `{"t":"subkey","name":"s","subkeys":0,"values":0}`
	val := `{"t":"value","name":"x","type":4,"size":4,"number":1}`
	match := `{"t":"match","kind":"key","path":["A","b"]}`
	xkey := `{"t":"xkey","path":["A","b"]}`
	ok := map[string]*agentproto.RegistryResult{
		"list":   parse(t, begin("list", `"A"`), sub, val),
		"value":  parse(t, begin("value", `"A"`), val),
		"search": parse(t, begin("search", `"A"`), match),
		"export": parse(t, begin("export", `"A"`), xkey),
	}
	for op, r := range ok {
		if err := checkRegistryResult(in(op), r); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	bad := map[string]struct {
		op string
		r  *agentproto.RegistryResult
	}{
		"another op":        {"list", ok["value"]},
		"another path":      {"list", parse(t, begin("list", `"B"`))},
		"too many subkeys":  {"list", parse(t, begin("list", `"A"`), sub, sub)},
		"too many values":   {"list", parse(t, begin("list", `"A"`), val, val)},
		"a match in a list": {"list", parse(t, begin("list", `"A"`), match)},
		"two values":        {"value", parse(t, begin("value", `"A"`), val, val)},
		"another value":     {"value", parse(t, begin("value", `"A"`), `{"t":"value","name":"y","type":4,"size":4,"number":1}`)},
		"a subkey in value": {"value", parse(t, begin("value", `"A"`), sub)},
		"too many matches":  {"search", parse(t, begin("search", `"A"`), match, match)},
		"outside the key":   {"search", parse(t, begin("search", `"A"`), `{"t":"match","kind":"key","path":["Z"]}`)},
		"a bad kind":        {"search", parse(t, begin("search", `"A"`), `{"t":"match","kind":"what","path":["A"]}`)},
		"a value in search": {"search", parse(t, begin("search", `"A"`), val)},
		"a key outside":     {"export", parse(t, begin("export", `"A"`), `{"t":"xkey","path":["Z"]}`)},
		"a value in export": {"export", parse(t, begin("export", `"A"`), val)},
		"a bad version":     {"list", parse(t, strings.Replace(begin("list", `"A"`), `"v":1`, `"v":9`, 1))},
	}
	for name, c := range bad {
		if err := checkRegistryResult(in(c.op), c.r); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRefusedInResultAndMasking(t *testing.T) {
	r := parse(t,
		`{"t":"begin","v":1,"op":"search","hive":"HKLM","view":"64","path":[],"rules":1,"agentVersion":"1"}`,
		`{"t":"match","kind":"key","path":["SOFTWARE","EasyRMM","x"]}`,
		`{"t":"subkey","name":"SAM","subkeys":-1,"values":-1,"state":"refused"}`,
		`{"t":"subkey","name":"SECURITY","subkeys":0,"values":0}`,
		`{"t":"xkey","path":["SOFTWARE","EasyPatch"]}`,
		`{"t":"xkey","path":["SAM"],"state":"refused"}`,
		`{"t":"key","kernel":"\\REGISTRY\\MACHINE\\SECURITY\\Policy","subkeys":0,"values":0,"readAt":"x"}`,
	)
	got := refusedInResult(r)
	if len(got) != 4 {
		t.Fatalf("%d refused paths: %+v", len(got), got)
	}
	m := parse(t,
		`{"t":"begin","v":1,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1,"agentVersion":"1"}`,
		`{"t":"value","name":"DbPassword","type":1,"size":4,"text":"x","raw":"AA=="}`,
		`{"t":"value","name":"Count","type":4,"size":4,"number":3}`,
		`{"t":"xkey","path":["A"],"values":[{"t":"value","name":"ApiToken","type":3,"size":2,"base64":"AA=="}]}`,
	)
	maskResult(m)
	if !m.Values[0].Masked || m.Values[0].Text != nil || m.Values[0].Raw != "" || m.Values[1].Masked || !m.XKeys[0].Values[0].Masked || m.XKeys[0].Values[0].Base64 != "" {
		t.Errorf("%+v %+v", m.Values, m.XKeys)
	}
	for i := range resultOrder(m) {
		if _, err := encodeResultLine(m, i); err != nil {
			t.Error(err)
		}
	}
	if _, err := encodeResultLine(m, 99); err == nil {
		t.Error("a line that is not there")
	}
}

func u16le(s string) string {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestBuildRegWritesEveryTypeAndSaysWhatItLeftOut(t *testing.T) {
	long := make([]byte, 40)
	for i := range long {
		long[i] = byte(i)
	}
	res := &agentproto.RegistryResult{Begin: agentproto.RegBegin{Hive: "HKLM", View: "32", Path: []string{"SOFTWARE", "V"}}}
	res.XKeys = []agentproto.RegXKey{{Path: []string{"SOFTWARE", "V"}, Left: []string{"one value was too large"}, Values: []agentproto.RegValue{
		{Name: "", Type: 1, Size: 4, Text: sp("d"), Raw: u16le("d\x00")},
		{Name: "Exp", Type: 2, Size: 4, Text: sp("%X%"), Raw: u16le("%X%\x00")},
		{Name: "Multi", Type: 7, Size: 4, Items: []string{"a", "b"}},
		{Name: "Qw", Type: 11, Size: 8, Decimal: "1"},
		{Name: "Long", Type: 3, Size: 40, Base64: base64.StdEncoding.EncodeToString(long)},
		{Name: "Link", Type: 6, Size: 2, Base64: "AA=="},
		{Name: "Odd", Type: 1, Size: 3, Odd: true, Raw: "AAAA", Display: "x"},
		{Name: "Bad\x01Name", Type: 4, Size: 4, Number: u32(1)},
		{Name: "NoData", Type: 3, Size: 9999, NoData: true},
		{Name: "Cut", Type: 3, Size: 9999, Cut: true, Raw: "AA=="},
		{Name: "Raw", RawName: "AA==", Odd: true, Type: 1},
		{Name: "NL", Type: 1, Size: 4, Text: sp("a\nb"), Raw: u16le("a\nb\x00")},
		{Name: "Secret", Type: 1, Size: 4, Masked: true},
	}}, {Path: []string{"SOFTWARE", "V", "L"}, State: agentproto.StateLink, Target: `\Registry\X`}, {Path: []string{"SOFTWARE", "V", "D"}, State: agentproto.StateDenied}}
	var u []uint16
	b := BuildReg(res)
	for i := 2; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	text := string(utf16.Decode(u))
	for _, want := range []string{"[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\V]", `@="d"`, `"Exp"=hex(2):`, `"Multi"=hex(7):`, `"Qw"=hex(b):01,00,00,00,00,00,00,00`,
		"\\\r\n  ", "; value left out, a link target: Link", "; value left out, its name is not valid text", "; value left out, its name holds a control character",
		"its data is not in the export: NoData", "its data is not in the export: Cut", "; value left out, masked: Secret", "; one value was too large",
		"; key is a link, not followed", "; key left out, access denied"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, `"NL"=hex(1):`) {
		t.Error("text with a line break is written as hex")
	}
	if js, err := BuildJSON("PC", "2026-11-26T10:00:00Z", &agentproto.RegistryResult{}); err != nil || !strings.Contains(string(js), `"keys": []`) {
		t.Errorf("%s %v", js, err)
	}
	if n := exportName("PC 1/x", &agentproto.RegistryResult{Begin: agentproto.RegBegin{Hive: "HKLM", Path: []string{"A B"}}}, "reg"); n != "PC_1_x-HKLM-A_B.reg" {
		t.Error(n)
	}
	if n := exportName("PC", &agentproto.RegistryResult{Begin: agentproto.RegBegin{Hive: "HKU"}}, "json"); n != "PC-HKU-HKU.json" {
		t.Error(n)
	}
}
