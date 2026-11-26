package agentproto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryInputIsCheckedStrictly(t *testing.T) {
	good := `{"v":1,"op":"list","hive":"HKLM","view":"64","path":["SOFTWARE"],"rules":1}`
	if _, err := DecodeRegistryInput([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"an unknown field":      `{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1,"write":true}`,
		"two documents":         good + good,
		"a bad version":         `{"v":2,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1}`,
		"write operation":       `{"v":1,"op":"set","hive":"HKLM","view":"64","path":[],"rules":1}`,
		"a bad view":            `{"v":1,"op":"list","hive":"HKLM","view":"16","path":[],"rules":1}`,
		"a value read, no name": `{"v":1,"op":"value","hive":"HKLM","view":"64","path":[],"rules":1}`,
		"a name on a list":      `{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"valueName":"x","rules":1}`,
		"a term on a list":      `{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"term":"x","rules":1}`,
		"a search no term":      `{"v":1,"op":"search","hive":"HKLM","view":"64","path":[],"rules":1}`,
		"a deep search":         `{"v":1,"op":"search","hive":"HKLM","view":"64","path":[],"term":"x","depth":33,"rules":1}`,
		"a long term":           `{"v":1,"op":"search","hive":"HKLM","view":"64","path":[],"term":"` + strings.Repeat("x", 257) + `","rules":1}`,
		"a big page":            `{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"maxSubkeys":1001,"rules":1}`,
		"an empty name":         `{"v":1,"op":"list","hive":"HKLM","view":"64","path":["a",""],"rules":1}`,
		"HKCU":                  `{"v":1,"op":"list","hive":"HKCU","view":"64","path":[],"rules":1}`,
	} {
		if _, err := DecodeRegistryInput([]byte(in)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	in, _ := DecodeRegistryInput([]byte(`{"v":1,"op":"list","hive":"HKLM","view":"32","path":["SOFTWARE","WOW6432Node","EasyRMM"],"rules":1}`))
	if in.Refused() == nil {
		t.Error("a refused path is not marked refused")
	}
}

func TestValidRegistryText(t *testing.T) {
	for _, ok := range []string{`{"a":"b"}`, `{"a":"\\u0000"}`, `{"a":"\ud83d\ude00"}`, `{"a":"\u00e9"}`, `{"a":"\n\\"}`} {
		if !ValidRegistryText([]byte(ok)) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{`{"a":"\u0000"}`, `{"a":"\u0000b"}`, `{"a":"\ud800"}`, `{"a":"\udc00x"}`, `{"a":"\ud800\u0041"}`, "{\"a\":\"\x00\"}", "{\"a\":\"\xff\"}", `{"a":"\u00`} {
		if ValidRegistryText([]byte(bad)) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func u16(s string, extra ...uint16) []byte {
	var b []byte
	for _, c := range append(utf16Encode(s), extra...) {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func utf16Encode(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3ff)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

func TestEncodeRegValueTypes(t *testing.T) {
	sz := EncodeRegValue("Path", 1, u16("C:\\Windows", 0), false, false, 4096)
	if sz.Text == nil || *sz.Text != `C:\Windows` || sz.Odd || sz.Size != 22 {
		t.Errorf("REG_SZ: %+v", sz)
	}
	// Never expanded.
	ex := EncodeRegValue("P", 2, u16("%SystemRoot%", 0), false, false, 4096)
	if ex.Text == nil || *ex.Text != "%SystemRoot%" {
		t.Errorf("REG_EXPAND_SZ: %+v", ex)
	}
	multi := EncodeRegValue("M", 7, u16("a\x00bc\x00", 0), false, false, 4096)
	if len(multi.Items) != 2 || multi.Items[1] != "bc" || multi.Odd {
		t.Errorf("REG_MULTI_SZ: %+v", multi)
	}
	empty := EncodeRegValue("M", 7, u16("", 0, 0), false, false, 4096)
	if empty.Items == nil || len(empty.Items) != 0 || empty.Odd {
		t.Errorf("an empty REG_MULTI_SZ: %+v", empty)
	}
	dw := EncodeRegValue("D", 4, []byte{0x0a, 0, 0, 0}, false, false, 4096)
	if dw.Number == nil || *dw.Number != 10 {
		t.Errorf("REG_DWORD: %+v", dw)
	}
	qw := EncodeRegValue("Q", 11, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, false, false, 4096)
	if qw.Decimal != "9223372036854775807" {
		t.Errorf("REG_QWORD keeps all its digits: %+v", qw)
	}
	bin := EncodeRegValue("B", 3, []byte{1, 2, 3}, false, false, 4096)
	if bin.Base64 != "AQID" {
		t.Errorf("REG_BINARY: %+v", bin)
	}
	// Other types are bytes with their number.
	for _, typ := range []uint32{0, 5, 6, 8, 9, 10, 99} {
		v := EncodeRegValue("X", typ, []byte{1}, false, false, 4096)
		if v.Base64 != "AQ==" || v.Type != typ {
			t.Errorf("type %d: %+v", typ, v)
		}
	}
	// The default value has the empty name.
	if d := EncodeRegValue("", 1, u16("x", 0), false, false, 4096); d.Name != "" || d.Text == nil {
		t.Errorf("default: %+v", d)
	}
}

func TestEncodeRegValueOddDataIsRawAndReadOnly(t *testing.T) {
	cases := map[string]RegValue{
		"no terminator":    EncodeRegValue("a", 1, u16("abc"), false, false, 4096),
		"odd length":       EncodeRegValue("a", 1, append(u16("abc", 0), 7), false, false, 4096),
		"a NUL inside":     EncodeRegValue("a", 1, u16("a\x00b", 0), false, false, 4096),
		"a lone surrogate": EncodeRegValue("a", 1, u16("", 0xD800, 0), false, false, 4096),
		"short dword":      EncodeRegValue("a", 4, []byte{1, 2}, false, false, 4096),
		"short qword":      EncodeRegValue("a", 11, []byte{1, 2, 3, 4}, false, false, 4096),
		"empty item":       EncodeRegValue("a", 7, u16("a\x00\x00b", 0, 0), false, false, 4096),
		"multi no end":     EncodeRegValue("a", 7, u16("a\x00b"), false, false, 4096),
		"empty sz":         EncodeRegValue("a", 1, nil, false, false, 4096),
	}
	for name, v := range cases {
		if !v.Odd || (v.Raw == "" && name != "empty sz") || v.Text != nil || v.Number != nil || v.Items != nil {
			t.Errorf("%s: %+v", name, v)
		}
		b, _ := json.Marshal(v)
		if !ValidRegistryText(b) {
			t.Errorf("%s: its line cannot go into jsonb: %s", name, b)
		}
		if raw, ok := RegValueBytes(v); !ok || len(raw) == 0 && name != "empty sz" {
			t.Errorf("%s: the bytes are lost", name)
		}
	}
	if d := cases["a NUL inside"].Display; d != `a\0b\0` {
		t.Errorf("display %q", d)
	}
	if d := cases["a lone surrogate"].Display; d != `\uD800\0` {
		t.Errorf("display %q", d)
	}
	// A name with a NUL or bad UTF-8 is sent as raw bytes with a display name.
	n := EncodeRegValue("a\x00b\xff", 1, u16("x", 0), false, false, 4096)
	if !n.Odd || n.RawName == "" || strings.ContainsRune(n.Name, 0) {
		t.Errorf("odd name: %+v", n)
	}
	if raw, _ := base64.StdEncoding.DecodeString(n.RawName); string(raw) != "a\x00b\xff" {
		t.Errorf("raw name %q", raw)
	}
	b, _ := json.Marshal(n)
	if !ValidRegistryText(b) {
		t.Errorf("%s", b)
	}
}

func TestEncodeRegValueMaskingAndLimits(t *testing.T) {
	m := EncodeRegValue("DbPassword", 1, u16("hunter2", 0), true, true, 4096)
	if !m.Masked || m.Text != nil || m.Raw != "" || m.Base64 != "" || m.Size != 16 {
		t.Errorf("masked: %+v", m)
	}
	big := make([]byte, 5000)
	p := EncodeRegValue("Blob", 3, big, false, false, 4096)
	if !p.NoData || p.Size != 5000 || p.Base64 != "" {
		t.Errorf("larger than a page shows: %+v", p)
	}
	v := EncodeRegValue("Blob", 3, big, false, true, 4096)
	if !v.Cut || v.Size != 5000 || v.Raw == "" {
		t.Errorf("a read cuts at its limit: %+v", v)
	}
}

func TestParseRegistryLines(t *testing.T) {
	lines := [][]byte{
		[]byte(`{"t":"begin","v":1,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1,"agentVersion":"1"}`),
		[]byte(`{"t":"key","kernel":"\\REGISTRY\\MACHINE","subkeys":2,"values":0,"readAt":"2026-11-26T10:00:00Z"}`),
		[]byte(`{"t":"subkey","name":"SOFTWARE","subkeys":3,"values":0}`),
		[]byte(`{"t":"value","name":"","type":1,"size":4,"text":"a"}`),
		[]byte(`{"t":"end","complete":true,"elapsedMs":3}`),
	}
	r, err := ParseRegistryLines(lines)
	if err != nil || r.End == nil || len(r.Subkeys) != 1 || len(r.Values) != 1 || r.Key == nil || r.Lines() != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	// Partial: no end.
	if r, err := ParseRegistryLines(lines[:3]); err != nil || r.End != nil {
		t.Errorf("a result without its end: %+v %v", r, err)
	}
	for name, bad := range map[string][][]byte{
		"empty":            nil,
		"no begin":         lines[1:],
		"begin twice":      append(append([][]byte{}, lines[0]), lines...),
		"an unknown field": {lines[0], []byte(`{"t":"subkey","name":"a","subkeys":0,"values":0,"x":1}`)},
		"an unknown line":  {lines[0], []byte(`{"t":"what"}`)},
		"after the end":    {lines[0], lines[4], lines[2]},
		"a NUL":            {lines[0], []byte(`{"t":"value","name":"\u0000","type":1,"size":0}`)},
		"a lone surrogate": {lines[0], []byte(`{"t":"value","name":"\ud800","type":1,"size":0}`)},
		"not json":         {lines[0], []byte(`{`)},
	} {
		if _, err := ParseRegistryLines(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSplitResultLinesDropsACutLastLine(t *testing.T) {
	got := SplitResultLines([]byte("{\"a\":1}\r\n\n{\"b\":2}\n{\"c\":"))
	if len(got) != 2 || string(got[1]) != `{"b":2}` {
		t.Errorf("%q", got)
	}
	if len(SplitResultLines([]byte(`{"a":1}`))) != 0 {
		t.Error("a line without its end is cut")
	}
}

func TestRegValueBytesRebuildsTypedFields(t *testing.T) {
	for _, v := range []RegValue{
		EncodeRegValue("a", 1, u16("hello", 0), false, false, 4096),
		EncodeRegValue("a", 7, u16("a\x00b", 0, 0), false, false, 4096),
		EncodeRegValue("a", 4, []byte{1, 2, 3, 4}, false, false, 4096),
		EncodeRegValue("a", 11, []byte{1, 2, 3, 4, 5, 6, 7, 8}, false, false, 4096),
		EncodeRegValue("a", 3, []byte{9, 9}, false, false, 4096),
	} {
		b, ok := RegValueBytes(v)
		if !ok || len(b) != v.Size {
			t.Errorf("%+v rebuilt %v %v", v, b, ok)
		}
	}
	if _, ok := RegValueBytes(EncodeRegValue("p", 1, nil, true, false, 4096)); ok {
		t.Error("masked data has no bytes")
	}
}

func TestSafeTextAndRawText(t *testing.T) {
	if SafeText("plain") != "plain" || RawText("plain") != "" {
		t.Error("plain text is unchanged")
	}
	if s := SafeText("a\x00b\xff"); s != `a\0b\xFF` {
		t.Errorf("%q", s)
	}
	if r, _ := base64.StdEncoding.DecodeString(RawText("a\x00b")); string(r) != "a\x00b" {
		t.Errorf("%q", r)
	}
}

func TestParseRegistryLinesEveryLineType(t *testing.T) {
	lines := [][]byte{
		[]byte(`{"t":"begin","v":1,"op":"export","hive":"HKLM","view":"32","path":["SOFTWARE"],"rules":1,"agentVersion":"1","cursor":{"subkey":"a"}}`),
		[]byte(`{"t":"match","kind":"valueName","path":["SOFTWARE"],"name":"x","type":1}`),
		[]byte(`{"t":"xkey","path":["SOFTWARE"],"state":"link","target":"t","rule":"r","lastWrite":"x","values":[{"t":"value","name":"a","type":4,"size":4,"number":1}],"left":["x"]}`),
		[]byte(`{"t":"refused","path":["SAM"],"rule":"r","kernel":"\\REGISTRY\\MACHINE\\SAM"}`),
		[]byte(`{"t":"error","code":"refused","message":"m"}`),
		[]byte(`{"t":"end","complete":false,"stoppedBy":"size","firstUnvisited":["a"],"visited":3,"matches":1,"moreSubkeys":true,"moreValues":true,"nextSubkey":"a","nextValue":"b","elapsedMs":4}`),
	}
	r, err := ParseRegistryLines(lines)
	if err != nil || len(r.Matches) != 1 || len(r.XKeys) != 1 || len(r.Refused) != 1 || len(r.Errors) != 1 || r.End == nil || r.End.StoppedBy != "size" {
		t.Fatalf("%+v %v", r, err)
	}
	two := [][]byte{lines[0], []byte(`{"t":"key","kernel":"k","subkeys":0,"values":0,"readAt":"x"}`), []byte(`{"t":"key","kernel":"k","subkeys":0,"values":0,"readAt":"x"}`)}
	if _, err := ParseRegistryLines(two); err == nil {
		t.Error("two key lines")
	}
	if _, err := ParseRegistryLines([][]byte{lines[0], []byte(`{"t":"end"} {"t":"end"}`)}); err == nil {
		t.Error("two documents on a line")
	}
}

func TestRegistryInputCursorAndLimits(t *testing.T) {
	good := []string{
		`{"v":1,"op":"list","hive":"HKU","view":"32","path":[],"cursor":{"subkey":"a","value":"b"},"maxSubkeys":10,"maxValues":10,"rules":1}`,
		`{"v":1,"op":"search","hive":"HKCR","view":"64","path":[],"term":"x","depth":32,"maxMatches":500,"rules":1}`,
		`{"v":1,"op":"value","hive":"HKCC","view":"64","path":[],"valueName":"","rules":1}`,
		`{"v":1,"op":"export","hive":"HKLM","view":"64","path":["a"],"rules":1}`,
	}
	for _, g := range good {
		if _, err := DecodeRegistryInput([]byte(g)); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	for _, bad := range []string{
		`{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"cursor":{"subkey":"a\u0000"},"rules":1}`,
		`{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"maxValues":501,"rules":1}`,
		`{"v":1,"op":"search","hive":"HKLM","view":"64","path":[],"term":"x","maxMatches":501,"rules":1}`,
		`{"v":1,"op":"export","hive":"HKLM","view":"64","path":[],"cursor":{},"rules":1}`,
		`{"v":1,"op":"value","hive":"HKLM","view":"64","path":[],"valueName":"a\u0000","rules":1}`,
		`{"v":1,"op":"search","hive":"HKLM","view":"64","path":[],"term":"a\u0000","rules":1}`,
	} {
		if _, err := DecodeRegistryInput([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestOddSurrogatesAndTrailingBytesAreShownEscaped(t *testing.T) {
	v := EncodeRegValue("a", 1, append(u16("x", 0xDC00, 0xD83D, 0xDE00), 0x41, 0, 0), false, false, 4096)
	if !v.Odd || !strings.Contains(v.Display, `\uDC00`) || !strings.Contains(v.Display, "😀") || !strings.Contains(v.Display, `A\x00`) {
		t.Errorf("%+v", v)
	}
	if v := EncodeRegValue("a", 7, u16("a", 0xD800, 0, 0), false, false, 4096); !v.Odd {
		t.Errorf("a lone high surrogate in a list: %+v", v)
	}
	if v := EncodeRegValue("a", 7, u16("a", 0xD800, 0xDC00, 0, 0), false, false, 4096); v.Odd || len(v.Items) != 1 {
		t.Errorf("a pair is a character: %+v", v)
	}
	if v := EncodeRegValue("a", 7, []byte{0, 0, 0}, false, false, 4096); !v.Odd {
		t.Error("odd length multi")
	}
	if v := EncodeRegValue("a", 7, nil, false, false, 4096); v.Odd || v.Items == nil {
		t.Errorf("empty multi %+v", v)
	}
	if v := EncodeRegValue("a", 7, []byte{0, 0}, false, false, 4096); v.Odd || len(v.Items) != 0 {
		t.Errorf("one NUL multi %+v", v)
	}
	if v := EncodeRegValue("a", 1, u16("é", 0), false, true, 2); !v.Cut || v.Raw == "" || v.Text != nil {
		t.Errorf("cut %+v", v)
	}
}
