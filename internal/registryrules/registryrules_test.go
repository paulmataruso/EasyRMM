package registryrules

import (
	"errors"
	"strings"
	"testing"
)

// spellings writes one HKLM path in every spelling the console's address
// bar and the kernel accept, in several cases.
func spellings(path string) []string {
	var out []string
	for _, root := range []string{`HKLM\`, `HKEY_LOCAL_MACHINE\`, `\Registry\Machine\`, `Registry::HKEY_LOCAL_MACHINE\`,
		`Computer\HKEY_LOCAL_MACHINE\`, `HKLM:\`, `Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\`, `hklm\`, `\REGISTRY\MACHINE\`} {
		out = append(out, root+path, root+strings.ToUpper(path), root+strings.ToLower(path))
	}
	return out
}

func TestRefusedPathsInEverySpelling(t *testing.T) {
	refused := []string{
		`SAM`, `SAM\SAM\Domains`, `SECURITY`, `SECURITY\SAM`, `SECURITY\Policy\Secrets`,
		`SOFTWARE\EasyRMM`, `SOFTWARE\EasyRMM\Agent`, `SOFTWARE\EasyPatch`, `SOFTWARE\Open Source`, `SOFTWARE\Open Source\MeshAgent`,
		`SOFTWARE\WOW6432Node\EasyRMM`, `SOFTWARE\WOW6432Node\Open Source\Mesh Agent`, `SOFTWARE\WowAA32Node\EasyPatch`,
		`SYSTEM\CurrentControlSet\Services\EasyRMMAgent`, `SYSTEM\ControlSet001\Services\EasyRMMMeshAgent\Parameters`,
		`SYSTEM\ControlSet002\Services\EasyPatchAgent`,
	}
	for _, p := range refused {
		for _, text := range spellings(p) {
			h, names, err := ParseText(text)
			if err != nil {
				t.Fatalf("%q: %v", text, err)
			}
			for _, v := range []View{View64, View32} {
				if Check(h, v, names) == nil {
					t.Errorf("%q in view %s is allowed", text, v)
				}
			}
		}
	}
}

func TestAllowedPaths(t *testing.T) {
	for _, p := range []string{`SOFTWARE\Microsoft`, `SOFTWARE\EasyRMMother`, `SYSTEM\CurrentControlSet\Services\Spooler`,
		`SYSTEM\CurrentControlSet\Services`, `SOFTWARE`, `SYSTEM\Setup`, `SAMPLE`, `SOFTWARE\Wow6432Node\Vendor`} {
		h, names, err := ParseText(`HKLM\` + p)
		if err != nil {
			t.Fatal(err)
		}
		if r := Check(h, View64, names); r != nil {
			t.Errorf("%s refused: %v", p, r)
		}
	}
}

func TestSimpleCaseFoldingSpellings(t *testing.T) {
	// The long s, the dotless i and the Kelvin sign are equal to S, I and K.
	for _, names := range [][]string{
		{"ſAM"}, {"SECURıTY"}, {"SOFTWARE", "EaſyRMM"}, {"SOFTWARE", "Open ſource"}, {"SOFTWARE", "EaſyPatch"},
		{"SYSTEM", "CurrentControlSet", "Services", "EaſyRMMAgent"}, {"SYſTEM", "ControlSet001", "Services", "EasyPatchAgent"},
		{"SOFTWARE", "Key"}, // K: only to prove Fold handles it below
	} {
		got := Check(HKLM, View64, names)
		want := names[len(names)-1] != "Key"
		if (got != nil) != want {
			t.Errorf("%q: refused=%v, want %v", names, got != nil, want)
		}
	}
	if !Equal("K", "k") || !Equal("ı", "I") || !Equal("ſ", "S") {
		t.Error("Fold does not match the Kelvin sign, the dotless i and the long s")
	}
}

func TestHKCRAndHKCCAreResolved(t *testing.T) {
	if h, n := Resolve(HKCR, []string{"CLSID"}); h != HKLM || strings.Join(n, `\`) != `SOFTWARE\Classes\CLSID` {
		t.Errorf("HKCR resolved to %s %v", h, n)
	}
	if h, n := Resolve(HKCC, nil); h != HKLM || strings.Join(n, `\`) != `SYSTEM\CurrentControlSet\Hardware Profiles\Current` {
		t.Errorf("HKCC resolved to %s %v", h, n)
	}
}

func TestParseTextKeepsSlashesAndRefusesBadNames(t *testing.T) {
	h, names, err := ParseText(`HKEY_LOCAL_MACHINE\SOFTWARE\a/b\c\`)
	if err != nil || h != HKLM || len(names) != 3 || names[1] != "a/b" {
		t.Fatalf("got %v %v %v", h, names, err)
	}
	if _, _, err := ParseText(`HKCU\Software`); !errors.Is(err, ErrCurrentUser) {
		t.Errorf("HKCU: %v", err)
	}
	if h, names, err := ParseText(`\REGISTRY\USER\S-1-5-18\Software`); err != nil || h != HKU || names[0] != "S-1-5-18" {
		t.Errorf("kernel user path: %v %v %v", h, names, err)
	}
	for _, bad := range []string{`HKLM\a\\b`, `HKLM\a\.\b`, `HKLM\a\..\b`, `HKLM\` + strings.Repeat("x", 256), `HKLM\a` + "\x00", `nothive\a`,
		`HKLM\` + strings.Repeat("a\\", 513), `HKLM\` + strings.Repeat(strings.Repeat("x", 200)+`\`, 11)} {
		if _, _, err := ParseText(bad); err == nil {
			t.Errorf("%.30q was accepted", bad)
		}
	}
}

func TestPhysicalNamesFor32BitView(t *testing.T) {
	got := PhysicalNames(HKLM, View32, []string{"SOFTWARE", "Vendor"})
	if strings.Join(got, `\`) != `SOFTWARE\WOW6432Node\Vendor` {
		t.Errorf("got %v", got)
	}
	if got := PhysicalNames(HKLM, View32, []string{"SYSTEM", "X"}); len(got) != 2 {
		t.Errorf("shared key changed: %v", got)
	}
	if got := PhysicalNames(HKLM, View64, []string{"SOFTWARE", "Vendor"}); len(got) != 2 {
		t.Errorf("64-bit view changed: %v", got)
	}
}

func TestMasking(t *testing.T) {
	for _, n := range []string{"DefaultPassword", "dbpwd", "ClientSecret", "AuthToken", "Credential", "PreSharedKey_psk", "Cookie", "ApiKey",
		"api_key", "AccessKeyId", "PrivateKey", "private_key", "ConnectionString", "DigitalProductId", "DigitalProductId4", "PASSWORD"} {
		if !IsMasked(n, TypeSZ) || !IsMasked(n, TypeBinary) {
			t.Errorf("%s is not masked", n)
		}
		if IsMasked(n, TypeDWord) || IsMasked(n, TypeQWord) {
			t.Errorf("%s is masked as a number", n)
		}
	}
	for _, n := range []string{"DisplayName", "Version", "", "Path"} {
		if IsMasked(n, TypeSZ) {
			t.Errorf("%q is masked", n)
		}
	}
}

func TestValueNames(t *testing.T) {
	if ValidateValueName("") != nil || ValidateValueName("a/b") != nil {
		t.Error("default or slash refused")
	}
	if ValidateValueName("a\x00b") == nil || ValidateValueName(strings.Repeat("x", 16384)) == nil {
		t.Error("NUL or long name accepted")
	}
}

func TestFormat(t *testing.T) {
	if got := Format(HKU, []string{"S-1-5-18", "Software"}); got != `HKEY_USERS\S-1-5-18\Software` {
		t.Error(got)
	}
	if Format(HKLM, nil) != "HKEY_LOCAL_MACHINE" {
		t.Error("root")
	}
}

func TestValidAndErrorText(t *testing.T) {
	if !HKLM.Valid() || !HKU.Valid() || !HKCR.Valid() || !HKCC.Valid() || Hive("HKCU").Valid() {
		t.Error("hives")
	}
	if !View64.Valid() || !View32.Valid() || View("16").Valid() {
		t.Error("views")
	}
	r := Check(HKLM, View64, []string{"SAM"})
	if r == nil || !strings.HasPrefix(r.Error(), "refused by EasyRMM: ") || r.Path != `HKLM\SAM` {
		t.Errorf("%+v", r)
	}
}

func TestCheckWithRefusesLoadedCopies(t *testing.T) {
	extra := []Prefix{{Hive: HKLM, Names: []string{"Copy"}}, {Hive: HKU, Names: []string{"Temp", "x"}}}
	if CheckWith(HKLM, View64, []string{"copy", "a"}, extra) == nil || CheckWith(HKU, View64, []string{"TEMP", "x", "y"}, extra) == nil {
		t.Error("a copy is allowed")
	}
	if CheckWith(HKLM, View64, []string{"Other"}, extra) != nil || CheckWith(HKU, View64, []string{"Temp"}, extra) != nil {
		t.Error("another key is refused")
	}
	if r := CheckWith(HKLM, View64, []string{"SAM"}, extra); r == nil || r.Rule == "a loaded copy of SAM or SECURITY" {
		t.Errorf("the static rule comes first: %+v", r)
	}
}

func TestControlSetNamesAndWowNodes(t *testing.T) {
	for _, n := range []string{"ControlSet001", "ControlSet12", "CurrentControlSet", "currentcontrolset"} {
		if !isControlSet(n) {
			t.Errorf("%s", n)
		}
	}
	for _, n := range []string{"ControlSet", "ControlSetX", "Control", ""} {
		if isControlSet(n) {
			t.Errorf("%q", n)
		}
	}
	if got := PhysicalNames(HKLM, View32, []string{"SOFTWARE", "WOW6432Node", "A"}); strings.Join(got, `\`) != `SOFTWARE\WOW6432Node\A` {
		t.Errorf("%v", got)
	}
	if got := PhysicalNames(HKLM, View32, []string{"SOFTWARE"}); strings.Join(got, `\`) != `SOFTWARE\WOW6432Node` {
		t.Errorf("%v", got)
	}
	if got := PhysicalNames(HKCR, View32, []string{"CLSID"}); len(got) != 4 || got[1] != "WOW6432Node" {
		t.Errorf("HKCR in the 32-bit view: %v", got)
	}
	if _, _, err := ParseText(`\REGISTRY\NOPE\x`); err == nil {
		t.Error("a bad kernel root")
	}
	if _, _, err := ParseText(`HKLM\a` + string(rune(7))); err == nil {
		t.Error("a control character")
	}
	if err := ValidateName("bad\\name"); err == nil {
		t.Error("a backslash")
	}
	if err := ValidateName("\xff"); err == nil {
		t.Error("invalid text")
	}
}
