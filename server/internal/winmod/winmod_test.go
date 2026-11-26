package winmod

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

type shape struct {
	Name  string `json:"name"`
	Items []int  `json:"items"`
}

func sample() Action {
	const script = "Write-Output 'x'\n"
	return Action{
		Module: modules.Defender, Name: "defender.sample", Label: "Sample", Version: 2,
		Script: script, ScriptSHA256: agentproto.HashScript(script), Permission: rbac.PermDefenderView, Timeout: 30,
		Keep: time.Hour, Decode: Typed[shape](), CountField: "items",
		Params: []Param{
			{Name: "user", Type: Name, Required: true, Max: 20},
			{Name: "folder", Type: Path},
			{Name: "id", Type: GUID},
			{Name: "sid", Type: SID},
			{Name: "n", Type: Int, Min: 1, Max: 10},
			{Name: "flag", Type: Bool},
			{Name: "mode", Type: Enum, Values: []string{"quick", "full"}},
			{Name: "password", Type: Text, Min: 8, Max: 64, Secret: true},
			{Name: "note", Type: Text, Sensitive: true},
		},
	}
}

func TestCatalogRefusesAForgedHash(t *testing.T) {
	a := sample()
	a.ScriptSHA256 = strings.Repeat("0", 64)
	if _, err := NewCatalog(a); !errors.Is(err, ErrScriptPin) {
		t.Fatalf("a forged hash was accepted: %v", err)
	}
	b := sample()
	b.Script += "# changed\n"
	if _, err := NewCatalog(b); !errors.Is(err, ErrScriptPin) {
		t.Fatalf("a changed script was accepted: %v", err)
	}
	c, err := NewCatalog(sample())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Lookup("defender.sample"); !ok || len(c.Actions()) != 1 {
		t.Error("the action is not in the catalog")
	}
	if _, err := NewCatalog(sample(), sample()); err == nil {
		t.Error("a duplicate name was accepted")
	}
}

func TestCatalogChecksActions(t *testing.T) {
	for name, mut := range map[string]func(*Action){
		"name not of the module":        func(a *Action) { a.Name = "dns.sample" },
		"destructive without a subject": func(a *Action) { a.Destructive = true },
		"sensitive without permission":  func(a *Action) { a.Sensitive = true },
		"secret that is not text":       func(a *Action) { a.Params = []Param{{Name: "p", Type: Name, Secret: true}} },
		"enum without values":           func(a *Action) { a.Params = []Param{{Name: "p", Type: Enum}} },
		"subject that is not a param":   func(a *Action) { a.Destructive, a.Subject = true, "nope" },
	} {
		a := sample()
		mut(&a)
		if _, err := NewCatalog(a); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestValidate(t *testing.T) {
	a := sample()
	ok, err := a.Validate(json.RawMessage(`{"user":"alice.b","folder":"C:\\Temp\\x","id":"{6F9619FF-8B86-D011-B42D-00C04FC964FF}","n":3,
		"flag":true,"mode":"quick","password":"correct horse","note":"hello","sid":"S-1-5-21-1-2-3-1001"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ok.Params), "correct horse") || ok.Secrets["password"] != "correct horse" {
		t.Errorf("the secret is in the params or missing: %s", ok.Params)
	}
	if ok.Audit["password"] != "(secret)" || strings.Contains(string(mustJSON(ok.Audit)), "hello") ||
		strings.Contains(string(mustJSON(ok.Audit)), "correct horse") {
		t.Errorf("audit %v", ok.Audit)
	}
	if !strings.Contains(string(ok.Params), `"id":"6f9619ff-8b86-d011-b42d-00c04fc964ff"`) {
		t.Errorf("the GUID is not canonical: %s", ok.Params)
	}

	bad := map[string]string{
		"missing required":  `{}`,
		"unknown":           `{"user":"a","extra":1}`,
		"injected name":     `{"user":"a; Remove-Item *"}`,
		"quote in name":     `{"user":"a\"b"}`,
		"too long":          `{"user":"aaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		"relative path":     `{"user":"a","folder":"Temp\\x"}`,
		"dotdot path":       `{"user":"a","folder":"C:\\Temp\\..\\Windows"}`,
		"device path":       `{"user":"a","folder":"\\\\.\\C:\\x"}`,
		"stream path":       `{"user":"a","folder":"C:\\x:stream"}`,
		"bad guid":          `{"user":"a","id":"nope"}`,
		"bad sid":           `{"user":"a","sid":"S-1-"}`,
		"int out of range":  `{"user":"a","n":11}`,
		"int as text":       `{"user":"a","n":"3"}`,
		"fraction":          `{"user":"a","n":2.5}`,
		"bool as text":      `{"user":"a","flag":"yes"}`,
		"enum outside":      `{"user":"a","mode":"fast"}`,
		"short secret":      `{"user":"a","password":"abc"}`,
		"control char":      `{"user":"a","note":"x\u0000y"}`,
		"not an object":     `["a"]`,
		"trailing document": `{"user":"a"} {}`,
	}
	for name, in := range bad {
		_, err := a.Validate(json.RawMessage(in))
		if e, isErr := apperr.As(err); !isErr || e == nil {
			t.Errorf("%s: got %v, want a validation error", name, err)
		}
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestParseResult(t *testing.T) {
	a := sample()
	line := func(s string) string { return "noise\n" + ResultPrefix + s + "\n" }
	r, err := a.ParseResult(line(`{"ok":true,"version":2,"data":{"name":"n","items":[1,2,3]},"error":null}`))
	if err != nil || !r.OK || r.Count != 3 {
		t.Fatalf("%+v, %v", r, err)
	}
	r, err = a.ParseResult(line(`{"ok":false,"version":2,"data":null,"error":{"code":"module_missing","message":"no"}}`))
	if err != nil || r.OK || r.Error.Code != "module_missing" {
		t.Fatalf("%+v, %v", r, err)
	}
	for name, out := range map[string]string{
		"no line":        "just text\n",
		"not last":       ResultPrefix + `{"ok":true,"version":2,"data":{"name":"n","items":[]},"error":null}` + "\nmore\n",
		"wrong version":  line(`{"ok":true,"version":1,"data":{"name":"n","items":[]},"error":null}`),
		"unknown field":  line(`{"ok":true,"version":2,"data":{"name":"n","items":[],"extra":1},"error":null}`),
		"wrong type":     line(`{"ok":true,"version":2,"data":{"name":5,"items":[]},"error":null}`),
		"no data":        line(`{"ok":true,"version":2,"error":null}`),
		"no error":       line(`{"ok":false,"version":2}`),
		"bad error code": line(`{"ok":false,"version":2,"error":{"code":"Bad Code","message":""}}`),
		"unknown in env": line(`{"ok":true,"version":2,"data":{"name":"n","items":[]},"x":1}`),
		"not json":       line(`{`),
		"empty":          "",
	} {
		if _, err := a.ParseResult(out); !errors.Is(err, ErrResultShape) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfirmAndStepUp(t *testing.T) {
	a := sample()
	if a.NeedsStepUp() {
		t.Error("a read needs no step-up")
	}
	a.Destructive, a.Subject = true, "user"
	if !a.NeedsStepUp() || a.ConfirmText("alice") != "defender.sample:alice" {
		t.Error("a destructive action needs a step-up and a confirmation text")
	}
	a.Destructive, a.Credential = false, true
	if !a.NeedsStepUp() {
		t.Error("a credential action needs a step-up")
	}
}

func TestParamsKeyIsTheHashOfTheCanonicalForm(t *testing.T) {
	for _, none := range []string{"", "  ", "null", "{}", " { } "} {
		if got, err := ParamsKey([]byte(none)); err != nil || got != "" {
			t.Errorf("ParamsKey(%q) = %q, %v; want no key", none, got, err)
		}
	}
	a, err := ParamsKey([]byte(`{"b": 2, "a": "x"}`))
	if err != nil || len(a) != 64 {
		t.Fatalf("%q, %v", a, err)
	}
	if b, _ := ParamsKey([]byte(`{"a":"x","b":2}`)); a != b {
		t.Error("the key depends on key order and white space")
	}
	if c, _ := ParamsKey([]byte(`{"a":"y","b":2}`)); a == c {
		t.Error("different parameters have one key")
	}
	if _, err := ParamsKey([]byte(`[1]`)); err == nil {
		t.Error("an array was accepted")
	}
}

func TestSnapshotActionsAreChecked(t *testing.T) {
	base := func() Action {
		return Action{Module: modules.Defender, Name: "defender.x", Version: 1, Script: "x", ScriptSHA256: agentproto.HashScript("x"),
			Permission: rbac.PermDefenderView, Timeout: 1, Keep: time.Hour, Decode: Typed[struct{}]()}
	}
	for name, mut := range map[string]func(*Action){
		"a schedule below an hour":     func(a *Action) { a.Freshness, a.Schedule = time.Minute, 30*time.Minute },
		"a schedule with no freshness": func(a *Action) { a.Schedule = time.Hour },
		"a scheduled change":           func(a *Action) { a.Freshness, a.Schedule, a.Changes = time.Minute, time.Hour, true },
		"a snapshot that destroys": func(a *Action) {
			a.Freshness, a.Destructive, a.Subject = time.Minute, true, "n"
			a.Params = []Param{{Name: "n", Type: Name}}
		},
	} {
		a := base()
		mut(&a)
		if _, err := NewCatalog(a); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	a := base()
	a.Freshness, a.Schedule = time.Minute, time.Hour
	if _, err := NewCatalog(a); err != nil {
		t.Errorf("an hourly snapshot read: %v", err)
	}
}

// A module's own Check sees the validated values and may refuse them; Confirm
// makes an action need the typed confirmation without a step-up, with or
// without a subject.
func TestCheckHookAndConfirm(t *testing.T) {
	a := sample()
	a.Check = func(p map[string]any) error {
		if p["user"] == "blocked" {
			return apperr.Conflict("blocked_user", "no")
		}
		p["note"] = "changed by the check"
		return nil
	}
	chk, err := a.Validate([]byte(`{"user":"alice"}`))
	if err != nil || !strings.Contains(string(chk.Params), "changed by the check") {
		t.Fatalf("check: %v %s", err, chk.Params)
	}
	if _, err := a.Validate([]byte(`{"user":"blocked"}`)); !errors.Is(err, apperr.Conflict("blocked_user", "")) {
		t.Errorf("a refusal from the check: %v", err)
	}
	if a.NeedsConfirm() || a.NeedsStepUp() {
		t.Error("a plain action needs no confirmation")
	}
	a.Confirm = true
	if _, err := NewCatalog(a); err != nil {
		t.Fatalf("a confirmed action with no subject: %v", err)
	}
	if !a.NeedsConfirm() || a.NeedsStepUp() || a.ConfirmText("") != "defender.sample:" {
		t.Errorf("confirm %v, step-up %v, text %q", a.NeedsConfirm(), a.NeedsStepUp(), a.ConfirmText(""))
	}
}
