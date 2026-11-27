package ntp

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestPins(t *testing.T) {
	for _, a := range Actions() {
		name := a.Name[len("ntp."):]
		want := pins[name]
		got := fmt.Sprintf("%x", sha256.Sum256([]byte(a.Script)))
		if got != want {
			t.Errorf("pin mismatch for %s: got %s, want %s", name, got, want)
		}
	}
}

func TestActions(t *testing.T) {
	actions := Actions()
	if len(actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(actions))
	}
	names := map[string]bool{}
	for _, a := range actions {
		if names[a.Name] {
			t.Errorf("duplicate action name: %s", a.Name)
		}
		names[a.Name] = true
		if a.Script == "" {
			t.Errorf("action %s has no script", a.Name)
		}
		if a.ScriptSHA256 == "" {
			t.Errorf("action %s has no pin", a.Name)
		}
	}
}
