package defender

import (
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Every catalog entry's pinned hash matches its script, and the catalog
// builds (which checks the same, and the schema).
func TestCatalogPinsMatchScripts(t *testing.T) {
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range c.Actions() {
		if got := agentproto.HashScript(a.Script); got != a.ScriptSHA256 {
			t.Errorf("%s: script hashes to %s, the catalog pins %s", a.Name, got, a.ScriptSHA256)
		}
	}
	if _, ok := c.Lookup("defender.status"); !ok {
		t.Error("defender.status is missing")
	}
}
