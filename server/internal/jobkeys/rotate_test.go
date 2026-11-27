package jobkeys

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestPlanRules(t *testing.T) {
	mk := func(g int64) Key {
		_, p, _ := ed25519.GenerateKey(nil)
		return Key{Generation: g, Public: p.Public().(ed25519.PublicKey), Private: p}
	}
	old, floor, newest := mk(1), mk(2), mk(3)
	now := time.Now()
	floor.CutOverAt = &now
	rep := func(ks ...Key) []reported {
		var out []reported
		for _, k := range ks {
			out = append(out, reported{Key: k.Public, Generation: k.Generation})
		}
		return out
	}
	keys := []Key{old, floor, newest}
	cases := []struct {
		name   string
		report []reported
		kind   string
		signer int64
		about  int64
	}{
		{"nothing reported", nil, "", 0, 0},
		{"on the floor and a newer key exists, trusts the floor only", rep(floor), agentproto.InstructionHandover, 2, 3},
		{"older than the floor: the hand-over to the floor", rep(old), agentproto.InstructionHandover, 1, 2},
		{"older and the floor: cut over to the floor", rep(old, floor), agentproto.InstructionCutover, 2, 2},
		{"all three: the floor is not its newest, nothing", rep(old, floor, newest), "", 0, 0},
		{"the floor and the newest: nothing", rep(floor, newest), "", 0, 0},
		{"older and the newest, lacks the floor: cut over to the newest first", rep(old, newest), agentproto.InstructionCutover, 3, 3},
	}
	for _, c := range cases {
		p := plan(keys, floor, c.report)
		if p.kind != c.kind || (c.kind != "" && (p.signer.Generation != c.signer || p.about.Generation != c.about)) {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
	// A device on the floor, with the newest key also being the floor.
	floor2 := newest
	floor2.CutOverAt = &now
	if p := plan([]Key{old, floor, floor2}, floor2, rep(floor2)); p.kind != "" {
		t.Errorf("on the floor: %+v", p)
	}
	// A key the server forgot: it cannot sign, so a device that trusts only it
	// is sent nothing (needs re-pinning).
	forgotten := old
	forgotten.Private = nil
	if p := plan([]Key{forgotten, floor, newest}, floor, rep(forgotten)); p.kind != "" {
		t.Errorf("a forgotten key: %+v", p)
	}
}

func TestVersionComparison(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		older bool
	}{
		{"1.0.0", "1.0.1", true}, {"v1.2.3", "1.2.3", false}, {"1.10.0", "1.9.0", false}, {"0.9", "1.0.0", true},
		{"dev", "1.0.0", false}, {"1.0.0", "dev", false}, {"1.2.3-rc1", "1.2.4", true}, {"", "1.0.0", false},
	} {
		if got := olderVersion(c.a, c.b); got != c.older {
			t.Errorf("olderVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
