package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestInventoryHash(t *testing.T) {
	inv := &Inventory{OS: OSInfo{Name: "Debian"}, Packages: []Package{{Name: "bash", Version: "5.2"}}}
	b, _ := json.Marshal(inv)
	sum := sha256.Sum256(b)
	if inv.Hash() != hex.EncodeToString(sum[:]) {
		t.Error("the hash is not the SHA-256 of the JSON")
	}
	other := *inv
	other.Packages = []Package{{Name: "bash", Version: "5.3"}}
	if other.Hash() == inv.Hash() {
		t.Error("a changed package keeps the hash")
	}
	// The heartbeat answer always names the server's hash, even when empty.
	out, _ := json.Marshal(HeartbeatResponse{})
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if _, ok := m["inventoryHash"]; !ok {
		t.Errorf("heartbeat answer %s", out)
	}
}
