package state

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAddressesKeepTheAddressesLeftNewestLast(t *testing.T) {
	t0 := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	var a Addresses
	if _, ok := a.Previous(); ok || a.Has("https://a.example.com") {
		t.Error("an empty record has a previous address")
	}
	a = a.Left("https://a.example.com", t0).Left("https://b.example.com", t0.Add(time.Hour))
	if p, ok := a.Previous(); !ok || p.Server != "https://b.example.com" || !p.At.Equal(t0.Add(time.Hour)) {
		t.Errorf("previous: %+v", p)
	}
	// Leaving an address again moves it to the end, never twice.
	a = a.Left("https://a.example.com", t0.Add(2*time.Hour))
	if len(a.Moved) != 2 || a.Moved[1].Server != "https://a.example.com" {
		t.Errorf("left again: %+v", a.Moved)
	}
	// Only the newest MaxMoved are kept.
	for i := range 2 * MaxMoved {
		a = a.Left("https://n"+strconv.Itoa(i)+".example.com", t0)
	}
	if len(a.Moved) != MaxMoved || a.Has("https://a.example.com") {
		t.Errorf("kept %d: %+v", len(a.Moved), a.Moved)
	}
	last := a.Moved[len(a.Moved)-1].Server
	if b := a.Without(last); len(b.Moved) != MaxMoved-1 || b.Has(last) {
		t.Errorf("without: %+v", b.Moved)
	}
}

func TestSetServerWritesBothFilesAndASaveConfigKeepsTheAddresses(t *testing.T) {
	s := open(t)
	key, _ := NewKey()
	cfg := &Config{Server: "https://old.example.com", CAFile: "/ca.pem", TrustSystem: true, DeviceID: "d1", EnrolledAt: time.Unix(1_800_000_000, 0).UTC(), MeshAgentMode: "child"}
	if err := s.Save(cfg, key); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	if err := s.SetServer(cfg, "https://new.example.com", at); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Load()
	if err != nil || got.Server != "https://new.example.com" || got.CAFile != "/ca.pem" || !got.TrustSystem || got.DeviceID != "d1" {
		t.Fatalf("config: %+v %v", got, err)
	}
	if cfg.Server != "https://old.example.com" {
		t.Error("SetServer changed the configuration it was given")
	}
	if p, ok := s.LoadAddresses().Previous(); !ok || p.Server != "https://old.example.com" || !p.At.Equal(at) {
		t.Errorf("previous: %+v", p)
	}
	// The addresses are a file of their own: rewriting the configuration, as
	// a build that does not know them does, leaves them alone.
	if err := s.SaveConfig(got); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.LoadAddresses().Previous(); !ok {
		t.Error("SaveConfig lost the addresses")
	}
	// Moving back to the address that was left removes it from the list, and
	// leaves the one just left.
	if err := s.SetServer(got, "https://old.example.com", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.LoadAddresses().Previous(); p.Server != "https://new.example.com" || s.LoadAddresses().Has("https://old.example.com") {
		t.Errorf("after moving back: %+v", s.LoadAddresses())
	}
	// A damaged file is an empty record, and a new enrollment forgets it.
	if err := os.WriteFile(filepath.Join(s.Dir(), addressFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(s.LoadAddresses().Moved) != 0 {
		t.Error("a damaged file was read")
	}
	if err := s.SaveAddresses(Addresses{}.Left("https://x.example.com", at)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(cfg, key); err != nil {
		t.Fatal(err)
	}
	if len(s.LoadAddresses().Moved) != 0 {
		t.Error("a new enrollment kept the addresses of the old one")
	}
}
