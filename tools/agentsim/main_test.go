package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPercentiles(t *testing.T) {
	if p := percentiles(nil); p != [4]time.Duration{} {
		t.Errorf("empty: %v", p)
	}
	var ds []time.Duration
	for i := 100; i >= 1; i-- {
		ds = append(ds, time.Duration(i)*time.Millisecond)
	}
	p := percentiles(ds)
	if p[0] != 51*time.Millisecond || p[1] != 96*time.Millisecond || p[2] != 100*time.Millisecond || p[3] != 100*time.Millisecond {
		t.Errorf("percentiles %v", p)
	}
	if ds[0] != 100*time.Millisecond {
		t.Error("percentiles sorted its argument")
	}
}

// Each device's inventory is its own and the same on every run, so the
// server's hash matches after the first upload and later runs upload none.
func TestInventory(t *testing.T) {
	a, b := inventory(7, "sim-00008", 300), inventory(7, "sim-00008", 300)
	if a.Hash() != b.Hash() {
		t.Error("the same device's inventory changed")
	}
	if a.Hash() == inventory(8, "sim-00009", 300).Hash() {
		t.Error("two devices share an inventory")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Packages) != 300 || len(raw) < 20_000 {
		t.Errorf("%d packages, %d bytes", len(a.Packages), len(raw))
	}
}

// The hardware report names the inventory's disks, as the agent's does, and
// is about the size ADR-0065 estimated: logged for the record.
func TestHardware(t *testing.T) {
	r, inv := hardware(7), inventory(7, "sim-00008", 0)
	if len(r.Disks) != len(inv.Disks) {
		t.Fatalf("%d disks reported, %d in the inventory", len(r.Disks), len(inv.Disks))
	}
	total := 0
	for i, d := range r.Disks {
		if d.Name != inv.Disks[i].Name || d.Model != inv.Disks[i].Model || d.Serial != inv.Disks[i].Serial {
			t.Errorf("disk %d: %s %q %q, inventory %+v", i, d.Name, d.Model, d.Serial, inv.Disks[i])
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s (%s, %d attributes): %d bytes", d.Name, d.Protocol, len(d.Attributes), len(b))
		total += len(b)
	}
	body, _ := json.Marshal(r)
	t.Logf("report: %d bytes", len(body))
	if len(body) < total || len(body) > 8<<10 {
		t.Errorf("report of %d bytes", len(body))
	}
	if r.Disks[1].Attributes[0].Threshold == r.Disks[1].Attributes[1].Threshold {
		t.Error("attributes share a threshold")
	}
}

func TestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sim.json")
	ids, err := loadState(path)
	if err != nil || ids != nil {
		t.Fatalf("missing state: %v %v", ids, err)
	}
	want := []identity{{ID: "d1", Seed: make([]byte, 32), Hostname: "sim-00001", JobKey: "k"}}
	if err := saveState(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(path)
	if err != nil || len(got) != 1 || got[0].ID != "d1" || got[0].Hostname != "sim-00001" || len(got[0].Seed) != 32 {
		t.Fatalf("state %+v, %v", got, err)
	}
}

func TestStats(t *testing.T) {
	s := newStats()
	s.record("heartbeat", 10*time.Millisecond, nil)
	s.record("heartbeat", 0, errors.New("connection refused"))
	if out := s.interval(); out == "" {
		t.Fatal("no report")
	}
	s.record("heartbeat", 20*time.Millisecond, nil)
	sum := s.summary(1, time.Minute)
	hb := sum.Ops["heartbeat"]
	if hb.OK != 2 || hb.Errors["connection refused"] != 1 || hb.Max != "20ms" {
		t.Errorf("summary %+v", hb)
	}
	if s.ops["heartbeat"].recentErrs != 0 || len(s.ops["heartbeat"].recent) != 1 {
		t.Error("the report did not start a new interval")
	}
}
