//go:build integration

package devices_test

import (
	"context"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/devices"
)

func TestListFiltersDevicesWhoseSettingsAreNotApplied(t *testing.T) {
	w := newWorld(t)
	add := func(name string, heartbeats int) {
		id := w.insert(t, `INSERT INTO devices (organization_id, site_id, name, platform) VALUES ($1, $2, $3, 'linux') RETURNING id`, w.acme, w.hq, name)
		w.exec(t, `INSERT INTO agent_device_state (device_id, not_applied_heartbeats) VALUES ($1, $2)`, id, heartbeats)
	}
	add("late", 3)
	add("fine", 1)

	got, err := w.svc.List(context.Background(), w.sys, devices.Query{Settings: devices.SettingsNotApplied})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "late" {
		t.Fatalf("filtered = %d devices", len(got))
	}
	if _, err := w.svc.List(context.Background(), w.sys, devices.Query{Settings: "nope"}); err == nil {
		t.Fatal("an unknown filter was accepted")
	}
}
