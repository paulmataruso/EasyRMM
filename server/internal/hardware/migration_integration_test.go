//go:build integration

package hardware_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// TestUpgradeMigration takes 00031 down and up again on an installation
// whose administrators already use some of the new policies' names
// (ADR-0065, "Names already taken"), with a metric alert open across it.
func TestUpgradeMigration(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["role"] = "easyrmm_owner"
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	must := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	policies := func() map[string]string {
		t.Helper()
		rows, err := super.Query(ctx, `SELECT check_name, name FROM alert_policies WHERE kind = 'disk_health'`)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for rows.Next() {
			var check, name string
			if err := rows.Scan(&check, &name); err != nil {
				t.Fatal(err)
			}
			out[check] = name
		}
		return out
	}

	if _, err := provider.DownTo(ctx, 29); err != nil {
		t.Fatal(err)
	}
	// Shared policies named as two of the new ones, and as one of them with
	// the fallback too; a device with an open metric alert.
	must(`INSERT INTO alert_policies (name, kind, threshold, minutes, severity) VALUES
		('disk failing', 'disk', 95, 5, 'critical'), ('Disk errors', 'disk', 80, 5, 'warning'),
		('Disk errors (disk health)', 'disk', 85, 5, 'warning')`)
	var org, site, device, policy string
	if err := super.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, 'pc-01') RETURNING id`,
		org, site).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `SELECT id FROM alert_policies WHERE name = 'Disk almost full'`).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	must(`INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, value, last_value)
		VALUES ($1, $2, 'Disk almost full', 'disk', 90, 5, 'critical', 95, 95)`, policy, device)

	if _, err := provider.UpTo(ctx, 31); err != nil {
		t.Fatal(err)
	}
	got := policies()
	want := map[string]string{
		"failing": "Disk failing (disk health)", "pending": "Disk sectors pending", "wear": "Disk wearing out", "temperature": "Disk too hot",
	}
	if len(got) != len(want) {
		t.Fatalf("disk health policies %v", got)
	}
	for check, name := range want {
		if got[check] != name {
			t.Errorf("%s: %q, want %q", check, got[check], name)
		}
	}
	var enabled int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM alert_policies WHERE kind = 'disk_health' AND enabled`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Errorf("%d disk health policies on, want only failing", enabled)
	}
	// The open alert kept its key: a second on the same policy and device
	// is refused, one on a disk is not.
	var subject string
	if err := super.QueryRow(ctx, `SELECT subject FROM alerts WHERE device_id = $1`, device).Scan(&subject); err != nil || subject != "" {
		t.Fatalf("subject %q %v", subject, err)
	}
	if _, err := super.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, value, last_value)
		VALUES ($1, $2, 'Disk almost full', 'disk', 90, 5, 'critical', 96, 96)`, policy, device); err == nil {
		t.Error("a second open alert on one policy and device")
	}

	// Down and up again: the old constraints and key come back, and so do
	// the policies, the same way.
	if _, err := provider.DownTo(ctx, 29); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename LIKE 'device_disk_health%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after down: %d %v", n, err)
	}
	if _, err := provider.UpTo(ctx, 31); err != nil {
		t.Fatal(err)
	}
	if got := policies(); got["failing"] != "Disk failing (disk health)" || len(got) != 4 {
		t.Errorf("after down and up: %v", got)
	}
}
