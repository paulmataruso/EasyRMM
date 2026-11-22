//go:build integration

package monitoring

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// measureEnv runs TestDiskFactsAtScale. It seeds 10.7 million rows, about
// 3 GiB with their indexes: run it against a PostgreSQL of your own.
const measureEnv = "EASYRMM_MEASURE_DISK_FACTS"

// TestDiskFactsAtScale measures loadDiskFacts' query on a fleet the size
// the ADR plans for: 5,000 devices with two disks each, an NVMe drive and
// a SATA disk, each with a week of readings every 30 minutes and two years
// of daily rows (1,066 rows a disk, 10.7 million in all), with every disk
// health policy turned on. Many disks never match a check (an NVMe drive
// keeps no pending sectors, an ATA disk no wear, half the ATA disks no
// temperature limit); 3% were never judged, 2% are missing, one reading in
// ten could not tell. After a VACUUM it prints the query's EXPLAIN
// (ANALYZE, BUFFERS) three times as the evaluation sees it (the runtime
// role under row-level security, with the system scope) but without the
// pool's 30-second statement timeout, checks that the readings' lower
// bound is an index condition, and that one evaluation opens the alerts
// the seed holds.
func TestDiskFactsAtScale(t *testing.T) {
	if os.Getenv(measureEnv) != "1" {
		t.Skipf("set %s=1 to seed 10.7 million readings and measure", measureEnv)
	}
	f := newDiskFixture(t)
	super, err := pgx.Connect(f.ctx, f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(f.ctx)
	start := time.Now()
	for _, stmt := range []string{
		`INSERT INTO devices (organization_id, site_id, name)
			SELECT $1, $2, 'dev-' || g FROM generate_series(1, 5000) g`,
		`INSERT INTO device_disk_health (device_id, disk_key, unstable, name, model, serial, state, reason, detail, read_at,
				received_at, protocol, route, facts, attributes, facts_at, judged_level, judged_reason, judged_detail, judged_at, missing_since)
			SELECT d.id, md5(d.id::text || k), false, CASE k WHEN 0 THEN 'nvme0n1' ELSE 'sda' END,
				CASE k WHEN 0 THEN 'Example NVMe 1TB' ELSE 'Example HDD 4TB' END, 'S' || g || '-' || k,
				CASE WHEN g % 33 = 0 THEN 'unknown' WHEN k = 0 AND g % 200 = 2 THEN 'failing' ELSE 'healthy' END,
				CASE WHEN g % 33 = 0 THEN 'asleep' ELSE '' END, '', now(), now(), CASE k WHEN 0 THEN 'nvme' ELSE 'ata' END,
				CASE k WHEN 0 THEN 'nvme' ELSE 'sg' END, '[]', '[]', CASE WHEN g % 33 <> 0 THEN now() END,
				CASE WHEN g % 33 = 0 THEN NULL WHEN k = 0 AND g % 200 = 2 THEN 'failing' ELSE 'healthy' END, '',
				CASE WHEN k = 0 AND g % 200 = 2 THEN 'NVMe critical warning: media read-only' ELSE '' END,
				CASE WHEN g % 33 <> 0 THEN now() END, CASE WHEN g % 50 = 1 THEN now() - interval '2 days' END
			FROM (SELECT id, substr(name, 5)::int AS g FROM devices WHERE name LIKE 'dev-%') d CROSS JOIN generate_series(0, 1) k`,
		// The rows are made from device_disk_health's own: skip the foreign
		// key's checks, row by row, for them.
		`SET session_replication_role = replica`,
		// A week of readings every 30 minutes, then a row a day for two
		// years.
		`INSERT INTO device_disk_health_samples (device_id, disk_key, at, daily, state, judged, temperature, temperature_limit,
				wear, reallocated, media_errors, pending, uncorrectable, drive_errors, power_on_hours)
			SELECT h.device_id, h.disk_key, x.at, x.daily,
				CASE WHEN NOT x.judged THEN 'unknown' WHEN h.failing THEN 'failing' ELSE 'healthy' END, x.judged,
				CASE WHEN x.judged THEN CASE WHEN h.nvme THEN 40 ELSE 35 END END,
				CASE WHEN x.judged THEN CASE WHEN h.nvme THEN 80 WHEN h.g % 2 = 1 THEN 60 END END,
				CASE WHEN x.judged AND h.nvme THEN 3 END,
				CASE WHEN x.judged AND NOT h.nvme THEN CASE WHEN h.g % 100 = 3 THEN 5 ELSE 0 END END,
				CASE WHEN x.judged AND h.nvme THEN 0 END,
				CASE WHEN x.judged AND NOT h.nvme THEN 0 END, CASE WHEN x.judged AND NOT h.nvme THEN 0 END,
				CASE WHEN x.judged THEN 0 END, CASE WHEN x.judged THEN 20000 END
			FROM (SELECT h.device_id, h.disk_key, h.protocol = 'nvme' AS nvme, substr(d.name, 5)::int AS g,
					h.judged_level = 'failing' AS failing, h.judged_at IS NOT NULL AS ever
				FROM device_disk_health h JOIN devices d ON d.id = h.device_id) h
			CROSS JOIN LATERAL (
				SELECT now() - make_interval(mins => 30 * i) AS at, false AS daily, h.ever AND i % 10 <> 3 AS judged
				FROM generate_series(0, 335) i
				UNION ALL
				SELECT date_trunc('day', now() - interval '8 days', 'UTC') - make_interval(days => j), true, h.ever
				FROM generate_series(0, 729) j
			) x`,
		`SET session_replication_role = DEFAULT`,
		`VACUUM (ANALYZE) devices, device_disk_health, device_disk_health_samples, alerts, alert_policies`,
	} {
		args := []any{}
		if strings.Contains(stmt, "$1") {
			args = []any{f.acme, f.hq}
		}
		if _, err := super.Exec(f.ctx, stmt, args...); err != nil {
			t.Fatalf("seeding: %v\n%s", err, stmt)
		}
	}
	var rows, size int64
	if err := super.QueryRow(f.ctx, `SELECT count(*), pg_total_relation_size('device_disk_health_samples') FROM device_disk_health_samples`).
		Scan(&rows, &size); err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d readings, %d MiB with their indexes, in %s", rows, size>>20, time.Since(start).Round(time.Second))

	f.exec(`UPDATE alert_policies SET enabled = true WHERE kind = 'disk_health'`)

	for _, stmt := range []string{`SET ROLE easyrmm_app`, `SELECT set_config('easyrmm.scope_all', 'on', false)`} {
		if _, err := super.Exec(f.ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	var plan []string
	for run := range 3 {
		rs, err := super.Query(f.ctx, `EXPLAIN (ANALYZE, BUFFERS) `+diskFactsSQL, time.Now(), openWindow.Seconds())
		if err != nil {
			t.Fatal(err)
		}
		if plan, err = pgx.CollectRows(rs, pgx.RowTo[string]); err != nil {
			t.Fatal(err)
		}
		t.Logf("run %d: %s", run+1, strings.TrimSpace(plan[len(plan)-1]))
	}
	t.Logf("EXPLAIN (ANALYZE, BUFFERS), the third run:\n%s", strings.Join(plan, "\n"))
	bound := false
	for _, line := range plan {
		bound = bound || strings.Contains(line, "Index Cond:") && strings.Contains(line, "opened_at IS NULL")
	}
	if !bound {
		t.Error("the readings' bound is not an index condition")
	}
	if _, err := super.Exec(f.ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}

	// Failing NVMe drives (g % 200 = 2) and ATA disks with reallocated
	// sectors (g % 100 = 3), less those never judged (g % 33 = 0); none of
	// them is missing (g % 50 = 1).
	if r := f.evaluate(); r.Opened != 25-countMultiples(2, 200, 5000, 33)+50-countMultiples(3, 100, 5000, 33) {
		t.Errorf("opened %d", r.Opened)
	}
}

// countMultiples counts the numbers first, first+step, ... up to last that
// are multiples of m.
func countMultiples(first, step, last, m int) int {
	n := 0
	for v := first; v <= last; v += step {
		if v%m == 0 {
			n++
		}
	}
	return n
}
