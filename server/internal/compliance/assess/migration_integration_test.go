//go:build integration

package assess_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The assessment migration goes down and up again, and down leaves none of its tables or functions behind.
func TestAssessmentMigrationDownAndUp(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["role"] = "easyrmm_owner"
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	count := func() int {
		var n int
		if err := super.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_tables WHERE tablename LIKE 'compliance\_%' AND tablename IN
			('compliance_assessments', 'compliance_evidence', 'compliance_org_keys', 'compliance_poam_items', 'compliance_score_snapshots'))
			+ (SELECT count(*) FROM pg_proc WHERE proname LIKE 'compliance\_%frozen%' OR proname IN ('compliance_evidence_immutable', 'compliance_attestations_immutable'))`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() == 0 {
		t.Fatal("the migration did not run")
	}
	if _, err := p.DownTo(ctx, 90390); err != nil {
		t.Fatalf("down: %v", err)
	}
	if n := count(); n != 0 {
		t.Errorf("down left %d tables or functions", n)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if count() == 0 {
		t.Error("up again made nothing")
	}
}
