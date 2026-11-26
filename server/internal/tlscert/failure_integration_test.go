//go:build integration

package tlscert

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

func (f *fixture) sql(q string, args ...any) {
	f.t.Helper()
	err := f.inst.DB.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, q, args...)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) due(name string) {
	f.sql(`UPDATE tls_certificates SET next_attempt_at = now() WHERE name = $1`, name)
}

var admin = audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Label: "admin@example.test"}

// A name whose validation fails: each failure is recorded and audited, the
// automatic attempts stop at the budget, Retry now makes one more and is then
// refused saying when it could run, the warning opens an hour after the name
// last had a certificate, and once validation works Retry now orders and the
// alert resolves.
func TestFailedOrderAlertsAndRetryNowRecovers(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"fail.test"}, nil)
	pb.pointAt("fail.test", "127.0.0.9") // nothing listens there: validation fails
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)

	f.tick(f.svc)
	r := f.row(f.svc, "fail.test")
	if r.Failures != 1 || r.LastError == "" || r.FailingSince.IsZero() || len(r.FailedAt) != 1 {
		t.Fatalf("after one failed order: %+v", r)
	}
	if !r.NextAttemptAt.After(time.Now().Add(30*time.Second)) || r.NextAttemptAt.After(time.Now().Add(2*time.Minute)) {
		t.Fatalf("the next attempt is at %s, a minute after the first failure", r.NextAttemptAt)
	}
	if f.auditCount("tls.certificate_fail") != 1 {
		t.Fatal("the failure was not audited")
	}
	// Not due: a pass makes no attempt.
	f.tick(f.svc)
	if f.row(f.svc, "fail.test").Failures != 1 {
		t.Fatal("an attempt was made before its time")
	}
	if ev := f.rec.last("fail.test"); ev != nil {
		t.Fatalf("an alert opened at the first failure: %+v", ev)
	}

	// The warning: no certificate for an hour.
	f.sql(`UPDATE tls_certificates SET missing_since = now() - interval '61 minutes' WHERE name = 'fail.test'`)
	f.svc.evaluate(f.ctx, "fail.test")
	ev := f.rec.last("fail.test")
	if ev == nil || !ev.Open || ev.Severity != LevelWarning || ev.Key != "tls:fail.test" || ev.LastError == "" || ev.Link == "" {
		t.Fatalf("the warning: %+v", ev)
	}
	n := len(f.rec.events)
	f.svc.evaluate(f.ctx, "fail.test")
	if len(f.rec.events) != n {
		t.Fatal("an unchanged alert was published again")
	}

	// Automatic attempts stop after 3 failed validations within the hour.
	for i := 0; i < 2; i++ {
		f.due("fail.test")
		f.tick(f.svc)
	}
	if got := f.row(f.svc, "fail.test").Failures; got != 3 {
		t.Fatalf("%d failures", got)
	}
	f.due("fail.test")
	f.tick(f.svc)
	if got := f.row(f.svc, "fail.test").Failures; got != 3 {
		t.Fatalf("an automatic attempt was made over the budget: %d failures", got)
	}
	// The state a restart finds: the budget is in the database.
	svc2 := f.build([]string{"fail.test"}, nil)
	defer svc2.Close()
	if err := svc2.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.due("fail.test")
	f.tick(svc2)
	if got := f.row(svc2, "fail.test").Failures; got != 3 {
		t.Fatalf("a restarted server attempted over the budget: %d failures", got)
	}

	// Retry now is one more, allowed while fewer than 4 have failed.
	if err := f.svc.RetryNow(f.ctx, admin, "fail.test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the retry to fail", 60*time.Second, func() bool { return f.row(f.svc, "fail.test").Failures == 4 })
	err := f.svc.RetryNow(f.ctx, admin, "fail.test")
	var refused *RefusedError
	if !errors.As(err, &refused) || !refused.RetryAt.After(time.Now()) || refused.RetryAt.After(time.Now().Add(time.Hour+time.Minute)) {
		t.Fatalf("a fifth attempt in the hour: %v", err)
	}
	if st, _ := f.svc.Status(f.ctx); st.Names[0].RetryRefusedUntil == nil || st.Names[0].State != StateFailing {
		t.Fatalf("the page does not show the refusal: %+v", st.Names[0])
	}
	if f.auditCount("tls.retry") != 1 {
		t.Fatalf("%d retries audited", f.auditCount("tls.retry"))
	}

	// During the host updater's hold, nothing is attempted.
	f.held = true
	if err := f.svc.RetryNow(f.ctx, admin, "fail.test"); !errors.Is(err, ErrHeld) {
		t.Fatalf("Retry now while held: %v", err)
	}
	f.held = false

	// Validation works again; an hour passes; Retry now orders and the alert resolves.
	pb.pointBack("fail.test")
	f.sql(`UPDATE tls_certificates SET failed_at = '{}' WHERE name = 'fail.test'`)
	if err := f.svc.RetryNow(f.ctx, admin, "fail.test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", 90*time.Second, func() bool { return f.row(f.svc, "fail.test").HasCertificate() })
	r = f.row(f.svc, "fail.test")
	if r.Failures != 0 || !r.FailingSince.IsZero() || r.LastError != "" || r.AlertLevel != LevelNone {
		t.Fatalf("after the success: %+v", r)
	}
	if ev := f.rec.last("fail.test"); ev == nil || ev.Open {
		t.Fatalf("the alert did not resolve: %+v", ev)
	}
	if f.served(f.svc, "fail.test") != r.Serial {
		t.Fatal("the new certificate is not served")
	}
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// Every attempt passes the gate: CertMagic's own (not started by the
// scheduler), one whose time has not come, one during the hold.
func TestGateRefusesWhatTheSchedulerDidNotStart(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"gate.test"}, nil)
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	if err := f.svc.ensureAccount(f.ctx); err != nil {
		t.Fatal(err)
	}
	// CertMagic's own call, as its maintenance loop makes it.
	err := f.svc.magic.ObtainCertSync(f.ctx, "gate.test")
	if !errors.Is(err, errGate) {
		t.Fatalf("an attempt EasyRMM did not start: %v", err)
	}
	if f.row(f.svc, "gate.test").HasCertificate() || pb.orders() != 0 {
		t.Fatal("CertMagic ordered by itself")
	}
	// The scheduler's, held.
	f.held = true
	f.tick(f.svc)
	if !f.row(f.svc, "gate.test").LastAttemptAt.IsZero() {
		t.Fatal("an attempt during the hold")
	}
	f.held = false
	// The scheduler's, not due.
	f.sql(`UPDATE tls_certificates SET next_attempt_at = now() + interval '1 hour' WHERE name = 'gate.test'`)
	f.tick(f.svc)
	if !f.row(f.svc, "gate.test").LastAttemptAt.IsZero() {
		t.Fatal("an attempt before its time")
	}
	if err := f.svc.attempt(f.ctx, "gate.test", kindScheduled); err == nil {
		t.Fatal("a scheduled attempt that was not due went through")
	}
	// Its time comes.
	f.due("gate.test")
	f.tick(f.svc)
	if !f.row(f.svc, "gate.test").HasCertificate() {
		t.Fatal("the due attempt did not order")
	}
}

// A server restarted ten times within a minute while its name fails makes
// the scheduled attempts and no more.
func TestRestartsDoNotRepeatAttempts(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"loop.test"}, nil)
	pb.pointAt("loop.test", "127.0.0.9")
	for i := 0; i < 10; i++ {
		svc := f.build([]string{"loop.test"}, nil)
		if err := svc.Start(f.ctx); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.serve(svc)
		}
		svc.Serving()
		f.tick(svc)
		svc.Close()
	}
	if got := f.row(f.svc, "loop.test").Failures; got != 1 {
		t.Fatalf("%d failed attempts in ten starts, want the one that was due", got)
	}
	if got := f.auditCount("tls.certificate_fail"); got != 1 {
		t.Fatalf("%d failures audited", got)
	}
}
