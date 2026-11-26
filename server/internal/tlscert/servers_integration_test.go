//go:build integration

package tlscert

import (
	"context"
	"testing"
	"time"
)

// Two servers on one database order once and both serve the result (ADR-0055,
// groundwork for several servers): the scheduler is led by one at a time, the
// challenge is answered from the shared storage by whichever has the ports,
// and the other loads the certificate when it is stored (NOTIFY) or at its next
// pass if it missed the notification.
func TestTwoServersOrderOnceAndBothServe(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"two.test"}, nil)
	b := f.build([]string{"two.test"}, func(s *Settings) { s.Instance = "second" })
	defer b.Close()
	for _, s := range []*Service{f.svc, b} {
		if err := s.Start(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	f.serve(f.svc) // only one has the ports; the other's attempt is answered through storage
	b.Serving()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go f.svc.Run(ctx)
	go b.Run(ctx)
	waitFor(t, "both to serve the certificate", 90*time.Second, func() bool {
		return f.served(f.svc, "two.test") != "" && f.served(b, "two.test") != ""
	})
	if f.served(f.svc, "two.test") != f.served(b, "two.test") {
		t.Fatal("the two servers serve different certificates")
	}
	if got := pb.orders(); got != 1 {
		t.Fatalf("%d orders for one name", got)
	}
	if f.auditCount("tls.certificate_obtain") != 1 {
		t.Fatal("the order was not audited once")
	}
}

// A name the environment no longer lists is dropped with its alert resolved,
// and MeshCentral's last read survives a restart.
func TestNamesDroppedAndMeshReadsRemembered(t *testing.T) {
	pb := startPebble(t, 3600)
	f := newFixture(t, pb, []string{"keep.test", "drop.test"}, func(s *Settings) { s.MeshName = "keep.test" })
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.sql(`UPDATE tls_certificates SET missing_since = now() - interval '2 hours' WHERE name = 'drop.test'`)
	f.svc.evaluate(f.ctx, "drop.test")
	if ev := f.rec.last("drop.test"); ev == nil || !ev.Open {
		t.Fatal("no warning to drop")
	}
	at := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	f.svc.RecordMeshRead(at)

	svc2 := f.build([]string{"keep.test"}, func(s *Settings) { s.MeshName = "keep.test" })
	defer svc2.Close()
	if err := svc2.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	if ev := f.rec.last("drop.test"); ev == nil || ev.Open {
		t.Fatalf("the dropped name's alert did not resolve: %+v", ev)
	}
	if rows, _ := svc2.loadRows(f.ctx); len(rows) != 1 || rows[0].Name != "keep.test" {
		t.Fatalf("rows: %+v", rows)
	}
	if got := svc2.Slot().lastRead; !got.Equal(at) {
		t.Fatalf("the last read was forgotten: %s, want %s", got, at)
	}
}

// A renewed certificate for MeshCentral's name waits in the slot while reads
// keep coming, and is applied at the cap, never before; the page shows the
// serial served and the one waiting.
func TestMeshCertificateIsAppliedAtTheCapWhileReadsContinue(t *testing.T) {
	oldWait, oldCap := meshWait, meshCap
	meshWait, meshCap = 3*time.Second, 6*time.Second
	t.Cleanup(func() { meshWait, meshCap = oldWait, oldCap })
	pb := startPebble(t, 90)
	f := newFixture(t, pb, []string{"mesh.test"}, func(s *Settings) { s.MeshName = "mesh.test" })
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.serve(f.svc)
	f.until(f.svc, "the first certificate", 60*time.Second, func() bool { return f.row(f.svc, "mesh.test").HasCertificate() })
	first := f.served(f.svc, "mesh.test")
	if first == "" {
		t.Fatal("not served")
	}
	var ready time.Time
	var seenPending bool
	deadline := time.Now().Add(150 * time.Second)
	for f.served(f.svc, "mesh.test") == first {
		if time.Now().After(deadline) {
			t.Fatal("the new certificate was never applied")
		}
		f.svc.RecordMeshRead(time.Now()) // MeshCentral keeps reading
		f.tick(f.svc)
		if _, p, r := f.svc.Slot().State(); p != "" {
			if !seenPending {
				seenPending, ready = true, r
				if st, _ := f.svc.Status(f.ctx); st.Names[0].PendingSerial != p || st.Names[0].ServedSerial != first {
					t.Fatalf("the page shows served %s, waiting %s", st.Names[0].ServedSerial, st.Names[0].PendingSerial)
				}
			}
			if time.Since(ready) < meshCap-time.Second && f.served(f.svc, "mesh.test") != first {
				t.Fatal("applied before the cap while reads continued")
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if seenPending && time.Since(ready) < meshCap-time.Second {
		t.Fatalf("applied %s after it was ready, before the cap", time.Since(ready))
	}
	if r := f.row(f.svc, "mesh.test"); r.ServedSerial == "" || r.ServedSerial == first && r.PendingSerial == "" {
		t.Fatalf("the row: %+v", r)
	}
}
