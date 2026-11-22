//go:build integration

package jobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TestArchiveRunsGoneMeanwhile: a run purged, or moved where the caller may
// no longer read it, between the archive's records and its read is listed
// as removed, without files: the caller could read it when the download
// began, so "needs permission" would be wrong.
func TestArchiveRunsGoneMeanwhile(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq},
		rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Gone", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	kept, purged, moved := f.device(f.hq, "HQ-01", "linux"), f.device(f.hq, "HQ-02", "linux"), f.device(f.hq, "HQ-03", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{kept, purged, moved}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []uuid.UUID{kept, purged, moved} {
		f.finish(d, f.runOn(job, d), "out "+d.String()+" "+outMarker+"\n", "")
	}
	arc, err := f.svc.OutputArchive(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Purged, and moved to a site where tech is Read-Only.
	f.asOwner(`DELETE FROM job_runs WHERE id = $1`, f.runOn(job, purged))
	f.asOwner(`UPDATE job_runs SET site_id = $2 WHERE id = $1`, f.runOn(job, moved), f.branch)

	var buf bytes.Buffer
	if err := arc.Write(f.ctx, &buf); err != nil {
		t.Fatal(err)
	}
	files := archive(t, buf.Bytes())
	for name, want := range map[string]string{"HQ-01": archiveIncluded, "HQ-02": archiveRemoved, "HQ-03": archiveRemoved} {
		if got := outputStates(t, files)[name]; got != want {
			t.Errorf("%s is %q, want %q:\n%s", name, got, want, files["runs.csv"])
		}
	}
	for name, body := range files {
		if strings.Contains(body, purged.String()+" "+outMarker) || strings.Contains(body, moved.String()+" "+outMarker) {
			t.Errorf("%s holds output that was gone", name)
		}
	}
	if !strings.Contains(files["HQ-01_"+f.runOn(job, kept).String()+"/stdout.txt"], outMarker) {
		t.Errorf("the kept run's output is missing: %v", keysOf(files))
	}
}

// TestArchiveAndCancelLockInOneOrder: preparing a job's archive locks its
// runs in the order canceling the job does (device name, then run), so the
// two wait on each other at most, and never deadlock. The runs' order on
// disk is made to differ from the names' order, and a third transaction
// holds the last run by name while the archive and a cancel start: the
// archive must then already hold the first run by name, and both finish
// once the third lets go. Locking in the table's order instead, the archive
// would hold the last run and wait for the first while the cancel held the
// first and waited for the last.
func TestArchiveAndCancelLockInOneOrder(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Order", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	first, last := f.device(f.hq, "A-01", "linux"), f.device(f.hq, "Z-01", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{first, last}})
	if err != nil {
		t.Fatal(err)
	}
	runFirst, runLast := f.runOn(job, first), f.runOn(job, last)
	ctx, cancel := context.WithTimeout(f.ctx, time.Minute)
	defer cancel()
	conn := func() *pgx.Conn {
		c, err := pgx.Connect(ctx, f.super)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	holder, probe := conn(), conn()

	// Finishing A-01's run writes its new row after Z-01's, which stays
	// queued for the cancel.
	f.finish(first, runFirst, "first "+outMarker+"\n", "")
	var onDisk string
	if err := probe.QueryRow(ctx, `SELECT string_agg(id::text, ',' ORDER BY ctid) FROM job_runs WHERE job_id = $1`, job.ID).Scan(&onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk != runLast.String()+","+runFirst.String() {
		t.Fatalf("the runs on disk: %s, want Z-01's first", onDisk)
	}

	hold, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(context.Background()) }()
	if _, err := hold.Exec(ctx, `SELECT 1 FROM job_runs WHERE id = $1 FOR UPDATE`, runLast); err != nil {
		t.Fatal(err)
	}
	// waiting waits until a session other than the test's own waits for a
	// lock while running a statement that contains text.
	waiting := func(text string) {
		t.Helper()
		for {
			var n int
			if err := probe.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()
				  AND strpos(query, $1) > 0`, text).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n > 0 {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("nothing waited running %q", text)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}

	type prepared struct {
		arc *OutputArchive
		err error
	}
	archived := make(chan prepared, 1)
	go func() {
		arc, err := f.svc.OutputArchive(ctx, super, job.ID)
		archived <- prepared{arc, err}
	}()
	waiting("easyrmm_job_output_zip")
	// The archive holds A-01's run while it waits for Z-01's.
	_, err = probe.Exec(ctx, `SELECT 1 FROM job_runs WHERE id = $1 FOR UPDATE NOWAIT`, runFirst)
	if pe := (*pgconn.PgError)(nil); !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Errorf("A-01's run while the archive waits for Z-01's: %v, want it held (55P03)", err)
	}

	canceled := make(chan error, 1)
	go func() {
		_, err := f.svc.CancelJob(ctx, super, job.ID)
		canceled <- err
	}()
	waiting("FOR UPDATE OF r")
	if err := hold.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	p := <-archived
	if p.err != nil {
		t.Fatalf("the archive: %v", p.err)
	}
	if err := <-canceled; err != nil {
		t.Fatalf("the cancel: %v", err)
	}
	var buf bytes.Buffer
	if err := p.arc.Write(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	files := archive(t, buf.Bytes())
	if got := outputStates(t, files); got["A-01"] != archiveIncluded || got["Z-01"] != archiveOpen {
		t.Errorf("runs.csv: %v", got)
	}
	if s := f.str(`SELECT status FROM job_runs WHERE id = $1`, runLast); s != StatusCanceled {
		t.Errorf("Z-01's run is %s after the cancel", s)
	}
}

// blockingWriter stands for a client that stops reading: its first Write
// blocks until released.
type blockingWriter struct {
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
	buf     bytes.Buffer
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.blocked)
		<-w.release
	})
	return w.buf.Write(p)
}

// TestArchiveHoldsNoConnectionWhileSending: while a client stops reading an
// archive, partway through the first run's files and before the second
// run's output is read, the archive holds none of the pool's connections.
func TestArchiveHoldsNoConnectionWhileSending(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Large", Shell: "sh", Body: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	one, two := f.device(f.hq, "HQ-01", "linux"), f.device(f.hq, "HQ-02", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{one, two}})
	if err != nil {
		t.Fatal(err)
	}
	// 64 KiB of random hex each, more than the archive buffers, so the
	// first run's files reach the client before the second run is read.
	outputs := map[uuid.UUID]string{}
	for _, d := range []uuid.UUID{one, two} {
		b := make([]byte, 32<<10)
		_, _ = rand.Read(b)
		outputs[d] = hex.EncodeToString(b)
		f.finish(d, f.runOn(job, d), outputs[d], "")
	}
	arc, err := f.svc.OutputArchive(f.ctx, super, job.ID)
	if err != nil {
		t.Fatal(err)
	}

	w := &blockingWriter{blocked: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- arc.Write(f.ctx, w) }()
	select {
	case <-w.blocked:
	case err := <-done:
		t.Fatalf("the archive was written without blocking: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the archive never wrote")
	}
	// The read of the first run's output has ended; poll briefly, as the
	// pool counts a connection released a moment after its transaction.
	deadline := time.Now().Add(5 * time.Second)
	for f.db.Pool.Stat().AcquiredConns() != 0 {
		if time.Now().After(deadline) {
			t.Errorf("%d connections held while the client is blocked", f.db.Pool.Stat().AcquiredConns())
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(w.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	files := archive(t, w.buf.Bytes())
	for _, d := range []uuid.UUID{one, two} {
		var name string
		for n := range files {
			if strings.HasSuffix(n, f.runOn(job, d).String()+"/stdout.txt") {
				name = n
			}
		}
		if files[name] != outputs[d] {
			t.Errorf("run on %s: %d bytes of stdout, want %d", d, len(files[name]), len(outputs[d]))
		}
	}
}
