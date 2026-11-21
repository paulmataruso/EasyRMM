package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// crashAt runs an upgrade whose process dies (runtime.Goexit: deferred
// calls run, as the kernel releases the lock of a killed process) at the
// first docker command crash matches. What the process had in memory is
// lost; only what it recorded remains, and the containers Docker runs: a
// reboot restarts them (restart: unless-stopped).
func (h *testHost) crashAt(req Request, crash func(dir, call string) bool, fail func(dir, call string) bool) {
	h.t.Helper()
	crashed := false
	h.docker.fail = func(dir string, args []string) error {
		call := strings.Join(args, " ")
		if !crashed && crash(dir, call) {
			crashed = true
			runtime.Goexit()
		}
		if fail != nil && fail(dir, call) {
			return errors.New("docker failed: " + call)
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.upgrade(req)
	}()
	<-done
	h.docker.fail = nil
	if !crashed {
		h.t.Fatal("the upgrade did not reach the crash")
	}
	if st := h.state(); st.Attempt.Result != ResultRunning {
		h.t.Fatalf("after the crash the attempt is %s", st.Attempt.Result)
	}
	h.now = h.now.Add(time.Hour)
}

// The next run finishes an attempt whose process died, by what it
// recorded: wherever it died, the previous version runs again, with its
// data, unheld, and the attempt ends.
func TestInterruptedAttemptIsFinished(t *testing.T) {
	newServerReady := func(h *testHost) func(dir, call string) bool {
		return func(dir, call string) bool {
			return dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck"
		}
	}
	for name, tc := range map[string]struct {
		crash, fail func(h *testHost) func(dir, call string) bool
		result      string
		failed      bool // v1.1.0 skipped by automatic upgrades
		restored    bool // the backup restored, the audit IDs moved
		headRead    bool // the discarded head read by the run that died
	}{
		"during the pull": {
			crash: func(*testHost) func(dir, call string) bool {
				return func(_, call string) bool { return call == "compose pull --quiet" }
			},
			result: ResultFailed,
		},
		"while stopping": {
			crash: func(*testHost) func(dir, call string) bool {
				return func(_, call string) bool { return strings.HasPrefix(call, "ps -q") }
			},
			result: ResultRolledBack,
		},
		"during the held start": {
			crash: newServerReady, result: ResultRolledBack, failed: true, restored: true, headRead: true,
		},
		"while starting the worker before the confirm was recorded": {
			crash: func(h *testHost) func(dir, call string) bool {
				return func(dir, call string) bool {
					return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up") && strings.HasSuffix(call, " "+workerService)
				}
			},
			result: ResultRolledBack, failed: true, restored: true, headRead: true,
		},
		"during the restore": {
			crash: func(h *testHost) func(dir, call string) bool {
				return func(dir, call string) bool {
					return dir == h.deploy("v1.0.0") && strings.HasPrefix(call, "compose up") && strings.HasSuffix(call, " postgres")
				}
			},
			fail:   newServerReady,
			result: ResultRolledBack, failed: true, restored: true, headRead: true,
		},
		"once the restore had put everything back": {
			crash: func(h *testHost) func(dir, call string) bool {
				return func(dir, call string) bool {
					return dir == h.deploy("v1.0.0") && strings.HasPrefix(call, "compose up") && strings.HasSuffix(call, " server")
				}
			},
			fail:   newServerReady,
			result: ResultRolledBack, failed: true, restored: true, headRead: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", nil)
			var fail func(dir, call string) bool
			if tc.fail != nil {
				fail = tc.fail(h)
			}
			h.crashAt(Request{Automatic: true}, tc.crash(h), func(dir, call string) bool {
				if fail != nil && fail(dir, call) {
					// The new version had written to the data root.
					writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "written by v1.1.0", 0o600)
					return true
				}
				return false
			})
			before := h.state().Attempt
			psqlBefore := len(h.docker.psql)
			// The next run finishes it, and does nothing else.
			if err := h.upgrade(Request{Automatic: true}); err != nil {
				t.Fatal(err)
			}
			st := h.state()
			a := st.Attempt
			if a.ID != before.ID || a.Result != tc.result || !strings.Contains(a.Reason, "the updater's process ended during the "+before.Step+" step") {
				t.Fatalf("attempt %+v", a)
			}
			if st.Running == "v1.1.0" || st.HasFailed("v1.1.0") != tc.failed || h.u.Config.Deployment != h.deploy("v1.0.0") || h.statusDir().Held() {
				t.Errorf("state %+v, deployment %s, held %v", st, h.u.Config.Deployment, h.statusDir().Held())
			}
			for svc, dir := range h.docker.running {
				if dir != h.deploy("v1.0.0") {
					t.Errorf("%s runs from %s", svc, dir)
				}
			}
			if h.docker.running["server"] == "" || h.docker.running[workerService] == "" {
				t.Errorf("not everything runs: %v", h.docker.running)
			}
			if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" {
				t.Errorf("the data root holds %q", got)
			}
			if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil || slices.Contains(st.Unpacked, filepath.Join(h.root, "easyrmm-v1.1.0")) {
				t.Errorf("the new version's directory is left: %v", st.Unpacked)
			}
			backups, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*"))
			for _, b := range backups {
				if _, err := openBackup(b); err != nil {
					t.Errorf("an incomplete backup is left: %s", b)
				}
			}
			if !tc.restored {
				if len(h.docker.psql) != psqlBefore {
					t.Errorf("a restore ran: %v", h.docker.psql[psqlBefore:])
				}
				return
			}
			// The rollback is recorded once, past the head the run that
			// died read: a restore done again does not read the half
			// restored database's head.
			var records []map[string]string
			for i, sql := range h.docker.psql {
				if strings.Contains(sql, "'updater.rolled_back'") {
					records = append(records, h.docker.vars[i])
				}
			}
			if len(records) == 0 {
				t.Fatal("no rollback recorded")
			}
			last := records[len(records)-1]
			if tc.headRead && (last["skip_to"] != "42" || last["margin"] != "0") {
				t.Errorf("vars %v", last)
			}
			if name == "once the restore had put everything back" && len(h.docker.psql) != psqlBefore {
				t.Errorf("the restore was done again: %v", h.docker.psql[psqlBefore:])
			}
		})
	}
}

// The reviewer's case, as it was: the process dies during the held start
// and Docker restarts the new version's containers. The next run must not
// take the new server's answer for the running version and stop there: it
// restores the previous version.
func TestInterruptedHeldStartAfterAReboot(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.crashAt(Request{Automatic: true}, func(dir, call string) bool {
		return dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck"
	}, nil)
	if !h.statusDir().Held() || h.docker.running["server"] != h.deploy("v1.1.0") {
		t.Fatalf("after the crash: held %v, running %v", h.statusDir().Held(), h.docker.running)
	}
	// status says so, but not while an updater holds the lock.
	interrupted := func() string {
		s, err := h.u.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var out strings.Builder
		s.Write(&out)
		return out.String()
	}
	const says = "No updater runs: its process ended before the attempt did. The next run (the timer's, or easyrmm-updater upgrade) finishes it."
	if out := interrupted(); !strings.Contains(out, says) || !strings.Contains(out, "running at start-held") {
		t.Errorf("status:\n%s", out)
	}
	unlock, err := h.u.lock()
	if err != nil {
		t.Fatal(err)
	}
	if out := interrupted(); strings.Contains(out, says) {
		t.Errorf("status while the lock is held:\n%s", out)
	}
	unlock()
	// A run by hand finishes it first, and says so.
	err = h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")})
	if err == nil || !strings.Contains(err.Error(), "finished an attempt whose process had ended (upgrade from v1.0.0 to v1.1.0, at its start-held step): rolled-back; nothing else was done: run the command again") {
		t.Fatalf("got %v", err)
	}
	if h.statusDir().Held() || h.docker.running["server"] != h.deploy("v1.0.0") || h.state().Running != "v1.0.0" {
		t.Errorf("held %v, running %v", h.statusDir().Held(), h.docker.running)
	}
	// Asked for by name again, it is tried again.
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
		t.Fatal(err)
	}
	if h.state().Running != "v1.1.0" {
		t.Errorf("running %s", h.state().Running)
	}
}

// An attempt killed during its backup leaves an incomplete backup, which
// the next run removes before it starts the previous version again.
func TestInterruptedBackup(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.crashAt(Request{Automatic: true}, func(_, call string) bool { return strings.HasPrefix(call, "ps -q") }, nil)
	// What the process recorded once its backup was under way.
	st := h.state()
	st.Attempt.Step = StepBackup
	st.Attempt.Backup = filepath.Join(h.u.Config.BackupDir, "20261121T030000Z-v1.0.0")
	writeFile(t, filepath.Join(st.Attempt.Backup, "data", "server", "data"), "half copied", 0o600)
	if err := st.save(h.u.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	st = h.state()
	if st.Attempt.Result != ResultRolledBack || st.HasFailed("v1.1.0") || h.docker.running["server"] != h.deploy("v1.0.0") {
		t.Errorf("attempt %+v, running %v", st.Attempt, h.docker.running)
	}
	if _, err := os.Stat(st.Attempt.Backup); err == nil {
		t.Error("the incomplete backup is left")
	}
	// Not counted against the version: the next automatic run upgrades.
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Running != "v1.1.0" {
		t.Errorf("the next run: %v, running %s", err, h.state().Running)
	}
}

// A rollback asked for and killed halfway is finished by the next run.
func TestInterruptedRollback(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	ctx := context.Background()
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "written by v1.1.0", 0o600)
	h.docker.fail = func(dir string, args []string) error {
		if dir == h.deploy("v1.0.0") && strings.Join(args, " ") == "compose up --detach --remove-orphans --wait --wait-timeout 180 postgres" {
			runtime.Goexit()
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.u.Rollback(ctx, "root on the host", false)
	}()
	<-done
	h.docker.fail = nil
	if a := h.state().Attempt; a.Action != "rollback" || a.Result != ResultRunning || a.Step != StepRestore {
		t.Fatalf("after the crash: %+v", a)
	}
	// The timer's next run finishes it.
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Attempt.Action != "rollback" || st.Attempt.Result != ResultRolledBack || st.Running != "v1.0.0" || st.Rollback != nil || !st.HasFailed("v1.1.0") {
		t.Errorf("state %+v, attempt %+v", st, st.Attempt)
	}
	if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" || h.docker.running["server"] != h.deploy("v1.0.0") {
		t.Errorf("the data root holds %q, running %v", got, h.docker.running)
	}
}

// After an attempt whose rollback failed the updater does nothing, by the
// timer or by hand, until an operator says the deployment is repaired: no
// upgrade on top of a broken deployment, and no backup rotated away.
func TestRollbackFailedStopsTheUpdater(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	ctx := context.Background()
	h.offer("v1.1.0", nil)
	h.docker.fail = failing(func(_, call string) bool {
		return strings.HasPrefix(call, "compose up") && strings.Contains(call, "server")
	})
	if err := h.upgrade(Request{Automatic: true}); err == nil || !strings.Contains(err.Error(), "rollback-failed") {
		t.Fatalf("got %v", err)
	}
	h.docker.fail = nil
	failed := h.state().Attempt
	backups, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*"))
	h.now = h.now.Add(time.Hour)
	h.offer("v1.2.0", nil)
	for _, req := range []Request{{Automatic: true}, {}, {Version: release.MustParseVersion("v1.2.0")}} {
		err := h.upgrade(req)
		if err == nil || !strings.Contains(err.Error(), "ended rollback-failed") || !strings.Contains(err.Error(), "--deployment-repaired") {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if err := h.u.Rollback(ctx, "x", false); err == nil || !strings.Contains(err.Error(), "--deployment-repaired") {
		t.Errorf("rollback: %v", err)
	}
	if _, err := h.u.PlanRollback(ctx, false); err == nil || !strings.Contains(err.Error(), "--deployment-repaired") {
		t.Errorf("rollback plan: %v", err)
	}
	if after, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*")); !slices.Equal(after, backups) || h.state().Attempt.ID != failed.ID {
		t.Errorf("backups %v, then %v", backups, after)
	}
	s, err := h.u.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	s.Write(&out)
	if !strings.Contains(out.String(), "does nothing more until the deployment is repaired by hand") {
		t.Errorf("status:\n%s", out.String())
	}
	// The operator repairs it by hand, as the guide says, and says so.
	h.docker.running = map[string]string{}
	if err := h.u.Docker.Start(ctx, h.deploy("v1.0.0"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := h.statusDir().Unhold(); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{Repaired: true, By: "root on the host"}); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Running != "v1.2.0" || st.Attempt.To != "v1.2.0" || st.Attempt.Result != ResultSucceeded {
		t.Errorf("state %+v, attempt %+v", st, st.Attempt)
	}
	// The failed attempt's backup, the one good copy while it was
	// unresolved, is kept.
	if _, err := openBackup(failed.Backup); err != nil {
		t.Errorf("the failed attempt's backup: %v", err)
	}
}

// The confirm records the new deployment before it lifts the hold, and
// lifts it only once the confirmed upgrade is recorded: a confirm that
// fails before then leaves the server held, never a version serving that
// the updater has not recorded.
func TestConfirmLiftsTheHoldLast(t *testing.T) {
	worker := func(h *testHost, dir, call string) bool {
		return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up") && strings.HasSuffix(call, " "+workerService)
	}
	t.Run("the deployment not recorded", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		conf := h.u.Config.Path
		var heldAtRestore []bool
		restoring := false
		h.docker.fail = func(dir string, args []string) error {
			call := strings.Join(args, " ")
			switch {
			case worker(h, dir, call):
				// updater.conf cannot be rewritten.
				if err := os.Rename(conf, conf+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(conf, 0o700); err != nil {
					t.Fatal(err)
				}
			case call == "compose stop" && dir == h.deploy("v1.1.0") && !restoring:
				restoring = true
				heldAtRestore = append(heldAtRestore, h.statusDir().Held())
				if err := os.Remove(conf); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(conf+".saved", conf); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		}
		if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "rolled-back") {
			t.Fatalf("got %v", err)
		}
		if !slices.Equal(heldAtRestore, []bool{true}) {
			t.Errorf("held when the restore began: %v", heldAtRestore)
		}
	})
	t.Run("the confirm not recorded", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		state := filepath.Join(h.u.StateDir, "state.json")
		h.docker.fail = func(dir string, args []string) error {
			if worker(h, dir, strings.Join(args, " ")) {
				// state.json cannot be written.
				if err := os.Rename(state, state+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(state, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			return nil
		}
		if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "recording the confirmed upgrade") {
			t.Fatalf("got %v", err)
		}
		h.docker.fail = nil
		if !h.statusDir().Held() {
			t.Error("a version the updater has not recorded serves")
		}
		if err := os.Remove(state); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(state+".saved", state); err != nil {
			t.Fatal(err)
		}
		// The next run restores the previous version.
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		if st := h.state(); st.Running != "v1.0.0" || st.Attempt.Result != ResultRolledBack || h.statusDir().Held() || h.docker.running["server"] != h.deploy("v1.0.0") {
			t.Errorf("attempt %+v, running %v", st.Attempt, h.docker.running)
		}
	})
	t.Run("the hold not lifted", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
		// The process ended between the record and the hold's lifting.
		if err := h.statusDir().Hold(); err != nil {
			t.Fatal(err)
		}
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		if h.statusDir().Held() || h.state().Running != "v1.1.0" {
			t.Errorf("held %v, running %s", h.statusDir().Held(), h.state().Running)
		}
	})
}

// A stop asked for (Ctrl-C, systemd's stop) ends an attempt that has not
// stopped the deployment, changing nothing and not counting against the
// version; once it has, the attempt runs on to its end.
func TestStopAskedFor(t *testing.T) {
	for name, tc := range map[string]struct {
		at      func(h *testHost, dir, call string) bool
		running string
	}{
		"before the stop": {at: func(_ *testHost, _, call string) bool { return call == "compose pull --quiet" }, running: "v1.0.0"},
		"after the stop": {at: func(h *testHost, dir, call string) bool {
			return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up")
		}, running: "v1.1.0"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.docker.fail = func(dir string, args []string) error {
				if tc.at(h, dir, strings.Join(args, " ")) {
					cancel()
				}
				return nil
			}
			err := h.u.Upgrade(ctx, Request{By: "a test"})
			st := h.state()
			if st.Running != tc.running && (tc.running != "v1.0.0" || st.Running != "") {
				t.Errorf("running %s: %v", st.Running, err)
			}
			if tc.running == "v1.0.0" && (err == nil || h.docker.called("compose stop") != 0 || st.HasFailed("v1.1.0") || st.Attempt.Result != ResultFailed) {
				t.Errorf("err %v, attempt %+v, failed %v", err, st.Attempt, st.Failed)
			}
		})
	}
}

// The updater that could not replace itself at the confirm says so, in the
// attempt and the status; the next run re-installs it from the running
// version's verified bundle, and leaves it once it is.
func TestFailedSelfReplacement(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.u.Self = release.MustParseVersion("v1.0.0")
	h.offer("v1.1.0", nil)
	sbin := filepath.Dir(h.u.Install.Binary)
	if err := os.Rename(sbin, sbin+".away"); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Attempt.Result != ResultSucceeded || !strings.Contains(st.Attempt.Warning, "the updater could not replace itself with v1.1.0's") {
		t.Fatalf("attempt %+v", st.Attempt)
	}
	if status := readFile(t, h.statusDir().path(StatusFile)); !strings.Contains(status, `"warning": "the updater could not replace itself`) {
		t.Errorf("status.json:\n%s", status)
	}
	s, err := h.u.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	s.Write(&out)
	if !strings.Contains(out.String(), "Warning: the updater could not replace itself") {
		t.Errorf("status:\n%s", out.String())
	}
	if err := os.Rename(sbin+".away", sbin); err != nil {
		t.Fatal(err)
	}
	// The old updater runs next: it re-installs the new one, and stops.
	h.installs = nil
	err = h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "re-installed the updater from v1.1.0's bundle (it was v1.0.0's)") {
		t.Fatalf("got %v", err)
	}
	if got := readFile(t, h.u.Install.Binary); got != "updater of v1.1.0" || !slices.Equal(h.installs, []string{"daemon-reload"}) {
		t.Errorf("installed %q, systemctl %v", got, h.installs)
	}
	// The same binary is not installed again.
	if err := h.upgrade(Request{Automatic: true}); err != nil || len(h.installs) != 1 {
		t.Errorf("again: %v, systemctl %v", err, h.installs)
	}
	// Nor from a deployment set up by hand.
	h = newTestHost(t, "v1.0.0", release.ChannelStable)
	h.u.Self = release.MustParseVersion("v0.9.0")
	st = &State{Running: "v1.0.0"}
	if err := os.Mkdir(h.u.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(h.u.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{}); err != nil || len(h.installs) != 0 {
		t.Errorf("from a deployment set up by hand: %v, %v", err, h.installs)
	}
}
