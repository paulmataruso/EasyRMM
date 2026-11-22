package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// hangingCopies has the updater's copies run the real cp, made to read
// named pipes (--copy-contents), so that a copy reaching the pipe at fifo
// hangs there as a long copy would; and kills that cp with SIGTERM, as
// systemd's stop did when it signaled the unit's whole control group. It
// returns a channel that says when it has, or why it could not.
func hangingCopies(t *testing.T, fifo string) <-chan error {
	t.Helper()
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	pids := filepath.Join(t.TempDir(), "pids")
	wrapper := filepath.Join(t.TempDir(), "cp")
	writeFile(t, wrapper, fmt.Sprintf("#!/bin/sh\necho $$ >> %s\nexec cp --copy-contents \"$@\"\n", pids), 0o755)
	cpProgram = wrapper
	killed := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(time.Minute)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(pids)
			for _, f := range strings.Fields(string(data)) {
				pid, _ := strconv.Atoi(f)
				comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				args, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				// The cp itself, past its wrapper's exec, copying what
				// holds the pipe.
				if string(comm) == "cp\n" && bytes.Contains(args, []byte(filepath.Dir(fifo)+"\x00")) {
					killed <- syscall.Kill(pid, syscall.SIGTERM)
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		killed <- errors.New("no cp reached the pipe")
	}()
	return killed
}

// systemd's stop, with KillMode=control-group (or the out-of-memory killer,
// or an operator), kills a command the updater runs once the deployment has
// stopped: a real cp, in the backup and in the restore. That is not the
// version failing: the attempt stops where it is, the server held, and the
// next run finishes it from its record, without counting it against the
// version. A restore cut short is done again: the copy it left goes once
// the second is checked, and so do the deployment directory's copies.
func TestCutShortByASignal(t *testing.T) {
	t.Run("the backup's cp", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		was := cpProgram
		t.Cleanup(func() { cpProgram = was })
		h.offer("v1.1.0", nil)
		fifo := filepath.Join(h.dataRoot, "server", "pipe")
		killed := hangingCopies(t, fifo)
		err := h.upgrade(Request{Automatic: true})
		if kerr := <-killed; kerr != nil {
			t.Fatal(kerr)
		}
		cpProgram = was
		if err == nil || !strings.Contains(err.Error(), "signal: terminated") || !strings.Contains(err.Error(), "the attempt stops at its backup step, the server held, and the next run") {
			t.Fatalf("got %v", err)
		}
		st := h.state()
		if a := st.Attempt; a.Result != ResultRunning || a.Step != StepBackup || !strings.Contains(a.Interrupted, "signal: terminated") || st.HasFailed("v1.1.0") {
			t.Fatalf("attempt %+v, failed %v", a, st.Failed)
		}
		if len(h.docker.running) != 0 {
			t.Errorf("the attempt went on: %v runs", h.docker.running)
		}
		if err := os.Remove(fifo); err != nil {
			t.Fatal(err)
		}
		// The timer's next run finishes it: the incomplete backup goes,
		// v1.0.0 starts again, and v1.1.0 is not counted as failed.
		h.now = h.now.Add(time.Hour)
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		st = h.state()
		if a := st.Attempt; a.Result != ResultRolledBack || !strings.Contains(a.Reason, "the attempt stopped during the backup step: ") || st.HasFailed("v1.1.0") || h.docker.running["server"] != h.deploy("v1.0.0") {
			t.Fatalf("attempt %+v, failed %v, running %v", a, st.Failed, h.docker.running)
		}
		if left, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*")); len(left) != 0 {
			t.Errorf("left %v", left)
		}
		// And the run after that upgrades.
		if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Running != "v1.1.0" {
			t.Errorf("the next run: %v, running %s", err, h.state().Running)
		}
	})
	t.Run("the restore's cp", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		was := cpProgram
		t.Cleanup(func() { cpProgram = was })
		h.offer("v1.1.0", nil)
		var fifo string
		var killed <-chan error
		h.docker.fail = func(dir string, args []string) error {
			if dir != h.deploy("v1.1.0") || strings.Join(args, " ") != "compose exec -T server easyrmm-server healthcheck" {
				return nil
			}
			writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "written by v1.1.0", 0o600)
			// The restore copies the backup back, and hangs at the pipe.
			fifo = filepath.Join(h.state().Attempt.Backup, "data", "server", "pipe")
			killed = hangingCopies(t, fifo)
			return errors.New("the server is not ready")
		}
		err := h.upgrade(Request{Automatic: true})
		h.docker.fail = nil
		if killed == nil {
			t.Fatalf("the upgrade did not reach the held start: %v", err)
		}
		if kerr := <-killed; kerr != nil {
			t.Fatal(kerr)
		}
		cpProgram = was
		if err == nil || !strings.Contains(err.Error(), "signal: terminated") || !strings.Contains(err.Error(), "the attempt stops at its restore step") {
			t.Fatalf("got %v", err)
		}
		st := h.state()
		// v1.1.0 failed its health check before the restore began.
		if a := st.Attempt; a.Result != ResultRunning || a.Step != StepRestore || !strings.Contains(a.Interrupted, "signal: terminated") || !st.HasFailed("v1.1.0") || !h.statusDir().Held() {
			t.Fatalf("attempt %+v, failed %v, held %v", a, st.Failed, h.statusDir().Held())
		}
		if err := os.Remove(fifo); err != nil {
			t.Fatal(err)
		}
		// A copy of the deployment directory an earlier restore left.
		writeFile(t, filepath.Join(h.root, "easyrmm-v1.0.0", ".deploy.replaced-20261120T000000Z-v1.0.9", "x"), "x", 0o600)
		h.now = h.now.Add(time.Hour)
		psqlBefore := len(h.docker.psql)
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		st = h.state()
		if a := st.Attempt; a.Result != ResultRolledBack || !strings.Contains(a.Reason, "the attempt stopped during the restore step: ") || h.docker.running["server"] != h.deploy("v1.0.0") || h.statusDir().Held() {
			t.Fatalf("attempt %+v, running %v", a, h.docker.running)
		}
		if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" {
			t.Errorf("the data root holds %q", got)
		}
		// The failed version's data root is kept aside; the copy the
		// first restore left, and the deployment directory's copies, go.
		aside := filepath.Join(h.dataRoot, failedPrefix+"20261121T030000Z-v1.1.0")
		if got := readFile(t, filepath.Join(aside, "server", "data")); got != "written by v1.1.0" {
			t.Errorf("kept aside: %q", got)
		}
		left, _ := filepath.Glob(filepath.Join(h.dataRoot, failedPrefix+"*"))
		replaced, _ := filepath.Glob(filepath.Join(h.root, "easyrmm-v1.0.0", ".*.replaced-*"))
		if !slices.Equal(left, []string{aside}) || len(replaced) != 0 {
			t.Errorf("left %v and %v", left, replaced)
		}
		// The discarded head, read before the copy was killed, is not
		// read again from the half restored database.
		for _, sql := range h.docker.psql[psqlBefore:] {
			if strings.Contains(sql, "encode(entry_hash") {
				t.Error("the discarded database's head was read again")
			}
		}
	})
}

// A command killed by a signal is told apart from one that failed, and from
// one its own context stopped (a timeout kills with SIGKILL too).
func TestKilledCommands(t *testing.T) {
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "docker"), "#!/bin/sh\ncase \"$1\" in\nkill) kill -TERM $$ ;;\nsleep) sleep 10 ;;\nfail) exit 3 ;;\nesac\n", 0o755)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	var killed *killedError
	ctx := context.Background()
	if _, err := (ExecRunner{}).Run(ctx, "", nil, "kill"); !errors.As(err, &killed) || !strings.Contains(err.Error(), "signal: terminated") {
		t.Errorf("killed: %v", err)
	}
	if _, err := (ExecRunner{}).Run(ctx, "", nil, "fail"); err == nil || errors.As(err, &killed) {
		t.Errorf("failed: %v", err)
	}
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := (ExecRunner{}).Run(tctx, "", nil, "sleep"); err == nil || errors.As(err, &killed) {
		t.Errorf("timed out: %v", err)
	}
	if err := asKilled(ctx, errors.New("not a command's")); errors.As(err, &killed) {
		t.Errorf("another error: %v", err)
	}
	// setup.sh, too.
	deploy := filepath.Join(t.TempDir(), "deploy")
	writeFile(t, filepath.Join(deploy, "scripts", "setup.sh"), "#!/bin/sh\nkill -TERM $$\n", 0o755)
	lock, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := runSetup(ctx, deploy, lock, slog.New(slog.DiscardHandler)); !errors.As(err, &killed) || !strings.Contains(err.Error(), "setup.sh --upgrade failed (signal: terminated)") {
		t.Errorf("setup.sh killed: %v", err)
	}
}

// A stop asked for once the deployment has stopped (systemd's stop at a
// reboot) lets the attempt run on; when systemd kills it at its stop
// timeout, the next run finishes it, and does not count it against the
// version: the stop was recorded at once.
func TestStopAskedThenKilled(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopFilePath := filepath.Join(h.u.StateDir, stopFile)
	h.docker.fail = func(dir string, args []string) error {
		switch call := strings.Join(args, " "); {
		case dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up"):
			cancel()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if _, err := os.Stat(stopFilePath); err == nil {
					return nil
				}
			}
			t.Error("the stop asked for was not recorded")
		case dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck":
			// systemd's stop timeout: SIGKILL.
			runtime.Goexit()
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.u.Upgrade(ctx, Request{By: "automatic", Automatic: true})
	}()
	<-done
	h.docker.fail = nil
	if a := h.state().Attempt; a.Result != ResultRunning || a.Step != StepStart {
		t.Fatalf("after the kill: %+v", a)
	}
	h.now = h.now.Add(time.Hour)
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if a := st.Attempt; a.Result != ResultRolledBack || !strings.Contains(a.Reason, "the attempt stopped during the start-held step: a stop was asked for at 2026-11-21T03:00:00Z") || st.HasFailed("v1.1.0") {
		t.Fatalf("attempt %+v, failed %v", a, st.Failed)
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Running != "v1.1.0" {
		t.Errorf("the next run: %v, running %s", err, h.state().Running)
	}
	// A stop asked for before an attempt began does not count for it.
	if _, err := os.Stat(stopFilePath); err == nil {
		t.Error("the stop's record outlived the attempts")
	}
	writeFile(t, stopFilePath, "2026-11-21T02:00:00Z\n", 0o600)
	if got := h.u.stopAsked(&Attempt{Started: h.now}); got != "" {
		t.Errorf("an older stop: %q", got)
	}
}

// failSaves has the state's disk fail from the first save when (a step, or
// what an attempt records) holds; it returns a function that mends it.
func failSaves(t *testing.T, when func(*State) bool) func() {
	t.Helper()
	was := saveState
	failing := false
	saveState = func(st *State, dir string) error {
		if failing || when(st) {
			failing = true
			return errors.New("input/output error")
		}
		return was(st, dir)
	}
	mend := func() { saveState = was }
	t.Cleanup(mend)
	return mend
}

// The updater never changes the data root (starting the new version, or
// restoring) unless the step that says so is recorded: the next run
// finishes an attempt by its record. Before the set-up a step it cannot
// record ends the attempt, and the previous version starts again on its
// own data; from the set-up on, the attempt stops where it is, the server
// held, and status says why.
func TestUnrecordedStep(t *testing.T) {
	t.Run("the set-up", func(t *testing.T) {
		// The reviewer's case: the record fails once the backup is taken,
		// and the process is killed; the next run, reading the backup
		// step, starts v1.0.0 again, which must find its own data, not
		// v1.1.0's migrated over it.
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		mend := failSaves(t, func(st *State) bool { return st.Attempt != nil && st.Attempt.Step == StepSetUp })
		err := h.upgrade(Request{Automatic: true})
		if err == nil || !strings.Contains(err.Error(), "could not record the set-up step: input/output error") {
			t.Fatalf("got %v", err)
		}
		if n := h.docker.called(h.deploy("v1.1.0") + ": compose up"); n != 0 || h.docker.running["server"] != h.deploy("v1.0.0") || h.statusDir().Held() {
			t.Errorf("v1.1.0 started %d times, running %v, held %v", n, h.docker.running, h.statusDir().Held())
		}
		mend()
		if a := h.state().Attempt; a.Result != ResultRunning || a.Step != StepBackup {
			t.Fatalf("recorded %+v", a)
		}
		h.now = h.now.Add(time.Hour)
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" || h.docker.running["server"] != h.deploy("v1.0.0") || h.state().HasFailed("v1.1.0") {
			t.Errorf("the data root holds %q, running %v, failed %v", got, h.docker.running, h.state().Failed)
		}
	})
	for name, tc := range map[string]struct {
		when func(*State) bool
		step string // recorded last
		says string
	}{
		"the held start": {
			when: func(st *State) bool { return st.Attempt != nil && st.Attempt.Step == StepStart },
			step: StepSetUp, says: "could not record the start-held step",
		},
		"the restore's end": {
			when: func(st *State) bool { return st.Attempt != nil && st.Attempt.Restored },
			step: StepRestore, says: "could not record the restore's end",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", nil)
			mend := failSaves(t, tc.when)
			if tc.step == StepRestore {
				h.docker.fail = failing(func(dir, call string) bool {
					return dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck"
				})
			}
			err := h.upgrade(Request{Automatic: true})
			h.docker.fail = nil
			if err == nil || !strings.Contains(err.Error(), tc.says) || !strings.Contains(err.Error(), "the attempt stops at its "+tc.step+" step, the server held") {
				t.Fatalf("got %v", err)
			}
			// Nothing started after the step not recorded; the hold stays.
			if !h.statusDir().Held() || h.docker.running["server"] != "" && tc.step == StepSetUp {
				t.Errorf("held %v, running %v", h.statusDir().Held(), h.docker.running)
			}
			mend()
			if a := h.state().Attempt; a.Result != ResultRunning || a.Step != tc.step || a.Restored {
				t.Fatalf("recorded %+v", a)
			}
			// status.json, which the console reads, and status say why.
			if status := readFile(t, h.statusDir().path(StatusFile)); !strings.Contains(status, `"interrupted": "`) || !strings.Contains(status, tc.says) {
				t.Errorf("status.json:\n%s", status)
			}
			s, err := h.u.Status(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			s.Write(&out)
			if !strings.Contains(out.String(), "No updater runs: the attempt stopped there (") || !strings.Contains(out.String(), tc.says+": input/output error). The next run") || !strings.Contains(out.String(), "Held:        true") {
				t.Errorf("status:\n%s", out.String())
			}
			// The next run finishes it from the record.
			h.now = h.now.Add(time.Hour)
			if err := h.upgrade(Request{Automatic: true}); err != nil {
				t.Fatal(err)
			}
			st := h.state()
			if st.Attempt.Result != ResultRolledBack || h.docker.running["server"] != h.deploy("v1.0.0") || h.statusDir().Held() {
				t.Errorf("attempt %+v, running %v", st.Attempt, h.docker.running)
			}
			if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" {
				t.Errorf("the data root holds %q", got)
			}
		})
	}
}

// What the updater writes is on its disk before it relies on it: a file it
// renames into place with its directory, a backup before backup.json marks
// it complete (and so before the set-up), and a restore's copies before the
// restore is recorded as done.
func TestDurability(t *testing.T) {
	wasDir, wasFS := syncDir, syncFS
	t.Cleanup(func() { syncDir, syncFS = wasDir, wasFS })
	// The real ones.
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := syncFS(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if syncDir("/nonexistent") == nil || syncFS("/nonexistent") == nil {
		t.Error("synced what is not there")
	}
	dir := t.TempDir()
	var synced []string
	syncDir = func(d string) error {
		synced = append(synced, d+": "+readFile(t, filepath.Join(d, "f")))
		return nil
	}
	if err := writeFileAtomic(filepath.Join(dir, "f"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(synced, []string{dir + ": new"}) {
		t.Errorf("synced %v", synced)
	}
	syncDir = func(string) error { return errors.New("input/output error") }
	if err := writeFileAtomic(filepath.Join(dir, "f"), []byte("newer"), 0o600); err == nil || !strings.Contains(err.Error(), "syncing "+dir) {
		t.Errorf("a directory that could not be synced: %v", err)
	}
	syncDir = wasDir

	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	var events []string
	syncFS = func(path string) error {
		_, err := os.Stat(filepath.Join(path, "backup.json"))
		a := h.state().Attempt
		events = append(events, fmt.Sprintf("%s at %s, complete %v, restored %v", path, a.Step, err == nil, a.Restored))
		return nil
	}
	h.docker.fail = failing(func(dir, call string) bool {
		return dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck"
	})
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "rolled-back") {
		t.Fatalf("got %v", err)
	}
	backup := h.state().Attempt.Backup
	want := []string{
		backup + " at backup, complete false, restored false",
		h.dataRoot + " at restore, complete false, restored false",
		filepath.Join(h.root, "easyrmm-v1.0.0") + " at restore, complete false, restored false",
	}
	if !slices.Equal(events, want) {
		t.Errorf("synced\n%s\nnot\n%s", strings.Join(events, "\n"), strings.Join(want, "\n"))
	}
	// A backup that cannot be synced fails, before the set-up.
	h = newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	syncFS = func(string) error { return errors.New("input/output error") }
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "syncing the backup to its disk") || h.docker.called(h.deploy("v1.1.0")+": compose up") != 0 {
		t.Errorf("got %v", err)
	}
}

// systemd's stop (at a reboot, or by hand) signals the updater alone, which
// runs on to the attempt's end, or brings the previous version back, while
// its commands run on; it kills them all at TimeoutStopSec, which the
// next run settles (docs/operations/updater.md#interrupted-attempts).
func TestServiceStopsTheUpdaterAlone(t *testing.T) {
	unit := readFile(t, "../../../deploy/updater/easyrmm-updater.service")
	for _, want := range []string{"\nKillMode=mixed\n", "\nTimeoutStopSec=30min\n", "\nTimeoutStartSec=infinity\n"} {
		if !strings.Contains(unit, want) {
			t.Errorf("easyrmm-updater.service lacks %q", strings.TrimSpace(want))
		}
	}
	if doc := readFile(t, "../../../docs/operations/updater.md"); !strings.Contains(doc, "`TimeoutStopSec=30min`") {
		t.Error("updater.md does not say why the stop timeout is 30 minutes")
	}
	// The real systemd, where there is one, reads the unit as written.
	if _, err := exec.LookPath("systemd-analyze"); err == nil {
		if out, err := exec.Command("systemd-analyze", "verify", "--man=no", "../../../deploy/updater/easyrmm-updater.service").CombinedOutput(); err != nil && bytes.Contains(out, []byte("KillMode")) {
			t.Errorf("systemd-analyze: %s", out)
		}
	}
}

// A restore done again, after one cut short, finds what the first moved
// aside: the failed version's data root stays as it was moved, whether the
// first was cut short while moving it or while copying the backup in; the
// copy the first left goes once the second is done.
func TestRestoreDoneAgain(t *testing.T) {
	for name, first := range map[string]func(t *testing.T, root, aside string){
		"cut short while moving": func(t *testing.T, root, aside string) {
			// postgres moved aside, server not yet.
			if err := os.Rename(filepath.Join(root, "postgres"), filepath.Join(aside, "postgres")); err != nil {
				t.Fatal(err)
			}
		},
		"cut short while copying": func(t *testing.T, root, aside string) {
			for _, e := range []string{"postgres", "server"} {
				if err := os.Rename(filepath.Join(root, e), filepath.Join(aside, e)); err != nil {
					t.Fatal(err)
				}
			}
			// postgres copied back, server half.
			writeFile(t, filepath.Join(root, "postgres", "db"), "the backup's", 0o600)
			writeFile(t, filepath.Join(root, "server", "half"), "half", 0o600)
		},
		"cut short again": func(t *testing.T, root, aside string) {
			for _, e := range []string{"postgres", "server"} {
				if err := os.Rename(filepath.Join(root, e), filepath.Join(aside, e)); err != nil {
					t.Fatal(err)
				}
			}
			// A restore done again, itself cut short.
			writeFile(t, filepath.Join(root+"/"+failedPrefix+"stamp.half-restored", "server", "half"), "half", 0o600)
			writeFile(t, filepath.Join(root, "server", "half"), "half", 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "srv")
			writeFile(t, filepath.Join(root, "postgres", "db"), "the failed version's", 0o600)
			writeFile(t, filepath.Join(root, "server", "data"), "the failed version's", 0o600)
			writeFile(t, filepath.Join(root, "updater", "status", "status.json"), "{}", 0o644)
			b := &Backup{Dir: t.TempDir()}
			writeFile(t, filepath.Join(b.Dir, "data", "postgres", "db"), "the backup's", 0o600)
			writeFile(t, filepath.Join(b.Dir, "data", "server", "data"), "the backup's", 0o600)
			aside := filepath.Join(root, failedPrefix+"stamp")
			if err := os.Mkdir(aside, 0o700); err != nil {
				t.Fatal(err)
			}
			first(t, root, aside)
			got, err := b.restoreData(t.Context(), root, "stamp")
			if err != nil || got != aside {
				t.Fatalf("%s, %v", got, err)
			}
			for path, want := range map[string]string{
				filepath.Join(root, "postgres", "db"):                   "the backup's",
				filepath.Join(root, "server", "data"):                   "the backup's",
				filepath.Join(aside, "postgres", "db"):                  "the failed version's",
				filepath.Join(aside, "server", "data"):                  "the failed version's",
				filepath.Join(root, "updater", "status", "status.json"): "{}",
			} {
				if got := readFile(t, path); got != want {
					t.Errorf("%s holds %q", path, got)
				}
			}
			entries, _ := os.ReadDir(root)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if !slices.Equal(names, []string{failedPrefix + "stamp", "postgres", "server", "updater"}) {
				t.Errorf("the data root holds %v", names)
			}
			if _, err := os.Stat(filepath.Join(root, "server", "half")); err == nil {
				t.Error("the copy cut short is left in the data root")
			}
		})
	}
}

// setupLock runs setup.sh's updater_lock with the updater's state in state,
// as root's setup.sh does first; then says whether the lock is held, as a
// new open of it finds.
func setupLock(t *testing.T, state string, env []string, extra ...*os.File) (string, error) {
	t.Helper()
	script := readFile(t, "../../../deploy/scripts/setup.sh")
	start := strings.Index(script, "\nupdater_lock() {\n")
	end := strings.Index(script[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("setup.sh has no updater_lock")
	}
	harness := fmt.Sprintf(`set -euo pipefail
die() { echo "error: $*" >&2; exit 1; }
install_updater=false
updater_state=%s
%s
updater_lock
if [[ ! -e "$updater_state/lock" ]]; then echo "no lock"; elif flock -n -o "$updater_state/lock" true; then echo free; else echo held; fi
`, state, script[start+1:start+end+3])
	cmd := exec.Command("bash", "-c", harness)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	cmd.ExtraFiles = extra
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// setup.sh, run as root, holds the updater's lock for its whole run, so
// it changes nothing while an attempt runs; the updater, which runs the new
// version's setup.sh --upgrade under its lock, hands the lock over, and
// neither waits for the other.
func TestSetupHoldsTheUpdatersLock(t *testing.T) {
	script := readFile(t, "../../../deploy/scripts/setup.sh")
	locks := strings.Index(script, "\n[[ $(id -u) -ne 0 ]] || updater_lock\n")
	for _, change := range []string{"\nif [[ \"$new_invitation\" == true ]]; then", "\nif [[ -e .env ]]; then", "\nfill_secret EASYPATCH", "\ninstall -d -m 0755 \"$data_root\"", "\n[[ \"$install_updater\" != true ]] || updater_install"} {
		if at := strings.Index(script, change); locks < 0 || at < locks {
			t.Errorf("setup.sh changes something (%s) before it takes the updater's lock", strings.TrimSpace(change))
		}
	}
	state := t.TempDir()
	lockPath := filepath.Join(state, "lock")
	open := func() *os.File {
		f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	// No attempt runs: setup.sh holds it.
	if out, err := setupLock(t, state, nil); err != nil || out != "held" {
		t.Errorf("free: %s, %v", out, err)
	}
	// An attempt holds it: setup.sh stops before it changes anything.
	attempt := open()
	if err := syscall.Flock(int(attempt.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if out, err := setupLock(t, state, nil); err == nil || out != "error: an updater attempt is running (easyrmm-updater status): setup.sh changes nothing while one does. Run it again once it has ended." {
		t.Errorf("held by an attempt: %s, %v", out, err)
	}
	// The attempt hands it to the setup.sh it runs, which takes it at once,
	// and leaves it held.
	if out, err := setupLock(t, state, []string{"EASYRMM_UPDATER_LOCK_FD=3"}, attempt); err != nil || out != "held" {
		t.Errorf("handed over: %s, %v", out, err)
	}
	if err := syscall.Flock(int(open().Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Error("setup.sh released the attempt's lock")
	}
	// Anything else handed over is refused.
	other, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, fd := range []string{"3", "3; true", "9"} {
		if out, err := setupLock(t, state, []string{"EASYRMM_UPDATER_LOCK_FD=" + fd}, other); err == nil || !strings.Contains(out, "is not the updater's lock, "+lockPath) {
			t.Errorf("%s handed over: %s, %v", fd, out, err)
		}
	}
	// No updater on the host, and none installed: no lock.
	if out, err := setupLock(t, filepath.Join(t.TempDir(), "none"), nil); err != nil || out != "no lock" {
		t.Errorf("no updater: %s, %v", out, err)
	}
}
