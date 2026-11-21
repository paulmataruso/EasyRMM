package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const buildName = "easyrmm-agent-linux-amd64"

var (
	oldBuild = []byte("the running build")
	newBuild = []byte("the new build, a little longer")
)

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type client struct {
	files     map[string][]byte
	err       error
	downloads int
}

func (c *client) Download(_ context.Context, file string, w io.Writer) error {
	c.downloads++
	if c.err != nil {
		return c.err
	}
	b, ok := c.files[file]
	if !ok {
		return errors.New("404 Not Found")
	}
	_, err := w.Write(b)
	return err
}

type jobs struct {
	paused, busy bool
	resumes      int
}

func (j *jobs) Pause()     { j.paused = true }
func (j *jobs) Resume()    { j.paused = false; j.resumes++ }
func (j *jobs) Busy() bool { return j.busy }

type fixture struct {
	t        *testing.T
	exe, dir string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	client   *client
	jobs     *jobs
	now      time.Time
	probeOut string
	probeErr error
	probed   []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		t: t, exe: filepath.Join(root, "bin", "easyrmm-agent"), dir: filepath.Join(root, "state"),
		client: &client{files: map[string][]byte{buildName: newBuild}}, jobs: &jobs{},
		now:      time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC),
		probeOut: "easyrmm-agent v2 (" + runtime.GOOS + "/" + runtime.GOARCH + ")\n",
	}
	f.pub, f.priv, _ = ed25519.GenerateKey(nil)
	for _, d := range []string{filepath.Dir(f.exe), f.dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.write(f.exe, oldBuild)
	return f
}

func (f *fixture) write(name string, b []byte) {
	f.t.Helper()
	if err := os.WriteFile(name, b, 0o755); err != nil { //nolint:gosec // a test executable
		f.t.Fatal(err)
	}
}

func (f *fixture) read(name string) string {
	b, err := os.ReadFile(name) //nolint:gosec // test files
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// updater is the agent running build b, as version v.
func (f *fixture) updater(b []byte, v string) *Updater {
	return &Updater{
		Client: f.client, DeviceID: "dev-1", Key: func() ed25519.PublicKey { return f.pub },
		Version: v, SHA256: digest(b), Exe: f.exe, Dir: f.dir, Jobs: f.jobs,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Probe: func(_ context.Context, exe string) (string, error) {
			f.probed = append(f.probed, exe)
			if got, _ := os.ReadFile(exe); !bytes.Equal(got, f.client.files[buildName]) { //nolint:gosec // test files
				f.t.Errorf("probed %q", got)
			}
			return f.probeOut, f.probeErr
		},
		Now: func() time.Time { return f.now },
	}
}

// instruction signs an update to the new build.
func (f *fixture) instruction(id string, mutate ...func(*agentproto.UpdatePayload)) *agentproto.SignedUpdate {
	f.t.Helper()
	p := agentproto.UpdatePayload{
		V: agentproto.UpdatePayloadVersion, ID: id, DeviceID: "dev-1", File: buildName,
		Size: int64(len(newBuild)), SHA256: digest(newBuild), Version: "v2",
		IssuedAt: f.now, ExpiresAt: f.now.Add(10 * time.Minute),
	}
	for _, m := range mutate {
		m(&p)
	}
	s, err := agentproto.SignUpdate(f.priv, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

func TestApplyAndConfirm(t *testing.T) {
	f := newFixture(t)
	u := f.updater(oldBuild, "v1")
	if u.Settle() {
		t.Fatal("Settle restarts without an update")
	}
	if !u.Apply(context.Background(), f.instruction("a1")) {
		t.Fatalf("not applied; report %+v", u.Report())
	}
	if f.read(f.exe) != string(newBuild) || f.read(f.exe+".old") != string(oldBuild) || exists(f.exe+".new") {
		t.Errorf("exe %q, old %q", f.read(f.exe), f.read(f.exe+".old"))
	}
	if len(f.probed) != 1 || f.probed[0] != f.exe+".new" || !f.jobs.paused {
		t.Errorf("probed %v, jobs %+v", f.probed, f.jobs)
	}
	m, err := u.loadMarker()
	if err != nil || m.ID != "a1" || m.Target != digest(newBuild) || m.Previous != digest(oldBuild) || m.Version != "v2" || m.PreviousVersion != "v1" {
		t.Fatalf("marker %+v %v", m, err)
	}
	if st, _ := os.Stat(f.exe); runtime.GOOS != "windows" && st.Mode().Perm()&0o100 == 0 {
		t.Errorf("the new build is not executable: %v", st.Mode())
	}

	// The new build starts on probation and is confirmed by a heartbeat.
	n := f.updater(newBuild, "v2")
	if n.Settle() || n.probation == nil {
		t.Fatal("not on probation")
	}
	if m, _ := n.loadMarker(); m.Starts != 1 {
		t.Errorf("starts %d", m.Starts)
	}
	if n.Apply(context.Background(), f.instruction("a2")) {
		t.Error("another update while on probation")
	}
	n.Reached()
	if exists(n.markerPath()) || exists(f.exe+".old") || n.probation != nil {
		t.Error("not confirmed")
	}
	if n.Unreached() {
		t.Error("undone after confirmation")
	}
}

func TestApplyRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		serve    []byte
		dlErr    error
		probeOut string
		probeErr error
		want     string
	}{
		"other bytes":   {serve: []byte(strings.Repeat("x", len(newBuild))), want: "does not have the SHA-256"},
		"too large":     {serve: append(append([]byte{}, newBuild...), 'x'), want: "larger than the update says"},
		"too short":     {serve: newBuild[:5], want: "has 5 bytes, not"},
		"download":      {dlErr: errors.New("connection reset"), want: "downloading easyrmm-agent-linux-amd64: connection reset"},
		"does not run":  {probeErr: errors.New("exec format error"), want: "the new build does not run: exec format error"},
		"wrong version": {probeOut: "easyrmm-agent v3 (" + runtime.GOOS + "/" + runtime.GOARCH + ")", want: "says it is version v3, not v2"},
		"wrong arch":    {probeOut: "easyrmm-agent v2 (plan9/mips)", want: "is for plan9/mips"},
		"garbage":       {probeOut: "Segmentation fault", want: `printed "Segmentation fault"`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if tc.serve != nil {
				f.client.files[buildName] = tc.serve
			}
			f.client.err = tc.dlErr
			if tc.probeOut != "" {
				f.probeOut = tc.probeOut
			}
			f.probeErr = tc.probeErr
			u := f.updater(oldBuild, "v1")
			u.Settle()
			if u.Apply(context.Background(), f.instruction("a1")) {
				t.Fatal("applied")
			}
			r := u.Report()
			if r == nil || r.ID != "a1" || !strings.Contains(r.Error, tc.want) {
				t.Errorf("report %+v, want %q", r, tc.want)
			}
			if f.read(f.exe) != string(oldBuild) || exists(f.exe+".new") || exists(f.exe+".old") || exists(u.markerPath()) {
				t.Error("left changes behind")
			}
			if f.jobs.paused {
				t.Error("jobs still held back")
			}
			// The repeated instruction is not tried again.
			downloads := f.client.downloads
			if u.Apply(context.Background(), f.instruction("a1")) || f.client.downloads != downloads {
				t.Error("tried the failed attempt again")
			}
			// A new attempt is, and the old report goes.
			f.client.files[buildName], f.client.err, f.probeOut, f.probeErr = newBuild, nil, "easyrmm-agent v2 ("+runtime.GOOS+"/"+runtime.GOARCH+")", nil
			if !u.Apply(context.Background(), f.instruction("a2")) || u.Report() != nil {
				t.Errorf("second attempt: report %+v", u.Report())
			}
		})
	}
}

func TestApplyIgnores(t *testing.T) {
	f := newFixture(t)
	u := f.updater(oldBuild, "v1")
	other, _, _ := ed25519.GenerateKey(nil)
	for name, su := range map[string]*agentproto.SignedUpdate{
		"another device": f.instruction("a1", func(p *agentproto.UpdatePayload) { p.DeviceID = "dev-2" }),
		"expired":        f.instruction("a1", func(p *agentproto.UpdatePayload) { p.ExpiresAt = f.now }),
		"running build":  f.instruction("a1", func(p *agentproto.UpdatePayload) { p.SHA256 = digest(oldBuild) }),
		"bad signature":  {Payload: f.instruction("a1").Payload, Signature: f.instruction("a1", func(p *agentproto.UpdatePayload) { p.Size++ }).Signature},
	} {
		if u.Apply(context.Background(), su) || f.client.downloads != 0 || u.Report() != nil {
			t.Errorf("%s: acted on it", name)
		}
	}
	u.Key = func() ed25519.PublicKey { return other }
	if u.Apply(context.Background(), f.instruction("a1")) || f.client.downloads != 0 {
		t.Error("acted on an update signed by another key")
	}
	u.Key = func() ed25519.PublicKey { return nil }
	if u.Apply(context.Background(), f.instruction("a1")) || f.client.downloads != 0 {
		t.Error("acted on an update without a pinned key")
	}
	// Canceled while downloading: no failure to report, nothing left.
	u.Key = func() ed25519.PublicKey { return f.pub }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.client.err = context.Canceled
	if u.Apply(ctx, f.instruction("a1")) || u.Report() != nil || exists(f.exe+".new") {
		t.Error("a canceled download counts as a failure")
	}
}

func TestApplyWaitsForJobs(t *testing.T) {
	f := newFixture(t)
	u := f.updater(oldBuild, "v1")
	f.jobs.busy = true
	ctx := context.Background()
	if u.Apply(ctx, f.instruction("a1")) || !f.jobs.paused || f.client.downloads != 0 {
		t.Fatalf("did not wait: %+v", f.jobs)
	}
	// No instruction in an answer: jobs go on.
	if u.Apply(ctx, nil) || f.jobs.paused {
		t.Error("jobs still held back without an instruction")
	}
	u.Apply(ctx, f.instruction("a1"))
	f.now = f.now.Add(JobWait - time.Second)
	if u.Apply(ctx, f.instruction("a1")) || !f.jobs.paused || u.Report() != nil {
		t.Error("gave up early")
	}
	f.now = f.now.Add(2 * time.Second)
	if u.Apply(ctx, f.instruction("a1")) || f.jobs.paused {
		t.Error("still waiting")
	}
	if r := u.Report(); r == nil || r.ID != "a1" || !strings.Contains(r.Error, "Scripts were still running") {
		t.Errorf("report %+v", r)
	}
	// Once the scripts are done, the next attempt goes ahead.
	f.jobs.busy = false
	if !u.Apply(ctx, f.instruction("a2")) || !f.jobs.paused {
		t.Error("the next attempt did not go ahead")
	}
}

func TestUndoAfterFailedStarts(t *testing.T) {
	f := newFixture(t)
	if !f.updater(oldBuild, "v1").Apply(context.Background(), f.instruction("a1")) {
		t.Fatal("not applied")
	}
	for range MaxStarts {
		if f.updater(newBuild, "v2").Settle() {
			t.Fatal("undone too early")
		}
	}
	n := f.updater(newBuild, "v2")
	if !n.Settle() {
		t.Fatal("not undone")
	}
	if f.read(f.exe) != string(oldBuild) || f.read(f.exe+".failed") != string(newBuild) || exists(f.exe+".old") {
		t.Errorf("exe %q, failed %q", f.read(f.exe), f.read(f.exe+".failed"))
	}
	// The previous build reports why and cleans up.
	o := f.updater(oldBuild, "v1")
	if o.Settle() {
		t.Fatal("restarts again")
	}
	if r := o.Report(); r == nil || r.ID != "a1" || !strings.Contains(r.Error, "started 3 times without reaching the server") {
		t.Errorf("report %+v", r)
	}
	if exists(o.markerPath()) || exists(f.exe+".failed") {
		t.Error("left the marker or the failed build")
	}
	// The report lasts ReportFor.
	f.now = f.now.Add(ReportFor + time.Second)
	if o.Report() != nil {
		t.Error("still reported")
	}
}

func TestUndoWhenUnreachable(t *testing.T) {
	f := newFixture(t)
	if !f.updater(oldBuild, "v1").Apply(context.Background(), f.instruction("a1")) {
		t.Fatal("not applied")
	}
	n := f.updater(newBuild, "v2")
	n.Settle()
	f.now = f.now.Add(ProbationTimeout - time.Second)
	if n.Unreached() {
		t.Fatal("undone early")
	}
	f.now = f.now.Add(2 * time.Second)
	if !n.Unreached() || f.read(f.exe) != string(oldBuild) {
		t.Fatal("not undone")
	}
	o := f.updater(oldBuild, "v1")
	o.Settle()
	if r := o.Report(); r == nil || !strings.Contains(r.Error, "could not reach the server for 10 minutes") {
		t.Errorf("report %+v", r)
	}
}

func TestUndoWithoutPreviousBuild(t *testing.T) {
	f := newFixture(t)
	if !f.updater(oldBuild, "v1").Apply(context.Background(), f.instruction("a1")) {
		t.Fatal("not applied")
	}
	if err := os.Remove(f.exe + ".old"); err != nil {
		t.Fatal(err)
	}
	n := f.updater(newBuild, "v2")
	n.Settle()
	f.now = f.now.Add(ProbationTimeout + time.Second)
	if n.Unreached() || f.read(f.exe) != string(newBuild) || exists(n.markerPath()) {
		t.Error("undid the update without a build to go back to")
	}
}

func TestSettle(t *testing.T) {
	f := newFixture(t)
	u := f.updater(oldBuild, "v1")
	for _, ext := range []string{".new", ".old", ".failed"} {
		f.write(f.exe+ext, []byte("leftover"))
	}
	if u.Settle() {
		t.Fatal("restart")
	}
	for _, ext := range []string{".new", ".old", ".failed"} {
		if exists(f.exe + ext) {
			t.Errorf("%s left", ext)
		}
	}
	// A damaged marker goes.
	f.write(u.markerPath(), []byte("{"))
	if u.Settle() || exists(u.markerPath()) {
		t.Error("damaged marker kept")
	}
	// The previous build started again: the update did not take effect.
	if err := u.saveMarker(&marker{ID: "a1", Target: digest(newBuild), Previous: digest(oldBuild)}); err != nil {
		t.Fatal(err)
	}
	if u.Settle() || exists(u.markerPath()) {
		t.Error("marker kept")
	}
	if r := u.Report(); r == nil || r.ID != "a1" || !strings.Contains(r.Error, "did not take effect") {
		t.Errorf("report %+v", r)
	}
	// A build installed meanwhile: forgotten silently.
	v := f.updater([]byte("another build"), "v9")
	if err := v.saveMarker(&marker{ID: "a2", Target: digest(newBuild), Previous: digest(oldBuild)}); err != nil {
		t.Fatal(err)
	}
	if v.Settle() || exists(v.markerPath()) || v.Report() != nil {
		t.Error("marker of another build kept or reported")
	}
}

func TestCheckVersion(t *testing.T) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	for out, want := range map[string]string{
		"easyrmm-agent v2 (" + platform + ")\n": "",
		"easyrmm-agent dev (" + platform + ")":  "says it is version dev",
		"easyrmm-agent v2":                      "printed",
		"other v2 (" + platform + ")":           "printed",
		"easyrmm-agent v2 (" + platform + ") x": "printed",
	} {
		err := checkVersion(out, "v2")
		if (want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", out, err)
		}
	}
	if err := checkVersion("easyrmm-agent anything ("+platform+")", ""); err != nil {
		t.Errorf("no version expected: %v", err)
	}
}

func TestSelf(t *testing.T) {
	exe, sum, err := Self()
	if err != nil || !filepath.IsAbs(exe) || !agentproto.ValidSHA256(sum) {
		t.Fatalf("Self = %q %q %v", exe, sum, err)
	}
	b, _ := os.ReadFile(exe) //nolint:gosec // the test binary
	if digest(b) != sum {
		t.Error("wrong digest")
	}
}

func TestProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "agent")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"easyrmm-agent v2 ($1)\"\n"), 0o700); err != nil { //nolint:gosec // a test script
		t.Fatal(err)
	}
	out, err := Probe(context.Background(), script)
	if err != nil || out != "easyrmm-agent v2 (version)\n" {
		t.Errorf("Probe = %q %v", out, err)
	}
	if _, err := Probe(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Error("probed a missing build")
	}
}

// TestMarkerName: the agent checks its state folder by name before reading
// it (state.layout); the marker is checked as update.json, and its
// temporary copy as update.json.tmp.
func TestMarkerName(t *testing.T) {
	u := &Updater{Dir: "state"}
	if markerName != "update.json" || u.markerPath() != filepath.Join("state", "update.json") {
		t.Errorf("marker = %s: rename it in state.layout too", u.markerPath())
	}
}
