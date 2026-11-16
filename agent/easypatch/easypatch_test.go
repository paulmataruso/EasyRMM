package easypatch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var testPackage = []byte("the EasyPatch agent package")

const testToken = "ept_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

func payload(now time.Time, formats ...string) agentproto.EasyPatchInstallPayload {
	sum := sha256.Sum256(testPackage)
	p := agentproto.EasyPatchInstallPayload{
		V: agentproto.EasyPatchInstallVersion, ID: "5b0e1d3a-77a9-4a8e-9f4e-0d5c6b7a8e9f", DeviceID: "dev-1",
		ServerURL: "https://patch.example.com", Token: testToken, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	for _, f := range formats {
		name := "EasyPatchAgent-1.9.0-x64." + f
		p.Packages = append(p.Packages, agentproto.EasyPatchPackage{FileName: name, URL: "https://patch.example.com/downloads/agent/" + name,
			Format: f, Arch: "x64", Version: "1.9.0", Size: int64(len(testPackage)), SHA256: hex.EncodeToString(sum[:])})
	}
	return p
}

// fakeSystem records what an install did.
type fakeSystem struct {
	mu         sync.Mutex
	formats    []string
	formatsErr error
	installErr error
	enrollErr  error
	installed  []string // file name and its contents
	enrolled   string   // the token
	release    chan struct{}
}

func (f *fakeSystem) Formats() ([]string, error) { return f.formats, f.formatsErr }

func (f *fakeSystem) Install(ctx context.Context, _ *agentproto.EasyPatchInstallPayload, pkg agentproto.EasyPatchPackage, file string) error {
	if f.release != nil {
		<-f.release
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = append(f.installed, pkg.FileName, string(b))
	return f.installErr
}

func (f *fakeSystem) Enroll(_ context.Context, p *agentproto.EasyPatchInstallPayload) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = p.Token
	if f.enrollErr != nil {
		return f.enrollErr
	}
	return nil
}

type fixture struct {
	t        *testing.T
	priv     ed25519.PrivateKey
	in       *Installer
	sys      *fakeSystem
	served   []byte
	finished int
	now      time.Time
}

func newFixture(t *testing.T, formats ...string) *fixture {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &fixture{t: t, priv: priv, sys: &fakeSystem{formats: formats}, served: testPackage, now: time.Now()}
	f.in = &Installer{
		DeviceID: "dev-1", Key: func() ed25519.PublicKey { return pub }, Dir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), System: f.sys, Now: func() time.Time { return f.now },
		Finished: func() { f.finished++ },
		Download: func(_ context.Context, url, ca string, limit int64, w io.Writer) error {
			if !strings.HasPrefix(url, "https://patch.example.com/downloads/agent/") {
				return errors.New("unexpected address " + url)
			}
			_, err := w.Write(f.served)
			return err
		},
	}
	return f
}

func (f *fixture) sign(p agentproto.EasyPatchInstallPayload) *agentproto.SignedEasyPatchInstall {
	s, err := agentproto.SignEasyPatchInstall(f.priv, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

// run starts an install and waits for it.
func (f *fixture) run(p agentproto.EasyPatchInstallPayload) *agentproto.EasyPatchInstallReport {
	f.in.Start(context.Background(), f.sign(p))
	f.in.Wait()
	return f.in.Status().Last
}

func TestInstall(t *testing.T) {
	f := newFixture(t, agentproto.EasyPatchRPM, agentproto.EasyPatchDeb)
	if st := f.in.Status(); st == nil || st.Busy != "" || st.Last != nil {
		t.Fatalf("idle status: %+v", st)
	}
	p := payload(f.now, agentproto.EasyPatchDeb, agentproto.EasyPatchRPM)
	last := f.run(p)
	if last == nil || !last.OK || last.ID != p.ID || last.Error != "" {
		t.Fatalf("report: %+v", last)
	}
	// The machine's preferred format wins over the instruction's order.
	if len(f.sys.installed) != 2 || f.sys.installed[0] != "EasyPatchAgent-1.9.0-x64.rpm" || f.sys.installed[1] != string(testPackage) {
		t.Errorf("installed: %q", f.sys.installed)
	}
	if f.sys.enrolled != testToken || f.finished != 1 {
		t.Errorf("enrolled %q, finished %d", f.sys.enrolled, f.finished)
	}
	if left, _ := os.ReadDir(filepath.Join(f.in.Dir, "easypatch")); len(left) != 0 {
		t.Errorf("downloads left behind: %v", left)
	}
	// The same instruction is not run twice.
	f.in.Start(context.Background(), f.sign(p))
	f.in.Wait()
	if len(f.sys.installed) != 2 || f.finished != 1 {
		t.Errorf("ran again: %q", f.sys.installed)
	}
	// The outcome is reported for an hour.
	f.now = f.now.Add(ReportFor)
	if st := f.in.Status(); st.Last != nil {
		t.Errorf("still reported: %+v", st.Last)
	}
	f.in.Start(context.Background(), nil)
	if f.in.Busy() {
		t.Error("busy without an instruction")
	}
}

func TestInstallBusy(t *testing.T) {
	f := newFixture(t, agentproto.EasyPatchMSI)
	f.sys.release = make(chan struct{})
	p := payload(f.now, agentproto.EasyPatchMSI)
	f.in.Start(context.Background(), f.sign(p))
	if !f.in.Busy() || f.in.Status().Busy != p.ID {
		t.Fatalf("not busy: %+v", f.in.Status())
	}
	other := payload(f.now, agentproto.EasyPatchMSI)
	other.ID = "another"
	f.in.Start(context.Background(), f.sign(other))
	close(f.sys.release)
	f.in.Wait()
	if f.in.Busy() || f.in.Status().Last.ID != p.ID || len(f.sys.installed) != 2 {
		t.Errorf("second install ran: %+v %q", f.in.Status(), f.sys.installed)
	}
}

func TestInstallRefusals(t *testing.T) {
	f := newFixture(t, agentproto.EasyPatchDeb)
	p := payload(f.now, agentproto.EasyPatchDeb)
	// Another key: refused and reported against the instruction's ID.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	s, _ := agentproto.SignEasyPatchInstall(otherPriv, p)
	f.in.Start(context.Background(), &s)
	if last := f.in.Status().Last; last == nil || last.OK || last.ID != p.ID || !strings.Contains(last.Error, "signature") {
		t.Errorf("another key: %+v", last)
	}
	// Another device.
	q := payload(f.now, agentproto.EasyPatchDeb)
	q.ID, q.DeviceID = "for-dev-2", "dev-2"
	f.in.Start(context.Background(), f.sign(q))
	if last := f.in.Status().Last; last == nil || last.ID != "for-dev-2" || !strings.Contains(last.Error, "another device") {
		t.Errorf("another device: %+v", last)
	}
	// Garbage: nothing to report against.
	f.in.Start(context.Background(), &agentproto.SignedEasyPatchInstall{Payload: "%%", Signature: "%%"})
	if last := f.in.Status().Last; last.ID != "for-dev-2" {
		t.Errorf("garbage reported: %+v", last)
	}
	// No pinned key yet.
	f.in.Key = func() ed25519.PublicKey { return nil }
	r := payload(f.now, agentproto.EasyPatchDeb)
	r.ID = "no-key"
	f.in.Start(context.Background(), f.sign(r))
	if last := f.in.Status().Last; last.ID != "no-key" || last.OK {
		t.Errorf("no key: %+v", last)
	}
	if len(f.sys.installed) != 0 || f.finished != 0 {
		t.Errorf("installed anyway: %q", f.sys.installed)
	}
}

func TestInstallFailures(t *testing.T) {
	cases := map[string]struct {
		setup func(f *fixture, p *agentproto.EasyPatchInstallPayload)
		want  string
	}{
		"no systemd": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.sys.formatsErr = errors.New("this device does not run systemd, which the EasyPatch agent needs")
		}, "This device does not run systemd"},
		"already installed": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.in.Present = func(context.Context) *agentproto.EasyPatchAgent { return &agentproto.EasyPatchAgent{Status: "Active"} }
		}, "already installed here (Active)"},
		"status unknown": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.in.Present = func(context.Context) *agentproto.EasyPatchAgent { return &agentproto.EasyPatchAgent{} }
		}, "(status unknown)"},
		"no package": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.sys.formats = []string{agentproto.EasyPatchRPM}
		},
			"no package this device installs (it installs rpm)"},
		"short": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) { f.served = testPackage[:5] }, "is 5 bytes, not the"},
		"changed": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.served = bytes.ToUpper(testPackage)
		}, "does not have the SHA-256"},
		"download": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.in.Download = func(context.Context, string, string, int64, io.Writer) error {
				return errors.New("EasyPatch answered 404 Not Found")
			}
		}, "Downloading EasyPatchAgent-1.9.0-x64.deb from EasyPatch: EasyPatch answered 404"},
		"install": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.sys.installErr = errors.New("apt-get could not install")
		},
			"Apt-get could not install"},
		"enroll echoes the token": {func(f *fixture, _ *agentproto.EasyPatchInstallPayload) {
			f.sys.enrollErr = errors.New("enroll failed for " + testToken)
		}, "Enroll failed for [token]"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, agentproto.EasyPatchDeb)
			p := payload(f.now, agentproto.EasyPatchDeb)
			c.setup(f, &p)
			last := f.run(p)
			if last == nil || last.OK || !strings.Contains(last.Error, c.want) || strings.Contains(last.Error, testToken) {
				t.Errorf("report: %+v", last)
			}
			if f.finished != 1 {
				t.Errorf("finished %d", f.finished)
			}
		})
	}
}

func TestInstallStopped(t *testing.T) {
	f := newFixture(t, agentproto.EasyPatchDeb)
	ctx, cancel := context.WithCancel(context.Background())
	f.in.Download = func(_ context.Context, _, _ string, _ int64, w io.Writer) error {
		_, err := w.Write(testPackage)
		cancel()
		return err
	}
	f.in.Start(ctx, f.sign(payload(f.now, agentproto.EasyPatchDeb)))
	f.in.Wait()
	if last := f.in.Status().Last; last == nil || !strings.Contains(last.Error, "stopped before") || len(f.sys.installed) != 0 {
		t.Errorf("report: %+v, installed %q", last, f.sys.installed)
	}
}

func TestDownload(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(testPackage) })
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/ok", http.StatusFound)
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	ctx := context.Background()
	var buf bytes.Buffer
	if err := Download(ctx, ts.URL+"/ok", ca, int64(len(testPackage)), &buf); err != nil || buf.String() != string(testPackage) {
		t.Fatalf("download: %v %q", err, buf.String())
	}
	if err := Download(ctx, ts.URL+"/ok", ca, 4, io.Discard); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("too large: %v", err)
	}
	if err := Download(ctx, ts.URL+"/missing", ca, 100, io.Discard); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing: %v", err)
	}
	if err := Download(ctx, ts.URL+"/plain", ca, 100, io.Discard); err == nil || !strings.Contains(err.Error(), "redirected") {
		t.Errorf("redirect to http: %v", err)
	}
	// Without its authority the server is not trusted.
	if err := Download(ctx, ts.URL+"/ok", "", 100, io.Discard); err == nil {
		t.Error("untrusted server accepted")
	}
	if err := Download(ctx, ts.URL+"/ok", "not a certificate", 100, io.Discard); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("bad CA: %v", err)
	}
	if err := Download(ctx, "https://\x00", "", 100, io.Discard); err == nil {
		t.Error("bad address accepted")
	}
}

func TestEnrollErrors(t *testing.T) {
	p := payload(time.Now(), agentproto.EasyPatchDeb)
	if err := enrollError(0, nil, &p, true); err != nil {
		t.Errorf("0: %v", err)
	}
	for code, want := range map[int]string{
		2: "refused the enrollment's arguments", 3: "another EasyPatch server", 4: "rejected the enrollment token",
		5: "administrator rights", 6: "could not reach EasyPatch at https://patch.example.com (exit code 6). Its enrollment token is revoked",
		7: "could not be stopped", 9: "failed (exit code 9): line 2 line 3 line 4",
	} {
		err := enrollError(code, []byte("line 1\nline 2\nline 3\nline 4\n"), &p, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%d: %v", code, err)
		}
	}
	p.CACert = "-----BEGIN CERTIFICATE-----"
	if err := enrollError(6, nil, &p, true); !strings.Contains(err.Error(), "system's certificate store") {
		t.Errorf("6 with a CA on Linux: %v", err)
	}
	if err := enrollError(6, nil, &p, false); strings.Contains(err.Error(), "certificate store") {
		t.Errorf("6 with a CA on Windows: %v", err)
	}
	if err := enrollError(1, nil, &p, false); err.Error() != "the EasyPatch agent's enrollment failed (exit code 1)" {
		t.Errorf("1 without output: %v", err)
	}
}

func TestHelpers(t *testing.T) {
	if got := clip(strings.Repeat("é", 400)); len(got) > agentproto.MaxEasyPatchError || !strings.HasPrefix(got, "Éé") || !utf8.ValidString(got) {
		t.Errorf("clip: %d bytes", len(got))
	}
	for in, want := range map[string]string{" x ": "X.", "failed (exit code 1)": "Failed (exit code 1).", "Done.": "Done.", "ok?": "Ok?", "": ""} {
		if got := clip(in); got != want {
			t.Errorf("clip(%q) = %q, want %q", in, got, want)
		}
	}
	if redact("a", "") != "a" {
		t.Error("redact without a token")
	}
	b, _ := json.Marshal(map[string]string{"id": "abc"})
	if unverifiedID(base64.StdEncoding.EncodeToString(b)) != "abc" || unverifiedID("%%") != "" ||
		unverifiedID(base64.StdEncoding.EncodeToString([]byte("[]"))) != "" {
		t.Error("unverifiedID")
	}
	if _, ok := choose(nil, []string{agentproto.EasyPatchMSI}); ok {
		t.Error("chose from nothing")
	}
	// run: exit codes, standard input and the environment.
	ctx := context.Background()
	code, out, err := run(ctx, "from stdin", []string{"EP_TEST=env"}, "sh", "-c", `read x; echo "$x $EP_TEST"; exit 3`)
	if err != nil || code != 3 || strings.TrimSpace(string(out)) != "from stdin env" {
		t.Errorf("run: %d %q %v", code, out, err)
	}
	if _, _, err := run(ctx, "", nil, filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "running missing") {
		t.Errorf("missing program: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, _, err := run(short, "", nil, "sleep", "5"); err == nil || !strings.Contains(err.Error(), "did not finish in time") {
		t.Errorf("timeout: %v", err)
	}
}
