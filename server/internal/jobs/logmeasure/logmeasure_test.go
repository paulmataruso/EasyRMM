package logmeasure

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "windows-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseWindowsSample(t *testing.T) {
	r, err := Parse([]byte(sample(t)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sources[0].FilteredBytes != 700 || len(r.Sources[0].Subcategories) != 2 {
		t.Fatalf("unexpected report: %+v", r.Sources[0])
	}
}

func TestParseRefuses(t *testing.T) {
	good := sample(t)
	for name, bad := range map[string]string{
		"not json":        "nope",
		"schema":          strings.Replace(good, "logmeasure/1", "logmeasure/2", 1),
		"platform":        strings.Replace(good, `"windows","hostname"`, `"plan9","hostname"`, 1),
		"source order":    strings.Replace(good, "windows.system", "windows.application", 1),
		"filtered > all":  strings.Replace(good, `"filteredEvents":2,"filteredBytes":700,"codes"`, `"filteredEvents":5,"filteredBytes":700,"codes"`, 1),
		"codes mismatch":  strings.Replace(good, `"events":3,"bytes":1000`, `"events":4,"bytes":1000`, 1),
		"null list":       strings.Replace(good, `"notes":[]`, `"notes":null`, 1),
		"absent but used": strings.Replace(good, `"present":true,"channels":["Security"]`, `"present":false,"channels":["Security"]`, 1),
	} {
		if bad == good {
			t.Errorf("%s: the replacement did not apply", name)
			continue
		}
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestLibrary(t *testing.T) {
	l := Library()
	if len(l) != 2 {
		t.Fatalf("%d entries", len(l))
	}
	for _, e := range l {
		if e.Name == "" || e.Description == "" || e.Body == "" || e.TimeoutSeconds < 1 {
			t.Errorf("incomplete entry %q", e.Name)
		}
		if len(e.Body) > 64<<10 {
			t.Errorf("%s: %d bytes is over the library's script size limit", e.Name, len(e.Body))
		}
		if !strings.Contains(e.Body, Schema) {
			t.Errorf("%s does not print %s", e.Name, Schema)
		}
	}
}

// The Linux script runs on any Linux host with sh and awk, a journal or not:
// absent sources are reported, never an error. The audit and auth files are
// fixtures.
func TestShScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the shell script is for Linux")
	}
	for _, tool := range []string{"sh", "awk", "sort", "date", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := t.TempDir()
	now := time.Now()
	old := now.AddDate(0, 0, -30)
	audit := filepath.Join(dir, "audit.log")
	auth := filepath.Join(dir, "auth.log")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	write(audit, "type=USER_LOGIN msg=audit("+ts+".1:1): pid=1\n"+
		"type=SYSCALL msg=audit("+ts+".1:2): key=\"easyrmm-logs-x\"\n"+
		"type=SYSCALL msg=audit("+ts+".1:3): a=1\n"+
		"type=USER_LOGIN msg=audit(100.1:4): too old\n")
	write(auth, now.Format("2006-01-02T15:04:05-07:00")+" h sshd[1]: Failed password for x\n"+
		old.Format("2006-01-02T15:04:05-07:00")+" h sshd[1]: Failed password for y\n")

	cmd := exec.Command("sh", "measure_logs.sh", "7")
	cmd.Env = append(os.Environ(), "LOGMEASURE_AUDIT_LOG="+audit, "LOGMEASURE_AUTH_FILE="+auth)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	r, err := Parse(stdout.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, stdout.String())
	}
	by := map[string]Source{}
	for _, s := range r.Sources {
		by[s.Source] = s
	}
	a := by["linux.audit"]
	if !a.Present || a.Events != 3 || a.FilteredEvents != 2 {
		t.Errorf("audit: %+v", a)
	}
	f := by["linux.file"]
	if !f.Present || f.Events != 1 || len(f.Codes) != 1 || f.Codes[0].Code != "sshd.failed" {
		t.Errorf("file: %+v", f)
	}
}
