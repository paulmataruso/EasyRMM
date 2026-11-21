package vmtest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUserData(t *testing.T) {
	ud := userData()
	body, ok := bytes.CutPrefix(ud, []byte("#cloud-config\n"))
	if !ok {
		t.Fatalf("no #cloud-config header: %.40q", ud)
	}
	var cfg struct {
		WriteFiles []map[string]string `json:"write_files"`
		Runcmd     [][]string          `json:"runcmd"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields() // no accounts, keys or passwords slip in
	if err := dec.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range cfg.WriteFiles {
		b, err := base64.StdEncoding.DecodeString(f["content"])
		if err != nil || f["encoding"] != "b64" || f["owner"] != "root:root" {
			t.Fatalf("%s: %v %q %q", f["path"], err, f["encoding"], f["owner"])
		}
		files[f["path"]+" "+f["permissions"]] = b
	}
	if !bytes.Equal(files["/usr/local/sbin/easyrmm-harness 0755"], runnerScript) {
		t.Error("the runner is not written as is, executable")
	}
	unit := files["/etc/systemd/system/easyrmm-harness.service 0644"]
	if !bytes.Equal(unit, runnerUnit) {
		t.Error("the unit is not written as is")
	}
	if !bytes.Contains(unit, []byte("ExecStart=/usr/local/sbin/easyrmm-harness /dev/virtio-ports/"+portName+"\n")) {
		t.Errorf("the unit does not start the runner on the port:\n%s", unit)
	}
	if string(files["/etc/cloud/cloud.cfg.d/99-easyrmm-harness.cfg 0644"]) != cloudInitCacheConfig {
		t.Error("cloud-init's cache setting is missing")
	}
	if len(cfg.Runcmd) != 2 || strings.Join(cfg.Runcmd[1], " ") != "systemctl enable --now --no-block easyrmm-harness.service" {
		t.Errorf("runcmd %q", cfg.Runcmd)
	}
}

func TestMetaData(t *testing.T) {
	var md map[string]string
	if err := json.Unmarshal(metaData("easyrmm-vm-1", "easyrmm-debian-12"), &md); err != nil {
		t.Fatal(err)
	}
	if md["instance-id"] != "easyrmm-vm-1" || md["local-hostname"] != "easyrmm-debian-12" || len(md) != 2 {
		t.Errorf("%v", md)
	}
}

func TestSeedServer(t *testing.T) {
	s, err := startSeed(t.Context(), map[string][]byte{"meta-data": []byte("md"), "vendor-data": nil})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !strings.HasPrefix(s.url(), "http://10.0.2.2:") || !strings.HasSuffix(s.url(), "/") {
		t.Errorf("url %s", s.url())
	}
	if s.log() != "none" {
		t.Errorf("log before any request: %s", s.log())
	}
	base := strings.Replace(s.url(), "10.0.2.2", "127.0.0.1", 1)
	for path, want := range map[string]struct {
		status int
		body   string
	}{
		"meta-data":   {200, "md"},
		"vendor-data": {200, ""},
		"user-data":   {404, "404 page not found\n"},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want.status || string(body) != want.body {
			t.Errorf("%s: %d %q", path, resp.StatusCode, body)
		}
	}
	if log := s.log(); !strings.Contains(log, "GET /meta-data true") || !strings.Contains(log, "GET /user-data false") {
		t.Errorf("log %s", log)
	}
	if s.count() != 3 {
		t.Errorf("count %d", s.count())
	}
	var none *seedServer // a seed on a CD-ROM
	if none.count() != 0 {
		t.Error("no server, but requests")
	}
}

// The CD-ROM's volume label is what cloud-init looks for. It runs where
// xorriso is installed, as in CI's machine jobs (`make test-vm` runs this
// package's unit tests too).
func TestSeedISO(t *testing.T) {
	if _, err := exec.LookPath("xorriso"); err != nil {
		t.Skip("xorriso is not installed")
	}
	dir := t.TempDir()
	iso, err := seedISO(t.Context(), dir, map[string][]byte{"meta-data": []byte("md"), "user-data": userData(), "vendor-data": nil})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(iso)
	if err != nil {
		t.Fatal(err)
	}
	// The primary volume descriptor is sector 16; its volume identifier
	// starts at byte 40.
	if len(b) < 16*2048+72 || strings.TrimRight(string(b[16*2048+40:16*2048+72]), " ") != "cidata" {
		t.Error("the image is not labeled cidata")
	}
	for _, name := range []string{"meta-data", "user-data"} {
		if !bytes.Contains(b, []byte(name)) {
			t.Errorf("%s is not on the image", name)
		}
	}
	if !bytes.Contains(b, userData()) {
		t.Error("the user data is not on the image")
	}
	if _, err := seedISO(t.Context(), dir, nil); err == nil {
		t.Error("a second seed in the same directory")
	}
}
