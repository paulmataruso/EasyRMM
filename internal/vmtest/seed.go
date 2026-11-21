package vmtest

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed runner.sh
var runnerScript []byte

//go:embed harness.service
var runnerUnit []byte

// The port's name, which udev links as /dev/virtio-ports/<name>.
const portName = "org.easyrmm.harness"

// cloudInitCacheConfig keeps cloud-init from fetching its seed again when
// the machine restarts, so that a firewall or a ban a test applies to the
// host's address cannot hold up the restart.
const cloudInitCacheConfig = "manual_cache_clean: true\n"

// userData is the cloud-config that installs and starts the runner. It
// creates no account and sets no password: tests reach the machine through
// the runner only. JSON is YAML, and needs no escaping by hand.
func userData() []byte {
	file := func(path, perm string, content []byte) map[string]string {
		return map[string]string{
			"path":        path,
			"permissions": perm,
			"owner":       "root:root",
			"encoding":    "b64",
			"content":     base64.StdEncoding.EncodeToString(content),
		}
	}
	cfg := map[string]any{
		"write_files": []map[string]string{
			file("/usr/local/sbin/easyrmm-harness", "0755", runnerScript),
			file("/etc/systemd/system/easyrmm-harness.service", "0644", runnerUnit),
			file("/etc/cloud/cloud.cfg.d/99-easyrmm-harness.cfg", "0644", []byte(cloudInitCacheConfig)),
		},
		"runcmd": [][]string{
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", "--now", "--no-block", "easyrmm-harness.service"},
		},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		panic(err) // maps of strings always marshal
	}
	return append([]byte("#cloud-config\n"), b...)
}

func metaData(instanceID, hostname string) []byte {
	b, err := json.Marshal(map[string]string{"instance-id": instanceID, "local-hostname": hostname})
	if err != nil {
		panic(err)
	}
	return b
}

// seedISO writes the seed's files to a CD-ROM image labeled cidata in dir.
func seedISO(ctx context.Context, dir string, files map[string][]byte) (string, error) {
	src := filepath.Join(dir, "seed")
	if err := os.Mkdir(src, 0o700); err != nil {
		return "", err
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(src, name), b, 0o600); err != nil {
			return "", err
		}
	}
	iso := filepath.Join(dir, "seed.iso")
	out, err := exec.CommandContext(ctx, "xorriso", "-as", "mkisofs", "-quiet", //nolint:gosec // the harness's own files
		"-output", iso, "-volid", "cidata", "-joliet", "-rock", src).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("xorriso: %w: %s", err, out)
	}
	return iso, nil
}

// seedServer serves a NoCloud seed to the machine over QEMU's user
// networking, where the host's loopback is 10.0.2.2.
type seedServer struct {
	srv  *http.Server
	port int

	mu       sync.Mutex
	requests []string
}

func startSeed(ctx context.Context, files map[string][]byte) (*seedServer, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &seedServer{port: ln.Addr().(*net.TCPAddr).Port}
	s.srv = &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
			s.mu.Lock()
			s.requests = append(s.requests, fmt.Sprintf("%s %s %t", r.Method, r.URL.Path, ok))
			s.mu.Unlock()
			if !ok || r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		}),
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// url is the seed's address as the machine sees it.
func (s *seedServer) url() string {
	return fmt.Sprintf("http://10.0.2.2:%d/", s.port)
}

// count is the number of requests the machine made: none without a server
// (a seed on a CD-ROM).
func (s *seedServer) count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// log lists the requests the machine made, for a failed test's output.
func (s *seedServer) log() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return "none"
	}
	return strings.Join(s.requests, "; ")
}

func (s *seedServer) close() error {
	return s.srv.Close()
}
