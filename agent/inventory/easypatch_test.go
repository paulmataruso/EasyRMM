//go:build !windows

package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// status is what EasyPatch agent 1.9.0 prints for `status --json` (recorded
// from a real agent; null fields are left out).
const status = `{
  "agentVersion": "1.9.0",
  "service": "unknown",
  "status": "Active",
  "serverUrl": "https://patch.example.com/",
  "endpointId": "01A1E4C7-8CFE-7182-94A4-E9F2C019670E",
  "credentialId": "c_CukPLyE9-BGxpq7hMaMurg",
  "credentialExpiresAt": "2027-11-16T14:34:05.4380731+00:00",
  "keyFingerprint": "1FBB-E2EA-533D-A960",
  "enrolledAt": "2026-11-16T14:34:07.4341111+00:00",
  "lastCheckInAt": "2026-11-16T14:34:14.3175591+00:00",
  "jobs": [],
  "queuedReports": 0
}`

func TestEasyPatch(t *testing.T) {
	root := t.TempDir()
	c := Collector{Root: root}
	if got := c.easyPatch(context.Background()); got != nil {
		t.Fatalf("without the agent %+v", got)
	}

	bin := filepath.Join(root, easyPatchBinary)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.easyPatch(context.Background()); got != nil {
		t.Fatalf("a file that cannot run %+v", got)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}

	var ran []string
	c.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append([]string{name}, args...)
		return []byte(status), nil
	}
	want := agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://patch.example.com",
		EndpointID: "01a1e4c7-8cfe-7182-94a4-e9f2c019670e", KeyFingerprint: "1FBB-E2EA-533D-A960"}
	if got := c.easyPatch(context.Background()); got == nil || *got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if strings.Join(ran, " ") != bin+" status --json" {
		t.Errorf("ran %q", ran)
	}

	// An agent that is not enrolled exits with an error and still says so.
	c.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"agentVersion": "1.9.0", "service": "inactive", "status": "NotEnrolled", "jobs": null}`), errors.New("exit status 1")
	}
	if got := c.easyPatch(context.Background()); got == nil || got.Status != "NotEnrolled" || got.EndpointID != "" || got.Error != "" {
		t.Errorf("not enrolled %+v", got)
	}

	// Anything else is reported as such, without breaking the inventory.
	for out, wantErr := range map[string]string{
		"":                  "status --json failed: exit status 2",
		"usage: easypatch…": "status --json failed: exit status 2",
	} {
		c.Run = func(context.Context, string, ...string) ([]byte, error) {
			return []byte(out), errors.New("exit status 2")
		}
		if got := c.easyPatch(context.Background()); got == nil || got.Status != "Unknown" || got.Error != wantErr {
			t.Errorf("%q: %+v", out, got)
		}
	}
	c.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte(`{"jobs": []}`), nil }
	if got := c.easyPatch(context.Background()); got == nil || got.Error != "status --json printed nothing EasyRMM understands" {
		t.Errorf("unknown output %+v", got)
	}

	long := strings.Repeat("é", 400)
	if got := short(long); len(got) > 512 || !strings.HasPrefix(long, got) {
		t.Errorf("short cut %d bytes", len(got))
	}
}
