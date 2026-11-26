package easypatch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenPackageReadsOnlyTheEnginesAgentPackages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/downloads/agent/EasyPatch-1.msi" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "msi bytes")
	}))
	defer srv.Close()
	signer, err := NewSigner(make([]byte, 32))
	if err != nil {
		t.Skipf("no signer for the stand-in: %v", err)
	}
	c, err := NewEngineClient(srv.URL, signer, "test")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.OpenPackage(context.Background(), AgentPackage{DownloadURL: "/downloads/agent/EasyPatch-1.msi"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	_ = r.Close()
	if string(b) != "msi bytes" {
		t.Fatalf("body = %q", b)
	}
	for _, bad := range []string{"/api/v1/agents/x", "/downloads/agent/../../api/v1/x", "/downloads/agent/x?y=1", `/downloads/agent/x\y`, ""} {
		if r, err := c.OpenPackage(context.Background(), AgentPackage{DownloadURL: bad}); err == nil {
			_ = r.Close()
			t.Errorf("%q was opened", bad)
		}
	}
	if _, err := c.OpenPackage(context.Background(), AgentPackage{DownloadURL: "/downloads/agent/missing.msi"}); err == nil {
		t.Error("a package the engine does not have was opened")
	}
}
