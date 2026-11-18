//go:build integration

package meshcentral_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral/meshtest"
)

func TestFilesAgainstMeshCentral(t *testing.T) {
	env := meshtest.Get(t)
	c := connect(t, env)
	ctx := context.Background()
	mesh, err := c.CreateMesh(ctx, "easyrmm-files-"+uuid.NewString()[:8], "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteMesh(context.Background(), mesh) })

	f, err := meshcentral.NewFiles(env.URL, env.Key)
	if err != nil {
		t.Fatal(err)
	}
	msh, err := f.Settings(ctx, mesh)
	if err != nil || !strings.Contains(string(msh), "MeshID=0x") || !strings.Contains(string(msh), "MeshServer=wss://") {
		t.Fatalf("settings = %q, %v", msh, err)
	}
	dl, err := f.Agent(ctx, 6)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, dl.Body)
	_ = dl.Body.Close()
	if n < 1<<20 || (dl.Length >= 0 && n != dl.Length) {
		t.Errorf("agent: %d bytes of %d", n, dl.Length)
	}

	// A refused session is replaced by signing in again.
	f.SpoilSession()
	if _, err := f.Settings(ctx, mesh); err != nil {
		t.Errorf("after the session expired: %v", err)
	}

	if _, err := f.Settings(ctx, "mesh//"+strings.Repeat("A", 64)); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("unknown group: %v", err)
	}
	if _, err := f.Settings(ctx, "not-a-group"); err == nil {
		t.Error("malformed group id accepted")
	}
	if _, err := f.Agent(ctx, 999); err == nil {
		t.Error("unknown agent architecture served")
	}

	// A wrong key cannot sign in.
	wrong, _ := meshcentral.NewFiles(env.URL, make([]byte, len(env.Key)))
	if _, err := wrong.Settings(ctx, mesh); err == nil {
		t.Error("downloads with a wrong login key")
	}
	if _, err := meshcentral.NewFiles("https://example.com", env.Key); err == nil {
		t.Error("an https internal URL was accepted")
	}
	closed, _ := meshcentral.NewFiles("http://127.0.0.1:1", env.Key)
	if _, err := closed.Agent(ctx, 6); err == nil || !strings.Contains(err.Error(), "login=[redacted]") {
		t.Errorf("unreachable MeshCentral: %v", err)
	}
}
