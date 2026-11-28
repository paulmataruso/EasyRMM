package runner

import (
	"context"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
)

// The heartbeat names the package that holds the agent (ADR-0056), only to a
// server of level 2 or higher and only while a package record exists.
func TestHeartbeatCarriesTheInstaller(t *testing.T) {
	s := &server{protocol: 3}
	r := newRunner(t, s, nil)
	ctx := context.Background()
	if err := r.Store.SavePackage(&state.Package{Kind: "deb", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// The first heartbeat has seen no answer, so the server's level is not known.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[0].Installer; got != "" {
		t.Fatalf("a level-1 request carried the installer %q", got)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[1].Installer; got != "deb" {
		t.Fatalf("installer = %q", got)
	}
	// Another package takes the agent over: the next heartbeat says so.
	if err := r.Store.SavePackage(&state.Package{Kind: "rpm", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[2].Installer; got != "rpm" {
		t.Fatalf("installer = %q after a package took over", got)
	}
	// The package is gone, and the agent installed by the command: none.
	if err := r.Store.RemovePackage(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[3].Installer; got != "" {
		t.Fatalf("installer = %q without a package record", got)
	}
}
