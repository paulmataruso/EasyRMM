//go:build integration

package meshcentral_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral/meshtest"
)

func connect(t *testing.T, env meshtest.Env) *meshcentral.Client {
	t.Helper()
	c, err := meshcentral.NewClient(meshcentral.ClientOptions{BaseURL: env.URL, Key: env.Key})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(20 * time.Second)
	for !c.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("never connected to MeshCentral")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return c
}

func TestControlChannelAgainstMeshCentral(t *testing.T) {
	env := meshtest.Get(t)
	c := connect(t, env)
	ctx := context.Background()

	if info := c.Info(); len(info.TLSHash) != 96 {
		t.Errorf("server info TLS hash = %q, want a SHA-384 from certUrl", info.TLSHash)
	}

	// Device groups.
	name := "Test " + uuid.NewString()[:8]
	meshID, err := c.CreateMesh(ctx, name, "created by a test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(meshID, "mesh//") {
		t.Fatalf("mesh id %q", meshID)
	}
	if err := c.EditMesh(ctx, meshID, name+" renamed", "edited"); err != nil {
		t.Fatal(err)
	}
	meshes, err := c.Meshes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *meshcentral.Mesh
	for i := range meshes {
		if meshes[i].ID == meshID {
			found = &meshes[i]
		}
	}
	if found == nil || found.Name != name+" renamed" || found.Description != "edited" {
		t.Fatalf("mesh after edit = %+v", found)
	}

	// Users and rights. The name is not one EasyRMM's reconciliation
	// manages, so remote-package tests running at the same time leave it be.
	account := "easyrmm-test-" + uuid.NewString()[:8]
	userID := meshcentral.UserID(account)
	if err := c.AddUser(ctx, account, "Pat Tester", meshcentral.TechnicianSiteRights); err != nil {
		t.Fatal(err)
	}
	if err := c.AddUser(ctx, account, "Pat Tester", meshcentral.TechnicianSiteRights); !meshcentral.IsAlreadyExists(err) {
		t.Errorf("second AddUser error = %v, want already exists", err)
	}
	if err := c.EditUser(ctx, userID, "Pat Renamed", meshcentral.TechnicianSiteRights); err != nil {
		t.Fatal(err)
	}
	rights := meshcentral.Access{Desktop: true, Files: true}.Rights()
	if err := c.SetMeshRights(ctx, meshID, userID, rights); err != nil {
		t.Fatal(err)
	}
	users, err := c.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var u *meshcentral.User
	for i := range users {
		if users[i].ID == userID {
			u = &users[i]
		}
	}
	if u == nil || u.RealName != "Pat Renamed" || u.SiteAdmin != meshcentral.TechnicianSiteRights {
		t.Fatalf("user = %+v", u)
	}
	if got := u.Links[meshID].Rights; got != rights {
		t.Errorf("rights on mesh = %#x, want %#x", got, rights)
	}

	// A login token opens a session for that user exactly once.
	token, err := meshcentral.LoginToken(env.Key, userID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !loggedIn(t, env.URL, token) {
		t.Error("login token did not sign the user in")
	}
	if loggedIn(t, env.URL, token) {
		t.Error("login token worked twice")
	}
	stale, _ := meshcentral.LoginToken(env.Key, userID, time.Now().Add(-2*time.Minute))
	if loggedIn(t, env.URL, stale) {
		t.Error("expired login token was accepted")
	}

	if err := c.RemoveMeshUser(ctx, meshID, userID); err != nil {
		t.Fatal(err)
	}
	nodes, err := c.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.MeshID == meshID {
			t.Errorf("unexpected device %s in a new group", n.ID)
		}
	}
	if err := c.DeleteUser(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, userID); !meshcentral.IsUnknown(err) {
		t.Errorf("deleting a missing user: %v, want unknown", err)
	}
	if err := c.DeleteMesh(ctx, meshID); err != nil {
		t.Fatal(err)
	}
	// MeshCentral keeps deleted groups (marked deleted, without members), so
	// a second delete is refused rather than reported as unknown.
	var ce *meshcentral.CommandError
	if err := c.DeleteMesh(ctx, meshID); !errors.As(err, &ce) {
		t.Errorf("deleting a deleted group: %v, want a MeshCentral error", err)
	}
	after, err := c.Meshes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range after {
		if m.ID == meshID {
			t.Error("deleted group is still listed")
		}
	}
}

func TestControlChannelRejectsWrongKey(t *testing.T) {
	env := meshtest.Get(t)
	wrong, _ := meshcentral.NewKey()
	c, err := meshcentral.NewClient(meshcentral.ClientOptions{BaseURL: env.URL, Key: wrong})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go c.Run(ctx)
	<-ctx.Done()
	if c.Connected() {
		t.Fatal("connected with a key MeshCentral does not know")
	}
}

// loggedIn opens MeshCentral's web interface with a login token and reports
// whether it rendered the signed-in application rather than the login page.
func loggedIn(t *testing.T, base, token string) bool {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, base+"/?login="+url.QueryEscape(token), nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), "var userinfo") || strings.Contains(string(body), "\"userid\"")
}
