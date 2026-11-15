//go:build integration

package app_test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// closedURL is an http:// loopback address nothing listens on.
func closedURL(t *testing.T) *url.URL {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://" + ln.Addr().String())
	_ = ln.Close()
	return u
}

func withRemote(t *testing.T) func(*config.Config) {
	return func(c *config.Config) {
		c.Mesh = config.MeshConfig{Enabled: true, InternalURL: closedURL(t), ConfigDir: t.TempDir(), CertURL: "https://127.0.0.1:443"}
	}
}

// meshGet requests a path on the MeshCentral hostname.
func (c *client) meshGet(path string, hdr ...string) response {
	c.h.t.Helper()
	return c.do("GET", path, nil, func(r *http.Request) {
		r.Host = "mesh.rmm.test"
		r.Header.Del("Origin")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
	})
}

type deviceView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	SiteName     string `json:"siteName"`
	RemoteAgent  bool   `json:"remoteAgent"`
	RemoteOnline bool   `json:"remoteOnline"`
	CanDesktop   bool   `json:"canDesktop"`
	CanTerminal  bool   `json:"canTerminal"`
	CanFiles     bool   `json:"canFiles"`
}

func TestRemoteAPI(t *testing.T) {
	h := newHarnessWith(t, false, withRemote(t))
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var site struct {
		ID string `json:"id"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ"}, &site)

	var list struct{ Items []deviceView }
	admin.expect(http.StatusOK, "GET", "/api/v1/devices", nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("devices before any were discovered: %+v", list.Items)
	}

	// Devices as discovery records them.
	var online, offline string
	err := h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		q := `INSERT INTO devices (organization_id, site_id, name, hostname, platform, mesh_node_id, remote_online)
			VALUES ($1, $2, $3, $3, 'windows', $4, $5) RETURNING id`
		if err := tx.QueryRow(context.Background(), q, acme, site.ID, "FRONT-DESK", "node//apitest1", true).Scan(&online); err != nil {
			return err
		}
		return tx.QueryRow(context.Background(), q, acme, site.ID, "back-office", "node//apitest2", false).Scan(&offline)
	})
	if err != nil {
		t.Fatal(err)
	}

	admin.expect(http.StatusOK, "GET", "/api/v1/devices", nil, &list)
	if len(list.Items) != 2 || list.Items[0].Name != "back-office" || list.Items[1].SiteName != "HQ" {
		t.Fatalf("devices: %+v", list.Items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices?status=online&siteId="+site.ID+"&organizationId="+acme+"&q=front", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != online || !list.Items[0].CanDesktop || !list.Items[0].CanFiles {
		t.Fatalf("filtered devices: %+v", list.Items)
	}
	wantStatus(t, admin.do("GET", "/api/v1/devices?status=sleeping", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/devices?siteId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/devices?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	var dev deviceView
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+online, nil, &dev)
	if dev.Name != "FRONT-DESK" || !dev.RemoteAgent || !dev.RemoteOnline || !dev.CanTerminal {
		t.Fatalf("device: %+v", dev)
	}
	wantStatus(t, admin.do("GET", "/api/v1/devices/nope", nil), http.StatusNotFound, "not_found")
	// A site with devices cannot be deleted.
	wantStatus(t, admin.do("DELETE", "/api/v1/sites/"+site.ID, nil), http.StatusConflict, "site_not_empty")

	// Starting sessions.
	start := func(c *client, id, kind string) response {
		return c.do("POST", "/api/v1/devices/"+id+"/remote-sessions", map[string]string{"kind": kind})
	}
	wantStatus(t, start(admin, offline, "desktop"), http.StatusConflict, "device_offline")
	wantStatus(t, start(admin, online, "teleport"), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+online+"/remote-sessions", "x"), http.StatusBadRequest, "")
	wantStatus(t, start(admin, "nope", "desktop"), http.StatusNotFound, "not_found")
	// MeshCentral is not running in this test.
	r := start(admin, online, "desktop")
	wantStatus(t, r, http.StatusServiceUnavailable, "remote_unavailable")

	var st struct {
		Address       string `json:"address"`
		Connected     bool   `json:"connected"`
		Devices       int    `json:"devices"`
		DevicesOnline int    `json:"devicesOnline"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/remote-access/status", nil, &st)
	if st.Connected || st.Devices != 2 || st.DevicesOnline != 1 || st.Address != h.cfg.MeshPublicURL.String() {
		t.Fatalf("status: %+v", st)
	}

	// A read-only user sees devices but cannot open sessions or the status.
	invite(t, h, admin, "rob@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	rob := h.client()
	rob.signIn("rob@acme.example", "a long and unusual passphrase", "")
	rob.expect(http.StatusOK, "GET", "/api/v1/devices/"+online, nil, &dev)
	if dev.CanDesktop || dev.CanTerminal || dev.CanFiles {
		t.Fatalf("read-only device permissions: %+v", dev)
	}
	wantStatus(t, start(rob, online, "terminal"), http.StatusForbidden, "forbidden")
	wantStatus(t, rob.do("GET", "/api/v1/remote-access/status", nil), http.StatusForbidden, "forbidden")

	// Signed out, nothing is reachable.
	anon := h.client()
	wantStatus(t, anon.do("GET", "/api/v1/devices", nil), http.StatusUnauthorized, "")

	// The MeshCentral hostname is served by the gateway, not the console.
	for _, c := range []struct {
		path   string
		hdr    []string
		status int
		text   string
	}{
		{"/", []string{"Sec-Fetch-Mode", "navigate"}, http.StatusForbidden, "Remote session required"},
		{"/api/v1/health", nil, http.StatusForbidden, "Remote session required"},
		{"/.easyrmm/launch?t=not-a-real-token", nil, http.StatusForbidden, "expired"},
		{"/agent.ashx", nil, http.StatusBadGateway, "unavailable"},
		{"/meshsettings?id=x", []string{"Sec-Fetch-Mode", "navigate"}, http.StatusForbidden, "Not available"},
	} {
		r := anon.meshGet(c.path, c.hdr...)
		if r.status != c.status || !strings.Contains(string(r.body), c.text) {
			t.Errorf("mesh host %s: %d %.200s", c.path, r.status, r.body)
		}
		if strings.Contains(r.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("mesh host %s carries the console's security headers", c.path)
		}
	}
}

func TestRemoteAccessDisabled(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	wantStatus(t, admin.do("GET", "/api/v1/devices", nil), http.StatusNotFound, "not_found")
	if r := admin.meshGet("/"); r.status != http.StatusMisdirectedRequest {
		t.Fatalf("mesh host with remote access disabled: %d", r.status)
	}
}
