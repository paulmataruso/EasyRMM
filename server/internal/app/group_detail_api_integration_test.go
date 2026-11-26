//go:build integration

package app_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestGetDeviceGroup covers GET /device-groups/{id} (ADR-0072): the group with
// its site, organization, device count and verbose logging; a caller with
// access to another organization only, and a missing group, both get 404.
func TestGetDeviceGroup(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var other idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &other)
	var hq, far idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+other.ID+"/sites", map[string]string{"name": "Far", "timezone": "UTC"}, &far)
	var servers, hidden idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/device-groups", map[string]string{"name": "Servers"}, &servers)
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+far.ID+"/device-groups", map[string]string{"name": "Hidden"}, &hidden)

	type detail struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		OrganizationID   string     `json:"organizationId"`
		OrganizationName string     `json:"organizationName"`
		SiteID           string     `json:"siteId"`
		SiteName         string     `json:"siteName"`
		DeviceCount      int        `json:"deviceCount"`
		VerboseUntil     *time.Time `json:"verboseUntil"`
		CanManage        bool       `json:"canManage"`
		CanEditDevices   bool       `json:"canEditDevices"`
	}
	path := "/api/v1/device-groups/" + servers.ID

	var g detail
	admin.expect(http.StatusOK, "GET", path, nil, &g)
	if g.ID != servers.ID || g.Name != "Servers" || g.OrganizationID != acme || g.OrganizationName != "Acme" || g.SiteID != hq.ID || g.SiteName != "HQ" ||
		g.DeviceCount != 0 || g.VerboseUntil != nil || !g.CanManage || !g.CanEditDevices {
		t.Fatalf("admin sees %+v", g)
	}

	// Verbose logging, set the way the page sets it, shows on the group.
	admin.expect(http.StatusOK, "PUT", path+"/agent-logs/verbose", map[string]int{"hours": 2}, nil)
	admin.expect(http.StatusOK, "GET", path, nil, &g)
	if g.VerboseUntil == nil || !g.VerboseUntil.After(time.Now()) {
		t.Errorf("verbose until %v", g.VerboseUntil)
	}
	admin.expect(http.StatusNoContent, "DELETE", path+"/agent-logs/verbose", nil, nil)
	admin.expect(http.StatusOK, "GET", path, nil, &g)
	if g.VerboseUntil != nil {
		t.Errorf("verbose still on: %v", g.VerboseUntil)
	}

	// A read-only person in the group's organization may see it, not change it.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	viewer.expect(http.StatusOK, "GET", path, nil, &g)
	if g.Name != "Servers" || g.CanManage || g.CanEditDevices {
		t.Errorf("viewer sees %+v", g)
	}

	// The same person cannot see another organization's group, and a missing group is the same answer.
	wantStatus(t, viewer.do("GET", "/api/v1/device-groups/"+hidden.ID, nil), http.StatusNotFound, "")
	wantStatus(t, viewer.do("GET", "/api/v1/device-groups/"+uuid.NewString(), nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("GET", "/api/v1/device-groups/"+uuid.NewString(), nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("GET", "/api/v1/device-groups/not-an-id", nil), http.StatusNotFound, "")
	wantStatus(t, h.client().do("GET", path, nil), http.StatusUnauthorized, "")
}
