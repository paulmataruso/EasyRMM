//go:build integration

package app_test

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAuditForwardingAPI configures audit forwarding through the console API
// and sends a test message to a collector (ADR-0023).
func TestAuditForwardingAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('}')
		got <- line
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	type settings struct {
		Configured   bool   `json:"configured"`
		Enabled      bool   `json:"enabled"`
		Transport    string `json:"transport"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		Facility     int    `json:"facility"`
		ClientKeySet bool   `json:"clientKeySet"`
		Hostname     string `json:"hostname"`
		UpdatedBy    string `json:"updatedBy"`
		Status       struct {
			Backlog int64 `json:"backlog"`
			Stored  int64 `json:"stored"`
		} `json:"status"`
	}
	var s settings
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/audit-forwarding", nil, &s)
	if s.Configured || s.Transport != "tls" || s.Port != 6514 || s.Hostname != "rmm.test" || s.Status.Stored == 0 {
		t.Fatalf("defaults %+v", s)
	}

	// A test message to an unsaved destination.
	var res struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	in := map[string]any{"enabled": true, "transport": "tcp", "host": "127.0.0.1", "port": port, "facility": 13, "startFrom": "now"}
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/audit-forwarding/test", in, &res)
	if !res.OK {
		t.Fatalf("test: %+v", res)
	}
	select {
	case m := <-got:
		if !strings.Contains(m, " easyrmm - test [origin software=\"EasyRMM\"") || !strings.Contains(m, `"requestedBy":"admin@msp.example"`) {
			t.Fatalf("test message %q", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the collector received no test message")
	}
	wantStatus(t, admin.do("POST", "/api/v1/settings/audit-forwarding/test", map[string]any{"transport": "tcp", "host": "127.0.0.1"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/settings/audit-forwarding/test", map[string]any{"bogus": 1}), http.StatusUnprocessableEntity, "validation_failed")

	// Saving.
	wantStatus(t, admin.do("PUT", "/api/v1/settings/audit-forwarding", map[string]any{"transport": "carrier pigeon"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/audit-forwarding", []int{1}), http.StatusBadRequest, "")
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/audit-forwarding", in, &s)
	if !s.Configured || !s.Enabled || s.Transport != "tcp" || s.Port != port || s.UpdatedBy != "admin@msp.example" || s.Status.Backlog != 1 {
		t.Fatalf("saved %+v", s)
	}

	// Both are in the audit log.
	var entries struct {
		Items []struct {
			Action   string `json:"action"`
			TargetID string `json:"targetId"`
			Outcome  string `json:"outcome"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=audit_forwarding", nil, &entries)
	if len(entries.Items) != 2 || entries.Items[0].Action != "audit_forwarding.update" || entries.Items[1].Action != "audit_forwarding.test" ||
		entries.Items[0].TargetID != ln.Addr().String() {
		t.Fatalf("audit %+v", entries.Items)
	}

	// Only platform-wide settings managers: forwarding carries every
	// organization's records.
	invite(t, h, admin, "olive@acme.example", []map[string]any{{"role": "org_admin", "organizationId": orgID(t, admin, "Acme")}})
	org := h.client()
	org.signIn("olive@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, org.do("GET", "/api/v1/settings/audit-forwarding", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, org.do("PUT", "/api/v1/settings/audit-forwarding", in), http.StatusForbidden, "forbidden")
	wantStatus(t, org.do("POST", "/api/v1/settings/audit-forwarding/test", in), http.StatusForbidden, "forbidden")
	wantStatus(t, h.client().do("GET", "/api/v1/settings/audit-forwarding", nil), http.StatusUnauthorized, "")
}
