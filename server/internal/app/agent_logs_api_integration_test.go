//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestAgentLogsAPI sends log batches through the agent API with the agent's
// own client, reads them through the console API, turns verbose mode on and
// sees it in the heartbeat answer and the batch's acknowledgement
// (ADR-0069, Part L).
func TestAgentLogsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Logs", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("log-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := "/api/v1/devices/" + enr.DeviceID
	now := time.Now()

	ack, err := ac.AgentLogs(ctx, agentproto.LogBatch{Records: []agentproto.LogRecord{
		{Seq: 1, Time: now, Source: "agent", Level: "info", Message: "started with ert_AbCdEf0123456789"},
		{Seq: 2, Time: now, Source: "easypatch", Level: "error", Message: "scan failed", Attrs: map[string]string{"password": "hunter2"}},
	}})
	if err != nil || ack.Seq != 2 || ack.Logs != nil {
		t.Fatalf("ack = %+v, %v", ack, err)
	}
	// Sent again after a lost answer: stored once.
	if _, err := ac.AgentLogs(ctx, agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: 2, Time: now, Source: "easypatch", Level: "error", Message: "scan failed"}}}); err != nil {
		t.Fatal(err)
	}

	type page struct {
		Items []struct {
			ID      int64             `json:"id"`
			Source  string            `json:"source"`
			Level   string            `json:"level"`
			Message string            `json:"message"`
			Attrs   map[string]string `json:"attrs"`
		} `json:"items"`
		Verbose *struct{ Scope string } `json:"verbose"`
	}
	var p page
	admin.expect(http.StatusOK, "GET", device+"/agent-logs", nil, &p)
	if len(p.Items) != 2 || strings.Contains(p.Items[0].Message, "AbCdEf") || p.Items[1].Attrs["password"] != "***" {
		t.Fatalf("records %+v", p.Items)
	}
	admin.expect(http.StatusOK, "GET", device+"/agent-logs?source=easypatch&level=error&q=SCAN", nil, &p)
	if len(p.Items) != 1 {
		t.Errorf("filtered %+v", p.Items)
	}
	wantStatus(t, admin.do("GET", device+"/agent-logs?level=loud", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Read-Only cannot read logs; it can still read the device.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	viewer.expect(http.StatusOK, "GET", device, nil, nil)
	wantStatus(t, viewer.do("GET", device+"/agent-logs", nil), http.StatusForbidden, "")
	wantStatus(t, viewer.do("PUT", device+"/agent-logs/verbose", map[string]int{"hours": 2}), http.StatusForbidden, "")

	// Verbose mode: 2 hours by default, then in the heartbeat and the ack.
	wantStatus(t, admin.do("PUT", device+"/agent-logs/verbose", map[string]int{"hours": 99}), http.StatusUnprocessableEntity, "validation_failed")
	var set struct {
		Until time.Time `json:"until"`
	}
	admin.expect(http.StatusOK, "PUT", device+"/agent-logs/verbose", map[string]int{}, &set)
	if d := time.Until(set.Until); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("until = %v", set.Until)
	}
	hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("log-01")})
	if err != nil || hb.Logs == nil || hb.Logs.VerboseUntil != set.Until.Unix() {
		t.Fatalf("heartbeat logs = %+v, %v", hb.Logs, err)
	}
	// A watcher: the console's read with follow=true shows in the next ack.
	admin.expect(http.StatusOK, "GET", device+"/agent-logs?follow=true", nil, &p)
	if p.Verbose == nil || p.Verbose.Scope != "device" {
		t.Errorf("verbose = %+v", p.Verbose)
	}
	ack, err = ac.AgentLogs(ctx, agentproto.LogBatch{})
	if err != nil || ack.Logs == nil || ack.Logs.FollowUntil == 0 || ack.Logs.VerboseUntil == 0 {
		t.Errorf("ack = %+v, %v", ack, err)
	}
	admin.expect(http.StatusNoContent, "DELETE", device+"/agent-logs/verbose", nil, nil)

	// A group's verbose mode: needs device.edit at its site, audited, ends with a DELETE.
	var group idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/device-groups", map[string]string{"name": "Servers"}, &group)
	groupPath := "/api/v1/device-groups/" + group.ID + "/agent-logs/verbose"
	wantStatus(t, viewer.do("PUT", groupPath, map[string]int{"hours": 2}), http.StatusForbidden, "")
	wantStatus(t, admin.do("PUT", groupPath, map[string]int{"hours": 0}), http.StatusOK, "")
	wantStatus(t, admin.do("PUT", groupPath, map[string]int{"hours": 25}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", groupPath, map[string]string{"hours": "x"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/device-groups/00000000-0000-0000-0000-000000000000/agent-logs/verbose", map[string]int{"hours": 2}), http.StatusNotFound, "")
	admin.expect(http.StatusNoContent, "DELETE", groupPath, nil, nil)
	admin.expect(http.StatusNoContent, "DELETE", groupPath, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/not-an-id/agent-logs/verbose", nil), http.StatusNotFound, "")
	wantStatus(t, admin.do("GET", device+"/agent-logs?after=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", device+"/agent-logs?since=yesterday", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", device+"/agent-logs?source=nope", nil), http.StatusUnprocessableEntity, "validation_failed")

	// Downloads.
	r := admin.do("GET", device+"/agent-logs/download?format=jsonl", nil)
	if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Disposition"), "attachment") || strings.Count(string(r.body), "\n") != 2 {
		t.Errorf("download %d %q %q", r.status, r.header.Get("Content-Disposition"), r.body)
	}
	wantStatus(t, admin.do("GET", device+"/agent-logs/download?format=xml", nil), http.StatusUnprocessableEntity, "validation_failed")
}
