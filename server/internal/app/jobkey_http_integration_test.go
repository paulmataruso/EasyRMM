//go:build integration

package app_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Rotating the job key through the API (ADR-0057): every change needs the
// session stepped up, and the refusals say why.
func TestHTTPJobKeyRotation(t *testing.T) {
	h := newHarness(t, false)
	admin := h.client()
	setup, _ := os.ReadFile(filepath.Join(h.dataDir, "setup-token"))
	const pw = "correct horse battery staple"
	admin.expect(http.StatusNoContent, "POST", "/api/v1/setup", map[string]string{"token": strings.TrimSpace(string(setup)),
		"email": "admin@msp.example", "displayName": "Ada", "password": pw}, nil)
	secret := admin.signIn("admin@msp.example", pw, "")
	const base = "/api/v1/settings/job-key"

	var st struct {
		Floor int64 `json:"floor"`
		Keys  []struct {
			Generation  int64  `json:"generation"`
			Fingerprint string `json:"fingerprint"`
			Held        bool   `json:"held"`
		} `json:"keys"`
		Rotation *struct {
			Generation  int64     `json:"generation"`
			MayFinishAt time.Time `json:"mayFinishAt"`
		} `json:"rotation"`
	}
	admin.expect(http.StatusOK, "GET", base, nil, &st)
	if len(st.Keys) != 1 || st.Floor != st.Keys[0].Generation || !st.Keys[0].Held || st.Rotation != nil {
		t.Fatalf("status: %+v", st)
	}
	if strings.Contains(string(admin.do("GET", base, nil).body), "seed") {
		t.Fatal("the status mentions a seed")
	}

	// Without the step-up nothing changes.
	for _, c := range []struct{ path string }{{"/rotate"}, {"/finish"}, {"/forget"}, {"/replace-lost"}, {"/recover"}} {
		if r := admin.do("POST", base+c.path, map[string]any{"reason": "planned", "generation": 1}); r.status != http.StatusUnauthorized || r.errorCode(t) != "step_up_required" {
			t.Fatalf("%s without step-up: %d %s", c.path, r.status, r.body)
		}
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/auth/step-up/totp", map[string]string{"code": code(t, secret, time.Now().Add(30*time.Second))}, nil)

	if r := admin.do("POST", base+"/rotate", map[string]string{"reason": "nonsense"}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("a bad reason: %d %s", r.status, r.body)
	}
	admin.expect(http.StatusCreated, "POST", base+"/rotate", map[string]string{"reason": "planned"}, nil)
	admin.expect(http.StatusOK, "GET", base, nil, &st)
	if len(st.Keys) != 2 || st.Rotation == nil || st.Floor != st.Keys[0].Generation || st.Rotation.Generation != st.Keys[1].Generation {
		t.Fatalf("after rotate: %+v", st)
	}
	if !st.Rotation.MayFinishAt.After(time.Now().Add(23 * time.Hour)) {
		t.Fatalf("may finish at %v", st.Rotation.MayFinishAt)
	}

	if r := admin.do("POST", base+"/rotate", map[string]string{"reason": "planned"}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_rotation_in_progress" {
		t.Fatalf("a second rotation: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", base+"/finish", map[string]bool{"backupTakenSinceStart": false}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_backup_unconfirmed" {
		t.Fatalf("no backup: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", base+"/finish", map[string]bool{"backupTakenSinceStart": true}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_too_early" {
		t.Fatalf("too early: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", base+"/forget", map[string]int64{"generation": st.Keys[1].Generation}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_newest" {
		t.Fatalf("forget the newest: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", base+"/forget", map[string]int64{"generation": 0}); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("forget nothing: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", base+"/replace-lost", map[string]string{}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_nothing_lost" {
		t.Fatalf("nothing is lost: %d %s", r.status, r.body)
	}

	// A compromise ends the planned rotation and makes its key the floor.
	admin.expect(http.StatusCreated, "POST", base+"/rotate", map[string]string{"reason": "compromised"}, nil)
	st.Rotation = nil
	admin.expect(http.StatusOK, "GET", base, nil, &st)
	if len(st.Keys) != 3 || st.Rotation != nil || st.Floor != st.Keys[2].Generation {
		t.Fatalf("after the compromise: %+v", st)
	}
	var out struct {
		Devices int `json:"devicesNeedingRepinning"`
	}
	admin.expect(http.StatusOK, "POST", base+"/forget", map[string]int64{"generation": st.Keys[0].Generation}, &out)
	if r := admin.do("POST", base+"/forget", map[string]int64{"generation": st.Keys[0].Generation}); r.status != http.StatusConflict || r.errorCode(t) != "job_key_no_seed" {
		t.Fatalf("forgotten twice: %d %s", r.status, r.body)
	}
}
