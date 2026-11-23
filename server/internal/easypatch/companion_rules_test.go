package easypatch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// What the engine does with RepairCompanion and CollectLogs jobs (ADR-0069),
// asked of the real engine by the contract test and of eptest by
// TestEptestKeepsTheEnginesCompanionRules: the same questions, so that
// eptest cannot drift from the engine.

// companionHash is a SHA-256 as the engine wants one: 64 lower-case hex
// digits.
const companionHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// checkCompanionRules asks engine about the endpoint. capable makes the
// endpoint's agent declare (true) or not declare (false) the repair-companion
// and collect-logs capabilities; reader is a client that may only read.
func checkCompanionRules(t *testing.T, ctx, reader context.Context, engine *Client, endpoint uuid.UUID, capable func(bool)) {
	t.Helper()
	refused := func(what string, err error, status int, code string) {
		t.Helper()
		var e *Error
		if !errors.As(err, &e) || e.Status != status || e.Code != code {
			t.Errorf("%s: %#v, want %d %s", what, err, status, code)
		}
	}

	// An agent that does not declare the capability is sent neither job.
	capable(false)
	_, err := engine.RepairCompanion(ctx, endpoint, "meshagent", "restart", "", "")
	refused("a restart for an agent without the capability", err, http.StatusConflict, "agent_upgrade_required")
	_, err = engine.CollectLogs(ctx, endpoint, "")
	refused("log collection for an agent without the capability", err, http.StatusConflict, "agent_upgrade_required")

	capable(true)
	// A target and a step from fixed lists, nothing else; a hash only for
	// the EasyRMM agent's repair, in the form of a SHA-256.
	for _, bad := range [][4]string{
		{"powershell", "restart", ""},
		{"easyrmm-agent", "reinstall", ""},
		{"easyrmm-agent", "repair", ""},
		{"easyrmm-agent", "repair", "not-a-hash"},
		{"easyrmm-agent", "repair", strings.ToUpper(companionHash)},
		{"easyrmm-agent", "restart", companionHash},
		{"meshagent", "repair", companionHash},
		{"meshagent", "repair", ""},
		{"meshagent", "restart", companionHash},
		{"", "", ""},
	} {
		_, err := engine.RepairCompanion(ctx, endpoint, bad[0], bad[1], bad[2], "")
		refused("a job for "+strings.Join(bad[:3], "/"), err, http.StatusBadRequest, "validation_failed")
	}
	if _, err := engine.RepairCompanion(reader, endpoint, "meshagent", "restart", "", ""); !IsStatus(err, http.StatusForbidden) {
		t.Errorf("a read-only caller asked for a repair: %v", err)
	}
	if _, err := engine.CollectLogs(reader, endpoint, ""); !IsStatus(err, http.StatusForbidden) {
		t.Errorf("a read-only caller asked for logs: %v", err)
	}

	var created []Job
	for _, step := range [][3]string{{"meshagent", "restart", ""}, {"easyrmm-agent", "restart", ""}, {"easyrmm-agent", "repair", companionHash}} {
		j, err := engine.RepairCompanion(ctx, endpoint, step[0], step[1], step[2], "")
		if err != nil || j.ID == uuid.Nil || j.Type != "RepairCompanion" || j.Status != "Queued" || j.EndpointID != endpoint {
			t.Fatalf("%v: %+v, %v", step, j, err)
		}
		created = append(created, j)
		// The same step again while it waits is a duplicate, naming it.
		_, err = engine.RepairCompanion(ctx, endpoint, step[0], step[1], step[2], "")
		refused("the same step twice", err, http.StatusConflict, "duplicate_job")
	}
	logs, err := engine.CollectLogs(ctx, endpoint, "")
	if err != nil || logs.Type != "CollectLogs" || logs.Status != "Queued" {
		t.Fatalf("log collection: %+v, %v", logs, err)
	}
	created = append(created, logs)
	_, err = engine.CollectLogs(ctx, endpoint, "")
	refused("log collection twice", err, http.StatusConflict, "duplicate_job")

	// A job that has not run has no diagnostics, and shows as null.
	d, err := engine.Job(ctx, logs.ID)
	if err != nil || d.Summary.Type != "CollectLogs" || d.Diagnostics != "" {
		t.Errorf("a job that has not run: %+v, %v", d, err)
	}
	for _, j := range created {
		if _, err := engine.CancelJob(ctx, j.ID, ""); err != nil {
			t.Errorf("canceling %s: %v", j.ID, err)
		}
	}
}

// eptest answers as the engine does (checked against the real one by the
// contract test, which asks the same).
func TestEptestKeepsTheEnginesCompanionRules(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	srv := eptest.NewEngine(t, key)
	engine := engineClient(t, srv.URL(), key)
	org := srv.Org("Acme")
	e := srv.AddEndpoint(org, "pc", "", "fp")
	ctx := WithStatement(context.Background(), Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleAdmin, AllOrganizations: true})
	reader := WithStatement(context.Background(), Statement{Subject: ServiceSubject, Name: "reader", Role: RoleReadOnly, AllOrganizations: true})
	checkCompanionRules(t, ctx, reader, engine, e.ID, func(capable bool) { srv.Set(func() { e.CannotRepairCompanion = !capable }) })

	// The agent's result: diagnostics apart from the message, at most
	// 256 KiB.
	j, err := engine.CollectLogs(ctx, e.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if srv.SetJobResult(j.ID, "Completed", "Collected.", "", strings.Repeat("x", eptest.MaxDiagnostics+1)) {
		t.Error("the engine took more than 256 KiB of diagnostics")
	}
	if !srv.SetJobResult(j.ID, "Completed", "Collected.", "", "==== meshagent ====\nline") {
		t.Fatal("the result was refused")
	}
	d, err := engine.Job(ctx, j.ID)
	if err != nil || d.Diagnostics != "==== meshagent ====\nline" || d.Summary.ProgressMessage != "Collected." || d.Summary.Status != "Completed" {
		t.Errorf("job = %+v, %v", d, err)
	}
	// Not for an endpoint that is not active.
	srv.Set(func() { e.Status = "Revoked" })
	if _, err := engine.CollectLogs(ctx, e.ID, ""); !IsStatus(err, http.StatusConflict) {
		t.Errorf("an endpoint that is not active: %v", err)
	}
}
