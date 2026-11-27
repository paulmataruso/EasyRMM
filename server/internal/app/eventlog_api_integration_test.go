//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// TestEventlogAPI: the console's endpoints for the event viewer (ADR-0068,
// slice 1), with a real agent client taking the signed job a new server sends,
// and one that does not list the builtin.
func TestEventlogAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	accepts := []string{agentproto.CapJobPwsh, agentproto.CapJobParams, agentproto.CapJobStructured, agentproto.CapBuiltin("eventlog", 1)}
	pc := windowsAt(t, h, admin, hq.ID, "win-01", accepts)
	old := windowsAt(t, h, admin, hq.ID, "win-old", []string{agentproto.CapJobPwsh, agentproto.CapJobStructured, agentproto.CapBuiltin("registry", 1)})
	signIn := func(email string, assignments ...map[string]any) *client {
		invite(t, h, admin, email, assignments)
		c := h.client()
		c.signIn(email, "a long and unusual passphrase", "")
		return c
	}
	tech := signIn("tess@acme.example", map[string]any{"role": "technician", "organizationId": acme, "siteId": hq.ID})
	other := signIn("tom@acme.example", map[string]any{"role": "technician", "organizationId": acme, "siteId": hq.ID})
	viewer := signIn("rory@acme.example", map[string]any{"role": "read_only", "organizationId": acme})
	orgAdmin := signIn("olga@acme.example", map[string]any{"role": "org_admin", "organizationId": acme})

	body := map[string]any{"op": "query", "channels": []string{"System"}, "levels": []int{2}}
	wantStatus(t, viewer.do("POST", "/api/v1/devices/"+pc.id+"/eventlog", body), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, h.client().do("POST", "/api/v1/devices/"+pc.id+"/eventlog", body), http.StatusUnauthorized, "")
	r := tech.do("POST", "/api/v1/devices/"+old.id+"/eventlog", body)
	if r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), "cannot open the event viewer; update the agent") {
		t.Errorf("an agent without the builtin: %d %s", r.status, r.body)
	}
	r = tech.do("POST", "/api/v1/devices/"+pc.id+"/eventlog", map[string]any{"op": "query", "channels": []string{"Security"}, "sensitive": true})
	if r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), "Refused by EasyRMM") {
		t.Errorf("the Security log for a technician: %d %s", r.status, r.body)
	}

	var run struct {
		RunID     string `json:"runId"`
		Sensitive bool   `json:"sensitive"`
	}
	tech.expect(http.StatusAccepted, "POST", "/api/v1/devices/"+pc.id+"/eventlog", body, &run)
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil), http.StatusConflict, "run_open")

	poll, err := pc.ac.Poll(ctx, accepts, nil)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(pc.key, poll.Jobs[0], pc.id, time.Now())
	if err != nil || p.Executor != "builtin" || p.Builtin != "eventlog" || p.Lane != "quick" {
		t.Fatalf("%+v %v", p, err)
	}
	in, err := eventrules.DecodeInput(p.Input)
	if err != nil || in.Op != "query" || in.Channels[0] != "System" || in.Sensitive {
		t.Fatalf("%+v %v", in, err)
	}
	if st, err := pc.ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>7034</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime="2026-11-26T10:00:00.000Z"/><EventRecordID>77</EventRecordID><Execution ProcessID="1" ThreadID="2"/><Channel>System</Channel><Computer>win-01</Computer><Security/></System><EventData><Data Name="param1">The Print Spooler service terminated unexpectedly.</Data></EventData></Event>`
	pe, _ := eventrules.ParseXML(xml)
	zero := 0
	res := lines(
		eventrules.Begin{T: "begin", V: 1, Op: "query", Rules: 1, AgentVersion: "9.9.9", Arch: "x64", Clock: time.Now().UTC().Format(time.RFC3339Nano)},
		eventrules.Pos{T: "pos", Channel: "System", State: "ok"},
		eventrules.Event{T: "event", Log: "System", Channel: "System", Record: 77, Provider: pe.Provider, ID: 7034, Level: 2, Keywords: "0x8080000000000000",
			Time: pe.Time, Computer: "win-01", PID: 1, TID: 2, Data: pe.Data, Message: "The Print Spooler service terminated unexpectedly.", XML: xml},
		eventrules.End{T: "end", Complete: true, Returned: 1, Read: 1, StoppedBy: "end", Cursor: &eventrules.Cursor{Channels: []eventrules.ChannelCursor{{Channel: "System", Record: 77, Done: true}}}},
	)
	if err := pc.ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero, Result: res, AgentVersion: "9.9.9"}); err != nil {
		t.Fatal(err)
	}

	var view struct {
		State  string `json:"state"`
		Events []struct {
			Record   int64  `json:"record"`
			Provider string `json:"provider"`
		} `json:"events"`
		AgentVersion string `json:"agentVersion"`
		Complete     bool   `json:"complete"`
	}
	got := tech.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil, &view)
	if view.State != "reported" || len(view.Events) != 1 || view.Events[0].Record != 77 || view.AgentVersion != "9.9.9" || !view.Complete {
		t.Errorf("result %s", got.body)
	}
	if cc := got.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	// Only the asker reads it.
	wantStatus(t, other.do("GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, orgAdmin.do("GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/nope/eventlog", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", "/api/v1/job-runs/"+run.RunID+"/eventlog", nil), http.StatusUnauthorized, "")

	// The next page names the run and nothing else; the last page has none.
	wantStatus(t, tech.do("POST", "/api/v1/devices/"+pc.id+"/eventlog", map[string]any{"previousRunId": run.RunID}), http.StatusConflict, "no_more")
	wantStatus(t, other.do("POST", "/api/v1/devices/"+pc.id+"/eventlog", map[string]any{"previousRunId": run.RunID}), http.StatusForbidden, "forbidden")

	// An organization administrator reads the Security log by asking for it.
	var sec struct {
		Sensitive bool `json:"sensitive"`
	}
	orgAdmin.expect(http.StatusAccepted, "POST", "/api/v1/devices/"+pc.id+"/eventlog", map[string]any{"op": "query", "channels": []string{"Security"}, "sensitive": true}, &sec)
	if !sec.Sensitive {
		t.Error("an organization administrator's sensitive query")
	}

	// The Jobs list leaves event log reads out without its filter.
	var list struct {
		Items []struct{ ID, Kind string } `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs", nil, &list)
	for _, j := range list.Items {
		if strings.HasPrefix(j.Kind, "eventlog") {
			t.Errorf("an event log read in the Jobs list: %+v", j)
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs?kind=eventlog", nil, &list)
	if len(list.Items) == 0 {
		t.Error("the Event logs filter shows nothing")
	}

	// The audit log: one record per first page, the refusal; no event data.
	var audit struct {
		Items []struct {
			Action  string         `json:"action"`
			Details map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=eventlog&limit=100", nil, &audit)
	counts := map[string]int{}
	for _, e := range audit.Items {
		counts[e.Action]++
	}
	if counts["eventlog.query"] != 2 || counts["eventlog.refused"] < 1 {
		t.Errorf("records %v", counts)
	}
	all := admin.do("GET", "/api/v1/audit?limit=500", nil)
	if strings.Contains(string(all.body), "Print Spooler") {
		t.Error("event data in the audit log")
	}
	_ = json.Marshal
}
