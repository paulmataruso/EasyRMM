//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// windowsAt enrolls a Windows device whose agent lists the registry
// editor, through the real agent client.
func windowsAt(t *testing.T, h *harness, admin *client, site, name string, accepts []string) enrolled {
	t.Helper()
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+site+"/enrollment-tokens", map[string]any{"name": name, "expiresInDays": 1}, &token)
	ac := h.agentClient()
	key := newKey(t)
	f := facts(name)
	f.Platform, f.OS = "windows", "Windows Server 2025 Standard"
	enr, err := ac.Enroll(context.Background(), token.Secret, key.Public().(ed25519.PublicKey), f)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	// The agent learns the server's protocol level from a heartbeat answer, and
	// only then says what it accepts, in its poll or its heartbeat.
	if _, err := ac.Heartbeat(context.Background(), agentproto.HeartbeatRequest{Facts: f, Accepts: accepts}); err != nil {
		t.Fatal(err)
	}
	return enrolled{id: enr.DeviceID, ac: ac, key: jobKey}
}

func lines(v ...any) string {
	var b strings.Builder
	for _, l := range v {
		j, _ := json.Marshal(l)
		b.Write(j)
		b.WriteByte('\n')
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}

// TestRegistryAPI: the console's endpoints for a read of a Windows
// computer's registry (ADR-0067, slice 1), with a real agent client taking
// the signed job a new server sends, and one that does not list the editor.
func TestRegistryAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	accepts := []string{agentproto.CapJobPwsh, agentproto.CapJobParams, agentproto.CapJobStructured, agentproto.CapBuiltin("registry", 1)}
	pc := windowsAt(t, h, admin, hq.ID, "win-01", accepts)
	old := windowsAt(t, h, admin, hq.ID, "win-old", []string{agentproto.CapJobPwsh})
	signIn := func(email string, assignments ...map[string]any) *client {
		invite(t, h, admin, email, assignments)
		c := h.client()
		c.signIn(email, "a long and unusual passphrase", "")
		return c
	}
	tech := signIn("tess@acme.example", map[string]any{"role": "technician", "organizationId": acme, "siteId": hq.ID})
	other := signIn("tom@acme.example", map[string]any{"role": "technician", "organizationId": acme, "siteId": hq.ID})
	viewer := signIn("rory@acme.example", map[string]any{"role": "read_only", "organizationId": acme})

	// Who may ask, and of whom.
	body := map[string]any{"op": "list", "hive": "HKLM", "path": []string{"SOFTWARE"}}
	wantStatus(t, viewer.do("POST", "/api/v1/devices/"+pc.id+"/registry/query", body), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, h.client().do("POST", "/api/v1/devices/"+pc.id+"/registry/query", body), http.StatusUnauthorized, "")
	r := tech.do("POST", "/api/v1/devices/"+old.id+"/registry/query", body)
	if r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), "cannot open the registry editor; update the agent") {
		t.Errorf("an agent without the editor: %d %s", r.status, r.body)
	}
	r = tech.do("POST", "/api/v1/devices/"+pc.id+"/registry/query", map[string]any{"op": "list", "text": `HKLM\SECURITY\SAM`})
	if r.status != http.StatusUnprocessableEntity || !strings.Contains(string(r.body), "Refused by EasyRMM") {
		t.Errorf("a refused path: %d %s", r.status, r.body)
	}

	var run struct {
		RunID string   `json:"runId"`
		Path  []string `json:"path"`
		Hive  string   `json:"hive"`
	}
	tech.expect(http.StatusAccepted, "POST", "/api/v1/devices/"+pc.id+"/registry/query", map[string]any{"op": "list", "text": `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Vendor`}, &run)
	if run.Hive != "HKLM" || strings.Join(run.Path, `\`) != `SOFTWARE\Vendor` {
		t.Errorf("run %+v", run)
	}
	// Open: nothing to read yet.
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+run.RunID+"/result", nil), http.StatusConflict, "run_open")

	// The real agent client takes the signed job, which carries the input.
	poll, err := pc.ac.Poll(ctx, accepts)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(pc.key, poll.Jobs[0], pc.id, time.Now())
	if err != nil || p.Executor != "builtin" || p.Builtin != "registry" || p.Lane != "quick" {
		t.Fatalf("%+v %v", p, err)
	}
	in, err := agentproto.DecodeRegistryInput(p.Input)
	if err != nil || in.Op != "list" || strings.Join(in.Path, `\`) != `SOFTWARE\Vendor` {
		t.Fatalf("%+v %v", in, err)
	}
	if st, err := pc.ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	zero := 0
	res := lines(
		agentproto.RegBegin{T: "begin", V: 1, Op: "list", Hive: "HKLM", View: "64", Path: []string{"SOFTWARE", "Vendor"}, Rules: 1, AgentVersion: "9.9.9", Arch: "x64"},
		agentproto.RegKey{T: "key", Kernel: `\REGISTRY\MACHINE\SOFTWARE\Vendor`, Subkeys: 0, Values: 2, ReadAt: time.Now().UTC().Format(time.RFC3339)},
		agentproto.RegValue{T: "value", Name: "Name", Type: 1, Size: 12, Text: strPtr("vendor")},
		agentproto.RegValue{T: "value", Name: "ApiToken", Type: 1, Size: 20, Text: strPtr("api-marker-77c1")},
		agentproto.RegEnd{T: "end", Complete: true, ElapsedMS: 4},
	)
	if err := pc.ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero, Result: res, AgentVersion: "9.9.9"}); err != nil {
		t.Fatal(err)
	}

	// The asker reads it; the value a rule of ours masks is masked.
	var view struct {
		State  string `json:"state"`
		Values []struct {
			Name   string  `json:"name"`
			Masked bool    `json:"masked"`
			Text   *string `json:"text"`
		} `json:"values"`
		AgentVersion string `json:"agentVersion"`
	}
	got := tech.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+run.RunID+"/result", nil, &view)
	if view.State != "reported" || len(view.Values) != 2 || view.AgentVersion != "9.9.9" || strings.Contains(string(got.body), "api-marker-77c1") {
		t.Errorf("result %s", got.body)
	}
	for _, v := range view.Values {
		if (v.Name == "ApiToken") != v.Masked {
			t.Errorf("value %+v", v)
		}
	}
	if cc := got.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	// Nobody else: not another technician of the site, not a viewer; an outsider finds nothing.
	wantStatus(t, other.do("GET", "/api/v1/job-runs/"+run.RunID+"/result", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("GET", "/api/v1/job-runs/"+run.RunID+"/result", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/nope/result", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", "/api/v1/job-runs/"+run.RunID+"/result", nil), http.StatusUnauthorized, "")
	// The input, through the arguments endpoint, follows the same rule.
	var args struct {
		Input json.RawMessage `json:"input"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs/"+p.JobID+"/arguments", nil, &args)
	if !strings.Contains(string(args.Input), `"SOFTWARE"`) {
		t.Errorf("input %s", args.Input)
	}
	wantStatus(t, other.do("GET", "/api/v1/jobs/"+p.JobID+"/arguments", nil), http.StatusForbidden, "forbidden")

	// The Jobs list leaves registry reads out without its filter.
	var list struct {
		Items []struct{ ID, Kind string } `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs", nil, &list)
	for _, j := range list.Items {
		if strings.HasPrefix(j.Kind, "registry") {
			t.Errorf("a registry read in the Jobs list: %+v", j)
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs?kind=registry", nil, &list)
	if len(list.Items) == 0 {
		t.Error("the Registry filter shows nothing")
	}

	// An export is a file for the person who asked.
	var ex struct {
		RunID string `json:"runId"`
	}
	tech.expect(http.StatusAccepted, "POST", "/api/v1/devices/"+pc.id+"/registry/query", map[string]any{"op": "export", "hive": "HKLM", "path": []string{"SOFTWARE", "Vendor"}}, &ex)
	poll, _ = pc.ac.Poll(ctx, accepts)
	if len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v", poll)
	}
	ep, _ := agentproto.VerifyJob(pc.key, poll.Jobs[0], pc.id, time.Now())
	if _, err := pc.ac.Start(ctx, ep.RunID); err != nil {
		t.Fatal(err)
	}
	if err := pc.ac.Result(ctx, ep.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero, Result: lines(
		agentproto.RegBegin{T: "begin", V: 1, Op: "export", Hive: "HKLM", View: "64", Path: []string{"SOFTWARE", "Vendor"}, Rules: 1},
		agentproto.RegXKey{T: "xkey", Path: []string{"SOFTWARE", "Vendor"}, Values: []agentproto.RegValue{{T: "value", Name: "N", Type: 4, Size: 4, Number: u32(5)}}},
		agentproto.RegEnd{T: "end", Complete: true},
	)}); err != nil {
		t.Fatal(err)
	}
	f := tech.do("GET", "/api/v1/job-runs/"+ex.RunID+"/export?format=reg", nil)
	if f.status != http.StatusOK || f.header.Get("Content-Disposition") == "" || f.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("export %d %v", f.status, f.header)
	}
	if f.body[0] != 0xFF || f.body[1] != 0xFE {
		t.Error("a .reg file starts with a byte order mark")
	}
	var u []uint16
	for i := 2; i+1 < len(f.body); i += 2 {
		u = append(u, uint16(f.body[i])|uint16(f.body[i+1])<<8)
	}
	if text := string(utf16.Decode(u)); !strings.Contains(text, `"N"=dword:00000005`) {
		t.Errorf("file %q", text)
	}
	wantStatus(t, other.do("GET", "/api/v1/job-runs/"+ex.RunID+"/export?format=reg", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("GET", "/api/v1/job-runs/"+ex.RunID+"/export?format=xml", nil), http.StatusUnprocessableEntity, "validation_failed")

	// The audit log: one record per read, the export, the refusal; no data, no term.
	var audit struct {
		Items []struct {
			Action  string         `json:"action"`
			Details map[string]any `json:"details"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=registry&limit=100", nil, &audit)
	counts := map[string]int{}
	for _, e := range audit.Items {
		counts[e.Action]++
	}
	if counts["registry.read"] != 2 || counts["registry.export"] != 1 || counts["registry.refused"] != 1 {
		t.Errorf("records %v", counts)
	}
	all := admin.do("GET", "/api/v1/audit?limit=500", nil)
	if strings.Contains(string(all.body), "api-marker-77c1") {
		t.Error("data in the audit log")
	}
	// A result over MaxResultBody is refused; the agent API limit is 8 MiB.
	if agentproto.MaxResultBody != 8<<20 {
		t.Error("MaxResultBody")
	}
}

func strPtr(s string) *string { return &s }
func u32(n uint32) *uint32    { return &n }
