//go:build integration

package agents

import (
	"io"
	"log/slog"
	"testing"

	"github.com/paulmataruso/easyrmm/agent/settings"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type memSettings struct{ saved *state.Settings }

func (m *memSettings) LoadSettings() *state.Settings { return m.saved }
func (m *memSettings) SaveSettings(s state.Settings) error {
	m.saved = &s
	return nil
}

// The real agent code against the real server code: a document is issued,
// verified, applied and acknowledged, a change in between is issued as a newer
// version, the agent's restart applies what it saved, and the server ends
// with the agent's report.
func TestTheAgentAppliesWhatTheServerIssuesAndTheServerHearsIt(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "srv")
	store := &memSettings{}
	newAgent := func() *settings.Agent {
		a := &settings.Agent{DeviceID: d.ID.String(), Keys: func() agentproto.Keys { return agentproto.Keys{f.k1.Public} }, Store: store,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		a.Load()
		return a
	}
	a := newAgent()
	// One heartbeat as the runner makes it, with the report from the agent's
	// own code, and the answer given back to it.
	beat := func(secs int) *agentproto.HeartbeatResponse {
		t.Helper()
		resp := f.settingsBeat(d, settingsBeat{sha: oldSHA, caps: a.Capabilities(), report: a.Report(), secs: secs})
		a.Answered(agentproto.Protocol, resp.Settings)
		return resp
	}

	f.setSite("240")
	if resp := beat(60); resp.Settings == nil {
		t.Fatal("the first heartbeat with the report got no document")
	}
	if got, held := a.Interval(300); got != 240 || !held {
		t.Fatalf("the agent's interval after applying: %d %v", got, held)
	}
	if resp := beat(240); resp.Settings != nil {
		t.Fatal("the document was sent again after it was applied")
	}
	st := f.state(d)
	if st.AppliedVersion != st.DocVersion || st.AppliedVersion == 0 || st.NotApplied() || len(st.Problems) != 0 {
		t.Fatalf("the server did not hear it: %+v", st)
	}
	if secs := f.count(`SELECT agent_heartbeat_seconds FROM devices WHERE id = $1`, d.ID); secs != 240 {
		t.Errorf("the interval kept: %d", secs)
	}
	// A change is issued as a newer version and applied.
	first := st.DocVersion
	f.setSite("90")
	beat(240)
	if got, _ := a.Interval(300); got != 90 || a.Report().Version <= first {
		t.Errorf("after the change: interval %d, version %d (was %d)", got, a.Report().Version, first)
	}
	beat(90)
	if st := f.state(d); st.AppliedVersion != a.Report().Version || st.NotAppliedHeartbeats != 0 {
		t.Errorf("after the change: %+v", st)
	}
	// A restart applies the saved settings before any heartbeat, and the
	// server has nothing more to send it.
	a = newAgent()
	if got, held := a.Interval(300); got != 90 || !held {
		t.Fatalf("after a restart: %d %v", got, held)
	}
	if resp := beat(90); resp.Settings != nil {
		t.Error("a restarted agent holding the current version was sent it again")
	}
	// An agent that lost its file (reinstalled) reports version 0 and is sent
	// the current document again, which keeps its version: above its own 0
	// and the one the server issued.
	store.saved = nil
	a = newAgent()
	before := f.state(d).DocVersion
	if resp := beat(60); resp.Settings == nil {
		t.Fatal("an agent that lost its settings was sent nothing")
	}
	if got := a.Report().Version; got != before {
		t.Errorf("the agent holds version %d, the server issued %d", got, before)
	}
}
