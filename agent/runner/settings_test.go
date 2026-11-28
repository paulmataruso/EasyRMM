package runner

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/settings"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// settingsRunner is a runner with the agent's real settings, over the fake
// server, whose job key signs the documents.
func settingsRunner(t *testing.T, s *server) *Runner {
	t.Helper()
	r := newRunner(t, s, nil)
	r.Settings = &settings.Agent{DeviceID: "dev-1", Keys: r.Keys, Store: r.Store, Log: r.Log}
	return r
}

// document is the answer's "settings" field, signed by the server's job key,
// with the interval the answer names.
func document(t *testing.T, s *server, version int64, device string, values map[string]string, answerSeconds int) string {
	t.Helper()
	m := map[string]json.RawMessage{}
	for k, v := range values {
		m[k] = json.RawMessage(v)
	}
	doc, err := agentproto.SignSettings(s.job, agentproto.SettingsPayload{V: 1, DeviceID: device, Version: version, IssuedAt: time.Now(), Settings: m})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	out := `,"settings":` + string(b)
	if answerSeconds > 0 {
		out += `,"heartbeatSeconds":` + itoa(answerSeconds)
	}
	return out
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// The report for signed settings follows ADR-0009's rule: none in the first
// heartbeat of a process or after an answer of level 1, and from an answer
// of level 2 on; the second heartbeat of a process comes within 10 seconds of
// the first answer of level 2, so the server hears the report.
func TestSettingsReportFollowsTheProtocolRule(t *testing.T) {
	s := &server{}
	r := settingsRunner(t, s)
	ctx := context.Background()

	wait, err := r.beat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h := s.heartbeats[0]; h.Capabilities != nil || h.Settings != nil || h.HeartbeatSeconds != 0 {
		t.Fatalf("the first heartbeat carried the report: %+v", h)
	}
	if wait < 54*time.Second {
		t.Errorf("a server of level 1 pulled the next heartbeat in to %v", wait)
	}
	// Another answer of level 1: still none.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if h := s.heartbeats[1]; h.Capabilities != nil || h.Settings != nil {
		t.Fatalf("after a level 1 answer: %+v", h)
	}

	// The first answer of level 2: the next heartbeat comes within 10 seconds.
	s.protocol = 3
	wait, err = r.beat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wait > 10*time.Second || wait != r.ReportWithin {
		t.Errorf("after the first answer of level 2, the next heartbeat is in %v", wait)
	}
	h := s.heartbeats[len(s.heartbeats)-1]
	if h.Capabilities != nil {
		t.Fatalf("the heartbeat before the first level 2 answer carried the report: %+v", h)
	}
	// The report, with the interval the agent uses.
	wait, err = r.beat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h = s.heartbeats[len(s.heartbeats)-1]
	if !h.Capabilities.Takes(agentproto.CapSettings) || h.Capabilities.Settings[settings.HeartbeatKey] != 1 ||
		h.Settings == nil || h.Settings.Version != 0 || h.HeartbeatSeconds != 60 {
		t.Fatalf("the report: %+v %+v", h, h.Settings)
	}
	if wait < 54*time.Second {
		t.Errorf("with the report sent, the next heartbeat is in %v", wait)
	}
}

func TestADocumentIsAppliedAndAcknowledgedWithinTenSeconds(t *testing.T) {
	s := &server{protocol: 3}
	r := settingsRunner(t, s)
	ctx := context.Background()
	for range 2 { // the report is on its way
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	s.extra = document(t, s, 5, "dev-1", map[string]string{settings.HeartbeatKey: "120"}, 0)
	wait, err := r.beat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wait != r.ReportWithin || wait > 10*time.Second {
		t.Errorf("after applying, the next heartbeat is in %v", wait)
	}
	if st := r.Settings.Report(); st.Version != 5 {
		t.Fatalf("not applied: %+v", st)
	}
	// The saved file is there, and the acknowledgment names version and interval.
	if st := r.Store.LoadSettings(); st == nil || string(st.Applied[settings.HeartbeatKey]) != "120" {
		t.Errorf("not saved: %+v", st)
	}
	s.extra = ""
	wait, err = r.beat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := s.heartbeats[len(s.heartbeats)-1]
	if h.Settings == nil || h.Settings.Version != 5 || h.HeartbeatSeconds != 60 {
		// The interval used while the answer said 60: the shorter of 120 and 60.
		t.Errorf("the acknowledgment: %+v interval %d", h.Settings, h.HeartbeatSeconds)
	}
	if wait < 54*time.Second || wait > 66*time.Second {
		t.Errorf("after acknowledging, the next heartbeat is in %v", wait)
	}
}

func TestTheIntervalIsTheShorterOfTheDocumentsAndTheAnswers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		doc, answered int
		want          time.Duration
	}{
		{"the document is shorter", 90, 300, 90 * time.Second},
		{"the answer is shorter", 300, 60, 60 * time.Second},
		{"never below 30 seconds", 30, 10, 30 * time.Second},
		{"no answer interval", 120, 0, 120 * time.Second},
	} {
		s := &server{protocol: 3}
		r := settingsRunner(t, s)
		ctx := context.Background()
		s.extra = document(t, s, 5, "dev-1", map[string]string{settings.HeartbeatKey: itoa(tc.doc)}, tc.answered)
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		s.extra = `,"heartbeatSeconds":` + itoa(tc.answered)
		wait, err := r.beat(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if r.interval != tc.want || wait < tc.want*9/10 || wait > tc.want*11/10 {
			t.Errorf("%s: the interval is %v and the wait %v; want %v", tc.name, r.interval, wait, tc.want)
		}
	}
}

func TestARefusedDocumentKeepsTheSettingsAndIsReported(t *testing.T) {
	s := &server{protocol: 3}
	r := settingsRunner(t, s)
	ctx := context.Background()
	s.extra = document(t, s, 5, "dev-1", map[string]string{settings.HeartbeatKey: "120"}, 0)
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	// For another device, then one with an unreported key.
	for _, bad := range []string{
		document(t, s, 6, "dev-2", map[string]string{settings.HeartbeatKey: "45"}, 0),
		document(t, s, 6, "dev-1", map[string]string{"logs.collect": "true"}, 0),
	} {
		s.extra = bad
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		s.extra = ""
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		h := s.heartbeats[len(s.heartbeats)-1]
		if h.Settings == nil || h.Settings.Version != 5 || h.Settings.Problems[agentproto.SettingsDocumentKey] == "" {
			t.Errorf("the refusal was not reported: %+v", h.Settings)
		}
		if secs, _ := r.Settings.Interval(300); secs != 120 {
			t.Errorf("a refused document changed the interval to %d", secs)
		}
	}
}

// A heartbeat that fails reports nothing and changes nothing.
func TestAServerItCannotReachChangesNothing(t *testing.T) {
	s := &server{protocol: 3}
	r := settingsRunner(t, s)
	ctx := context.Background()
	s.extra = document(t, s, 5, "dev-1", map[string]string{settings.HeartbeatKey: "120"}, 0)
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	s.extra = ""
	s.status, s.code = 503, "unavailable"
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if st := r.Settings.Report(); st.Version != 5 {
		t.Errorf("an unreachable server changed what is held: %+v", st)
	}
	if secs, _ := r.Settings.Interval(60); secs != 60 {
		t.Errorf("interval %d", secs)
	}
}

// Metrics go on a heartbeat only 0.8 of the interval after the last whose
// metrics the server accepted, and on the next one after a heartbeat failed.
func TestMetricsAreSpacedAtAnEightOfTheInterval(t *testing.T) {
	s := &server{protocol: 3}
	r := settingsRunner(t, s)
	measured := 0
	r.Metrics = func(context.Context) agentproto.Metrics { measured++; return agentproto.Metrics{CPUPercent: 1} }
	ctx := context.Background()
	carried := func() bool { return s.heartbeats[len(s.heartbeats)-1].Metrics != nil }
	beat := func() {
		t.Helper()
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}

	beat() // the first: metrics
	if !carried() || measured != 1 {
		t.Fatal("the first heartbeat carried no metrics")
	}
	// Extra heartbeats seconds later (the second of a process, a document
	// applied, a wake) carry none, and measure nothing.
	beat()
	beat()
	if carried() || measured != 1 {
		t.Fatalf("an extra heartbeat carried metrics (measured %d)", measured)
	}
	// 0.8 of 60 seconds is 48: just before, none; just after, metrics.
	r.metricsAt = time.Now().Add(-47 * time.Second)
	beat()
	if carried() {
		t.Error("metrics 47 seconds after the last")
	}
	r.metricsAt = time.Now().Add(-49 * time.Second)
	beat()
	if !carried() || measured != 2 {
		t.Errorf("no metrics 49 seconds after the last (measured %d)", measured)
	}
	// A heartbeat that failed counts as carrying none: the next one does.
	r.metricsAt = time.Now().Add(-49 * time.Second)
	s.status, s.code = 503, "unavailable"
	beat()
	if r.metricsAt.After(time.Now().Add(-48 * time.Second)) {
		t.Error("a failed heartbeat moved the time of the last accepted metrics")
	}
	s.status = 0
	beat()
	if !carried() {
		t.Error("the heartbeat after a failed one carried no metrics")
	}
	// With the interval at 5 minutes the rule is 4 minutes.
	s.extra = document(t, s, 5, "dev-1", map[string]string{settings.HeartbeatKey: "300"}, 300)
	beat()
	s.extra = `,"heartbeatSeconds":300`
	beat()
	r.metricsAt = time.Now().Add(-3 * time.Minute)
	beat()
	if carried() {
		t.Error("metrics 3 minutes after the last at a 5-minute interval")
	}
	r.metricsAt = time.Now().Add(-241 * time.Second)
	beat()
	if !carried() {
		t.Error("no metrics 241 seconds after the last at a 5-minute interval")
	}
}

// Wakes every half interval still leave a heartbeat with metrics about once an
// interval: the rule is on the last accepted metrics, not on the schedule.
func TestWakesEveryHalfIntervalStillLeaveMetricsOncePerInterval(t *testing.T) {
	s := &server{protocol: 3}
	r := settingsRunner(t, s)
	r.Metrics = func(context.Context) agentproto.Metrics { return agentproto.Metrics{} }
	ctx := context.Background()
	r.interval = time.Minute
	with := 0
	// A heartbeat every 30 seconds for 5 minutes, on a clock the test moves
	// by shifting the time of the last accepted metrics back.
	for range 10 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
		if s.heartbeats[len(s.heartbeats)-1].Metrics != nil {
			with++
		}
		r.metricsAt = r.metricsAt.Add(-30 * time.Second)
	}
	if with < 4 || with > 6 {
		t.Errorf("%d of 10 heartbeats half an interval apart carried metrics; want about 5 (one a minute)", with)
	}
}
