package monitoring

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDecideRemote(t *testing.T) {
	now := time.Now()
	floor := now.Add(-time.Hour)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	alert := uuid.New()
	down := remoteFacts{kind: KindRemoteDown, minutes: 15, hasGroup: true, agentSeen: ago(time.Minute), changedAt: ago(20 * time.Minute)}
	silent := remoteFacts{kind: KindAgentSilent, minutes: 15, remoteOnline: true, agentSeen: ago(20 * time.Minute), changedAt: ago(time.Hour)}
	with := func(f remoteFacts, mut func(*remoteFacts)) remoteFacts { mut(&f); return f }

	for name, c := range map[string]struct {
		f     remoteFacts
		judge bool
		want  action
		gone  bool
	}{
		"down opens":                     {down, true, actOpen, false},
		"down not yet":                   {with(down, func(f *remoteFacts) { f.changedAt = ago(14 * time.Minute) }), true, actNone, false},
		"down not judged":                {down, false, actNone, false},
		"down without a group":           {with(down, func(f *remoteFacts) { f.hasGroup = false }), true, actNone, false},
		"down, agent silent too":         {with(down, func(f *remoteFacts) { f.agentSeen = ago(time.Hour) }), true, actNone, false},
		"down, never changed":            {with(down, func(f *remoteFacts) { f.changedAt = nil }), true, actNone, false},
		"down, connected, no alert":      {with(down, func(f *remoteFacts) { f.remoteOnline = true }), true, actNone, false},
		"down, connected, alert":         {with(down, func(f *remoteFacts) { f.remoteOnline, f.alertID = true, &alert }), true, actResolve, false},
		"down, connected, not judged":    {with(down, func(f *remoteFacts) { f.remoteOnline, f.alertID = true, &alert }), false, actNone, false},
		"down, alert stays":              {with(down, func(f *remoteFacts) { f.alertID = &alert }), true, actUpdate, false},
		"down, alert stays, agent quiet": {with(down, func(f *remoteFacts) { f.alertID, f.agentSeen = &alert, ago(time.Hour) }), true, actUpdate, false},
		"down, leaving":                  {with(down, func(f *remoteFacts) { f.leaving = true }), true, actNone, false},
		"down, leaving, alert":           {with(down, func(f *remoteFacts) { f.leaving, f.alertID = true, &alert }), false, actResolve, true},
		"silent opens":                   {silent, true, actOpen, false},
		"silent not yet":                 {with(silent, func(f *remoteFacts) { f.agentSeen = ago(14 * time.Minute) }), true, actNone, false},
		"silent, mesh not connected":     {with(silent, func(f *remoteFacts) { f.remoteOnline = false }), true, actNone, false},
		"silent, never seen":             {with(silent, func(f *remoteFacts) { f.agentSeen = nil }), true, actNone, false},
		"silent, back, alert":            {with(silent, func(f *remoteFacts) { f.agentSeen, f.alertID = ago(time.Minute), &alert }), true, actResolve, false},
		"silent, back, alert, no judge":  {with(silent, func(f *remoteFacts) { f.agentSeen, f.alertID = ago(time.Minute), &alert }), false, actResolve, false},
		"silent, back, no alert":         {with(silent, func(f *remoteFacts) { f.agentSeen = ago(time.Minute) }), true, actNone, false},
		"silent, alert stays":            {with(silent, func(f *remoteFacts) { f.alertID = &alert }), true, actUpdate, false},
		"silent, leaving, alert":         {with(silent, func(f *remoteFacts) { f.leaving, f.alertID = true, &alert }), true, actResolve, true},
		"another kind":                   {remoteFacts{kind: KindOffline, minutes: 15}, true, actNone, false},
	} {
		// The agent counts as online for three of its intervals, a minute each here
		// (devices.agent_online_until, ADR-0058).
		c.f.agentOnline = c.f.agentSeen != nil && now.Sub(*c.f.agentSeen) < 3*time.Minute
		got := decideRemote(c.f, now, floor, c.judge)
		if got.act != c.want || got.gone != c.gone {
			t.Errorf("%s: %+v, want %v gone %v", name, got, c.want, c.gone)
		}
	}
	// Just after the server began serving, an agent has had no chance to
	// check in: its silence opens nothing yet.
	silent.agentOnline = false
	if got := decideRemote(silent, now, now.Add(-5*time.Minute), true); got.act != actNone {
		t.Errorf("silent right after the start: %+v", got)
	}
	if got := decideRemote(silent, now, now.Add(-15*time.Minute), true); got.act != actOpen {
		t.Errorf("silent 15 minutes after the start: %+v", got)
	}
}
