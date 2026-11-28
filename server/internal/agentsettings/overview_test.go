package agentsettings

import (
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestDescribe(t *testing.T) {
	takes := &agentproto.SettingsCapabilities{Accepts: []string{agentproto.CapSettings}}
	now := time.Now()
	for _, c := range []struct {
		name   string
		st     State
		online bool
		want   string
	}{
		{"no report", State{}, true, DocUnsupported},
		{"nothing issued", State{Capabilities: takes}, true, DocNone},
		{"applied", State{Capabilities: takes, DocVersion: 2, AppliedVersion: 2, DocIssuedAt: now}, false, DocApplied},
		{"pending", State{Capabilities: takes, DocVersion: 2, AppliedVersion: 1}, true, DocPending},
		{"offline", State{Capabilities: takes, DocVersion: 2, AppliedVersion: 1}, false, DocWaiting},
		{"not applied", State{Capabilities: takes, DocVersion: 2, AppliedVersion: 1, NotAppliedHeartbeats: 3}, true, DocNotApplied},
	} {
		if got := Describe(c.st, c.online); got.State != c.want || got.Problems == nil {
			t.Errorf("%s: %+v, want %s", c.name, got, c.want)
		}
	}
}
