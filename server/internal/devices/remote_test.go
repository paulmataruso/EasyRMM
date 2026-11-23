package devices

import (
	"testing"
	"time"
)

func TestRemoteReason(t *testing.T) {
	no, yes := false, true
	state := func(installed, running bool, hostOK *bool) []byte {
		b := `{"installed":` + map[bool]string{true: "true", false: "false"}[installed] +
			`,"running":` + map[bool]string{true: "true", false: "false"}[running]
		if hostOK != nil {
			b += `,"hostOk":` + map[bool]string{true: "true", false: "false"}[*hostOK]
		}
		return []byte(b + "}")
	}
	for name, c := range map[string]struct {
		connected, agentOnline, wrongGroup bool
		state                              []byte
		want                               string
	}{
		"connected":                  {true, true, false, state(true, true, &yes), RemoteConnected},
		"connected beats the rest":   {true, false, true, state(false, false, &no), RemoteConnected},
		"the device is offline":      {false, false, false, state(false, false, nil), RemoteDeviceOffline},
		"an older agent":             {false, true, false, nil, RemoteUnknown},
		"a damaged record":           {false, true, false, []byte("{"), RemoteUnknown},
		"not installed":              {false, true, false, state(false, false, nil), RemoteNotInstalled},
		"not installed beats server": {false, true, true, state(false, true, &no), RemoteNotInstalled},
		"not running":                {false, true, false, state(true, false, &yes), RemoteNotRunning},
		"another server":             {false, true, false, state(true, true, &no), RemoteOtherServer},
		"another group":              {false, true, true, state(true, true, &yes), RemoteOtherGroup},
		"another server beats group": {false, true, true, state(true, true, &no), RemoteOtherServer},
		"host not judged":            {false, true, false, state(true, true, nil), RemoteNotConnected},
		"not connected":              {false, true, false, state(true, true, &yes), RemoteNotConnected},
	} {
		got, msg := RemoteReason(c.connected, c.agentOnline, c.wrongGroup, c.state)
		if got != c.want || msg == "" {
			t.Errorf("%s: %q %q, want %q", name, got, msg, c.want)
		}
	}
}

func TestRemoteStatusSince(t *testing.T) {
	enrolled := time.Now().Add(-48 * time.Hour)
	changed := time.Now().Add(-time.Hour)
	in := remoteInput{agentOnline: true, state: []byte(`{"installed":true,"running":true,"host":"m:443","error":"boom"}`), enrolledAt: &enrolled}
	if st := remoteStatus(in); st.Reason != RemoteNotConnected || st.Since != &enrolled || st.Host != "m:443" || st.Error != "boom" {
		t.Errorf("before MeshCentral's view changed: %+v", st)
	}
	in.changedAt = &changed
	if st := remoteStatus(in); st.Since != &changed {
		t.Errorf("after: %+v", st)
	}
	in.state = []byte(`{"installed":false}`)
	if st := remoteStatus(in); st.Since != nil {
		t.Errorf("a cause that is not the connection has no time: %+v", st)
	}
}
