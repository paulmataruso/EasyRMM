package dhcp

import (
	"encoding/json"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

func kind(t *testing.T, name string) monitoring.ModuleKind {
	t.Helper()
	for _, k := range AlertKinds().Kinds {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("no kind %s", name)
	return monitoring.ModuleKind{}
}

func TestScopeExhausted(t *testing.T) {
	k := kind(t, KindScopeExhausted)
	at := func(n int) *int { return &n }
	for _, tc := range []struct {
		name, data string
		threshold  *int
		holds      bool
		err        bool
	}{
		{"full", `{"scopes":[{"scopeId":"10.0.0.0","state":"Active","free":2,"inUse":98,"percentageInUse":98}]}`, at(95), true, false},
		{"below", `{"scopes":[{"scopeId":"10.0.0.0","state":"Active","free":50,"inUse":50,"percentageInUse":50}]}`, at(95), false, false},
		{"small scope ignored", `{"scopes":[{"scopeId":"10.0.0.0","state":"Active","free":0,"inUse":10,"percentageInUse":100}]}`, at(95), false, false},
		{"inactive ignored", `{"scopes":[{"scopeId":"10.0.0.0","state":"InActive","free":0,"inUse":100,"percentageInUse":100}]}`, at(95), false, false},
		{"the worst scope", `{"scopes":[{"scopeId":"10.0.0.0","state":"Active","free":50,"inUse":50,"percentageInUse":50},{"scopeId":"10.0.1.0","state":"Active","free":1,"inUse":99,"percentageInUse":99}]}`, at(95), true, false},
		{"none", `{"scopes":[]}`, at(95), false, false},
		{"no threshold", `{"scopes":[]}`, nil, false, true},
		{"junk", `[1]`, at(95), false, true},
	} {
		v, err := k.Eval(json.RawMessage(tc.data), tc.threshold)
		if (err != nil) != tc.err || v.Holds != tc.holds {
			t.Errorf("%s: %+v %v", tc.name, v, err)
		}
	}
}

func TestNotAuthorized(t *testing.T) {
	k := kind(t, KindNotAuthorized)
	for _, tc := range []struct {
		name, data string
		holds, na  bool
		err        bool
	}{
		{"unauthorized in a domain", `{"serviceState":"running","domainJoined":true,"authorized":false}`, true, false, false},
		{"authorized", `{"serviceState":"running","domainJoined":true,"authorized":true}`, false, false, false},
		{"workgroup", `{"serviceState":"running","domainJoined":false,"authorized":null}`, false, true, false},
		{"stopped says nothing", `{"serviceState":"stopped","domainJoined":null,"authorized":null}`, false, false, true},
	} {
		v, err := k.Eval(json.RawMessage(tc.data), nil)
		if (err != nil) != tc.err || v.Holds != tc.holds || v.NotApplicable != tc.na {
			t.Errorf("%s: %+v %v", tc.name, v, err)
		}
	}
}

func TestServiceStopped(t *testing.T) {
	k := kind(t, KindServiceStopped)
	if v, err := k.Eval(json.RawMessage(`{"serviceState":"stopped"}`), nil); err != nil || !v.Holds {
		t.Errorf("%+v %v", v, err)
	}
	if v, err := k.Eval(json.RawMessage(`{"serviceState":"running"}`), nil); err != nil || v.Holds {
		t.Errorf("%+v %v", v, err)
	}
}

func TestAlertsRegister(t *testing.T) {
	if err := monitoring.RegisterModuleAlerts(AlertKinds()); err != nil {
		t.Fatal(err)
	}
}
