package dns

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

func TestServiceStoppedAlert(t *testing.T) {
	k := AlertKinds().Kinds[0]
	for _, tc := range []struct {
		data  string
		holds bool
		err   bool
	}{
		{`{"serviceState":"stopped"}`, true, false},
		{`{"serviceState":"running"}`, false, false},
		{`{"serviceState":"absent"}`, false, false},
		{`{"serviceState":""}`, false, true},
		{`nope`, false, true},
	} {
		v, err := k.Eval(json.RawMessage(tc.data), nil)
		if (err != nil) != tc.err || (err != nil && !errors.Is(err, monitoring.ErrUnknown)) || v.Holds != tc.holds {
			t.Errorf("%s: %+v %v", tc.data, v, err)
		}
	}
}

// The kinds and default policies register (monitoring validates each).
func TestAlertsRegister(t *testing.T) {
	if err := monitoring.RegisterModuleAlerts(AlertKinds()); err != nil {
		t.Fatal(err)
	}
}
