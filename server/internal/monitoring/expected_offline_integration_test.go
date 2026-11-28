//go:build integration

package monitoring

import "testing"

// A restart or shutdown the scheduler made says the device will be offline
// (feature 11, slice 3): no new offline or remote-access alert opens for it
// until that time passes, an alert already open is kept, and other devices
// are judged as before.
func TestExpectedOfflineHoldsNewAlerts(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "Offline", Kind: KindOffline, Minutes: MinOfflineMinutes, Severity: SeverityCritical})
	restarting := f.device(f.acme, f.hq, "restarting", 0)
	other := f.device(f.acme, f.hq, "other", 0)
	f.agoSeconds(restarting, 10*60)
	f.agoSeconds(other, 10*60)
	f.exec(`INSERT INTO device_expected_offline (device_id, until_at, reason) VALUES ($1, now() + interval '20 minutes', 'Scheduled restart.')`, restarting)

	f.evaluate()
	if f.alertOn(restarting, "Offline") != nil {
		t.Error("an offline alert opened for a device that is restarting")
	}
	if f.alertOn(other, "Offline") == nil {
		t.Error("the other device was not judged")
	}

	// The expectation runs out: the device is offline for real.
	f.exec(`UPDATE device_expected_offline SET until_at = now() - interval '1 minute' WHERE device_id = $1`, restarting)
	f.evaluate()
	if f.alertOn(restarting, "Offline") == nil {
		t.Error("no alert after the expected time passed")
	}

	// An expectation made while the alert is open does not resolve it.
	f.exec(`UPDATE device_expected_offline SET until_at = now() + interval '1 hour' WHERE device_id = $1`, restarting)
	f.evaluate()
	if f.alertOn(restarting, "Offline") == nil {
		t.Error("the open alert was resolved by an expectation")
	}
}
