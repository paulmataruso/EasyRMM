package keystore

import (
	"testing"
	"time"
)

func kinds(cs []condition) map[string]string {
	out := map[string]string{}
	for _, c := range cs {
		out[c.kind+"/"+c.subject] = c.severity
	}
	return out
}

func TestConditionsOfStatus(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ok := Status{State: StateUnsealed, Mode: ModeTPM, Primary: 1, RecoveryVerified: true,
		Versions: []KEKVersion{{Version: 1, State: "active", CreatedAt: now.Add(-90 * 24 * time.Hour), RecoveryVerifiedAt: &now}}}
	if got := conditionsOf(ok, 0, 0, now); len(got) != 0 {
		t.Fatalf("a healthy keystore raised %v", got)
	}
	// Unreachable only after three failed checks in a row.
	un := Status{State: StateUnavailable}
	if len(conditionsOf(un, UnreachableAfter-1, 0, now)) != 0 {
		t.Error("a restart is not an alert")
	}
	if got := kinds(conditionsOf(un, UnreachableAfter, 0, now)); got[AlertUnreachable+"/keystore"] != "critical" || len(got) != 1 {
		t.Errorf("unreachable: %v", got)
	}
	// Sealed: only after fifteen minutes.
	sealed := Status{State: StateSealed, Mode: ModeTPM, Primary: 1, Versions: []KEKVersion{{Version: 1}}}
	if len(conditionsOf(sealed, 0, SealedAfter-time.Second, now)) != 0 {
		t.Error("a short seal is not an alert")
	}
	if got := kinds(conditionsOf(sealed, 0, SealedAfter, now)); got[AlertSealed+"/keystore"] != "critical" {
		t.Errorf("sealed: %v", got)
	}
	// A changed TPM policy is its own critical alert.
	sealed.Detail = "TPM policy changed: restore from the recovery bundle"
	if got := kinds(conditionsOf(sealed, 0, time.Minute, now)); got[AlertTPMPolicy+"/keystore"] != "critical" {
		t.Errorf("tpm policy: %v", got)
	}
	// File mode is a standing warning.
	fm := ok
	fm.Mode = ModeFile
	if got := kinds(conditionsOf(fm, 0, 0, now)); got[AlertFileMode+"/keystore"] != "warning" || len(got) != 1 {
		t.Errorf("file mode: %v", got)
	}
	// No verified version: the keystore wraps nothing.
	np := Status{State: StateUnsealed, Mode: ModeTPM, Versions: []KEKVersion{{Version: 1, State: "pending", CreatedAt: now}}}
	if got := kinds(conditionsOf(np, 0, 0, now)); got[AlertRecoveryUnproved+"/keystore"] != "warning" {
		t.Errorf("unproved: %v", got)
	}
	// A pending version: after a day, then overdue after a week.
	pend := ok
	pend.Versions = append(append([]KEKVersion{}, ok.Versions...), KEKVersion{Version: 2, State: "pending", CreatedAt: now.Add(-30 * time.Hour)})
	if got := kinds(conditionsOf(pend, 0, 0, now)); got[AlertRecoveryUnproved+"/v2"] != "warning" || len(got) != 1 {
		t.Errorf("a day: %v", got)
	}
	pend.Versions[1].CreatedAt = now.Add(-8 * 24 * time.Hour)
	if got := kinds(conditionsOf(pend, 0, 0, now)); got[AlertKEKOverdue+"/v2"] != "warning" || len(got) != 1 {
		t.Errorf("a week: %v", got)
	}
	// An uninitialised keystore is not an alert: the console says what to do.
	if len(conditionsOf(Status{State: StateUninitialised}, 0, 0, now)) != 0 {
		t.Error("uninitialised raised an alert")
	}
}
