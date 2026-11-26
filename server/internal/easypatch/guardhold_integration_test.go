//go:build integration

package easypatch

import (
	"testing"

	"github.com/google/uuid"
)

// An install waits while a hardening change on the computer is unconfirmed.
func TestHardeningGuardHoldsInstalls(t *testing.T) {
	f := newPatching(t)
	held := func() bool {
		t.Helper()
		h, err := f.svc.hardeningHeld(f.ctx, f.web)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if held() {
		t.Fatal("held with no guard")
	}
	job := uuid.New()
	f.exec(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, args, timeout_seconds, expires_at, created_at, kind, hardening)
		VALUES ($1, 'Apply Windows hardening', 'powershell', 'x', decode(repeat('00', 32), 'hex'), '{}', 60, now() + interval '1 day', now(), 'hardening', '{"mode":"apply"}')`, job)
	f.exec(`INSERT INTO hardening_guards (apply_job_id, device_id, settings, armed_at, rollback_at, state)
		VALUES ($1, $2, '{}', now(), now() + interval '10 minutes', 'armed')`, job, f.web)
	if !held() {
		t.Error("an armed guard does not hold installs")
	}
	f.exec(`UPDATE hardening_guards SET state = 'confirmed' WHERE apply_job_id = $1`, job)
	if held() {
		t.Error("a confirmed guard still holds installs")
	}
}
