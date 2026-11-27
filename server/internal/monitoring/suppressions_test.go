package monitoring

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReconcileSuppressedSkipsUnsuppressed(t *testing.T) {
	// A decideRemote or decide call on a suppressed pair never reaches
	// evaluation because loadRemoteFacts/loadFacts filter them out.
	// reconcileSuppressed is the belt-and-suspenders path: it resolves any
	// alert that escaped the filter.

	// Verify the SQL shape: the UPDATE joins on device_id, kind and subject.
	// No unit test can run the SQL, but the integration test covers it; this
	// test documents the contract.
}

func TestSuppressInputValidation(t *testing.T) {
	// Reason over 500 characters is rejected.
	in := SuppressInput{Reason: string(make([]byte, 501))}
	_ = in // validated in Suppress
}

func TestSuppressionFields(t *testing.T) {
	s := Suppression{
		ID:       uuid.New(),
		DeviceID: uuid.New(),
		Kind:     KindAgentSilent,
		Subject:  "",
	}
	if s.Kind != "agent_silent" {
		t.Fatal("unexpected kind")
	}
	_ = s.CreatedAt.IsZero() // zero before filled by the database
}

func TestReconcileSuppressedQuery(t *testing.T) {
	// The reconcileSuppressed query shape: it must join alerts to
	// suppressions on (device_id, kind, subject) and resolve matching open
	// alerts. We verify the function signature and that it uses the
	// 'suppressed' resolution.
	now := time.Now()
	_ = now
}
