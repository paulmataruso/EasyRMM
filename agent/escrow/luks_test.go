package escrow_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

const luksVol = "6c4a9e2a-1111-4222-8333-444455556666"

// stubLUKS stands in for cryptsetup, which the real-volume test in
// cryptsetup_linux_test.go exercises. It keeps the slice the agent gave it, to
// check the agent zeroed the passphrase.
type stubLUKS struct {
	mu       sync.Mutex
	volumes  []escrow.LUKSVolume
	addErr   error
	slot     escrow.LUKSSlot
	adds     int
	removed  []string
	removeEr map[string]error
	pass     []byte // the slice the agent passed to AddSlot
	copy     string // what it held when AddSlot returned
}

func (s *stubLUKS) Volumes(context.Context) ([]escrow.LUKSVolume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.volumes, nil
}

func (s *stubLUKS) AddSlot(_ context.Context, _ string, pass []byte) (escrow.LUKSSlot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adds++
	s.pass, s.copy = pass, string(pass)
	if s.addErr != nil {
		return escrow.LUKSSlot{}, s.addErr
	}
	return s.slot, nil
}

func (s *stubLUKS) RemoveSlot(_ context.Context, _, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed = append(s.removed, token)
	return s.removeEr[token]
}

func luksFx(t *testing.T) (*fx, *stubLUKS) {
	f := newFx(t)
	l := &stubLUKS{
		volumes: []escrow.LUKSVolume{{UUID: luksVol, Mount: "/", Version: 2, State: agentproto.LUKSEscrowable}},
		slot:    escrow.LUKSSlot{TokenID: "0a0a0a0a-0000-4000-8000-000000000001", Hash: strings.Repeat("ab", 32)},
	}
	f.a.LUKS = l
	f.a.Reader = &stubReader{err: escrow.ErrUnsupported} // a Linux computer has no BitLocker
	f.server.need = nil
	return f, l
}

func (f *fx) lastLUKSReport() agentproto.EscrowVolumesReport {
	f.t.Helper()
	for i := len(f.server.reports) - 1; i >= 0; i-- {
		if f.server.reports[i].Kind == agentproto.EscrowLUKS {
			return f.server.reports[i]
		}
	}
	f.t.Fatal("no LUKS report was sent")
	return agentproto.EscrowVolumesReport{}
}

func TestLUKSEscrowSealsUploadsAndWipesItsCopy(t *testing.T) {
	f, l := luksFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol}}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())

	rep := f.lastLUKSReport()
	if rep.Kind != agentproto.EscrowLUKS || len(rep.Volumes) != 1 || rep.Volumes[0].State != agentproto.LUKSEscrowable || rep.Check() != nil {
		t.Fatalf("report: %+v", rep)
	}
	if l.adds != 1 || len(f.server.records) != 1 {
		t.Fatalf("adds %d records %d", l.adds, len(f.server.records))
	}
	rec := f.server.records[0]
	if rec.Kind != agentproto.EscrowLUKS || rec.VolumeID != luksVol || rec.ProtectorID != l.slot.TokenID || rec.SlotHash != l.slot.Hash || rec.Check() != nil {
		t.Fatalf("record: %+v", rec)
	}
	// The organization's key opens it to the very passphrase the slot got.
	enc, _ := base64.StdEncoding.DecodeString(rec.Enc)
	ct, _ := base64.StdEncoding.DecodeString(rec.Ciphertext)
	pt, err := escrowcrypto.Open(f.orgPriv, escrowcrypto.Context{Org: org, Device: device, Volume: luksVol, Protector: l.slot.TokenID, OrgKey: "key-1"}, enc, ct)
	if err != nil || string(pt) != l.copy {
		t.Fatalf("the sealed record is not the slot's passphrase: %v", err)
	}
	fp := escrowcrypto.Fingerprint(l.slot.TokenID, pt)
	if rec.Fingerprint != hexOf(fp[:]) {
		t.Error("fingerprint")
	}
	// The agent's copy is wiped, and the passphrase is in no log line.
	for _, b := range l.pass {
		if b != 0 {
			t.Fatal("the agent kept its copy of the passphrase")
		}
	}
	if strings.Contains(f.logs.String(), l.copy) {
		t.Error("the passphrase is in the log")
	}
	if len(l.removed) != 0 {
		t.Errorf("removed %v", l.removed)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestLUKSNothingWithoutAVerifiedKey(t *testing.T) {
	f, l := luksFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol}}
	f.a.Sync(context.Background())
	if l.adds != 0 || len(f.server.reports) != 0 {
		t.Fatalf("a computer with no organization key reported or changed a volume: %d %d", l.adds, len(f.server.reports))
	}
}

func TestLUKSCannotEscrowIsReportedAndNothingIsDone(t *testing.T) {
	f, l := luksFx(t)
	l.volumes = []escrow.LUKSVolume{
		{UUID: luksVol, Mount: "/", Version: 2, State: agentproto.LUKSCannotEscrow, Reason: "Only a passphrase unlocks this volume."},
		{UUID: "6c4a9e2a-1111-4222-8333-444455556667", Mount: "/data", Version: 2, State: agentproto.LUKSManagedElsewhere, Reason: "Clevis"},
	}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	rep := f.lastLUKSReport()
	if len(rep.Volumes) != 2 || rep.Volumes[0].State != agentproto.LUKSCannotEscrow || rep.Volumes[1].State != agentproto.LUKSManagedElsewhere || rep.Volumes[0].Reason == "" {
		t.Fatalf("report: %+v", rep)
	}
	if l.adds != 0 || len(f.server.records) != 0 {
		t.Error("the agent touched a volume it cannot escrow")
	}
}

func TestLUKSReplacesStaleSlotsOnlyAfterTheNewOneIsVerified(t *testing.T) {
	old := "0a0a0a0a-0000-4000-8000-0000000000aa"
	f, l := luksFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol, Replace: []string{old}}}
	f.server.answer = agentproto.EscrowAnswer{State: agentproto.EscrowPending}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if len(f.server.records) != 1 || len(l.removed) != 0 {
		t.Fatalf("a pending record removed %v", l.removed)
	}

	f2, l2 := luksFx(t)
	f2.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol, Replace: []string{old, l2.slot.TokenID}}}
	f2.a.Answered(f2.signed(1, "key-1", nil))
	f2.a.Sync(context.Background())
	if len(l2.removed) != 1 || l2.removed[0] != old {
		t.Fatalf("removed %v, want only the old slot (never the new one)", l2.removed)
	}
}

func TestLUKSAFailedUploadRemovesTheSlotItJustMade(t *testing.T) {
	f, l := luksFx(t)
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol}}
	f.server.err = errors.New("network down")
	f.a.Answered(f.signed(1, "key-1", nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f.a.Sync(ctx)
	if len(l.removed) != 1 || l.removed[0] != l.slot.TokenID {
		t.Fatalf("a key that never reached the server stayed in a slot: %v", l.removed)
	}
	for _, b := range l.pass {
		if b != 0 {
			t.Fatal("copy kept after a failed upload")
		}
	}
}

func TestLUKSStaleOrConflictAnswerRemovesTheSlot(t *testing.T) {
	for _, state := range []string{agentproto.EscrowStale, agentproto.EscrowConflict} {
		f, l := luksFx(t)
		f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol}}
		f.server.answer = agentproto.EscrowAnswer{State: state, Again: true}
		f.a.Answered(f.signed(1, "key-1", nil))
		f.a.Sync(context.Background())
		if len(l.removed) != 1 {
			t.Errorf("%s: the slot of a key the server did not accept stayed: %v", state, l.removed)
		}
	}
}

func TestLUKSAddFailureBacksOffForAnHour(t *testing.T) {
	f, l := luksFx(t)
	l.addErr = errors.New("the keyfile does not open the volume")
	f.server.need = []agentproto.EscrowNeed{{VolumeID: luksVol}}
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	f.now = f.now.Add(10 * time.Minute)
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if l.adds != 1 {
		t.Fatalf("a volume that cannot be unlocked was tried %d times in ten minutes", l.adds)
	}
	f.now = f.now.Add(time.Hour)
	f.a.Answered(f.signed(1, "key-1", nil))
	f.a.Sync(context.Background())
	if l.adds != 2 {
		t.Fatalf("not tried again after the backoff: %d", l.adds)
	}
	if len(f.server.records) != 0 {
		t.Error("a record was sent for a slot that was never made")
	}
}
