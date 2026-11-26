package escrow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// LUKS escrow (ADR-0081 section 5). The agent can only escrow a volume it can
// unlock by itself: a key file named in /etc/crypttab or a TPM2 token. It adds a
// key slot of its own with a passphrase it makes, marks the slot with a LUKS2
// token of type easyrmm-escrow, tests the passphrase, seals it to the
// organization's key and uploads it. Its copy is wiped once the server has the
// record. A volume protected only by a passphrase is reported as one that cannot
// be escrowed; nothing is done to it.

// LUKSVolume is a LUKS volume the agent found.
type LUKSVolume struct {
	// UUID is the volume's LUKS UUID, its escrow ID.
	UUID string
	// Mount is where it is mounted, or its device when it is not.
	Mount string
	// Version is 1 or 2.
	Version int
	// State is agentproto.LUKSEscrowable, LUKSCannotEscrow or
	// LUKSManagedElsewhere, and Reason says why in words for the others.
	State, Reason string
	// Slots are the key slots of EasyRMM's own tokens.
	Slots []LUKSSlot
}

// LUKSSlot is a key slot the agent added and marked with its token.
type LUKSSlot struct {
	// TokenID is the escrow ID in the token, a UUID: the protector's ID.
	TokenID string
	// Hash is the hex SHA-256 of the slot's header area.
	Hash string
}

// LUKS is what the agent needs of a computer's LUKS volumes. On Linux it runs
// cryptsetup in its own process, with a key only ever on standard input.
type LUKS interface {
	// Volumes lists the LUKS volumes and the agent's verdict on each.
	Volumes(ctx context.Context) ([]LUKSVolume, error)
	// AddSlot adds a key slot with the passphrase, marks it with the agent's
	// token and tests the passphrase against that slot. On any failure the
	// volume is as it was. The caller zeroes the passphrase.
	AddSlot(ctx context.Context, volume string, passphrase []byte) (LUKSSlot, error)
	// RemoveSlot removes a slot of the agent's by its token's ID. It refuses to
	// remove the last slot, a slot without the agent's token, and a slot another
	// token uses.
	RemoveSlot(ctx context.Context, volume, tokenID string) error
}

// Errors a LUKS backend returns for what it refuses.
var (
	ErrLastSlot      = errors.New("escrow: it is the last key slot of the volume")
	ErrNotOurSlot    = errors.New("escrow: the slot does not carry EasyRMM's token")
	ErrSharedSlot    = errors.New("escrow: another token uses the slot")
	ErrCannotUnlock  = errors.New("escrow: the agent cannot unlock the volume by itself")
	ErrUnknownVolume = errors.New("escrow: no such LUKS volume")
)

// failBackoff is how long a volume the agent could not add a key slot to is left
// alone.
const failBackoff = time.Hour

type luksState struct {
	lastRead, lastReport time.Time
	sent                 []byte
	needs                []agentproto.EscrowNeed
	lastTry, backoff     map[string]time.Time
}

// syncLUKS is Sync for LUKS: report the volumes when due, then make the key
// slots the server asked for.
func (a *Agent) syncLUKS(ctx context.Context, key *agentproto.EscrowKeyPayload, pub []byte, now time.Time) {
	st := &a.luks
	readEvery, reportEvery := a.ReadEvery, a.ReportEvery
	if readEvery == 0 {
		readEvery = defaultReadEvery
	}
	if reportEvery == 0 {
		reportEvery = defaultReportEvery
	}
	if st.lastRead.IsZero() || now.Sub(st.lastRead) >= readEvery {
		st.lastRead = now
		vols, err := a.LUKS.Volumes(ctx)
		if err != nil {
			if !errors.Is(err, ErrUnsupported) {
				a.Log.Debug("reading LUKS volumes failed", "error", err)
			}
			return
		}
		a.reportLUKS(ctx, vols, now, reportEvery)
	}
	for _, n := range slices.Clone(st.needs) {
		if ctx.Err() != nil {
			return
		}
		a.escrowLUKS(ctx, key, pub, n)
	}
}

func (a *Agent) reportLUKS(ctx context.Context, vols []LUKSVolume, now time.Time, every time.Duration) {
	st := &a.luks
	rep := agentproto.EscrowVolumesReport{Kind: agentproto.EscrowLUKS, Volumes: make([]agentproto.EscrowVolume, 0, len(vols))}
	for _, v := range vols {
		ev := agentproto.EscrowVolume{ID: v.UUID, Mount: v.Mount, Status: "luks" + string(rune('0'+v.Version)), State: v.State, Reason: v.Reason, Protectors: []agentproto.EscrowProtector{}}
		for _, s := range v.Slots {
			ev.Protectors = append(ev.Protectors, agentproto.EscrowProtector{ID: s.TokenID, Hash: s.Hash})
		}
		rep.Volumes = append(rep.Volumes, ev)
	}
	if rep.Check() != nil {
		a.Log.Warn("the LUKS volumes found cannot be reported")
		return
	}
	fp := hashReport(rep)
	if st.sent == nil && len(vols) == 0 {
		return // nothing here, and nothing was ever reported
	}
	if st.sent != nil && string(fp) == string(st.sent) && now.Sub(st.lastReport) < every {
		return
	}
	ans, err := a.Server.EscrowVolumes(ctx, rep)
	if err != nil {
		a.Log.Warn("reporting the LUKS volumes failed", "error", err)
		st.sent = nil
		return
	}
	st.sent, st.lastReport, st.needs = fp, now, ans.Need
}

// escrowLUKS makes one key slot for a volume the server asked for, escrows its
// passphrase and, when the new one is confirmed, removes the slots it replaces.
// The passphrase is zeroed before the function returns, whatever happens.
func (a *Agent) escrowLUKS(ctx context.Context, key *agentproto.EscrowKeyPayload, pub []byte, n agentproto.EscrowNeed) {
	st := &a.luks
	if st.lastTry == nil {
		st.lastTry, st.backoff = map[string]time.Time{}, map[string]time.Time{}
	}
	now := a.now()
	if t, ok := st.lastTry[n.VolumeID]; ok && now.Sub(t) < VolumeEvery {
		return
	}
	if t, ok := st.backoff[n.VolumeID]; ok && now.Before(t) {
		return
	}
	st.lastTry[n.VolumeID] = now
	pw, err := escrowcrypto.NewLUKSPassphrase()
	if err != nil {
		a.Log.Warn("making a LUKS passphrase failed")
		return
	}
	defer escrowcrypto.Zero(pw)
	slot, err := a.LUKS.AddSlot(ctx, n.VolumeID, pw)
	if err != nil {
		a.Log.Warn("adding a key slot to a LUKS volume failed", "error", err, "volume", n.VolumeID)
		st.backoff[n.VolumeID] = now.Add(failBackoff)
		return
	}
	rollback := func(why string) {
		// Nothing is removed before the key is safe, and a key that did not
		// reach the server is not kept in a slot nobody can open.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := a.LUKS.RemoveSlot(rctx, n.VolumeID, slot.TokenID); err != nil {
			a.Log.Warn("removing a key slot that was not escrowed failed", "error", err, "volume", n.VolumeID)
		}
		a.Log.Warn("a LUKS key was not escrowed; its slot was removed", "why", why, "volume", n.VolumeID)
	}
	enc, ct, err := escrowcrypto.Seal(pub, escrowcrypto.Context{
		Org: key.OrgID, Device: a.DeviceID, Volume: n.VolumeID, Protector: slot.TokenID, OrgKey: key.KeyID,
	}, pw)
	if err != nil {
		rollback("sealing failed")
		return
	}
	fp := escrowcrypto.Fingerprint(slot.TokenID, pw)
	rec := agentproto.EscrowRecord{
		VolumeID: n.VolumeID, ProtectorID: slot.TokenID, Kind: agentproto.EscrowLUKS, KeyID: key.KeyID,
		Enc: base64.StdEncoding.EncodeToString(enc), Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Fingerprint: hex.EncodeToString(fp[:]), SlotHash: slot.Hash,
	}
	var ans agentproto.EscrowAnswer
	for try := range 3 {
		if try > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
		if ans, err = a.Server.EscrowUpload(ctx, rec); err == nil || ctx.Err() != nil {
			break
		}
	}
	// The passphrase is not needed past this point: the server has the sealed
	// record or the slot goes.
	escrowcrypto.Zero(pw)
	if err != nil {
		a.Log.Warn("sending a LUKS recovery key to the server failed", "error", err)
		rollback("upload failed")
		return
	}
	if ans.State != agentproto.EscrowVerified && ans.State != agentproto.EscrowPending {
		rollback("the server did not accept the record: " + ans.State)
		return
	}
	a.Log.Info("escrowed a LUKS recovery key", "state", ans.State, "volume", n.VolumeID)
	if ans.State == agentproto.EscrowVerified {
		for _, old := range n.Replace {
			if old == slot.TokenID {
				continue
			}
			if err := a.LUKS.RemoveSlot(ctx, n.VolumeID, old); err != nil {
				a.Log.Warn("removing a replaced key slot failed", "error", err, "volume", n.VolumeID)
			}
		}
	}
	st.needs = slices.DeleteFunc(st.needs, func(x agentproto.EscrowNeed) bool { return x.VolumeID == n.VolumeID })
	// The report that follows shows the new slot.
	st.sent, st.lastRead = nil, time.Time{}
}
