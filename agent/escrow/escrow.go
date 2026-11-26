// Package escrow is the agent's side of recovery-key escrow (ADR-0081). It
// reads a Windows computer's BitLocker recovery passwords itself, in its own
// process, seals each to the organization's escrow public key and sends the
// record on a signed route of its own. The password is never a job's output,
// a script's, a log line or a file: it lives in this process's memory until
// the upload is done, and is zeroed.
package escrow

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// Volume is a volume with BitLocker on it and its numerical-password
// protectors' IDs. A password is read only by RecoveryPassword.
type Volume struct {
	ID, Mount, Status string
	Protectors        []string
}

// Reader reads BitLocker. On Windows it calls Win32_EncryptableVolume through
// WMI (GetKeyProtectors, GetKeyProtectorNumericalPassword), never manage-bde
// and never a script, whose output Group Policy's transcription could write
// to disk.
type Reader interface {
	// Volumes lists the volumes with BitLocker and their numerical-password
	// protector IDs.
	Volumes(ctx context.Context) ([]Volume, error)
	// RecoveryPassword reads one protector's numerical password. The caller
	// zeroes the result.
	RecoveryPassword(ctx context.Context, volumeID, protectorID string) ([]byte, error)
}

// ErrUnsupported is returned by a reader on a platform without BitLocker.
var ErrUnsupported = errors.New("escrow: BitLocker is not available on this platform")

// Server is the agent's side of the escrow routes (client.Client).
type Server interface {
	EscrowVolumes(ctx context.Context, rep agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error)
	EscrowUpload(ctx context.Context, rec agentproto.EscrowRecord) (agentproto.EscrowAnswer, error)
}

// KeyStore keeps the newest escrow key version verified (state.Store).
type KeyStore interface {
	LoadEscrowKey() state.EscrowKey
	SaveEscrowKey(state.EscrowKey) error
}

// Timing, shortened by tests.
const (
	defaultReadEvery   = 10 * time.Minute
	defaultReportEvery = time.Hour
	// VolumeEvery is the server's limit: one upload per volume in five
	// minutes; the agent keeps to it so that no request is wasted.
	VolumeEvery = 5 * time.Minute
)

// Agent runs escrow. Its methods are safe to call from the heartbeat loop.
type Agent struct {
	DeviceID string
	// Key returns the pinned job key, nil while none is pinned.
	Key    func() ed25519.PublicKey
	Reader Reader
	Server Server
	Store  KeyStore
	Log    *slog.Logger
	// Now is the clock, replaced by tests.
	Now func() time.Time

	ReadEvery, ReportEvery time.Duration

	mu       sync.Mutex
	key      *agentproto.EscrowKeyPayload
	pub      []byte
	lastRead time.Time
	// lastReport is when volumes were last sent; sent is what was sent, so
	// that an unchanged report waits for ReportEvery.
	lastReport time.Time
	sent       []byte
	needs      []agentproto.EscrowNeed
	lastTry    map[string]time.Time
	busy       atomic.Bool
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Caps is what the agent announces to the server in its heartbeat.
func (a *Agent) Caps() []string { return []string{agentproto.CapEscrow} }

// Answered takes the escrow key a heartbeat answer carried. It is verified
// with the pinned job key, and the agent keeps the newest version it has
// verified and never goes back: an older version, or another key of the same
// version, is refused.
func (a *Agent) Answered(s *agentproto.SignedEscrowKey) {
	if s == nil {
		// The server offers no key: the keystore is not ready, or the
		// organization is not in scope. Escrow waits for the next one.
		a.mu.Lock()
		a.key, a.pub = nil, nil
		a.mu.Unlock()
		return
	}
	pinned := a.Key()
	if len(pinned) == 0 {
		return // no job key is pinned yet: nothing is trusted
	}
	p, pub, err := agentproto.VerifyEscrowKey(pinned, *s, a.DeviceID, a.now())
	if err != nil {
		a.Log.Warn("refused an escrow key", "error", err)
		return
	}
	known := a.Store.LoadEscrowKey()
	if known.OrgID != "" && known.OrgID != p.OrgID {
		known = state.EscrowKey{} // the device moved to another organization
	}
	if p.KeyVersion < known.Version || (p.KeyVersion == known.Version && known.KeyID != "" && p.KeyID != known.KeyID) {
		a.Log.Warn("refused an escrow key older than the newest this agent verified", "version", p.KeyVersion, "known", known.Version)
		return
	}
	if p.KeyVersion != known.Version || p.KeyID != known.KeyID || known.OrgID != p.OrgID {
		if err := a.Store.SaveEscrowKey(state.EscrowKey{OrgID: p.OrgID, KeyID: p.KeyID, Version: p.KeyVersion}); err != nil {
			// Without the record the agent cannot promise never to go back;
			// it still escrows to a verified key.
			a.Log.Warn("recording the escrow key version failed", "error", err)
		}
	}
	a.mu.Lock()
	a.key, a.pub = &p, pub
	a.mu.Unlock()
}

// Start runs one Sync in the background unless one is running. It never
// blocks the heartbeat.
func (a *Agent) Start(ctx context.Context) {
	if !a.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.busy.Store(false)
		a.Sync(ctx)
	}()
}

// Sync reports the volumes when due and sends the records the server asked
// for.
func (a *Agent) Sync(ctx context.Context) {
	a.mu.Lock()
	key, pub := a.key, a.pub
	a.mu.Unlock()
	now := a.now()
	if key == nil || !now.Before(key.ExpiresAt) {
		return
	}
	readEvery, reportEvery := a.ReadEvery, a.ReportEvery
	if readEvery == 0 {
		readEvery = defaultReadEvery
	}
	if reportEvery == 0 {
		reportEvery = defaultReportEvery
	}
	if a.lastRead.IsZero() || now.Sub(a.lastRead) >= readEvery {
		a.lastRead = now
		vols, err := a.Reader.Volumes(ctx)
		if err != nil {
			if !errors.Is(err, ErrUnsupported) {
				a.Log.Debug("reading BitLocker volumes failed", "error", err)
			}
			return
		}
		a.report(ctx, vols, now, reportEvery)
	}
	for _, n := range slices.Clone(a.needs) {
		if ctx.Err() != nil {
			return
		}
		a.upload(ctx, key, pub, n)
	}
}

// report sends the volumes when they changed or an hour passed.
func (a *Agent) report(ctx context.Context, vols []Volume, now time.Time, every time.Duration) {
	rep := agentproto.EscrowVolumesReport{Volumes: make([]agentproto.EscrowVolume, 0, len(vols))}
	for _, v := range vols {
		ev := agentproto.EscrowVolume{ID: v.ID, Mount: v.Mount, Status: v.Status, Protectors: []agentproto.EscrowProtector{}}
		for _, p := range v.Protectors {
			ev.Protectors = append(ev.Protectors, agentproto.EscrowProtector{ID: p})
		}
		rep.Volumes = append(rep.Volumes, ev)
	}
	if rep.Check() != nil {
		a.Log.Warn("the BitLocker volumes found cannot be reported")
		return
	}
	fp := hashReport(rep)
	if a.sent != nil && string(fp) == string(a.sent) && now.Sub(a.lastReport) < every {
		return
	}
	ans, err := a.Server.EscrowVolumes(ctx, rep)
	if err != nil {
		a.Log.Warn("reporting the BitLocker volumes failed", "error", err)
		a.sent = nil
		return
	}
	a.sent, a.lastReport, a.needs = fp, now, ans.Need
}

func hashReport(r agentproto.EscrowVolumesReport) []byte {
	b, _ := marshal(r)
	return b
}

// upload reads one protector's password, seals it and sends it. The password
// is zeroed before the function returns, whatever happens.
func (a *Agent) upload(ctx context.Context, key *agentproto.EscrowKeyPayload, pub []byte, n agentproto.EscrowNeed) {
	if a.lastTry == nil {
		a.lastTry = map[string]time.Time{}
	}
	now := a.now()
	if t, ok := a.lastTry[n.VolumeID]; ok && now.Sub(t) < VolumeEvery {
		return
	}
	a.lastTry[n.VolumeID] = now
	pw, err := a.Reader.RecoveryPassword(ctx, n.VolumeID, n.ProtectorID)
	if err != nil {
		a.Log.Warn("reading a BitLocker recovery password failed", "error", err)
		return
	}
	defer escrowcrypto.Zero(pw)
	secret, err := escrowcrypto.NormalizeBitLockerBytes(pw)
	if err != nil {
		a.Log.Warn("a BitLocker recovery password is not in the expected form; it is not escrowed")
		return
	}
	enc, ct, err := escrowcrypto.Seal(pub, escrowcrypto.Context{
		Org: key.OrgID, Device: a.DeviceID, Volume: n.VolumeID, Protector: n.ProtectorID, OrgKey: key.KeyID,
	}, secret)
	if err != nil {
		a.Log.Warn("sealing a recovery password failed", "error", err)
		return
	}
	fp := escrowcrypto.Fingerprint(n.ProtectorID, secret)
	ans, err := a.Server.EscrowUpload(ctx, agentproto.EscrowRecord{
		VolumeID: n.VolumeID, ProtectorID: n.ProtectorID, Kind: agentproto.EscrowBitLocker, KeyID: key.KeyID,
		Enc: base64.StdEncoding.EncodeToString(enc), Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Fingerprint: hex.EncodeToString(fp[:]),
	})
	if err != nil {
		a.Log.Warn("sending a recovery key to the server failed", "error", err)
		return
	}
	a.Log.Info("escrowed a BitLocker recovery key", "state", ans.State, "volume", n.VolumeID)
	if !ans.Again {
		// Done: asked for again only when a later report says so.
		a.needs = slices.DeleteFunc(a.needs, func(x agentproto.EscrowNeed) bool { return x == n })
	}
}
