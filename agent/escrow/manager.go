package escrow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
)

// This file is what changes BitLocker (ADR-0081 section 5): turning it on
// behind the verified-escrow gate, and the rotation of a recovery password
// after it was read. Both add a protector first, escrow it and wait for the
// server to say it is verified, and only then do the step that cannot be
// taken back: starting encryption, or removing the old protector. A volume is
// never without a verified escrowed recovery password.

// VolumeInfo is what the agent needs to know of a volume before it changes it.
type VolumeInfo struct {
	// ID is the volume's device ID (its escrow ID), Mount its drive letter.
	ID, Mount string
	// Status is "decrypted" when BitLocker is not on the volume.
	Status string
	// Protectors are the volume's numerical-password protector IDs.
	Protectors []string
	// AnyProtectors says the volume has a protector of some type.
	AnyProtectors bool
}

// Preconditions are facts about the computer that decide whether BitLocker may
// be turned on (ADR-0081 section 5, step 4a).
type Preconditions struct {
	// Computer is the computer's name, which a person typed to confirm.
	Computer string
	// DomainController: the computer is a domain controller, where this action
	// is refused.
	DomainController bool
	// TPMReady: a TPM is present, enabled and activated.
	TPMReady bool
	// EditionAllows: the edition of Windows has BitLocker.
	EditionAllows bool
	// RebootPending: a restart is waiting, which would end a started
	// encryption's first step badly.
	RebootPending bool
}

// Manager changes BitLocker. On Windows it calls Win32_EncryptableVolume
// through WMI in the agent's own process, as the Reader does. A recovery
// password it creates is read only by Reader.RecoveryPassword.
type Manager interface {
	// Preconditions reads the facts above.
	Preconditions(ctx context.Context) (Preconditions, error)
	// Volume finds a volume by its drive letter ("C:"); nil when there is none.
	Volume(ctx context.Context, letter string) (*VolumeInfo, error)
	// AddRecoveryPassword adds a numerical-password protector and returns its ID.
	AddRecoveryPassword(ctx context.Context, volumeID string) (protectorID string, err error)
	// DeleteProtector removes one protector by its ID.
	DeleteProtector(ctx context.Context, volumeID, protectorID string) error
	// AddTPMProtector adds the TPM protector.
	AddTPMProtector(ctx context.Context, volumeID string) error
	// StartEncryption starts encrypting; usedSpaceOnly encrypts only the space
	// in use.
	StartEncryption(ctx context.Context, volumeID string, usedSpaceOnly bool) error
}

// escrowWait is how long the enable action waits for the busy flag, which the
// periodic sync holds while it runs.
const escrowWait = 2 * time.Minute

// uploadOnce seals a password the agent just read and sends it, with the
// retries a flaky line needs. The password is zeroed by the caller.
func (a *Agent) uploadSecret(ctx context.Context, key *agentproto.EscrowKeyPayload, pub []byte, volume, protector string, pw []byte) (agentproto.EscrowAnswer, error) {
	secret, err := escrowcrypto.NormalizeBitLockerBytes(pw)
	if err != nil {
		return agentproto.EscrowAnswer{}, errors.New("the recovery password is not in the expected form")
	}
	enc, ct, err := escrowcrypto.Seal(pub, escrowcrypto.Context{Org: key.OrgID, Device: a.DeviceID, Volume: volume, Protector: protector, OrgKey: key.KeyID}, secret)
	if err != nil {
		return agentproto.EscrowAnswer{}, errors.New("sealing the recovery password failed")
	}
	fp := escrowcrypto.Fingerprint(protector, secret)
	rec := agentproto.EscrowRecord{
		VolumeID: volume, ProtectorID: protector, Kind: agentproto.EscrowBitLocker, KeyID: key.KeyID,
		Enc: base64.StdEncoding.EncodeToString(enc), Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Fingerprint: hex.EncodeToString(fp[:]),
	}
	var ans agentproto.EscrowAnswer
	for try := range 3 {
		if try > 0 {
			select {
			case <-ctx.Done():
				return ans, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		if ans, err = a.Server.EscrowUpload(ctx, rec); err == nil {
			return ans, nil
		}
	}
	return ans, err
}

// currentKey returns the escrow key the server last signed, nil when it is
// missing or expired.
func (a *Agent) currentKey() (*agentproto.EscrowKeyPayload, []byte) {
	a.mu.Lock()
	key, pub := a.key, a.pub
	a.mu.Unlock()
	if key == nil || !a.now().Before(key.ExpiresAt) {
		return nil, nil
	}
	return key, pub
}

// rotateBitLocker adds a new recovery password to a volume whose old one was
// read, escrows it and, only once the server says it is verified, removes the
// old protector. A new password that did not verify is removed again and the
// old one stays, so the volume is never without a verified escrowed one.
func (a *Agent) rotateBitLocker(ctx context.Context, key *agentproto.EscrowKeyPayload, pub []byte, n agentproto.EscrowNeed) {
	if a.Manager == nil {
		return
	}
	if a.lastTry == nil {
		a.lastTry = map[string]time.Time{}
	}
	now := a.now()
	if t, ok := a.lastTry[n.VolumeID]; ok && now.Sub(t) < VolumeEvery {
		return
	}
	a.lastTry[n.VolumeID] = now
	vol, err := a.volumeByID(ctx, n.VolumeID)
	if err != nil || vol == nil || !slices.Contains(vol.Protectors, n.Rotating) {
		return // the old protector is gone, or the volume is: nothing to rotate
	}
	newID, err := a.Manager.AddRecoveryPassword(ctx, n.VolumeID)
	if err != nil {
		a.Log.Warn("adding a recovery password for a rotation failed", "error", err, "volume", n.VolumeID)
		return
	}
	rollback := func(why string) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := a.Manager.DeleteProtector(rctx, n.VolumeID, newID); err != nil {
			a.Log.Warn("removing a recovery password that was not escrowed failed", "error", err, "volume", n.VolumeID)
		}
		a.Log.Warn("a rotation did not verify; the new recovery password was removed and the old one stays", "why", why, "volume", n.VolumeID)
	}
	a.reportFresh(ctx)
	pw, err := a.Reader.RecoveryPassword(ctx, n.VolumeID, newID)
	if err != nil {
		rollback("reading it failed")
		return
	}
	defer escrowcrypto.Zero(pw)
	ans, err := a.uploadSecret(ctx, key, pub, n.VolumeID, newID, pw)
	escrowcrypto.Zero(pw)
	a.dropProtector(n.VolumeID, newID)
	switch {
	case err != nil:
		rollback("sending it failed")
		return
	case ans.State == agentproto.EscrowPending:
		// The keystore is away: the new password is stored and will be
		// checked; the server then names the old one for removal.
		a.Log.Info("a rotated recovery key is waiting to be verified", "volume", n.VolumeID)
		a.forceReport()
		return
	case ans.State != agentproto.EscrowVerified:
		rollback("the server did not verify it: " + ans.State)
		return
	}
	a.Log.Info("escrowed a rotated BitLocker recovery key", "volume", n.VolumeID)
	a.removeOld(ctx, n.VolumeID, []string{n.Rotating}, newID)
	a.forceReport()
}

// removeOld removes protectors the server replaced with a verified one,
// provided the successor is on the volume and never the successor itself.
func (a *Agent) removeOld(ctx context.Context, volumeID string, old []string, successor string) {
	vol, err := a.volumeByID(ctx, volumeID)
	if err != nil || vol == nil || !slices.Contains(vol.Protectors, successor) {
		a.Log.Warn("a recovery password was not removed: its successor is not on the volume", "volume", volumeID)
		return
	}
	for _, id := range old {
		if id == successor || !slices.Contains(vol.Protectors, id) {
			continue
		}
		if err := a.Manager.DeleteProtector(ctx, volumeID, id); err != nil {
			a.Log.Warn("removing a replaced recovery password failed", "error", err, "volume", volumeID)
		}
	}
}

// removeBitLocker follows the server's word that a verified successor
// replaces old protectors (the verification came after the agent's rotation
// step, because the keystore was away then).
func (a *Agent) removeBitLocker(ctx context.Context, n agentproto.EscrowNeed) {
	if a.Manager == nil {
		return
	}
	a.removeOld(ctx, n.VolumeID, n.Remove, n.Successor)
	a.forceReport()
}

func (a *Agent) volumeByID(ctx context.Context, id string) (*VolumeInfo, error) {
	vols, err := a.Reader.Volumes(ctx)
	if err != nil {
		return nil, err
	}
	for _, v := range vols {
		if v.ID == id {
			return &VolumeInfo{ID: v.ID, Mount: v.Mount, Status: v.Status, Protectors: slices.Clone(v.Protectors), AnyProtectors: len(v.Protectors) > 0}, nil
		}
	}
	return nil, nil
}

// reportFresh reads the volumes and reports them now, so that a protector the
// agent just added is one the server knows before the record for it arrives.
// The needs the answer carries are dropped for that protector by the caller:
// it is being escrowed here.
func (a *Agent) reportFresh(ctx context.Context) {
	vols, err := a.Reader.Volumes(ctx)
	if err != nil {
		a.Log.Debug("reading BitLocker volumes failed", "error", err)
		return
	}
	a.mu.Lock()
	a.sent = nil
	a.mu.Unlock()
	a.report(ctx, vols, a.now(), 0)
}

// dropProtector forgets any need that names a protector the agent has escrowed
// itself.
func (a *Agent) dropProtector(volume, protector string) {
	a.needs = slices.DeleteFunc(a.needs, func(x agentproto.EscrowNeed) bool {
		return x.VolumeID == volume && x.ProtectorID == protector
	})
}

// forceReport has the next sync read and report the volumes again.
func (a *Agent) forceReport() {
	a.mu.Lock()
	a.sent, a.lastRead = nil, time.Time{}
	a.mu.Unlock()
}

// Enable errors, as the result line's codes.
const (
	codeUnsupported     = "unsupported"
	codeNotReady        = "escrow_not_ready"
	codeWrongComputer   = "wrong_computer"
	codeDomainCtrl      = "domain_controller"
	codeNoVolume        = "volume_not_found"
	codeAlreadyOn       = "already_encrypted"
	codeTPM             = "tpm_not_ready"
	codeEdition         = "edition_unsupported"
	codeReboot          = "reboot_pending"
	codeBusy            = "agent_busy"
	codeProtector       = "protector_failed"
	codeUnverified      = "escrow_unverified"
	codeTPMProtector    = "tpm_protector_failed"
	codeEncrypt         = "encrypt_failed"
	codeBadParams       = "bad_params"
	enableUsedSpace     = "used_space"
	enableFull          = "full"
	enableResultVersion = agentproto.NativeBitLockerEnableVersion
)

// EnableBitLocker turns BitLocker on for a volume through the verified-escrow
// gate (ADR-0081 section 5, step 4). The order is fixed, and nothing after
// (b) is taken before the step before it succeeded:
//
//	(a) check the preconditions: the computer is the one named, it is not a
//	    domain controller, a TPM is ready, the edition has BitLocker, no restart
//	    is pending, and the volume is not encrypted;
//	(b) add a numerical-password protector;
//	(c) escrow it and wait for the server to say verified: encryption is
//	    refused until then;
//	(d) add the TPM protector, and
//	(e) start encryption (used space only by default).
//
// A failure after (b) leaves the added protector; it is removed again only
// when the server did not verify it, which makes it useless to keep. The
// result is the one line a script's output would carry, and holds no key.
func (a *Agent) EnableBitLocker(ctx context.Context, p agentproto.BitLockerEnableParams) string {
	fail := func(code, msg string) string {
		return agentproto.NativeResult(enableResultVersion, nil, code, msg)
	}
	if a.Manager == nil {
		return fail(codeUnsupported, "This agent cannot manage BitLocker.")
	}
	mode := p.Encryption
	switch mode {
	case "":
		mode = enableUsedSpace
	case enableUsedSpace, enableFull:
	default:
		return fail(codeBadParams, "The encryption mode is not one this agent knows.")
	}
	key, pub := a.currentKey()
	if key == nil {
		return fail(codeNotReady, "The agent has no escrow key from the server that is current, so no recovery password can be escrowed. Nothing was changed.")
	}
	// The periodic sync and this action must not upload the same protector
	// twice: wait for the sync to end, and hold it off.
	deadline := time.Now().Add(escrowWait)
	for !a.busy.CompareAndSwap(false, true) {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fail(codeBusy, "The agent was busy escrowing keys. Nothing was changed; try again.")
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer a.busy.Store(false)

	// (a) preconditions.
	pre, err := a.Manager.Preconditions(ctx)
	switch {
	case err != nil:
		return fail(codeUnsupported, "BitLocker's state could not be read on this computer. Nothing was changed.")
	case !strings.EqualFold(strings.TrimSpace(pre.Computer), strings.TrimSpace(p.Computer)):
		return fail(codeWrongComputer, "The name typed is not this computer's name. Nothing was changed.")
	case pre.DomainController:
		return fail(codeDomainCtrl, "This computer is a domain controller; BitLocker is not turned on here by EasyRMM. Nothing was changed.")
	case !pre.EditionAllows:
		return fail(codeEdition, "This edition of Windows does not have BitLocker. Nothing was changed.")
	case !pre.TPMReady:
		return fail(codeTPM, "There is no TPM that is present, enabled and ready. Nothing was changed.")
	case pre.RebootPending:
		return fail(codeReboot, "A restart is pending; restart the computer and try again. Nothing was changed.")
	}
	vol, err := a.Manager.Volume(ctx, p.Volume)
	switch {
	case err != nil:
		return fail(codeUnsupported, "The volume could not be read. Nothing was changed.")
	case vol == nil:
		return fail(codeNoVolume, "That volume is not on this computer. Nothing was changed.")
	case vol.Status != "decrypted" || vol.AnyProtectors:
		return fail(codeAlreadyOn, "BitLocker is already on this volume, or has protectors on it. Nothing was changed.")
	}

	// (b) a recovery password.
	pid, err := a.Manager.AddRecoveryPassword(ctx, vol.ID)
	if err != nil {
		return fail(codeProtector, "A recovery password could not be added. Nothing else was changed.")
	}
	removeIt := func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := a.Manager.DeleteProtector(rctx, vol.ID, pid); err != nil {
			a.Log.Warn("removing a recovery password that was not escrowed failed", "error", err)
		}
	}
	// (c) escrow it and wait for verified. The server must know the protector
	// before it takes a record for it.
	a.reportFresh(ctx)
	pw, err := a.Reader.RecoveryPassword(ctx, vol.ID, pid)
	if err != nil {
		removeIt()
		return fail(codeUnverified, "The new recovery password could not be read to escrow it. Encryption was not started.")
	}
	defer escrowcrypto.Zero(pw)
	ans, err := a.uploadSecret(ctx, key, pub, vol.ID, pid, pw)
	escrowcrypto.Zero(pw)
	a.dropProtector(vol.ID, pid)
	if err != nil {
		removeIt()
		return fail(codeUnverified, "The recovery password could not be escrowed. Encryption was not started.")
	}
	if ans.State != agentproto.EscrowVerified {
		if ans.State != agentproto.EscrowPending {
			removeIt()
		}
		return fail(codeUnverified, "The server did not verify the escrowed recovery password ("+ans.State+"). Encryption was not started.")
	}
	// (d) the TPM protector, then (e) encryption.
	if err := a.Manager.AddTPMProtector(ctx, vol.ID); err != nil {
		return fail(codeTPMProtector, "The recovery password is escrowed, but the TPM protector could not be added. Encryption was not started.")
	}
	if err := a.Manager.StartEncryption(ctx, vol.ID, mode == enableUsedSpace); err != nil {
		return fail(codeEncrypt, "The recovery password is escrowed and the TPM protector added, but encryption could not be started.")
	}
	a.forceReport()
	return agentproto.NativeResult(enableResultVersion, agentproto.BitLockerEnableResult{
		Volume: p.Volume, Escrow: agentproto.EscrowVerified, Encryption: "started", Mode: mode,
	}, "", "")
}

// removeLUKS follows the server's word that a verified successor replaces old
// key slots: each is removed through the backend, which refuses the last slot,
// a slot without EasyRMM's token and a slot another token uses.
func (a *Agent) removeLUKS(ctx context.Context, n agentproto.EscrowNeed) {
	vols, err := a.LUKS.Volumes(ctx)
	if err != nil {
		return
	}
	var have []string
	for _, v := range vols {
		if v.UUID == n.VolumeID {
			for _, s := range v.Slots {
				have = append(have, s.TokenID)
			}
		}
	}
	if !slices.Contains(have, n.Successor) {
		a.Log.Warn("a key slot was not removed: its successor is not on the volume", "volume", n.VolumeID)
		return
	}
	for _, id := range n.Remove {
		if id == n.Successor || !slices.Contains(have, id) {
			continue
		}
		if err := a.LUKS.RemoveSlot(ctx, n.VolumeID, id); err != nil {
			a.Log.Warn("removing a replaced key slot failed", "error", err, "volume", n.VolumeID)
		}
	}
	a.luks.sent, a.luks.lastRead = nil, time.Time{}
}
