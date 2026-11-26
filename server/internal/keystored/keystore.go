package keystored

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/paulmataruso/easyrmm/internal/escrowcrypto"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// Error is a failure with a code the server maps to a state or a message.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func fail(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// MinPassphrase is the shortest passphrase init accepts.
const MinPassphrase = 16

// Options configure a Keystore.
type Options struct {
	// Dir is the state directory.
	Dir string
	// Mode names the protection mode to use at init: "" chooses TPM where
	// the TPM device exists and a passphrase otherwise; "file" is the
	// opt-in stand-in and is the only way to get it (EASYRMM_KEYSTORE_MODE).
	Mode string
	// OpenTPM opens the TPM; nil uses the kernel's /dev/tpmrm0. Tests give
	// a simulator.
	OpenTPM func() (transport.TPMCloser, error)
	// HasTPM says whether to choose TPM mode when Mode is empty; nil checks
	// that the device exists.
	HasTPM func() bool
	Log    *slog.Logger
	Now    func() time.Time
	// Limits override the plaintext-read limits; zero fields use the
	// keystore package's. Tests shorten them.
	Limits Limits
}

// Keystore holds the KEK versions and does every wrap and check. It is safe
// for concurrent use; one lock covers all, which suffices at the rates
// escrow runs at.
type Keystore struct {
	mu   sync.Mutex
	opts Options
	st   *stateFile
	prot protector
	keks map[int]*Secret
	// detail says why the keystore is sealed, for the console.
	detail      string
	sealedSince time.Time
	log         *journal
	reads       *readCounters
}

// Open loads the state directory. An uninitialized directory is fine; the
// keystore then says so and waits for init. TPM and file modes unseal here;
// a passphrase keystore stays sealed until Unseal.
func Open(opts Options) (*Keystore, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.OpenTPM == nil {
		opts.OpenTPM = openHostTPM
	}
	if opts.HasTPM == nil {
		opts.HasTPM = func() bool { _, err := os.Stat(TPMDevice); return err == nil }
	}
	if opts.Mode != "" && opts.Mode != keystore.ModeTPM && opts.Mode != keystore.ModePassphrase && opts.Mode != keystore.ModeFile {
		return nil, fmt.Errorf("keystore: unknown mode %q", opts.Mode)
	}
	if err := os.MkdirAll(filepath.Join(opts.Dir, recoveryDir), 0o700); err != nil {
		return nil, err
	}
	k := &Keystore{opts: opts, keks: map[int]*Secret{}}
	j, entries, err := openJournal(opts.Dir, opts.Now)
	if err != nil {
		return nil, err
	}
	k.log = j
	k.reads = newReadCounters(opts.Limits, entries, opts.Now())
	st, err := loadState(opts.Dir)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return k, nil
	}
	k.st = st
	if k.prot, err = k.protectorFor(st); err != nil {
		return nil, err
	}
	k.sealedSince = opts.Now()
	k.unsealAll()
	return k, nil
}

func (k *Keystore) protectorFor(st *stateFile) (protector, error) {
	switch st.Mode {
	case keystore.ModeTPM:
		return tpmProtector{open: k.opts.OpenTPM}, nil
	case keystore.ModePassphrase:
		return &passProtector{salt: st.Salt}, nil
	case keystore.ModeFile:
		return fileProtector{}, nil
	}
	return nil, fmt.Errorf("keystore: the state names an unknown mode %q", st.Mode)
}

// Close destroys every key held in memory.
func (k *Keystore) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lockAll()
	k.log.close()
}

func (k *Keystore) lockAll() {
	for v, s := range k.keks {
		s.Destroy()
		delete(k.keks, v)
	}
	if p, ok := k.prot.(*passProtector); ok {
		p.Lock()
	}
}

func (k *Keystore) blobPath(v int) string {
	return filepath.Join(k.opts.Dir, versionFile(v)+".sealed")
}

// unsealAll opens every version the protector can open without a person and
// records why when one cannot. The caller holds the lock (or is Open).
func (k *Keystore) unsealAll() {
	k.detail = ""
	for _, rec := range k.st.Versions {
		if k.keks[rec.Version] != nil {
			continue
		}
		blob, err := os.ReadFile(k.blobPath(rec.Version))
		if err != nil {
			k.detail = fmt.Sprintf("the sealed key of version %d is missing", rec.Version)
			k.opts.Log.Error("keystore: a sealed KEK version cannot be read", "version", rec.Version, "error", err)
			continue
		}
		kek, err := k.prot.Unseal(rec.Version, blob)
		if err != nil {
			switch {
			case errors.Is(err, ErrSealed):
				k.detail = "sealed: waiting for an unseal at the host"
			case errors.Is(err, ErrTPMPolicy):
				k.detail = "TPM policy changed: restore from the recovery bundle"
			default:
				k.detail = "a KEK version cannot be opened"
			}
			k.opts.Log.Warn("keystore: a KEK version did not unseal", "version", rec.Version, "mode", k.st.Mode, "reason", k.detail)
			continue
		}
		if subtle.ConstantTimeCompare(checkValue(kek), rec.CheckValue) != 1 {
			zero(kek)
			k.detail = fmt.Sprintf("KEK version %d fails its check value", rec.Version)
			k.opts.Log.Error("keystore: a KEK version fails its key check value", "version", rec.Version)
			continue
		}
		s, err := NewSecret(kek)
		zero(kek)
		if err != nil {
			k.detail = "memory for the key could not be locked"
			k.opts.Log.Error("keystore: locking the memory of a KEK failed", "error", err)
			continue
		}
		k.keks[rec.Version] = s
	}
}

// Status says what the keystore is and which versions it holds.
func (k *Keystore) Status() keystore.Status {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.statusLocked()
}

func (k *Keystore) statusLocked() keystore.Status {
	if k.st == nil {
		return keystore.Status{State: keystore.StateUninitialised, Versions: []keystore.KEKVersion{}}
	}
	out := keystore.Status{Mode: k.st.Mode, Primary: k.st.primary(), Versions: []keystore.KEKVersion{}}
	for _, r := range k.st.Versions {
		out.Versions = append(out.Versions, keystore.KEKVersion{
			Version: r.Version, CheckValue: fmt.Sprintf("%x", r.CheckValue), Mode: r.Mode, State: r.State,
			Open: k.keks[r.Version] != nil, CreatedAt: r.CreatedAt, RecoveryVerifiedAt: r.RecoveryVerifiedAt,
		})
	}
	out.RecoveryVerified = out.Primary != 0
	if len(k.keks) > 0 {
		out.State = keystore.StateUnsealed
		// A version the data needs may be missing while another opens.
		for _, v := range out.Versions {
			if !v.Open {
				out.Detail = k.detail
			}
		}
		return out
	}
	out.State, out.Detail = keystore.StateSealed, k.detail
	if !k.sealedSince.IsZero() {
		t := k.sealedSince
		out.SealedSince = &t
	}
	return out
}

// chooseMode picks the protection mode for a new keystore.
func (k *Keystore) chooseMode(requested string) (string, error) {
	if requested == keystore.ModeFile && k.opts.Mode != keystore.ModeFile {
		return "", fail(keystore.CodeRefused, "file mode needs EASYRMM_KEYSTORE_MODE=file set on purpose")
	}
	mode := k.opts.Mode
	if requested == keystore.ModeTPM || requested == keystore.ModePassphrase {
		mode = requested
	}
	switch mode {
	case "":
		if k.opts.HasTPM() {
			return keystore.ModeTPM, nil
		}
		return keystore.ModePassphrase, nil
	}
	return mode, nil
}

// Init makes the keystore: a recovery code, KEK version 1 sealed by the mode,
// and version 1's bundle. It returns the recovery code, shown once and never
// stored, and the bundle's path. The version stays pending, and the keystore
// wraps nothing, until VerifyRecovery proves the bundle opens with the code.
func (k *Keystore) Init(requestedMode string, passphrase []byte) (code []byte, bundleFile string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.st != nil {
		return nil, "", fail(keystore.CodeRefused, "the keystore is already initialized")
	}
	mode, err := k.chooseMode(requestedMode)
	if err != nil {
		return nil, "", err
	}
	st := &stateFile{Format: stateFormat, Mode: mode}
	var prot protector
	switch mode {
	case keystore.ModePassphrase:
		if len(passphrase) < MinPassphrase {
			return nil, "", fail(keystore.CodeBadRequest, "the passphrase must be at least %d characters", MinPassphrase)
		}
		st.Salt = make([]byte, saltSize)
		if _, err := rand.Read(st.Salt); err != nil {
			return nil, "", err
		}
		p := &passProtector{salt: st.Salt}
		if err := p.Unlock(passphrase); err != nil {
			return nil, "", err
		}
		prot = p
	case keystore.ModeTPM:
		if !k.opts.HasTPM() {
			return nil, "", fail(keystore.CodeRefused, "no TPM at %s: use passphrase mode", TPMDevice)
		}
		prot = tpmProtector{open: k.opts.OpenTPM}
	case keystore.ModeFile:
		prot = fileProtector{}
	}
	st.RecoverySalt = make([]byte, saltSize)
	if _, err := rand.Read(st.RecoverySalt); err != nil {
		return nil, "", err
	}
	code, err = NewRecoveryCode()
	if err != nil {
		return nil, "", err
	}
	priv, pub, err := recoveryKey(code, st.RecoverySalt)
	if err != nil {
		zero(code)
		return nil, "", err
	}
	zero(priv) // only the public half is kept
	st.RecoveryPub = pub

	k.st, k.prot = st, prot
	bf, err := k.addVersionLocked()
	if err != nil {
		k.st, k.prot = nil, nil
		k.lockAll()
		zero(code)
		return nil, "", err
	}
	return code, bf, nil
}

// addVersionLocked makes the next KEK version: random 32 bytes sealed by the
// mode, its bundle written, state saved. The version is pending.
func (k *Keystore) addVersionLocked() (bundleFile string, err error) {
	kek := make([]byte, KEKSize)
	defer zero(kek)
	if _, err := rand.Read(kek); err != nil {
		return "", err
	}
	v := k.st.newest() + 1
	blob, err := k.prot.Seal(v, kek)
	if err != nil {
		return "", err
	}
	bundleBytes, err := makeBundle(k.st.RecoveryPub, v, kek)
	if err != nil {
		return "", err
	}
	secret, err := NewSecret(kek)
	if err != nil {
		return "", err
	}
	bundleFile = bundlePath(k.opts.Dir, v)
	rec := versionRecord{Version: v, CheckValue: checkValue(kek), Mode: k.st.Mode, State: "pending", CreatedAt: k.opts.Now().UTC()}
	// The sealed key and bundle go to disk before the state names them, so a
	// crash leaves files nothing refers to and never a name with no file.
	if err := writeFileAtomic(k.blobPath(v), blob, 0o600); err != nil {
		secret.Destroy()
		return "", err
	}
	if err := writeFileAtomic(bundleFile, bundleBytes, 0o600); err != nil {
		secret.Destroy()
		return "", err
	}
	k.st.Versions = append(k.st.Versions, rec)
	if err := saveState(k.opts.Dir, k.st); err != nil {
		k.st.Versions = k.st.Versions[:len(k.st.Versions)-1]
		secret.Destroy()
		return "", err
	}
	k.keks[v] = secret
	return bundleFile, nil
}

// NewVersion makes the next KEK version with its bundle. It is pending, and
// the older version stays primary, until its recovery is verified. It needs
// no recovery code: the keystore holds the code's public half only.
func (k *Keystore) NewVersion() (version int, bundleFile string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.st == nil {
		return 0, "", fail(keystore.CodeUninitialised, "the keystore is not initialized")
	}
	if k.st.primary() == 0 {
		return 0, "", fail(keystore.CodeNotVerified, "verify the recovery of the first version before making another")
	}
	if p, ok := k.prot.(*passProtector); ok && p.key == nil {
		return 0, "", fail(keystore.CodeSealed, "%v", ErrSealed)
	}
	bf, err := k.addVersionLocked()
	if err != nil {
		return 0, "", err
	}
	return k.st.newest(), bf, nil
}

// Unseal opens a passphrase keystore. It is offered only on the admin
// socket, so a person at the host does it.
func (k *Keystore) Unseal(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.st == nil {
		return fail(keystore.CodeUninitialised, "the keystore is not initialized")
	}
	p, ok := k.prot.(*passProtector)
	if !ok {
		return fail(keystore.CodeRefused, "this keystore is in %s mode and unseals by itself", k.st.Mode)
	}
	if len(k.keks) > 0 {
		// Never replace the wrap key of an open keystore: a wrong passphrase
		// would then seal the next KEK version under the wrong key.
		return fail(keystore.CodeRefused, "the keystore is already unsealed")
	}
	if err := p.Unlock(passphrase); err != nil {
		return err
	}
	k.unsealAll()
	if len(k.keks) == 0 {
		p.Lock()
		return fail(keystore.CodeDenied, "the passphrase does not open the keystore")
	}
	k.sealedSince = time.Time{}
	return nil
}

// VerifyRecovery proves a bundle restores a KEK version: it opens the bundle
// with the code and compares the key check value. On success the version is
// marked verified, and when it is the newest it becomes primary.
func (k *Keystore) VerifyRecovery(path string, code []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.st == nil {
		return 0, fail(keystore.CodeUninitialised, "the keystore is not initialized")
	}
	v, kek, err := openBundle(path, code, k.st)
	if err != nil {
		return 0, fail(keystore.CodeDenied, "%v", err)
	}
	zero(kek)
	rec := k.st.version(v)
	now := k.opts.Now().UTC()
	prev := *rec
	rec.RecoveryVerifiedAt, rec.State = &now, "active"
	if err := saveState(k.opts.Dir, k.st); err != nil {
		*rec = prev
		return 0, err
	}
	return v, nil
}

// primaryKEK returns the version that wraps and its key, or why there is
// none. The caller holds the lock and must not keep the bytes.
func (k *Keystore) primaryKEK() (int, []byte, error) {
	if k.st == nil {
		return 0, nil, fail(keystore.CodeUninitialised, "the keystore is not initialized")
	}
	v := k.st.primary()
	if v == 0 {
		return 0, nil, fail(keystore.CodeNotVerified, "no KEK version has had its recovery verified: run verify-recovery")
	}
	s := k.keks[v]
	if s == nil {
		if k.st.Mode == keystore.ModeTPM && k.detail != "" {
			return 0, nil, fail(keystore.CodeTPMPolicy, "%s", k.detail)
		}
		return 0, nil, fail(keystore.CodeSealed, "the keystore is sealed")
	}
	return v, s.Bytes(), nil
}

// kekFor returns a version's key for unwrapping.
func (k *Keystore) kekFor(v int) ([]byte, error) {
	if k.st == nil {
		return nil, fail(keystore.CodeUninitialised, "the keystore is not initialized")
	}
	if k.st.version(v) == nil {
		return nil, fail(keystore.CodeVersionLost, "KEK version %d is not in this keystore", v)
	}
	s := k.keks[v]
	if s == nil {
		if len(k.keks) == 0 {
			return nil, fail(keystore.CodeSealed, "the keystore is sealed")
		}
		return nil, fail(keystore.CodeVersionLost, "KEK version %d is not open", v)
	}
	return s.Bytes(), nil
}

// CreateOrgKey makes an organization's key and wraps it under the primary
// KEK. For "escrow" it is an HPKE pair and the public half is returned; for
// "service" it is 32 random bytes. The private half never leaves except
// wrapped.
func (k *Keystore) CreateOrgKey(org, keyID, purpose string) (pub []byte, wrapped string, version int, err error) {
	if org == "" || keyID == "" || (purpose != "escrow" && purpose != "service") ||
		len(org) > 128 || len(keyID) > 128 {
		return nil, "", 0, fail(keystore.CodeBadRequest, "the organization key request is not valid")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	version, kek, err := k.primaryKEK()
	if err != nil {
		return nil, "", 0, err
	}
	var priv []byte
	if purpose == "escrow" {
		priv, pub, err = escrowcrypto.GenerateKey()
	} else {
		priv = make([]byte, KEKSize)
		_, err = rand.Read(priv)
	}
	if err != nil {
		return nil, "", 0, err
	}
	defer zero(priv)
	wrapped, err = wrap(kek, version, wrapAAD(org, keyID, purpose), priv)
	if err != nil {
		return nil, "", 0, err
	}
	return pub, wrapped, version, nil
}

// VerifyEscrow opens an escrow record inside the keystore, computes its
// fingerprint and returns only keystore.Match or keystore.Mismatch. The
// plaintext exists in this function and is zeroed before it returns. A
// record that does not open, does not parse or does not carry the claimed
// fingerprint is a mismatch; a keystore that cannot try is an error.
func (k *Keystore) VerifyEscrow(wrappedPrivate string, c escrowcrypto.Context, enc, ct, claimed []byte, kind string) (string, error) {
	if kind != escrowcrypto.KindBitLocker && kind != escrowcrypto.KindLUKS {
		return "", fail(keystore.CodeBadRequest, "the kind of the record is not known")
	}
	if !c.Valid() || len(claimed) != escrowcrypto.FingerprintSize {
		return "", fail(keystore.CodeBadRequest, "the escrow check request is not valid")
	}
	ver, sealed, err := parseWrapped(wrappedPrivate)
	if err != nil {
		return "", fail(keystore.CodeBadRequest, "the wrapped key is not in a known format")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	kek, err := k.kekFor(ver)
	if err != nil {
		return "", err
	}
	priv, err := unwrap(kek, sealed, wrapAAD(c.Org, c.OrgKey, "escrow"))
	if err != nil {
		// The wrapped key is not this organization's key: a server error,
		// not a verdict on the record.
		return "", fail(keystore.CodeBadRequest, "the wrapped key does not open for this organization")
	}
	defer zero(priv)
	pt, err := escrowcrypto.Open(priv, c, enc, ct)
	if err != nil {
		return keystore.Mismatch, nil
	}
	defer zero(pt)
	norm, err := escrowcrypto.NormalizeBytes(kind, pt)
	if err != nil {
		return keystore.Mismatch, nil
	}
	fp := escrowcrypto.Fingerprint(c.Protector, norm)
	if subtle.ConstantTimeCompare(fp[:], claimed) != 1 {
		return keystore.Mismatch, nil
	}
	return keystore.Match, nil
}

// ReadRequest is what ReadEscrow needs: the same as an escrow check, and the
// IDs for the log.
type ReadRequest struct {
	RequestID, Record string
	// Kind is the record's kind (bitlocker when empty).
	Kind            string
	Wrapped         string
	Context         escrowcrypto.Context
	Enc, Ciphertext []byte
	Fingerprint     []byte
}

// ReadEscrow opens one escrow record and returns its recovery key (a BitLocker password or a LUKS passphrase),
// normalized, in a slice the caller must zero. It is the only call that
// returns a key (ADR-0081 sections 6 and 7). Before it opens anything it
// checks the keystore's own limits (per organization and in total); the log
// line that says a key left is written before the key is returned, and if
// that cannot be written the key is zeroed and refused. A record that does not
// open, or does not carry the fingerprint the server holds for it, is
// refused: nothing is returned for a record that is not the verified one.
func (k *Keystore) ReadEscrow(r ReadRequest) ([]byte, error) {
	c := r.Context
	if !c.Valid() || len(r.Fingerprint) != escrowcrypto.FingerprintSize || r.RequestID == "" || len(r.RequestID) > 128 || len(r.Record) > 128 {
		return nil, fail(keystore.CodeBadRequest, "the read request is not valid")
	}
	ver, sealed, err := parseWrapped(r.Wrapped)
	if err != nil {
		return nil, fail(keystore.CodeBadRequest, "the wrapped key is not in a known format")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	refuse := func(e *Error) ([]byte, error) {
		k.note(keystore.LogEntry{Op: keystore.OpReadEscrow, Org: c.Org, Record: r.Record, RequestID: r.RequestID, Result: e.Code})
		return nil, e
	}
	kek, err := k.kekFor(ver)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return refuse(e)
		}
		return nil, err
	}
	if e := k.reads.check(c.Org, k.opts.Now()); e != nil {
		return refuse(e)
	}
	priv, err := unwrap(kek, sealed, wrapAAD(c.Org, c.OrgKey, "escrow"))
	if err != nil {
		return refuse(fail(keystore.CodeBadRequest, "the wrapped key does not open for this organization"))
	}
	defer zero(priv)
	pt, err := escrowcrypto.Open(priv, c, r.Enc, r.Ciphertext)
	if err != nil {
		return refuse(fail(keystore.CodeRefused, "the record does not open"))
	}
	defer zero(pt) // norm is a subslice of pt; the caller gets a copy
	kind := r.Kind
	if kind == "" {
		kind = escrowcrypto.KindBitLocker
	}
	norm, err := escrowcrypto.NormalizeBytes(kind, pt)
	if err != nil {
		return refuse(fail(keystore.CodeRefused, "the record is not a recovery key"))
	}
	fp := escrowcrypto.Fingerprint(c.Protector, norm)
	if subtle.ConstantTimeCompare(fp[:], r.Fingerprint) != 1 {
		return refuse(fail(keystore.CodeRefused, "the record is not the verified one"))
	}
	if _, err := k.log.append(keystore.LogEntry{Op: keystore.OpReadEscrow, Org: c.Org, Record: r.Record, RequestID: r.RequestID, Result: "ok", Plaintext: true}); err != nil {
		return nil, fail(keystore.CodeLogBroken, "the keystore cannot write its log, so it returns no key")
	}
	k.reads.add(c.Org, k.opts.Now())
	return bytes.Clone(norm), nil
}

// note writes a log line for an operation that returns no key; a failure is
// reported, never fatal.
func (k *Keystore) note(e keystore.LogEntry) {
	if _, err := k.log.append(e); err != nil {
		k.opts.Log.Error("keystore: writing the log failed", "error", err)
	}
}

// LogSince returns the log's entries after seq.
func (k *Keystore) LogSince(seq int64, limit int) (prev string, entries []keystore.LogEntry, err error) {
	prev, entries, err = k.log.since(seq, limit)
	if err != nil {
		return "", nil, fail(keystore.CodeLogBroken, "the keystore's log does not verify or cannot be read")
	}
	return prev, entries, nil
}
