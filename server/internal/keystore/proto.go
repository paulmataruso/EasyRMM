// Package keystore is the main server's side of the keystore (ADR-0081): the
// socket client, the wire protocol it shares with the keystore process, the
// escrow service and the per-volume escrow state. It holds no key. Every
// wrap, unwrap and check happens in the keystore process
// (server/internal/keystored), which has no network and no database; the
// server passes it wrapped values and gets back public keys, wrapped keys
// and the words "match" or "mismatch".
package keystore

import "time"

// Operations the service socket (server container) accepts.
const (
	OpStatus       = "status"
	OpCreateOrgKey = "create_org_key"
	OpVerifyEscrow = "verify_escrow"
	// OpReadEscrow returns one record's plaintext (ADR-0081 section 7): the
	// only operation that does, counted per organization and in total inside
	// the keystore and written to its log before the answer leaves.
	OpReadEscrow = "read_escrow"
	// OpLog returns the keystore's own log from a sequence number on, for
	// the server's hourly reconciliation.
	OpLog = "log"
	// OpRewrapOrgKey moves an organization's wrapped private key from the
	// KEK version that wraps it to the primary version, inside the keystore
	// (ADR-0081 section 10). The private key never leaves; only the new
	// wrapped form comes back.
	OpRewrapOrgKey = "rewrap_org_key"
	// OpResealEscrow opens an escrow record under the organization's old key
	// and seals it to its new one inside the keystore, with no plaintext
	// leaving it (ADR-0081 section 10, organization key rotation).
	OpResealEscrow = "reseal_escrow"
)

// Web operations: relayed by the server from the HTTP API to the service
// socket so that init, unseal and verify-recovery can be done from the
// console instead of the CLI (ADR-0081 amendment). The server gates them
// behind PermSettingsManage and an active session.
const (
	OpWebInit           = "web_init"
	OpWebUnseal         = "web_unseal"
	OpWebVerifyRecovery = "web_verify_recovery" //nolint:gosec // Not a credential.
)

// Operations only the admin socket accepts: it exists inside the keystore
// container, so only a person at the host (docker compose exec) reaches it.
const (
	OpInit           = "init"
	OpUnseal         = "unseal"
	OpVerifyRecovery = "verify_recovery"
	OpNewVersion     = "new_version"
)

// Error codes in Response.Code.
const (
	CodeUninitialised = "uninitialised"
	CodeSealed        = "sealed"
	CodeNotVerified   = "recovery_not_verified"
	CodeVersionLost   = "kek_version_missing"
	CodeTPMPolicy     = "tpm_policy_changed"
	CodeBadRequest    = "bad_request"
	CodeDenied        = "denied"
	CodeRefused       = "refused"
	// CodeLimit: the keystore's own limit on plaintext-returning calls.
	CodeLimit = "rate_limited"
	// CodeLogBroken: the keystore\'s own log does not verify, so it returns no
	// key and cannot be reconciled.
	CodeLogBroken = "log_broken"
	CodeInternal  = "internal"
)

// Escrow check results.
const (
	Match    = "match"
	Mismatch = "mismatch"
)

// Modes of protecting the KEK on the host (ADR-0081, section 2).
const (
	ModeTPM        = "tpm"
	ModePassphrase = "passphrase"
	ModeFile       = "file"
)

// States of the keystore as a whole.
const (
	StateUninitialised = "uninitialised"
	StateSealed        = "sealed"
	StateUnsealed      = "unsealed"
	// StateUnavailable is the server's own word, for a keystore it cannot
	// reach.
	StateUnavailable = "unavailable"
)

// EscrowContext names what a record belongs to (escrowcrypto.Context).
type EscrowContext struct {
	Org       string `json:"org"`
	Device    string `json:"device"`
	Volume    string `json:"volume"`
	Protector string `json:"protector"`
	OrgKey    string `json:"orgKey"`
	// Kind is the record's kind ("bitlocker", or "luks"); it travels as the
	// request's own field, not in the record's context.
	Kind string `json:"-"`
}

func (c EscrowContext) kindOrDefault() string {
	if c.Kind == "" {
		return "bitlocker"
	}
	return c.Kind
}

// Request is one call. Fields are used by the operation that names them.
type Request struct {
	Op string `json:"op"`
	// ID is the caller's request ID, for the keystore's own record.
	ID string `json:"id,omitempty"`

	// create_org_key
	Org     string `json:"org,omitempty"`
	KeyID   string `json:"keyId,omitempty"`
	Purpose string `json:"purpose,omitempty"`

	// verify_escrow
	WrappedPrivate string         `json:"wrappedPrivate,omitempty"`
	Context        *EscrowContext `json:"context,omitempty"`
	Enc            []byte         `json:"enc,omitempty"`
	Ciphertext     []byte         `json:"ciphertext,omitempty"`
	Fingerprint    []byte         `json:"fingerprint,omitempty"`
	Kind           string         `json:"kind,omitempty"`

	// read_escrow: the escrow record's ID, for the keystore's log.
	Record string `json:"record,omitempty"`

	// reseal_escrow: the organization's new escrow key, as its wrapped private
	// half (the keystore derives the recipient from it; a caller cannot name one). Context names the
	// old key (the one WrappedPrivate is); NewContext differs from it in
	// the key's ID only.
	NewWrapped string         `json:"newWrapped,omitempty"`
	NewContext *EscrowContext `json:"newContext,omitempty"`

	// log
	Since int64 `json:"since,omitempty"`
	Limit int   `json:"limit,omitempty"`

	// Admin operations. Secrets are byte slices so the keystore can zero
	// them; the admin socket is reached only from inside the container.
	Mode       string `json:"mode,omitempty"`
	Passphrase []byte `json:"passphrase,omitempty"`
	Code       []byte `json:"code,omitempty"`
	Bundle     string `json:"bundle,omitempty"`
}

// Response is the answer.
type Response struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`

	Status *Status `json:"status,omitempty"`

	// create_org_key
	PublicKey      []byte `json:"publicKey,omitempty"`
	WrappedPrivate string `json:"wrappedPrivate,omitempty"`
	KEKVersion     int    `json:"kekVersion,omitempty"`

	// verify_escrow: Match or Mismatch, nothing else.
	Result string `json:"result,omitempty"`

	// reseal_escrow: the record sealed to the new key (ciphertext only).
	Enc        []byte `json:"enc,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`

	// read_escrow: the BitLocker recovery password, normalized. The only
	// plaintext the keystore ever returns; both sides zero it after use.
	Plaintext []byte `json:"plaintext,omitempty"`

	// log
	Entries []LogEntry `json:"entries,omitempty"`
	// LogPrev is the hash of the entry before the first returned.
	LogPrev string `json:"logPrev,omitempty"`

	// init
	RecoveryCode string `json:"recoveryCode,omitempty"`
	BundlePath   string `json:"bundlePath,omitempty"`
	Version      int    `json:"version,omitempty"`
}

// KEKVersion is the metadata of one KEK version; no key material.
type KEKVersion struct {
	Version    int    `json:"version"`
	CheckValue string `json:"checkValue"`
	Mode       string `json:"mode"`
	// State is "active" or "pending" (made, its recovery not proved yet).
	State string `json:"state"`
	// Open says whether the version is unsealed in this process.
	Open               bool       `json:"open"`
	CreatedAt          time.Time  `json:"createdAt"`
	RecoveryVerifiedAt *time.Time `json:"recoveryVerifiedAt,omitempty"`
}

// Status is what the keystore says of itself.
type Status struct {
	State string `json:"state"`
	Mode  string `json:"mode,omitempty"`
	// Primary is the version that wraps new keys; 0 while none has its
	// recovery verified.
	Primary  int          `json:"primary"`
	Versions []KEKVersion `json:"versions"`
	// RecoveryVerified says the primary version's recovery was proved.
	RecoveryVerified bool `json:"recoveryVerified"`
	// Detail is the reason in words when the state is not unsealed, such as
	// "TPM policy changed".
	Detail string `json:"detail,omitempty"`
	// SealedAt is when a sealed keystore started waiting for an unseal.
	SealedSince *time.Time `json:"sealedSince,omitempty"`
}

// MaxMessage bounds one request or answer on either socket.
const MaxMessage = 64 << 10

// Limits on plaintext-returning calls inside the keystore (ADR-0081 section
// 7): they hold even when the server's own are skipped.
const (
	OrgReadsPerHour   = 10
	OrgReadsPerDay    = 50
	TotalReadsPerHour = 30
)
