// Package state keeps the agent's enrollment on disk: the server it belongs
// to, its device id and its private key.
package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Config is the agent's enrollment, stored as JSON. It holds no secret.
type Config struct {
	Server string `json:"server"`
	CAFile string `json:"caFile,omitempty"`
	// TrustSystem is set when a trust instruction widened the agent's trust
	// (ADR-0055): from then on it trusts the system's roots and CAFile
	// together. Without it, CAFile alone is trusted when there is one.
	TrustSystem bool      `json:"trustSystem,omitempty"`
	DeviceID    string    `json:"deviceId"`
	EnrolledAt  time.Time `json:"enrolledAt"`
	// MeshAgentMode is how MeshAgent runs: "service" (a systemd unit or a
	// Windows service; "systemd" in older enrollments) or "child".
	MeshAgentMode string `json:"meshAgentMode"`
	// JobKey is the server's job-signing public key, pinned the first time
	// the server sends it (ADR-0017). Jobs signed by any other key are
	// refused.
	//
	// Since ADR-0057 it is the oldest key of JobKeys, written again with
	// every change so that a build from before that ADR, which reads this
	// field alone, still trusts the key that is used for it. When JobKeys
	// exists the agent ignores JobKey on reading.
	JobKey string `json:"jobKey,omitempty"`
	// JobKeys are the keys the agent trusts, each with its generation
	// (ADR-0057): two in practice, three when it also trusts a key the
	// server never held, at most four.
	JobKeys []JobKey `json:"jobKeys,omitempty"`
	// DroppedJobKeys are keys a cut-over (or trust-key) took away, kept to
	// recognize a job signed with one and to name them in errors. They are
	// public keys and are never trusted.
	DroppedJobKeys []JobKey `json:"droppedJobKeys,omitempty"`
	// KeyTransitionUntil is the end of the declared key transition: ten
	// minutes after the signed cut-over the agent accepted (ADR-0057).
	KeyTransitionUntil time.Time `json:"keyTransitionUntil,omitzero"`
}

// JobKey is a server key and its generation; generation 0 is unknown.
type JobKey struct {
	Key        string `json:"key"`
	Generation int64  `json:"generation,omitempty"`
}

// PinFirstKey pins the server's key from an enrollment answer, with its
// generation (0 from a server that sends none). An empty key pins nothing.
func (c *Config) PinFirstKey(key string, generation int64) {
	if key == "" {
		return
	}
	c.JobKey, c.JobKeys = key, []JobKey{{Key: key, Generation: max(generation, 0)}}
}

// Store reads and writes the agent's files in its state folder. Only Open
// makes one, once it has checked the folder; a Store made any other way
// reads and writes nothing.
type Store struct {
	dir string
}

const (
	pendingFile = "pending.json"
	configFile  = "agent.json"
	keyFile     = "device.key"
	statusFile  = "status.json"
	escrowFile  = "escrow.json"
	trustFile   = "trust.json"
	keysFile    = "jobkeys.json"
	instrFile   = "instructions.json"
	caFile      = "ca.pem"
	packageFile = "package.json"
	// settingsFile holds the settings document the agent applied (ADR-0058).
	settingsFile = "settings.json"
)

// layout is what the agent reads and writes in its folder, for the check
// before any of it is read (host.Paths.CheckState). A folder comes before
// what is in it. When one entry fails the check, its whole group is moved
// aside: the enrollment goes as one, since a key without its configuration,
// or the reverse, is no enrollment; anything else goes on its own, and the
// enrollment stays.
//
// jobs\work is left out: scripts run there, and may leave links or files
// others own. The agent reads nothing from it and empties it when it starts.
var layout = [][]string{
	{configFile, keyFile, pendingFile, caFile},
	{statusFile},
	{escrowFile},
	{trustFile},
	{keysFile},
	{instrFile},
	{settingsFile},
	{packageFile},
	{".tmp-*"},                         // writeFile's
	{"removal.json"},                   // removal.File
	{"update.json", "update.json.tmp"}, // the update's probation marker
	{"logs"},
	{filepath.Join("logs", "*")},
	{"jobs"},
	{filepath.Join("jobs", "journal")},
	{filepath.Join("jobs", "journal", "*")},
	{"easypatch"},
	{filepath.Join("easypatch", "*")},
	{RecoveryDir},
	{filepath.Join(RecoveryDir, "*")},
}

// Open returns the store of the agent's state folder, p.State(), once the
// folder is safe to read: on Windows, what the agent did not make there, or
// cannot trust, is moved aside first and never read (host.Paths.CheckState).
// checked tells what the check changed.
func Open(p host.Paths) (s Store, checked host.StateCheck, err error) {
	checked, err = p.CheckState(layout)
	if err != nil {
		return Store{}, checked, fmt.Errorf("checking the agent's state folder %s: %w", p.State(), err)
	}
	return Store{dir: p.State()}, checked, nil
}

// RecoveryDir is the folder of the agent's recovery copy in its state
// folder (ADR-0069).
const RecoveryDir = "recovery"

// RecoveryCopy is the path of the recovery copy of an executable kept under
// the name of exe's own extension.
func (s Store) RecoveryCopy(exe string) string {
	return filepath.Join(s.dir, RecoveryDir, "easyrmm-agent"+filepath.Ext(exe))
}

// KeepRecovery makes the recovery copy: the program at exe, which is the
// build that is running, in the recovery folder, protected like the rest of
// the state folder. It is written beside the copy and renamed over it, and
// not at all when the copy is the same program already.
func (s Store) KeepRecovery(exe string) error {
	if s.dir == "" {
		return errNotOpened
	}
	dir := filepath.Join(s.dir, RecoveryDir)
	if err := host.Protect(dir); err != nil {
		return fmt.Errorf("protecting %s: %w", dir, err)
	}
	dst := s.RecoveryCopy(exe)
	src, err := os.ReadFile(exe) //nolint:gosec // the agent's own, running executable
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, src) { //nolint:gosec // the recovery copy
		return nil
	}
	return writeFile(dst, src, 0o700)
}

// RemoveRecovery deletes the recovery copy, which goes first when the agent
// is removed. A folder that is not there is not an error.
func (s Store) RemoveRecovery() error {
	if s.dir == "" {
		return errNotOpened
	}
	return os.RemoveAll(filepath.Join(s.dir, RecoveryDir))
}

// errNotOpened stops a store that Open did not make.
var errNotOpened = errors.New("the agent's state folder is used before it was checked")

// path is name in the state folder, or errNotOpened.
func (s Store) path(name string) (string, error) {
	if s.dir == "" {
		return "", errNotOpened
	}
	return filepath.Join(s.dir, name), nil
}

// Dir is the state folder, "" for a store Open did not make.
func (s Store) Dir() string { return s.dir }

// ErrNotEnrolled means the agent has no enrollment yet.
var ErrNotEnrolled = errors.New("the agent is not enrolled")

// Load returns the enrollment and private key.
func (s Store) Load() (*Config, ed25519.PrivateKey, error) {
	path, err := s.path(configFile)
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", configFile, err)
	}
	if c.Server == "" || c.DeviceID == "" {
		return nil, nil, fmt.Errorf("%s is incomplete", configFile)
	}
	key, err := s.loadKey()
	if err != nil {
		return nil, nil, err
	}
	return &c, key, nil
}

func (s Store) loadKey() (ed25519.PrivateKey, error) {
	path, err := s.path(keyFile)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	// On Windows the directory's access list protects the key (host.Protect),
	// and Open checked who made it; file modes say nothing there.
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be readable by its owner only (mode %v)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "EASYRMM DEVICE KEY" || len(blk.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a device key", path)
	}
	return ed25519.NewKeyFromSeed(blk.Bytes), nil
}

// Pending is an agent installed with an approval token, waiting for someone
// to approve the device in the console (ADR-0024). It holds what the
// enrollment needs once approved; the key is the device's own, written
// beside it.
type Pending struct {
	Server        string `json:"server"`
	CAFile        string `json:"caFile,omitempty"`
	MeshAgentMode string `json:"meshAgentMode"`
	// Token is the install command's token: the agent asks with it until
	// the server decides.
	Token string `json:"token"`
	// Code is the device code the console shows.
	Code  string    `json:"code"`
	Since time.Time `json:"since"`
	// Stopped says why the agent stopped asking: the device was rejected,
	// or the server no longer knows the token or the request.
	Stopped   string    `json:"stopped,omitempty"`
	StoppedAt time.Time `json:"stoppedAt,omitzero"`
}

// ErrNotPending means the agent is not waiting for approval.
var ErrNotPending = errors.New("the agent is not waiting for approval")

// SavePending writes a pending enrollment and the device's key, the key
// first, under the same protection as an enrollment.
func (s Store) SavePending(p *Pending, key ed25519.PrivateKey) error {
	if err := s.protect(); err != nil {
		return err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: key.Seed()})
	if err := s.write(keyFile, pemKey); err != nil {
		return err
	}
	return s.UpdatePending(p)
}

// UpdatePending rewrites a pending enrollment.
func (s Store) UpdatePending(p *Pending) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return s.write(pendingFile, append(b, '\n'))
}

// LoadPending returns the pending enrollment and the device's key.
func (s Store) LoadPending() (*Pending, ed25519.PrivateKey, error) {
	path, err := s.path(pendingFile)
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotPending
	}
	if err != nil {
		return nil, nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", pendingFile, err)
	}
	if p.Server == "" || p.Token == "" {
		return nil, nil, fmt.Errorf("%s is incomplete", pendingFile)
	}
	key, err := s.loadKey()
	if err != nil {
		return nil, nil, err
	}
	return &p, key, nil
}

// Approved turns the pending enrollment into the enrollment c, with the key
// already written. The token goes with the pending file.
func (s Store) Approved(c *Config) error {
	if err := s.ClearKeyState(); err != nil {
		return err
	}
	if err := s.SaveConfig(c); err != nil {
		return err
	}
	path, err := s.path(pendingFile)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// NewKey generates a device key pair. Nothing is written yet.
func NewKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// Save writes the enrollment and key. The directory is reachable by root
// (on Windows SYSTEM and Administrators) only, and the key is written
// before the configuration, so a configuration never points at a missing
// key.
func (s Store) Save(c *Config, key ed25519.PrivateKey) error {
	if err := s.protect(); err != nil {
		return err
	}
	// A new enrollment starts a new log (ADR-0057).
	if err := s.ClearKeyState(); err != nil {
		return err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: key.Seed()})
	if err := s.write(keyFile, pemKey); err != nil {
		return err
	}
	return s.SaveConfig(c)
}

// SaveConfig rewrites the configuration of an enrolled agent.
func (s Store) SaveConfig(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return s.write(configFile, append(b, '\n'))
}

// SaveCA keeps a copy of the private certificate authority the agent
// trusts, and returns its path for Config.CAFile.
func (s Store) SaveCA(pem []byte) (string, error) {
	if err := s.protect(); err != nil {
		return "", err
	}
	path, err := s.path(caFile)
	if err != nil {
		return "", err
	}
	return path, writeFile(path, pem, 0o600)
}

// protect creates the state folder if needed, reachable by root (on
// Windows SYSTEM and Administrators) only.
func (s Store) protect() error {
	if s.dir == "" {
		return errNotOpened
	}
	if err := host.Protect(s.dir); err != nil {
		return fmt.Errorf("protecting %s: %w", s.dir, err)
	}
	return nil
}

// write replaces name in the state folder.
func (s Store) write(name string, b []byte) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	return writeFile(path, b, 0o600)
}

// JobsDir holds the job journal and the runs' working directories.
func (s Store) JobsDir() string { return filepath.Join(s.dir, "jobs") }

// Status is what the running agent last observed, for `easyrmm-agent status`.
type Status struct {
	LastHeartbeat time.Time `json:"lastHeartbeat,omitzero"`
	LastError     string    `json:"lastError,omitempty"`
	LastErrorAt   time.Time `json:"lastErrorAt,omitzero"`
	MeshAgent     string    `json:"meshAgent,omitempty"` // "installed", "not available", ...
	MeshNodeID    string    `json:"meshNodeId,omitempty"`
	// InventoryUploaded is when the inventory last reached the server.
	InventoryUploaded time.Time `json:"inventoryUploaded,omitzero"`
	InventoryError    string    `json:"inventoryError,omitempty"`
}

// SaveStatus records the running agent's status.
func (s Store) SaveStatus(st Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.write(statusFile, append(b, '\n'))
}

// LoadStatus reads the last recorded status.
func (s Store) LoadStatus() (Status, error) {
	var st Status
	path, err := s.path(statusFile)
	if err != nil {
		return st, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// EscrowKey is the newest escrow key (ADR-0081) the agent has verified. The
// agent never goes back to an older version, so a replayed instruction cannot
// hand it a key the organization has left. It is a public key and holds no
// secret.
type EscrowKey struct {
	// OrgID is the organization the key belongs to: rollback protection holds
	// within one organization, and a key of another resets the record (a
	// device moved).
	OrgID   string `json:"orgId,omitempty"`
	KeyID   string `json:"keyId"`
	Version int    `json:"version"`
}

// LoadEscrowKey reads the newest escrow key version the agent verified; the
// zero value when there is none.
func (s Store) LoadEscrowKey() EscrowKey {
	var k EscrowKey
	path, err := s.path(escrowFile)
	if err != nil {
		return k
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil || json.Unmarshal(b, &k) != nil {
		return EscrowKey{}
	}
	return k
}

// SaveEscrowKey records the newest escrow key version verified.
func (s Store) SaveEscrowKey(k EscrowKey) error {
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return s.write(escrowFile, append(b, '\n'))
}

// TrustLog is what the agent remembers of the trust instructions it handled
// (ADR-0055), so that one cannot be replayed: the newest issue time handled,
// and each recent instruction's ID with the report made for it.
type TrustLog struct {
	// Issued is the newest IssuedAt of an instruction handled; an instruction
	// issued before it is refused.
	Issued  time.Time      `json:"issued,omitzero"`
	Handled []TrustHandled `json:"handled,omitempty"`
}

// TrustHandled is one instruction handled: its ID, when it was issued and
// the report made for it, as JSON.
type TrustHandled struct {
	ID     string          `json:"id"`
	Issued time.Time       `json:"issued"`
	Report json.RawMessage `json:"report"`
}

// LoadTrustLog reads the trust log; an empty one when there is none or it is
// damaged.
func (s Store) LoadTrustLog() TrustLog {
	var l TrustLog
	path, err := s.path(trustFile)
	if err != nil {
		return l
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil || json.Unmarshal(b, &l) != nil {
		return TrustLog{}
	}
	return l
}

// SaveTrustLog records the trust log.
func (s Store) SaveTrustLog(l TrustLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return s.write(trustFile, append(b, '\n'))
}

// KeyLog is what the agent remembers of the key statements it handled
// (ADR-0057), so that none can be replayed: the newest issue time handled and
// the IDs of recent ones.
type KeyLog struct {
	Issued  time.Time `json:"issued,omitzero"`
	Handled []string  `json:"handled,omitempty"`
}

// LoadKeyLog reads the key statement log; an empty one when there is none or
// it is damaged.
func (s Store) LoadKeyLog() KeyLog {
	var l KeyLog
	path, err := s.path(keysFile)
	if err != nil {
		return l
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil || json.Unmarshal(b, &l) != nil {
		return KeyLog{}
	}
	return l
}

// SaveKeyLog records the key statement log.
func (s Store) SaveKeyLog(l KeyLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return s.write(keysFile, append(b, '\n'))
}

// InstructionLog is the agent's record of the instructions it accepted
// (ADR-0057): the last MaxInstructionLog of them, the sequence of the next,
// and the sequence of the last the server acknowledged.
type InstructionLog struct {
	Next  uint64 `json:"next"`
	Acked uint64 `json:"acked"`
	// Entries are the entries after Acked, oldest first.
	Entries []agentproto.LoggedInstruction `json:"entries,omitempty"`
	// Recent are the last acknowledged entries, for `status`.
	Recent []agentproto.LoggedInstruction `json:"recent,omitempty"`
}

// LoadInstructionLog reads the log; an empty one when there is none or it is
// damaged.
func (s Store) LoadInstructionLog() InstructionLog {
	var l InstructionLog
	path, err := s.path(instrFile)
	if err != nil {
		return l
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil || json.Unmarshal(b, &l) != nil {
		return InstructionLog{}
	}
	return l
}

// SaveInstructionLog records the log.
func (s Store) SaveInstructionLog(l InstructionLog) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return s.write(instrFile, append(b, '\n'))
}

// Settings is what the agent keeps of its signed settings (ADR-0058): the
// document as received, device ID included, and the values applied from it
// (a key whose value was invalid keeps the one it had). It is verified once,
// when it arrives; a rotation of the job key never makes it unreadable. It
// holds no secret.
type Settings struct {
	Document agentproto.SignedSettings  `json:"document"`
	Applied  map[string]json.RawMessage `json:"applied,omitempty"`
}

// LoadSettings reads the settings saved, nil when there are none or the file
// is damaged: the agent then starts from its built-in defaults.
func (s Store) LoadSettings() *Settings {
	path, err := s.path(settingsFile)
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	var st Settings
	if err != nil || json.Unmarshal(b, &st) != nil || st.Document.Payload == "" {
		return nil
	}
	return &st
}

// SaveSettings records the settings applied, as agent.json is written.
func (s Store) SaveSettings(st Settings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.write(settingsFile, append(b, '\n'))
}

// ClearKeyState deletes the key statement log and the instruction log: a new
// enrollment starts both again, so that a device enrolled again is never
// compared with what its previous identity was acknowledged (ADR-0057).
func (s Store) ClearKeyState() error {
	for _, name := range []string{keysFile, instrFile} {
		path, err := s.path(name)
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Package records which package holds the agent (ADR-0056) and what the
// agent says of its enrollment file for `status`. It holds no secret.
type Package struct {
	// Kind is the package that now holds the agent: deb, rpm or msi.
	Kind string `json:"package"`
	// Was is the package that held it before, "" for none: what a rollback
	// of this package goes back to.
	Was string `json:"was,omitempty"`
	// Made says that the install of this package put the agent there, so
	// that rolling it back removes the agent; false where it adopted one
	// already installed.
	Made bool      `json:"made,omitempty"`
	At   time.Time `json:"at"`
	// Note is what the agent last found about install.conf: a refusal, an
	// answer that will not change, or a file it deleted that named another
	// server. "" when there is nothing to say.
	Note   string    `json:"note,omitempty"`
	NoteAt time.Time `json:"noteAt,omitzero"`
}

// ErrNoPackage means no package holds the agent.
var ErrNoPackage = errors.New("no package holds the agent")

// SavePackage writes the package record.
func (s Store) SavePackage(p *Package) error {
	if err := s.protect(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return s.write(packageFile, append(b, '\n'))
}

// LoadPackage reads the package record; ErrNoPackage when there is none.
func (s Store) LoadPackage() (*Package, error) {
	path, err := s.path(packageFile)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoPackage
	}
	if err != nil {
		return nil, err
	}
	var p Package
	if err := json.Unmarshal(b, &p); err != nil || p.Kind == "" {
		return nil, fmt.Errorf("reading %s: damaged", packageFile)
	}
	return &p, nil
}

// RemovePackage deletes the package record.
func (s Store) RemovePackage() error {
	path, err := s.path(packageFile)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Remove deletes the agent's files. RemoveAll follows no link or junction
// below the folder: it deletes the link, not what it points to.
func (s Store) Remove() error {
	if s.dir == "" {
		return errNotOpened
	}
	return os.RemoveAll(s.dir)
}

// writeFile replaces path atomically.
func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
