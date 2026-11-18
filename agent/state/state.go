// Package state keeps the agent's enrollment on disk: the server it belongs
// to, its device id and its private key.
package state

import (
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
)

// Config is the agent's enrollment, stored as JSON. It holds no secret.
type Config struct {
	Server     string    `json:"server"`
	CAFile     string    `json:"caFile,omitempty"`
	DeviceID   string    `json:"deviceId"`
	EnrolledAt time.Time `json:"enrolledAt"`
	// MeshAgentMode is how MeshAgent runs: "service" (a systemd unit or a
	// Windows service; "systemd" in older enrollments) or "child".
	MeshAgentMode string `json:"meshAgentMode"`
	// JobKey is the server's job-signing public key, pinned the first time
	// the server sends it (ADR-0017). Jobs signed by any other key are
	// refused.
	JobKey string `json:"jobKey,omitempty"`
}

// Store reads and writes the agent's files under one directory.
type Store struct {
	Dir string
}

const (
	pendingFile = "pending.json"
	configFile  = "agent.json"
	keyFile     = "device.key"
	statusFile  = "status.json"
)

// ErrNotEnrolled means the agent has no enrollment yet.
var ErrNotEnrolled = errors.New("the agent is not enrolled")

// Load returns the enrollment and private key.
func (s Store) Load() (*Config, ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, configFile))
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
	path := filepath.Join(s.Dir, keyFile)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	// On Windows the directory's access list protects the key (host.Protect);
	// file modes say nothing there.
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
	if err := host.Protect(s.Dir); err != nil {
		return fmt.Errorf("protecting %s: %w", s.Dir, err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: key.Seed()})
	if err := writeFile(filepath.Join(s.Dir, keyFile), pemKey, 0o600); err != nil {
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
	return writeFile(filepath.Join(s.Dir, pendingFile), append(b, '\n'), 0o600)
}

// LoadPending returns the pending enrollment and the device's key.
func (s Store) LoadPending() (*Pending, ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, pendingFile))
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
	if err := s.SaveConfig(c); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.Dir, pendingFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
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
	if err := host.Protect(s.Dir); err != nil {
		return fmt.Errorf("protecting %s: %w", s.Dir, err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: key.Seed()})
	if err := writeFile(filepath.Join(s.Dir, keyFile), pemKey, 0o600); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.Dir, configFile), append(b, '\n'), 0o600)
}

// SaveConfig rewrites the configuration of an enrolled agent.
func (s Store) SaveConfig(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.Dir, configFile), append(b, '\n'), 0o600)
}

// JobsDir holds the job journal and the runs' working directories.
func (s Store) JobsDir() string { return filepath.Join(s.Dir, "jobs") }

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
	return writeFile(filepath.Join(s.Dir, statusFile), append(b, '\n'), 0o600)
}

// LoadStatus reads the last recorded status.
func (s Store) LoadStatus() (Status, error) {
	var st Status
	b, err := os.ReadFile(filepath.Join(s.Dir, statusFile))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// Remove deletes the agent's files.
func (s Store) Remove() error { return os.RemoveAll(s.Dir) }

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
